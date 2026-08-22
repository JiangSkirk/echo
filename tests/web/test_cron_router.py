"""Tests for the cron web router."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from js.config import JSSettings, SecurityConfig
from js.cron.engine import CronExpression, ScheduledJob
from js.models.providers import ChatMessage
from js.tools.registry import ToolResult
from js.web.routers.cron import router as cron_router


def _make_client() -> TestClient:
    """Create a TestClient with an admin API key for cron endpoints."""
    app = FastAPI()
    app.include_router(cron_router)
    _settings = JSSettings(
        workspace=Path("/tmp/js_test/workspace"),
        state_dir=Path("/tmp/js_test/state"),
        security=SecurityConfig(api_key_required=False),
    )
    patch("js.web.server._settings", _settings).start()

    from js.web.auth import AuthManager
    auth_mgr = AuthManager(_settings.state_dir)
    admin_key = auth_mgr.create_key("test-admin", role="admin")

    return TestClient(app, headers={"X-API-Key": admin_key})


def _make_job() -> ScheduledJob:
    job = ScheduledJob(
        id="job_1",
        name="Test Job",
        cron_expr="*/5 * * * *",
        task_type="custom",
    )
    return job


def _make_daemon() -> MagicMock:
    job = _make_job()

    daemon = MagicMock()
    daemon.list_jobs.return_value = [job]
    daemon.get_job.return_value = job
    daemon.remove_job.return_value = True
    daemon.cron._running = True
    daemon.cron.run_job_now = AsyncMock()
    daemon.store.get_history.return_value = []
    daemon.store.get_stats.return_value = {"total_runs": 5}
    return daemon


def _install_cron_echo_bridge(agent: MagicMock) -> None:
    """Model the Web-to-Echo handoff while handler tests cover real mutations."""
    payloads: dict[str, tuple[str, str, str, dict[str, Any]]] = {}
    results: dict[str, tuple[str, str, str, dict[str, Any]]] = {}
    sequence = 0

    def stage(
        owner: str,
        payload: dict[str, Any],
        *,
        product_id: str = "",
        session_id: str = "",
    ) -> str:
        nonlocal sequence
        assert product_id == "js-agent"
        assert session_id == "cron-control"
        sequence += 1
        reference = f"cron-payload-{sequence}"
        payloads[reference] = (owner, product_id, session_id, dict(payload))
        return reference

    def discard(
        reference: str,
        owner: str,
        *,
        product_id: str = "",
        session_id: str = "",
    ) -> None:
        entry = payloads.get(reference)
        if entry is not None and entry[:3] == (owner, product_id, session_id):
            payloads.pop(reference, None)

    def take_result(
        reference: str,
        owner: str,
        *,
        product_id: str = "",
        session_id: str = "",
    ) -> dict[str, Any] | None:
        entry = results.get(reference)
        if entry is None or entry[:3] != (owner, product_id, session_id):
            return None
        results.pop(reference, None)
        return dict(entry[3])

    def failure(message: str, status_code: int) -> tuple[ChatMessage, ToolResult]:
        result = ToolResult(
            success=False,
            error=message,
            metadata={"status_code": status_code},
        )
        return ChatMessage(role="tool", content=message), result

    async def execute(effect: Any, context: Any) -> tuple[ChatMessage, ToolResult]:
        arguments = json.loads(effect.arguments_json)
        owner, product_id, session_id, payload = payloads.pop(
            arguments["payload_ref"]
        )
        assert product_id == context.product_id
        assert session_id == context.session_id
        daemon = agent._daemon
        if daemon is None:
            return failure("Daemon is not running", 503)
        action = arguments["action"]
        if action == "create":
            template_id = payload.get("template_id")
            if template_id:
                from js.cron.templates import get_template

                template = get_template(template_id)
                if template is None:
                    return failure("Unknown cron template", 400)
                job = ScheduledJob(
                    name=payload.get("name", template.name),
                    description=payload.get("description", template.description),
                    cron_expr=payload.get("cron_expr", template.default_cron),
                    task_type=template.task_type,
                    payload={**template.default_payload, **payload.get("payload", {})},
                )
            else:
                cron_expr = payload.get("cron_expr", "")
                if not cron_expr:
                    from js.cron.nlp import parse_natural_language

                    parsed = parse_natural_language(payload.get("natural_language", ""))
                    if not parsed:
                        return failure("A cron schedule is required", 400)
                    cron_expr = parsed["cron_expr"]
                try:
                    CronExpression(cron_expr)
                except (TypeError, ValueError):
                    return failure("Invalid cron expression", 400)
                job = ScheduledJob(
                    name=payload.get("name", "Untitled Job"),
                    description=payload.get("description", ""),
                    cron_expr=cron_expr,
                    task_type=payload.get("task_type", "custom"),
                    payload=payload.get("payload", {}),
                    schedule_summary=payload.get("schedule_summary", ""),
                    notify_on_success=payload.get("notify_on_success", False),
                    notify_on_failure=payload.get("notify_on_failure", True),
                )
            job.owner_key_hash = owner
            job.product_id = "js-agent"
            job.session_id = f"cron:{job.id}"
            daemon.add_job(job)
            response: dict[str, Any] = {"success": True, "job": job.to_dict()}
        else:
            job_id = payload["job_id"]
            if action == "delete":
                if not daemon.remove_job(job_id, owner_key_hash=owner):
                    return failure("Cron job not found", 404)
                response = {"success": True}
            else:
                job = daemon.get_job(job_id, owner_key_hash=owner)
                if job is None:
                    return failure("Cron job not found", 404)
                if action == "run":
                    try:
                        run_result = await daemon.cron.run_job_now(job_id)
                    except ValueError:
                        return failure("Cron job not found", 404)
                    response = {
                        "success": run_result.success,
                        "status": run_result.status,
                        "duration_ms": run_result.duration_ms,
                        "output": run_result.output,
                        "error": run_result.error,
                    }
                else:
                    changes = payload["changes"]
                    if "cron_expr" in changes:
                        try:
                            cron = CronExpression(changes["cron_expr"])
                        except (TypeError, ValueError):
                            return failure("Invalid cron expression", 400)
                        job.cron_expr = changes["cron_expr"]
                        job.next_run_at = cron.next_run()
                    for field in (
                        "name",
                        "description",
                        "enabled",
                        "task_type",
                        "payload",
                        "notify_on_success",
                        "notify_on_failure",
                    ):
                        if field in changes:
                            setattr(job, field, changes[field])
                    job.updated_at = time.time()
                    daemon._persist_job(job)
                    response = {"success": True, "job": job.to_dict()}

        result_ref = f"cron-result-{arguments['payload_ref']}"
        results[result_ref] = (owner, product_id, session_id, response)
        result = ToolResult(
            success=True,
            output="Cron mutation completed",
            metadata={"result_ref": result_ref},
        )
        return ChatMessage(role="tool", content=result.output), result

    agent.settings.product_id = "js-agent"
    agent.stage_cron_mutation_payload = MagicMock(side_effect=stage)
    agent.discard_cron_mutation_payload = MagicMock(side_effect=discard)
    agent.take_cron_mutation_result = MagicMock(side_effect=take_result)
    context = MagicMock()
    context.product_id = "js-agent"
    context.session_id = "cron-control"
    agent.echo_runtime.build_context.return_value = context
    agent.echo_runtime.execute_tool_effect = AsyncMock(side_effect=execute)


def _make_agent() -> MagicMock:
    agent = MagicMock()
    _install_cron_echo_bridge(agent)
    return agent


# ---------------------------------------------------------------------------
# Jobs
# ---------------------------------------------------------------------------

def test_list_jobs_no_daemon() -> None:
    agent = _make_agent()
    agent._daemon = None

    client = _make_client()
    with patch("js.web.routers.cron.get_agent", return_value=agent):
        resp = client.get("/api/cron/jobs")

    assert resp.status_code == 200
    assert resp.json()["jobs"] == []
    assert resp.json()["running"] is False


def test_list_jobs_with_daemon() -> None:
    agent = _make_agent()
    agent._daemon = _make_daemon()

    client = _make_client()
    with patch("js.web.routers.cron.get_agent", return_value=agent):
        resp = client.get("/api/cron/jobs")

    assert resp.status_code == 200
    data = resp.json()
    assert len(data["jobs"]) == 1
    assert data["running"] is True


def test_get_job_success() -> None:
    agent = _make_agent()
    agent._daemon = _make_daemon()

    client = _make_client()
    with patch("js.web.routers.cron.get_agent", return_value=agent):
        resp = client.get("/api/cron/jobs/job_1")

    assert resp.status_code == 200
    assert resp.json()["job"]["id"] == "job_1"


def test_get_job_not_found() -> None:
    agent = _make_agent()
    daemon = _make_daemon()
    daemon.get_job.return_value = None
    agent._daemon = daemon

    client = _make_client()
    with patch("js.web.routers.cron.get_agent", return_value=agent):
        resp = client.get("/api/cron/jobs/missing")

    assert resp.status_code == 404


def test_get_job_no_daemon() -> None:
    agent = _make_agent()
    agent._daemon = None

    client = _make_client()
    with patch("js.web.routers.cron.get_agent", return_value=agent):
        resp = client.get("/api/cron/jobs/job_1")

    assert resp.status_code == 503


def test_create_job_no_daemon() -> None:
    agent = _make_agent()
    agent._daemon = None

    client = _make_client()
    with patch("js.web.routers.cron.get_agent", return_value=agent):
        resp = client.post("/api/cron/jobs", json={"name": "Job", "cron_expr": "* * * * *"})

    assert resp.status_code == 503


def test_create_job_raw() -> None:
    agent = _make_agent()
    agent._daemon = _make_daemon()

    client = _make_client()
    with patch("js.web.routers.cron.get_agent", return_value=agent):
        resp = client.post(
            "/api/cron/jobs",
            json={"name": "Raw Job", "cron_expr": "0 8 * * *", "task_type": "custom"},
        )

    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    assert data["job"]["name"] == "Raw Job"
    agent._daemon.add_job.assert_called_once()
    created = agent._daemon.add_job.call_args.args[0]
    assert created.owner_key_hash
    assert created.product_id == "js-agent"


def test_create_job_routes_private_payload_through_opaque_echo_effect() -> None:
    agent = _make_agent()
    agent._daemon = _make_daemon()
    private_name = "private customer schedule"
    private_prompt = "private synthetic prompt"
    agent.stage_cron_mutation_payload.side_effect = None
    agent.stage_cron_mutation_payload.return_value = "cron-private-ref"
    agent.take_cron_mutation_result.side_effect = None
    agent.take_cron_mutation_result.return_value = {
        "success": True,
        "job": {"id": "job-private", "name": private_name},
    }
    agent.echo_runtime.execute_tool_effect = AsyncMock(
        return_value=(
            ChatMessage(role="tool", content="Cron mutation completed"),
            ToolResult(
                success=True,
                output="Cron mutation completed",
                metadata={"result_ref": "cron-result-ref"},
            ),
        )
    )

    client = _make_client()
    with patch("js.web.routers.cron.get_agent", return_value=agent):
        resp = client.post(
            "/api/cron/jobs",
            json={
                "name": private_name,
                "cron_expr": "0 8 * * *",
                "payload": {"prompt": private_prompt},
            },
        )

    assert resp.status_code == 200
    agent._daemon.add_job.assert_not_called()
    effect, _context = agent.echo_runtime.execute_tool_effect.await_args.args
    assert effect.tool_name == "control_cron_mutate"
    assert effect.arguments_json == (
        '{"action":"create","payload_ref":"cron-private-ref"}'
    )
    assert private_name not in effect.arguments_json
    assert private_prompt not in effect.arguments_json


def test_create_job_natural_language() -> None:
    agent = _make_agent()
    agent._daemon = _make_daemon()

    client = _make_client()
    with patch("js.web.routers.cron.get_agent", return_value=agent):
        resp = client.post(
            "/api/cron/jobs",
            json={"name": "NL Job", "natural_language": "每天早上8点"},
        )

    assert resp.status_code == 200
    assert resp.json()["success"] is True


def test_create_job_invalid_cron() -> None:
    agent = _make_agent()
    agent._daemon = _make_daemon()

    client = _make_client()
    with patch("js.web.routers.cron.get_agent", return_value=agent):
        resp = client.post(
            "/api/cron/jobs",
            json={"name": "Bad Job", "cron_expr": "not-a-cron"},
        )

    assert resp.status_code == 400


def test_create_job_missing_schedule() -> None:
    agent = _make_agent()
    agent._daemon = _make_daemon()

    client = _make_client()
    with patch("js.web.routers.cron.get_agent", return_value=agent):
        resp = client.post("/api/cron/jobs", json={"name": "No Schedule"})

    assert resp.status_code == 400


def test_create_job_with_template() -> None:
    agent = _make_agent()
    agent._daemon = _make_daemon()

    client = _make_client()
    with patch("js.web.routers.cron.get_agent", return_value=agent):
        resp = client.post(
            "/api/cron/jobs",
            json={"template_id": "health_check", "name": "My Health"},
        )

    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    assert data["job"]["name"] == "My Health"


def test_create_job_unknown_template() -> None:
    agent = _make_agent()
    agent._daemon = _make_daemon()

    client = _make_client()
    with patch("js.web.routers.cron.get_agent", return_value=agent):
        resp = client.post("/api/cron/jobs", json={"template_id": "nonexistent"})

    assert resp.status_code == 400


def test_update_job_success() -> None:
    agent = _make_agent()
    agent._daemon = _make_daemon()

    client = _make_client()
    with patch("js.web.routers.cron.get_agent", return_value=agent):
        resp = client.put(
            "/api/cron/jobs/job_1",
            json={"name": "Updated", "cron_expr": "0 9 * * *"},
        )

    assert resp.status_code == 200
    assert resp.json()["success"] is True
    assert resp.json()["job"]["name"] == "Updated"


def test_update_job_invalid_cron() -> None:
    agent = _make_agent()
    agent._daemon = _make_daemon()

    client = _make_client()
    with patch("js.web.routers.cron.get_agent", return_value=agent):
        resp = client.put(
            "/api/cron/jobs/job_1",
            json={"cron_expr": "bad"},
        )

    assert resp.status_code == 400


def test_update_job_not_found() -> None:
    agent = _make_agent()
    daemon = _make_daemon()
    daemon.get_job.return_value = None
    agent._daemon = daemon

    client = _make_client()
    with patch("js.web.routers.cron.get_agent", return_value=agent):
        resp = client.put("/api/cron/jobs/missing", json={"name": "x"})

    assert resp.status_code == 404


def test_delete_job_success() -> None:
    agent = _make_agent()
    agent._daemon = _make_daemon()

    client = _make_client()
    with patch("js.web.routers.cron.get_agent", return_value=agent):
        resp = client.delete("/api/cron/jobs/job_1")

    assert resp.status_code == 200
    assert resp.json()["success"] is True


def test_delete_job_not_found() -> None:
    agent = _make_agent()
    daemon = _make_daemon()
    daemon.remove_job.return_value = False
    agent._daemon = daemon

    client = _make_client()
    with patch("js.web.routers.cron.get_agent", return_value=agent):
        resp = client.delete("/api/cron/jobs/missing")

    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Run / History / Stats / Templates / Parse
# ---------------------------------------------------------------------------

def test_run_job_now_success() -> None:
    agent = _make_agent()
    daemon = _make_daemon()
    result = MagicMock()
    result.success = True
    result.status = "completed"
    result.duration_ms = 123.0
    result.output = "done"
    result.error = None
    daemon.cron.run_job_now = AsyncMock(return_value=result)
    agent._daemon = daemon

    client = _make_client()
    with patch("js.web.routers.cron.get_agent", return_value=agent):
        resp = client.post("/api/cron/jobs/job_1/run")

    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    assert data["status"] == "completed"
    assert data["duration_ms"] == 123.0


def test_run_job_not_found() -> None:
    agent = _make_agent()
    daemon = _make_daemon()
    daemon.cron.run_job_now = AsyncMock(side_effect=ValueError("not found"))
    agent._daemon = daemon

    client = _make_client()
    with patch("js.web.routers.cron.get_agent", return_value=agent):
        resp = client.post("/api/cron/jobs/missing/run")

    assert resp.status_code == 404


def test_history_no_daemon() -> None:
    agent = _make_agent()
    agent._daemon = None

    client = _make_client()
    with patch("js.web.routers.cron.get_agent", return_value=agent):
        resp = client.get("/api/cron/history")

    assert resp.status_code == 200
    assert resp.json()["history"] == []


def test_history_with_daemon() -> None:
    agent = _make_agent()
    agent._daemon = _make_daemon()

    client = _make_client()
    with patch("js.web.routers.cron.get_agent", return_value=agent):
        resp = client.get("/api/cron/history?limit=10")

    assert resp.status_code == 200
    assert "history" in resp.json()


def test_stats_no_daemon() -> None:
    agent = _make_agent()
    agent._daemon = None

    client = _make_client()
    with patch("js.web.routers.cron.get_agent", return_value=agent):
        resp = client.get("/api/cron/stats")

    assert resp.status_code == 200
    assert resp.json()["running"] is False


def test_stats_with_daemon() -> None:
    agent = _make_agent()
    agent._daemon = _make_daemon()

    client = _make_client()
    with patch("js.web.routers.cron.get_agent", return_value=agent):
        resp = client.get("/api/cron/stats")

    assert resp.status_code == 200
    data = resp.json()
    assert data["running"] is True
    assert len(data["jobs"]) == 1


def test_templates() -> None:
    client = _make_client()
    resp = client.get("/api/cron/templates")

    assert resp.status_code == 200
    data = resp.json()
    assert len(data["templates"]) > 0
    assert any(t["id"] == "health_check" for t in data["templates"])


def test_templates_filter_category() -> None:
    client = _make_client()
    resp = client.get("/api/cron/templates?category=maintenance")

    assert resp.status_code == 200
    data = resp.json()
    # Should still return at least health_check
    assert len(data["templates"]) >= 1


def test_parse_natural_matched() -> None:
    client = _make_client()
    resp = client.post("/api/cron/parse", json={"text": "每天早上8点"})

    assert resp.status_code == 200
    data = resp.json()
    assert data["matched"] is True
    assert data["cron_expr"] == "0 8 * * *"


def test_parse_natural_empty() -> None:
    client = _make_client()
    resp = client.post("/api/cron/parse", json={"text": ""})

    assert resp.status_code == 200
    data = resp.json()
    assert "examples" in data


def test_parse_natural_no_match() -> None:
    client = _make_client()
    resp = client.post("/api/cron/parse", json={"text": "asdfghjkl12345"})

    assert resp.status_code == 200
    data = resp.json()
    assert data["matched"] is False
    assert "examples" in data
