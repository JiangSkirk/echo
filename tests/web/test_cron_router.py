"""Tests for the cron web router."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from js.config import JSSettings, SecurityConfig
from js.cron.engine import ScheduledJob
from js.web.routers.cron import router as cron_router


def _make_client() -> TestClient:
    """Create a TestClient with an admin API key for cron endpoints."""
    app = FastAPI()
    app.include_router(cron_router)
    _settings = JSSettings(
        workspace=Path("/tmp/js_test"),
        state_dir=Path("/tmp/js_test"),
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


# ---------------------------------------------------------------------------
# Jobs
# ---------------------------------------------------------------------------

def test_list_jobs_no_daemon() -> None:
    agent = MagicMock()
    agent._daemon = None

    client = _make_client()
    with patch("js.web.routers.cron.get_agent", return_value=agent):
        resp = client.get("/api/cron/jobs")

    assert resp.status_code == 200
    assert resp.json()["jobs"] == []
    assert resp.json()["running"] is False


def test_list_jobs_with_daemon() -> None:
    agent = MagicMock()
    agent._daemon = _make_daemon()

    client = _make_client()
    with patch("js.web.routers.cron.get_agent", return_value=agent):
        resp = client.get("/api/cron/jobs")

    assert resp.status_code == 200
    data = resp.json()
    assert len(data["jobs"]) == 1
    assert data["running"] is True


def test_get_job_success() -> None:
    agent = MagicMock()
    agent._daemon = _make_daemon()

    client = _make_client()
    with patch("js.web.routers.cron.get_agent", return_value=agent):
        resp = client.get("/api/cron/jobs/job_1")

    assert resp.status_code == 200
    assert resp.json()["job"]["id"] == "job_1"


def test_get_job_not_found() -> None:
    agent = MagicMock()
    daemon = _make_daemon()
    daemon.get_job.return_value = None
    agent._daemon = daemon

    client = _make_client()
    with patch("js.web.routers.cron.get_agent", return_value=agent):
        resp = client.get("/api/cron/jobs/missing")

    assert resp.status_code == 404


def test_get_job_no_daemon() -> None:
    agent = MagicMock()
    agent._daemon = None

    client = _make_client()
    with patch("js.web.routers.cron.get_agent", return_value=agent):
        resp = client.get("/api/cron/jobs/job_1")

    assert resp.status_code == 503


def test_create_job_no_daemon() -> None:
    agent = MagicMock()
    agent._daemon = None

    client = _make_client()
    with patch("js.web.routers.cron.get_agent", return_value=agent):
        resp = client.post("/api/cron/jobs", json={"name": "Job", "cron_expr": "* * * * *"})

    assert resp.status_code == 503


def test_create_job_raw() -> None:
    agent = MagicMock()
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


def test_create_job_natural_language() -> None:
    agent = MagicMock()
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
    agent = MagicMock()
    agent._daemon = _make_daemon()

    client = _make_client()
    with patch("js.web.routers.cron.get_agent", return_value=agent):
        resp = client.post(
            "/api/cron/jobs",
            json={"name": "Bad Job", "cron_expr": "not-a-cron"},
        )

    assert resp.status_code == 400


def test_create_job_missing_schedule() -> None:
    agent = MagicMock()
    agent._daemon = _make_daemon()

    client = _make_client()
    with patch("js.web.routers.cron.get_agent", return_value=agent):
        resp = client.post("/api/cron/jobs", json={"name": "No Schedule"})

    assert resp.status_code == 400


def test_create_job_with_template() -> None:
    agent = MagicMock()
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
    agent = MagicMock()
    agent._daemon = _make_daemon()

    client = _make_client()
    with patch("js.web.routers.cron.get_agent", return_value=agent):
        resp = client.post("/api/cron/jobs", json={"template_id": "nonexistent"})

    assert resp.status_code == 400


def test_update_job_success() -> None:
    agent = MagicMock()
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
    agent = MagicMock()
    agent._daemon = _make_daemon()

    client = _make_client()
    with patch("js.web.routers.cron.get_agent", return_value=agent):
        resp = client.put(
            "/api/cron/jobs/job_1",
            json={"cron_expr": "bad"},
        )

    assert resp.status_code == 400


def test_update_job_not_found() -> None:
    agent = MagicMock()
    daemon = _make_daemon()
    daemon.get_job.return_value = None
    agent._daemon = daemon

    client = _make_client()
    with patch("js.web.routers.cron.get_agent", return_value=agent):
        resp = client.put("/api/cron/jobs/missing", json={"name": "x"})

    assert resp.status_code == 404


def test_delete_job_success() -> None:
    agent = MagicMock()
    agent._daemon = _make_daemon()

    client = _make_client()
    with patch("js.web.routers.cron.get_agent", return_value=agent):
        resp = client.delete("/api/cron/jobs/job_1")

    assert resp.status_code == 200
    assert resp.json()["success"] is True


def test_delete_job_not_found() -> None:
    agent = MagicMock()
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
    agent = MagicMock()
    daemon = _make_daemon()
    result = MagicMock()
    result.success = True
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
    assert data["duration_ms"] == 123.0


def test_run_job_not_found() -> None:
    agent = MagicMock()
    daemon = _make_daemon()
    daemon.cron.run_job_now = AsyncMock(side_effect=ValueError("not found"))
    agent._daemon = daemon

    client = _make_client()
    with patch("js.web.routers.cron.get_agent", return_value=agent):
        resp = client.post("/api/cron/jobs/missing/run")

    assert resp.status_code == 404


def test_history_no_daemon() -> None:
    agent = MagicMock()
    agent._daemon = None

    client = _make_client()
    with patch("js.web.routers.cron.get_agent", return_value=agent):
        resp = client.get("/api/cron/history")

    assert resp.status_code == 200
    assert resp.json()["history"] == []


def test_history_with_daemon() -> None:
    agent = MagicMock()
    agent._daemon = _make_daemon()

    client = _make_client()
    with patch("js.web.routers.cron.get_agent", return_value=agent):
        resp = client.get("/api/cron/history?limit=10")

    assert resp.status_code == 200
    assert "history" in resp.json()


def test_stats_no_daemon() -> None:
    agent = MagicMock()
    agent._daemon = None

    client = _make_client()
    with patch("js.web.routers.cron.get_agent", return_value=agent):
        resp = client.get("/api/cron/stats")

    assert resp.status_code == 200
    assert resp.json()["running"] is False


def test_stats_with_daemon() -> None:
    agent = MagicMock()
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
