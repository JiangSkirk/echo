"""Tests for the simplified fleet web router."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from js.config import JSSettings, SecurityConfig
from js.models.providers import ChatMessage
from js.tools.registry import ToolResult
from js.web.routers.fleet import router as fleet_router


def _make_client() -> TestClient:
    """Create a TestClient with an admin API key for fleet endpoints."""
    app = FastAPI()
    app.include_router(fleet_router)
    _settings = JSSettings(
        workspace=Path("/tmp/js_test/workspace"),
        state_dir=Path("/tmp/js_test/state"),
        security=SecurityConfig(api_key_required=False),
    )
    patch("js.web.server._settings", _settings).start()

    from js.web.auth import AuthManager

    auth_mgr = AuthManager(_settings.state_dir)
    admin_key = auth_mgr.create_key("test-admin", role="admin")

    agent = MagicMock()
    agent.settings = _settings
    agent.echo_runtime.build_context.return_value = MagicMock(capabilities=("fleet_collaborate",))
    agent.echo_runtime.execute_tool_effect = AsyncMock(
        return_value=(
            ChatMessage(role="tool", content="done", name="fleet_collaborate"),
            ToolResult(
                success=True,
                output="done",
                metadata={
                    "session_id": "session-1",
                    "mode": "auto",
                    "subtask_count": 0,
                    "subtasks": {},
                },
            ),
        )
    )
    from js.web.deps import set_globals

    set_globals(agent, _settings)
    app.state.test_agent = agent

    return TestClient(app, headers={"X-API-Key": admin_key})


def _make_fleet() -> MagicMock:
    fleet = MagicMock()
    fleet.get_status.return_value = {"agents": []}
    fleet.collaborate = AsyncMock(return_value={"final": "done", "subtasks": {}, "review": None})
    return fleet


def test_fleet_status() -> None:
    fleet = _make_fleet()

    client = _make_client()
    with patch("js.web.routers.fleet.get_fleet", return_value=fleet):
        resp = client.get("/api/fleet/status")

    assert resp.status_code == 200
    fleet.get_status.assert_called_once()
    assert fleet.get_status.call_args.kwargs["owner_key_hash"]


def test_fleet_collaborate_success() -> None:
    client = _make_client()
    resp = client.post(
        "/api/fleet/collaborate",
        json={
            "task": "Build app",
            "subtasks": ["Write code", "Review code"],
        },
    )

    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    assert data["final"] == "done"
    agent = client.app.state.test_agent
    agent.echo_runtime.execute_tool_effect.assert_awaited_once()
    effect, _context = agent.echo_runtime.execute_tool_effect.await_args.args
    assert effect.tool_name == "fleet_collaborate"
    assert effect.allowed_tools == ("fleet_collaborate",)
    assert "Build app" in effect.arguments_json
    assert "Write code" in effect.arguments_json


def test_fleet_collaborate_no_subtasks() -> None:
    client = _make_client()
    resp = client.post(
        "/api/fleet/collaborate",
        json={"task": "Build app"},
    )

    assert resp.status_code == 200
    agent = client.app.state.test_agent
    effect, _context = agent.echo_runtime.execute_tool_effect.await_args.args
    assert '"subtasks":null' in effect.arguments_json
    assert '"mode":"auto"' in effect.arguments_json


def test_fleet_collaborate_failure() -> None:
    client = _make_client()
    agent = client.app.state.test_agent
    agent.echo_runtime.execute_tool_effect.return_value = (
        ChatMessage(role="tool", content="failed", name="fleet_collaborate"),
        ToolResult(
            success=False,
            error="Fleet collaboration failed",
            metadata={"status_code": 500},
        ),
    )
    resp = client.post("/api/fleet/collaborate", json={"task": "x"})

    assert resp.status_code == 500


def test_fleet_collaborate_capacity_exhausted() -> None:
    client = _make_client()
    agent = client.app.state.test_agent
    agent.echo_runtime.execute_tool_effect.return_value = (
        ChatMessage(role="tool", content="failed", name="fleet_collaborate"),
        ToolResult(
            success=False,
            error="Fleet capacity is exhausted",
            metadata={"status_code": 503},
        ),
    )
    resp = client.post("/api/fleet/collaborate", json={"task": "x"})

    assert resp.status_code == 503
    assert "capacity" in resp.json()["detail"].lower()


def test_fleet_collaborate_missing_task() -> None:
    fleet = _make_fleet()

    client = _make_client()
    with patch("js.web.routers.fleet.get_fleet", return_value=fleet):
        resp = client.post("/api/fleet/collaborate", json={})

    assert resp.status_code == 422


def test_fleet_continue_executes_hidden_echo_effect() -> None:
    client = _make_client()
    agent = client.app.state.test_agent
    agent.echo_runtime.execute_tool_effect.return_value = (
        ChatMessage(role="tool", content="continued", name="control_fleet_continue"),
        ToolResult(
            success=True,
            output="continued",
            metadata={"session_id": "session-1", "subtasks": {}},
        ),
    )

    with patch(
        "js.web.routers.fleet.get_fleet",
        side_effect=AssertionError("raw Fleet continuation bypass"),
    ):
        resp = client.post(
            "/api/fleet/sessions/session-1/continue",
            json={"follow_up": "Continue safely"},
        )

    assert resp.status_code == 200
    effect, _context = agent.echo_runtime.execute_tool_effect.await_args.args
    assert effect.tool_name == "control_fleet_continue"
    assert effect.allowed_tools == ("control_fleet_continue",)
    assert effect.arguments_json == ('{"follow_up":"Continue safely","session_id":"session-1"}')


def test_fleet_delete_executes_hidden_echo_effect() -> None:
    client = _make_client()
    agent = client.app.state.test_agent
    agent.echo_runtime.execute_tool_effect.return_value = (
        ChatMessage(role="tool", content="deleted", name="control_fleet_session_delete"),
        ToolResult(
            success=True,
            output="deleted",
            metadata={"session_id": "session-1"},
        ),
    )

    with patch(
        "js.web.routers.fleet.get_fleet",
        side_effect=AssertionError("raw Fleet deletion bypass"),
    ):
        resp = client.delete("/api/fleet/sessions/session-1")

    assert resp.status_code == 200
    effect, _context = agent.echo_runtime.execute_tool_effect.await_args.args
    assert effect.tool_name == "control_fleet_session_delete"
    assert effect.allowed_tools == ("control_fleet_session_delete",)
    assert effect.arguments_json == '{"session_id":"session-1"}'


def test_fleet_continue_rejects_non_string_follow_up() -> None:
    client = _make_client()
    agent = client.app.state.test_agent

    resp = client.post(
        "/api/fleet/sessions/session-1/continue",
        json={"follow_up": ["not", "a", "string"]},
    )

    assert resp.status_code == 422
    agent.echo_runtime.execute_tool_effect.assert_not_awaited()


@pytest.mark.parametrize("endpoint", ["/api/fleet/history", "/api/fleet/sessions/session-1"])
def test_fleet_read_errors_do_not_expose_internal_exception(
    endpoint: str,
) -> None:
    client = _make_client()
    secret = "/Users/private/customer/history.json secret-token"

    with patch(
        "js.web.routers.fleet.get_fleet",
        side_effect=RuntimeError(secret),
    ):
        resp = client.get(endpoint)

    assert resp.status_code == 500
    assert secret not in resp.text
    assert "/Users/private" not in resp.text
