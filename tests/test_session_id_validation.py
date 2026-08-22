"""F-01: unified session_id validation via real HTTP/WS TestClient requests."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from js.config import JSSettings, SecurityConfig
from js.echo.turn_context import RuntimeContext, runtime_context_error
from js.web.auth import AuthManager
from js.web.deps import (
    optional_query_session_id,
    require_path_session_id,
    require_upload_session_id,
)
from js.web.ids import InvalidRuntimeIdError, coerce_optional_session_id, validate_session_id
from js.web.server import (
    _require_path_session_id,
    _require_upload_session_id,
    create_app,
)

# Avoid `/` in path ids — `%2F` is treated as a path separator by Starlette.
_BAD_SESSION = 'evil"><script>alert(1)'
_BAD_PATH_SESSION = "a" * 200
_WS_ORIGIN = {"Host": "localhost", "Origin": "http://localhost"}


def _settings(tmp_path: Path) -> JSSettings:
    return JSSettings(
        workspace=tmp_path / "workspace",
        state_dir=tmp_path / "state",
        security=SecurityConfig(api_key_required=False),
        first_run_completed=True,
    )


def _mock_agent(settings: JSSettings) -> MagicMock:
    agent = MagicMock()
    agent.settings = settings
    agent._cancel_tokens = {}
    agent._active_run_tasks = {}
    agent._shutdown_requested = False
    agent._lane_executor = None
    agent.registry.get_stats.return_value = {}
    agent.secrets.get_stats.return_value = {}
    agent.memory.get_sessions.return_value = []
    agent.memory.get_episodes.return_value = []
    agent.memory.get_dream_logs.return_value = []
    agent.memory.get_all_semantic.return_value = []
    agent.memory.get_all_working.return_value = []
    agent.memory.list_memory_files.return_value = []
    agent.memory.get_context_string.return_value = ""
    agent.memory.get_working.return_value = []
    agent.memory.get_capsule.return_value = None
    agent.memory.get_session_messages.return_value = []
    agent.audit.query.return_value = []
    agent.request_cancel = MagicMock(return_value=False)
    agent.bind_cancel_token = MagicMock()
    agent.unbind_cancel_token = MagicMock()
    agent.echo_runtime = MagicMock()
    agent.echo_runtime.build_context.return_value = MagicMock(
        product_id="js-agent",
        session_id="sess",
        capabilities=("file_list",),
    )
    agent.echo_runtime.execute_tool_effect = AsyncMock(
        return_value=(MagicMock(), MagicMock(success=True, output=[], error=None))
    )
    return agent


def _client(tmp_path: Path, *, role: str = "admin") -> tuple[TestClient, MagicMock]:
    settings = _settings(tmp_path)
    agent = _mock_agent(settings)

    @asynccontextmanager
    async def _noop_lifespan(_app: Any) -> AsyncIterator[None]:
        yield

    with patch("js.web.server.lifespan", _noop_lifespan):
        from js.web import server as web_server
        from js.web.deps import set_globals

        web_server._agent = agent
        web_server._settings = settings
        set_globals(agent, settings)
        app = create_app()

    key = AuthManager(settings.state_dir).create_key("session-id-test", role=role)
    client = TestClient(
        app,
        base_url="http://localhost",
        headers={"Origin": "http://localhost", "X-API-Key": key},
    )
    return client, agent


def test_validate_session_id_rejects_metacharacters() -> None:
    for bad in (
        'sess"id',
        "sess'id",
        "sess<script>",
        "sess\nid",
        "a" * 200,
        "",
    ):
        with pytest.raises(InvalidRuntimeIdError):
            validate_session_id(bad)
    with pytest.raises(InvalidRuntimeIdError):
        coerce_optional_session_id(123)


def test_coerce_optional_session_id_allows_empty_as_none() -> None:
    assert coerce_optional_session_id(None) is None
    assert coerce_optional_session_id("") is None
    assert coerce_optional_session_id("  ") is None
    assert coerce_optional_session_id("sess-ok-1") == "sess-ok-1"


def test_http_path_session_id_rejects_malicious() -> None:
    with pytest.raises(HTTPException) as exc:
        _require_path_session_id(_BAD_SESSION)
    assert exc.value.status_code == 400
    assert "session" in str(exc.value.detail).lower()
    assert require_path_session_id("sess-ok-1") == "sess-ok-1"


def test_upload_session_id_required_message() -> None:
    with pytest.raises(HTTPException) as exc:
        _require_upload_session_id(None)
    assert exc.value.status_code == 400
    assert "session_id is required" in str(exc.value.detail)
    assert require_upload_session_id("upload-sess-1") == "upload-sess-1"


def test_runtime_context_session_id_matches_ids_rules(tmp_path: Path) -> None:
    """Echo RuntimeContext rejects the same hostile session_ids as ids.py."""
    workspace = (tmp_path / "workspace").resolve()
    state_dir = (tmp_path / "state").resolve()
    workspace.mkdir()
    state_dir.mkdir()

    base = {
        "product_id": "js-agent",
        "channel": "unit",
        "owner_key_hash": "owner",
        "run_id": "run-1",
        "role": "user",
        "profile": "default",
        "capabilities": (),
        "workspace": workspace,
        "state_dir": state_dir,
        "fs_roots": (workspace,),
        "cancel_token": asyncio.Event(),
        "deadline_ms": int(1e15),
    }
    assert runtime_context_error(RuntimeContext(session_id="sess-ok-1", **base)) is None
    for bad in (_BAD_SESSION, "a" * 200, "bad session", "sess\nid"):
        with pytest.raises(InvalidRuntimeIdError):
            validate_session_id(bad)
        err = runtime_context_error(RuntimeContext(session_id=bad, **base))
        assert err is not None
        assert "session_id" in err


def test_api_chat_rejects_hostile_session_id(tmp_path: Path) -> None:
    client, _agent = _client(tmp_path, role="user")
    resp = client.post(
        "/api/chat",
        json={"message": "hi", "session_id": _BAD_SESSION},
    )
    assert resp.status_code == 400
    assert "session" in resp.text.lower()


def test_api_cancel_rejects_hostile_session_id(tmp_path: Path) -> None:
    client, _agent = _client(tmp_path, role="user")
    resp = client.post(f"/api/cancel/{_BAD_PATH_SESSION}")
    assert resp.status_code == 400
    assert "session" in resp.text.lower()


def test_api_files_rejects_hostile_session_id(tmp_path: Path) -> None:
    client, agent = _client(tmp_path, role="user")
    resp = client.get("/api/files", params={"path": ".", "session_id": _BAD_SESSION})
    assert resp.status_code == 400
    assert "session" in resp.text.lower()
    agent.echo_runtime.execute_tool_effect.assert_not_awaited()


def test_api_memory_enhanced_rejects_hostile_session_id(tmp_path: Path) -> None:
    client, agent = _client(tmp_path, role="admin")
    resp = client.get(
        "/api/memory/enhanced",
        params={"session_id": _BAD_SESSION},
    )
    assert resp.status_code == 400
    assert "session" in resp.text.lower()
    agent.memory.get_working.assert_not_called()


def test_api_capsule_rejects_hostile_session_id(tmp_path: Path) -> None:
    client, agent = _client(tmp_path, role="user")
    resp = client.get(f"/api/sessions/{_BAD_PATH_SESSION}/capsule")
    assert resp.status_code == 400
    assert "session" in resp.text.lower()
    agent.memory.get_capsule.assert_not_called()


def test_api_fleet_session_rejects_hostile_session_id(tmp_path: Path) -> None:
    client, _agent = _client(tmp_path, role="admin")
    with patch(
        "js.web.routers.fleet.get_fleet",
        side_effect=AssertionError("fleet must not run for hostile session_id"),
    ):
        resp = client.get(f"/api/fleet/sessions/{_BAD_PATH_SESSION}")
    assert resp.status_code == 400
    assert "session" in resp.text.lower()


def test_ws_rejects_hostile_session_id(tmp_path: Path) -> None:
    client, agent = _client(tmp_path, role="user")
    with client.websocket_connect("/ws", headers=_WS_ORIGIN) as ws:
        ws.send_json(
            {
                "type": "message",
                "content": "hello",
                "session_id": _BAD_SESSION,
            }
        )
        frame = ws.receive_json()
        assert frame["type"] == "error"
        assert "session" in str(frame).lower()
        with pytest.raises(WebSocketDisconnect) as exc_info:
            ws.receive_json()
    assert exc_info.value.code == 1008
    agent.bind_cancel_token.assert_not_called()
    agent.unbind_cancel_token.assert_not_called()
    agent.request_cancel.assert_not_called()


def test_optional_query_session_id_dependency() -> None:
    assert optional_query_session_id(None) is None
    assert optional_query_session_id("sess-ok") == "sess-ok"
    with pytest.raises(HTTPException) as exc:
        optional_query_session_id(_BAD_SESSION)
    assert exc.value.status_code == 400
