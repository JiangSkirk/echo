"""Tests for the chat web router."""

from __future__ import annotations

import errno
import sqlite3
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from js.config import JSSettings, SecurityConfig
from js.echo.ledger.service import EchoBlockedError, EchoUnavailableError
from js.echo.turn_runtime import EchoRuntime, TurnRequest
from js.web.auth import AuthManager
from js.web.routers.chat import router as chat_router


class _AdmitPulse:
    def observe(self, **_kwargs):
        return MagicMock(admitted=True)


class _AgentRunLoop:
    def __init__(self, agent: MagicMock, request: TurnRequest) -> None:
        self._agent = agent
        self._request = request

    async def execute(self):
        request = self._request
        return await self._agent.run(
            request.message,
            session_id=request.context.session_id or None,
            model=request.model,
            attachments=list(request.attachments),
            stream_callback=request.stream_callback,
            progress_callback=request.progress_callback,
            event_callback=request.event_callback,
            disable_tools=request.disable_tools,
        )


def _echo_agent() -> MagicMock:
    agent = MagicMock()
    agent.settings = JSSettings(
        workspace=Path("/tmp/js_test"),
        state_dir=Path("/tmp/js_test"),
        security=SecurityConfig(api_key_required=False),
    )
    agent._shutdown_requested = False
    agent._lane_executor = None
    agent.echo_runtime = EchoRuntime(
        agent,
        pulse_runtime=_AdmitPulse(),
        turn_loop_factory=lambda runtime_agent, request: _AgentRunLoop(runtime_agent, request),
    )
    return agent


def _make_app() -> FastAPI:
    app = FastAPI()
    app.include_router(chat_router)
    # Provide a valid settings object with auth disabled so tests don't need API keys
    _settings = JSSettings(
        workspace=Path("/tmp/js_test"),
        state_dir=Path("/tmp/js_test"),
        security=SecurityConfig(api_key_required=False),
    )
    patch("js.web.server._settings", _settings).start()
    patch("js.web.deps._stats_store", None).start()
    return app


def _client(app: FastAPI) -> TestClient:
    """TestClient carrying a valid user key (anonymous guests are read-only)."""
    from js.web.auth import AuthManager

    key = AuthManager(Path("/tmp/js_test")).create_key("chat-test", role="user")
    return TestClient(
        app,
        base_url="http://localhost",
        headers={"Origin": "http://localhost", "X-API-Key": key},
    )


def test_chat_success() -> None:
    """POST /api/chat returns assistant response."""
    mock_state = MagicMock()
    mock_state.session_id = "sess-1"
    mock_state.turn_count = 1
    mock_state.total_tokens = {"input": 10, "output": 5}
    mock_state.status = "completed"
    mock_state.messages = [
        MagicMock(role="user", content="hello"),
        MagicMock(role="assistant", content="Hi there"),
    ]

    agent = _echo_agent()
    agent.run = AsyncMock(return_value=mock_state)

    app = _make_app()
    client = _client(app)
    with patch("js.web.routers.chat.get_agent", return_value=agent):
        resp = client.post("/api/chat", json={"message": "hello", "session_id": "sess-1"})

    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["response"] == "Hi there"
    assert data["session_id"] == "sess-1"
    assert data["status"] == "completed"
    agent.run.assert_awaited_once()


@pytest.mark.parametrize(
    "telemetry_error",
    [
        sqlite3.OperationalError("database is locked"),
        OSError(errno.ENOSPC, "No space left on device"),
    ],
    ids=["sqlite-locked", "enospc"],
)
def test_chat_success_survives_token_telemetry_failure(telemetry_error: Exception) -> None:
    mock_state = MagicMock()
    mock_state.session_id = "sess-telemetry"
    mock_state.run_id = "run-telemetry"
    mock_state.turn_count = 1
    mock_state.total_tokens = {"input": 10, "output": 5}
    mock_state.status = "completed"
    mock_state.cost_estimate = 0.01
    mock_state.model = "mock"
    mock_state.cached_tokens = 0
    mock_state.messages = [MagicMock(role="assistant", content="model already succeeded")]

    agent = _echo_agent()
    agent.run = AsyncMock(return_value=mock_state)
    agent.router.get_model_config.return_value = MagicMock(provider="mock-provider")
    stats_store = MagicMock()
    stats_store.record.side_effect = telemetry_error
    telemetry_logger = MagicMock()

    app = _make_app()
    client = _client(app)
    with (
        patch("js.web.routers.chat.get_agent", return_value=agent),
        patch("js.web.routers.chat.get_stats_store", return_value=stats_store),
        patch("js.web.routers.chat.logger", telemetry_logger),
    ):
        response = client.post(
            "/api/chat",
            json={"message": "hello", "session_id": "sess-telemetry"},
        )

    assert response.status_code == 200
    assert response.json()["response"] == "model already succeeded"
    agent.run.assert_awaited_once()
    stats_store.record.assert_called_once()
    telemetry_logger.warning.assert_called_once()
    assert "telemetry degraded" in telemetry_logger.warning.call_args.args[0].lower()


def test_chat_error() -> None:
    """Agent run failure returns 500."""
    agent = _echo_agent()
    agent.run = AsyncMock(side_effect=RuntimeError("boom"))

    app = _make_app()
    client = _client(app)
    with patch("js.web.routers.chat.get_agent", return_value=agent):
        resp = client.post("/api/chat", json={"message": "hello"})

    assert resp.status_code == 500
    detail = resp.json()["detail"]
    # User-friendly Chinese message — never leaks the raw exception text.
    assert "boom" not in detail
    assert "出错" in detail


def test_chat_error_state_returns_http_error() -> None:
    """Agent error states are surfaced as HTTP errors, not 200/empty response."""
    mock_state = MagicMock()
    mock_state.session_id = "sess-error"
    mock_state.turn_count = 1
    mock_state.total_tokens = {"input": 0, "output": 0}
    mock_state.status = "error"
    mock_state.error_message = "provider exploded"
    mock_state.messages = []

    agent = _echo_agent()
    agent.run = AsyncMock(return_value=mock_state)

    app = _make_app()
    client = _client(app)
    with patch("js.web.routers.chat.get_agent", return_value=agent):
        resp = client.post("/api/chat", json={"message": "hello"})

    assert resp.status_code == 500
    assert "出错" in resp.json()["detail"]


def test_chat_cancelled_state_is_not_reported_as_success() -> None:
    mock_state = MagicMock()
    mock_state.session_id = "sess-cancelled"
    mock_state.turn_count = 1
    mock_state.total_tokens = {"input": 0, "output": 0}
    mock_state.status = "cancelled"
    mock_state.error_message = "Run cancelled by user request"
    mock_state.messages = []

    agent = _echo_agent()
    agent.run = AsyncMock(return_value=mock_state)

    app = _make_app()
    client = _client(app)
    with patch("js.web.routers.chat.get_agent", return_value=agent):
        resp = client.post("/api/chat", json={"message": "hello"})

    assert resp.status_code == 409


def test_chat_empty_message() -> None:
    """Empty message still produces a valid response."""
    mock_state = MagicMock()
    mock_state.session_id = "sess-2"
    mock_state.turn_count = 1
    mock_state.total_tokens = {"input": 0, "output": 0}
    mock_state.status = "completed"
    mock_state.messages = []

    agent = _echo_agent()
    agent.run = AsyncMock(return_value=mock_state)

    app = _make_app()
    client = _client(app)
    with patch("js.web.routers.chat.get_agent", return_value=agent):
        resp = client.post("/api/chat", json={"message": ""})

    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["response"] == ""
    assert data["session_id"] == "sess-2"


def test_chat_on_mode_preserves_legacy_response(monkeypatch) -> None:
    """T9-A on-mode must keep /api/chat externally compatible."""
    monkeypatch.setenv("JS_ECHO_ENGINE", "on")
    mock_state = MagicMock()
    mock_state.session_id = "sess-on"
    mock_state.turn_count = 1
    mock_state.total_tokens = {"input": 10, "output": 5}
    mock_state.status = "completed"
    mock_state.cost_estimate = 0.0
    mock_state.model = "mock"
    mock_state.error_message = None
    mock_state.compression_stats = {}
    mock_state.messages = [
        MagicMock(role="user", content="hello"),
        MagicMock(role="assistant", content="Hi from on"),
    ]

    agent = _echo_agent()
    agent.run = AsyncMock(return_value=mock_state)

    app = _make_app()
    client = _client(app)
    with patch("js.web.routers.chat.get_agent", return_value=agent):
        resp = client.post("/api/chat", json={"message": "hello", "session_id": "sess-on"})

    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["response"] == "Hi from on"
    assert data["session_id"] == "sess-on"
    assert data["status"] == "completed"
    agent.run.assert_awaited_once()


def test_chat_on_mode_calls_echo_turn_runtime_without_changing_response(monkeypatch) -> None:
    monkeypatch.setenv("JS_ECHO_ENGINE", "on")
    mock_state = MagicMock()
    mock_state.session_id = "sess-runtime"
    mock_state.turn_count = 1
    mock_state.total_tokens = {"input": 10, "output": 5}
    mock_state.status = "completed"
    mock_state.cost_estimate = 0.0
    mock_state.model = "mock"
    mock_state.error_message = None
    mock_state.compression_stats = {}
    mock_state.messages = [MagicMock(role="assistant", content="Runtime response")]

    agent = _echo_agent()
    agent.run = AsyncMock(return_value=mock_state)
    runtime_calls: list[dict[str, object]] = []

    async def _runtime(agent_arg, message, **kwargs):
        runtime_calls.append({"agent": agent_arg, "message": message, **kwargs})
        return await agent_arg.run(message, **kwargs)

    app = _make_app()
    # A keyed request must run under that key's owner hash (per-user scoping),
    # not the anonymous "local-user" partition.
    chat_key = AuthManager(Path("/tmp/js_test")).create_key("chat-owner", role="user")
    client = TestClient(
        app,
        base_url="http://localhost",
        headers={"Origin": "http://localhost", "X-API-Key": chat_key},
    )
    with (
        patch("js.web.routers.chat.get_agent", return_value=agent),
        patch("js.web.routers.chat.run_echo_turn", side_effect=_runtime),
    ):
        resp = client.post(
            "/api/chat",
            json={"message": "hello", "session_id": "sess-runtime", "model": "mock"},
        )

    assert resp.status_code == 200
    assert resp.json()["response"] == "Runtime response"
    assert len(runtime_calls) == 1
    assert runtime_calls[0]["agent"] is agent
    assert runtime_calls[0]["message"] == "hello"
    assert runtime_calls[0]["channel"] == "api_chat"
    expected_owner = AuthManager(Path("/tmp/js_test")).verify(chat_key)["key_hash"]
    assert runtime_calls[0]["owner_key_hash"] == expected_owner
    assert runtime_calls[0]["session_id"] == "sess-runtime"
    assert runtime_calls[0]["model"] == "mock"
    agent.run.assert_awaited_once()


def test_chat_echo_mode_delegates_primary_gate_to_agent_boundary(
    tmp_path: Path,
) -> None:
    settings = JSSettings(
        workspace=tmp_path / "workspace",
        state_dir=tmp_path / "state",
        security=SecurityConfig(api_key_required=False),
    )

    mock_state = MagicMock()
    mock_state.session_id = "sess-primary"
    mock_state.turn_count = 1
    mock_state.total_tokens = {"input": 10, "output": 5}
    mock_state.status = "completed"
    mock_state.cost_estimate = 0.0
    mock_state.model = "mock"
    mock_state.messages = [MagicMock(role="assistant", content="Primary wrapper response")]

    async def _run(*_args, **_kwargs):
        return mock_state

    agent = _echo_agent()
    agent.settings = settings
    agent.run = AsyncMock(side_effect=_run)

    app = _make_app()
    client = _client(app)
    with (
        patch("js.web.routers.chat.get_agent", return_value=agent),
    ):
        resp = client.post("/api/chat", json={"message": "hello", "session_id": "sess-primary"})

    assert resp.status_code == 200
    assert resp.json()["response"] == "Primary wrapper response"
    agent.run.assert_awaited_once()


def test_chat_echo_mode_rejects_plain_workspace_attachment(
    monkeypatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("JS_ECHO_ENGINE", "on")
    settings = JSSettings(
        workspace=tmp_path / "workspace",
        state_dir=tmp_path / "state",
        security=SecurityConfig(api_key_required=False),
    )
    settings.workspace.mkdir(parents=True, exist_ok=True)
    (settings.workspace / "notes.txt").write_text("plain workspace attachment", encoding="utf-8")

    agent = _echo_agent()
    agent.settings = settings
    agent.run = AsyncMock()

    app = _make_app()
    client = _client(app)
    with (
        patch("js.web.routers.chat.get_agent", return_value=agent),
    ):
        resp = client.post(
            "/api/chat",
            json={
                "message": "summarize attachment",
                "session_id": "sess-plain-attachment",
                "attachments": ["notes.txt"],
            },
        )

    assert resp.status_code == 403
    assert "attachment" in resp.json()["detail"].lower()
    agent.run.assert_not_awaited()


def test_chat_echo_mode_blocks_secret_before_agent_call(tmp_path: Path) -> None:
    settings = JSSettings(
        workspace=tmp_path / "workspace",
        state_dir=tmp_path / "state",
        security=SecurityConfig(api_key_required=False),
    )
    agent = _echo_agent()
    agent.settings = settings
    agent.run = AsyncMock(
        side_effect=EchoBlockedError(
            "Secret data cannot enter Echo on-mode model path"
        )
    )

    app = _make_app()
    client = _client(app)
    with (
        patch("js.web.routers.chat.get_agent", return_value=agent),
    ):
        resp = client.post(
            "/api/chat",
            json={"message": "please use sk-test-1234567890abcdef", "session_id": "sess-secret"},
        )

    assert resp.status_code == 400
    assert "sensitive" in resp.json()["detail"]
    agent.run.assert_awaited_once()


def test_chat_echo_mode_fails_closed_when_begin_errors(
    tmp_path: Path,
) -> None:
    settings = JSSettings(
        workspace=tmp_path / "workspace",
        state_dir=tmp_path / "state",
        security=SecurityConfig(api_key_required=False),
    )
    agent = _echo_agent()
    agent.settings = settings
    agent.run = AsyncMock(
        side_effect=EchoUnavailableError(
            "Echo safety layer unavailable before model execution"
        )
    )

    app = _make_app()
    client = _client(app)
    with (
        patch("js.web.routers.chat.get_agent", return_value=agent),
    ):
        resp = client.post("/api/chat", json={"message": "hello", "session_id": "sess-fail"})

    assert resp.status_code == 503
    detail = resp.json()["detail"]
    assert "请稍后重试" in detail
    assert "safety layer" not in detail
    assert "model execution" not in detail
    agent.run.assert_awaited_once()
