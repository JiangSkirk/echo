from __future__ import annotations

import errno
import sqlite3
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from js.config import JSSettings, SecurityConfig
from js.echo.ledger.service import EchoBlockedError, EchoUnavailableError
from js.web.runtime_context import WebRuntime, bind_web_runtime


def _build_app(monkeypatch: pytest.MonkeyPatch) -> Any:
    monkeypatch.setenv("JS_ALLOWED_ORIGINS", "http://localhost")
    import js.web.auth as auth_mod

    monkeypatch.setattr(auth_mod, "_ALLOWED_ORIGINS", None)

    @asynccontextmanager
    async def _noop_lifespan(_app: Any) -> AsyncIterator[None]:
        yield

    with patch("js.web.server.lifespan", _noop_lifespan):
        from js.web.server import create_app

        return create_app()


def _settings(tmp_path: Path) -> JSSettings:
    return JSSettings(
        workspace=tmp_path / "workspace",
        state_dir=tmp_path / "state",
        security=SecurityConfig(api_key_required=False),
        echo_engine="on",
    )


def _state(*, content: str = "WS primary response", status: str = "completed") -> MagicMock:
    state = MagicMock()
    state.session_id = "ws-primary"
    state.turn_count = 1
    state.total_tokens = {"input": 10, "output": 5}
    state.status = status
    state.cost_estimate = 0.0
    state.model = "mock"
    state.error_message = None
    state.compression_stats = {}
    state.messages = [MagicMock(role="assistant", content=content)] if content else []
    return state


def _agent(settings: JSSettings) -> MagicMock:
    agent = MagicMock()
    agent.settings = settings
    agent.router.get_model_config.return_value = None
    agent._dream_scheduler = MagicMock()
    agent.run = AsyncMock(side_effect=AssertionError("WS path must not call agent.run"))
    return agent


def _client(app: Any) -> TestClient:
    return TestClient(app, base_url="http://localhost", headers={"Origin": "http://localhost"})


_WIRED_WS_HEADERS: dict[str, str] = {"Origin": "http://localhost"}


def _assert_identified_frame(frame: dict[str, Any], expected: dict[str, Any]) -> None:
    assert {key: frame.get(key) for key in expected} == expected
    for key in ("request_id", "turn_id", "run_id", "session_id"):
        assert isinstance(frame.get(key), str) and frame[key]


def _wire(
    monkeypatch: pytest.MonkeyPatch,
    *,
    settings: JSSettings,
    agent: MagicMock,
    run_echo_turn: Any,
) -> Any:
    global _WIRED_WS_HEADERS
    from js.web.auth import AuthManager

    app = _build_app(monkeypatch)
    monkeypatch.setattr("js.web.server._settings", settings)
    monkeypatch.setattr("js.web.server._agent", agent)
    monkeypatch.setattr("js.web.server.get_agent", lambda: agent)
    monkeypatch.setattr("js.web.server.run_echo_turn", run_echo_turn)
    user_key = AuthManager(settings.state_dir).create_key("ws-primary", role="user")
    _WIRED_WS_HEADERS = {"Origin": "http://localhost", "X-API-Key": user_key}
    return app


def test_ws_message_echo_on_delegates_primary_gate_to_echo_turn_boundary(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)
    agent = _agent(settings)
    state = _state(content="WS wrapped response")
    run_echo_turn = AsyncMock(return_value=state)
    app = _wire(monkeypatch, settings=settings, agent=agent, run_echo_turn=run_echo_turn)

    with _client(app).websocket_connect("/ws", headers=_WIRED_WS_HEADERS) as ws:
        ws.send_json({"type": "message", "content": "hello through ws", "session_id": "ws-primary"})
        status = ws.receive_json()
        response = ws.receive_json()

    _assert_identified_frame(status, {"type": "status", "content": "thinking..."})
    assert response["type"] == "response"
    assert response["content"] == "WS wrapped response"
    run_echo_turn.assert_awaited_once()
    agent.run.assert_not_awaited()
    agent._dream_scheduler.notify_activity.assert_not_called()
    assert not (settings.state_dir / "echo" / "ledger" / "chat.jsonl").exists()


def test_ws_stream_echo_on_delegates_primary_gate_to_echo_turn_boundary(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)
    agent = _agent(settings)
    state = _state(content="Hello")

    async def _runtime(*_args: Any, stream_callback: Any = None, **_kwargs: Any) -> Any:
        if stream_callback is not None:
            await stream_callback("He")
            await stream_callback("llo")
        return state

    run_echo_turn = AsyncMock(side_effect=_runtime)
    app = _wire(monkeypatch, settings=settings, agent=agent, run_echo_turn=run_echo_turn)

    with _client(app).websocket_connect("/ws", headers=_WIRED_WS_HEADERS) as ws:
        ws.send_json({"type": "stream", "content": "stream through ws", "session_id": "ws-primary"})
        frames = [ws.receive_json() for _ in range(4)]

    assert [frame["type"] for frame in frames] == ["status", "token", "token", "done"]
    assert [frame.get("provisional") for frame in frames if frame["type"] == "token"] == [
        True,
        True,
    ]
    assert "".join(frame["content"] for frame in frames if frame["type"] == "token") == "Hello"
    run_echo_turn.assert_awaited_once()
    agent.run.assert_not_awaited()
    agent._dream_scheduler.notify_activity.assert_not_called()
    assert not (settings.state_dir / "echo" / "ledger" / "chat.jsonl").exists()


def test_ws_message_echo_on_calls_turn_runtime_without_changing_frames(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)
    agent = _agent(settings)
    state = _state(content="WS runtime response")
    runtime_calls: list[dict[str, object]] = []

    async def _runtime(agent_arg: Any, message: str, **kwargs: Any) -> Any:
        runtime_calls.append({"agent": agent_arg, "message": message, **kwargs})
        return state

    app = _wire(monkeypatch, settings=settings, agent=agent, run_echo_turn=_runtime)

    with _client(app).websocket_connect("/ws", headers=_WIRED_WS_HEADERS) as ws:
        ws.send_json(
            {
                "type": "message",
                "content": "hello through ws runtime",
                "session_id": "ws-runtime",
            }
        )
        status = ws.receive_json()
        response = ws.receive_json()

    _assert_identified_frame(status, {"type": "status", "content": "thinking..."})
    assert response["type"] == "response"
    assert response["content"] == "WS runtime response"
    assert len(runtime_calls) == 1
    assert runtime_calls[0]["agent"] is agent
    assert runtime_calls[0]["message"] == "hello through ws runtime"
    assert runtime_calls[0]["channel"] == "ws_message"
    assert runtime_calls[0]["session_id"] == "ws-runtime"
    agent.run.assert_not_awaited()


def test_ws_stream_echo_on_calls_turn_runtime_without_changing_frames(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)
    agent = _agent(settings)
    state = _state(content="Hello")
    runtime_calls: list[dict[str, object]] = []

    async def _runtime(agent_arg: Any, message: str, **kwargs: Any) -> Any:
        runtime_calls.append({"agent": agent_arg, "message": message, **kwargs})
        stream_callback = kwargs.get("stream_callback")
        if stream_callback is not None:
            await stream_callback("He")
            await stream_callback("llo")
        return state

    app = _wire(monkeypatch, settings=settings, agent=agent, run_echo_turn=_runtime)

    with _client(app).websocket_connect("/ws", headers=_WIRED_WS_HEADERS) as ws:
        ws.send_json(
            {
                "type": "stream",
                "content": "stream through ws runtime",
                "session_id": "ws-runtime",
            }
        )
        frames = [ws.receive_json() for _ in range(4)]

    assert [frame["type"] for frame in frames] == ["status", "token", "token", "done"]
    assert "".join(frame["content"] for frame in frames if frame["type"] == "token") == "Hello"
    assert len(runtime_calls) == 1
    assert runtime_calls[0]["agent"] is agent
    assert runtime_calls[0]["message"] == "stream through ws runtime"
    assert runtime_calls[0]["channel"] == "ws_stream"
    assert runtime_calls[0]["session_id"] == "ws-runtime"
    assert runtime_calls[0]["disable_tools"] is False
    agent.run.assert_not_awaited()


def test_ws_stream_diagnostic_sanitizes_provider_error(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)
    agent = _agent(settings)
    state = _state(content="safe response")
    private_detail = "/Users/private/Documents/customer.xlsx secret-token"

    async def _runtime(*_args: Any, event_callback: Any = None, **_kwargs: Any) -> Any:
        assert event_callback is not None
        await event_callback({"kind": "error", "error": private_detail})
        return state

    app = _wire(monkeypatch, settings=settings, agent=agent, run_echo_turn=_runtime)

    with _client(app).websocket_connect("/ws", headers=_WIRED_WS_HEADERS) as ws:
        ws.send_json(
            {
                "type": "stream",
                "content": "hello",
                "session_id": "ws-private-diagnostic",
            }
        )
        frames = [ws.receive_json() for _ in range(4)]

    diagnostic = next(frame for frame in frames if frame["type"] == "stream_diagnostic")
    assert private_detail not in diagnostic["content"]


def test_ws_stream_echo_on_records_token_usage(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)
    agent = _agent(settings)
    state = _state(content="Hello")
    records: list[dict[str, Any]] = []

    class _Stats:
        def record(self, **kwargs: Any) -> None:
            records.append(kwargs)

    async def _runtime(*_args: Any, stream_callback: Any = None, **_kwargs: Any) -> Any:
        if stream_callback is not None:
            await stream_callback("Hello")
        return state

    app = _build_app(monkeypatch)
    monkeypatch.setattr("js.web.server._settings", settings)
    monkeypatch.setattr("js.web.server._agent", agent)
    monkeypatch.setattr("js.web.server.get_agent", lambda: agent)
    monkeypatch.setattr("js.web.server.run_echo_turn", _runtime)
    bind_web_runtime(
        app,
        WebRuntime(agent=agent, settings=settings, stats_store=_Stats()),
    )
    from js.web.auth import AuthManager

    user_key = AuthManager(settings.state_dir).create_key("ws-token-usage", role="user")
    ws_headers = {"Origin": "http://localhost", "X-API-Key": user_key}

    with _client(app).websocket_connect("/ws", headers=ws_headers) as ws:
        ws.send_json(
            {
                "type": "stream",
                "content": "stream through ws runtime",
                "session_id": "ws-runtime",
            }
        )
        frames = [ws.receive_json() for _ in range(3)]

    assert [frame["type"] for frame in frames] == ["status", "token", "done"]
    assert len(records) == 1
    assert records[0]["prompt_tokens"] == 10
    assert records[0]["completion_tokens"] == 5
    assert records[0]["session_id"] == "ws-primary"
    agent.run.assert_not_awaited()


@pytest.mark.parametrize(
    "telemetry_error",
    [
        sqlite3.OperationalError("database is locked"),
        OSError(errno.ENOSPC, "No space left on device"),
    ],
    ids=["sqlite-locked", "enospc"],
)
def test_ws_success_survives_token_telemetry_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    telemetry_error: Exception,
) -> None:
    settings = _settings(tmp_path)
    agent = _agent(settings)
    state = _state(content="model already succeeded")
    run_echo_turn = AsyncMock(return_value=state)
    telemetry_logger = MagicMock()

    class _FailingStats:
        def record(self, **_kwargs: Any) -> None:
            raise telemetry_error

    app = _wire(
        monkeypatch,
        settings=settings,
        agent=agent,
        run_echo_turn=run_echo_turn,
    )
    bind_web_runtime(
        app,
        WebRuntime(agent=agent, settings=settings, stats_store=_FailingStats()),
    )
    monkeypatch.setattr("js.web.server.logger", telemetry_logger)

    with _client(app).websocket_connect("/ws", headers=_WIRED_WS_HEADERS) as ws:
        ws.send_json(
            {
                "type": "message",
                "content": "hello",
                "session_id": "ws-telemetry",
            }
        )
        frames = [ws.receive_json() for _ in range(2)]

    assert [frame["type"] for frame in frames] == ["status", "response"]
    assert all(frame["type"] != "error" for frame in frames)
    run_echo_turn.assert_awaited_once()
    agent.run.assert_not_awaited()
    telemetry_logger.warning.assert_called_once()
    assert "telemetry degraded" in telemetry_logger.warning.call_args.args[0].lower()


def test_ws_message_echo_on_blocks_secret_at_echo_turn_boundary(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)
    agent = _agent(settings)
    run_echo_turn = AsyncMock(
        side_effect=EchoBlockedError("Secret data cannot enter Echo on-mode model path")
    )
    app = _wire(monkeypatch, settings=settings, agent=agent, run_echo_turn=run_echo_turn)

    with _client(app).websocket_connect("/ws", headers=_WIRED_WS_HEADERS) as ws:
        ws.send_json(
            {
                "type": "message",
                "content": "please call the model with sk-test-1234567890abcdef",
                "session_id": "ws-secret",
            }
        )
        status = ws.receive_json()
        error = ws.receive_json()

    _assert_identified_frame(status, {"type": "status", "content": "thinking..."})
    assert error["type"] == "error"
    assert "sensitive" in error["content"]
    run_echo_turn.assert_awaited_once()
    agent.run.assert_not_awaited()


def test_ws_message_echo_on_rejects_plain_workspace_attachment(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)
    settings.workspace.mkdir(parents=True, exist_ok=True)
    (settings.workspace / "notes.txt").write_text("plain workspace attachment", encoding="utf-8")
    agent = _agent(settings)
    run_echo_turn = AsyncMock()
    app = _wire(monkeypatch, settings=settings, agent=agent, run_echo_turn=run_echo_turn)

    with _client(app).websocket_connect("/ws", headers=_WIRED_WS_HEADERS) as ws:
        ws.send_json(
            {
                "type": "message",
                "content": "use attachment",
                "session_id": "ws-plain-attachment",
                "attachments": ["notes.txt"],
            }
        )
        error = ws.receive_json()

    assert error["type"] == "error"
    assert "attachment" in error["content"].lower()
    run_echo_turn.assert_not_awaited()
    agent.run.assert_not_awaited()


def test_ws_stream_rejects_non_list_attachments_like_http(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)
    agent = _agent(settings)
    run_echo_turn = AsyncMock()
    app = _wire(monkeypatch, settings=settings, agent=agent, run_echo_turn=run_echo_turn)

    with _client(app).websocket_connect("/ws", headers=_WIRED_WS_HEADERS) as ws:
        ws.send_json(
            {
                "type": "stream",
                "content": "bad attachments",
                "session_id": "ws-bad-attachments",
                "attachments": "notes.txt",
            }
        )
        error = ws.receive_json()

    _assert_identified_frame(
        error,
        {
            "type": "error",
            "content": "attachments must be a list",
            "session_id": "ws-bad-attachments",
        },
    )
    run_echo_turn.assert_not_awaited()
    agent.run.assert_not_awaited()


def test_ws_stream_echo_on_blocks_secret_at_echo_turn_boundary(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)
    agent = _agent(settings)
    run_echo_turn = AsyncMock(
        side_effect=EchoBlockedError("Secret data cannot enter Echo on-mode model path")
    )
    app = _wire(monkeypatch, settings=settings, agent=agent, run_echo_turn=run_echo_turn)

    with _client(app).websocket_connect("/ws", headers=_WIRED_WS_HEADERS) as ws:
        ws.send_json(
            {
                "type": "stream",
                "content": "stream this bearer abcdef1234567890 to the model",
                "session_id": "ws-stream-secret",
            }
        )
        status = ws.receive_json()
        error = ws.receive_json()

    _assert_identified_frame(status, {"type": "status", "content": "streaming..."})
    assert error["type"] == "error"
    assert "sensitive" in error["content"]
    run_echo_turn.assert_awaited_once()
    agent.run.assert_not_awaited()


def test_ws_message_echo_on_fails_closed_when_begin_errors(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)
    agent = _agent(settings)
    run_echo_turn = AsyncMock(
        side_effect=EchoUnavailableError("Echo safety layer unavailable before model execution")
    )
    app = _wire(monkeypatch, settings=settings, agent=agent, run_echo_turn=run_echo_turn)

    with _client(app).websocket_connect("/ws", headers=_WIRED_WS_HEADERS) as ws:
        ws.send_json(
            {
                "type": "message",
                "content": "hello",
                "session_id": "ws-begin-fail",
            }
        )
        status = ws.receive_json()
        error = ws.receive_json()

    _assert_identified_frame(status, {"type": "status", "content": "thinking..."})
    assert error["type"] == "error"
    assert "safety layer" in error["content"]
    run_echo_turn.assert_awaited_once()
    agent.run.assert_not_awaited()


def test_ws_echo_unavailable_does_not_echo_private_exception(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)
    agent = _agent(settings)
    private_detail = "/Users/private/.state/echo-ledger secret-token"
    run_echo_turn = AsyncMock(side_effect=EchoUnavailableError(private_detail))
    app = _wire(monkeypatch, settings=settings, agent=agent, run_echo_turn=run_echo_turn)

    with _client(app).websocket_connect("/ws", headers=_WIRED_WS_HEADERS) as ws:
        ws.send_json(
            {
                "type": "message",
                "content": "hello",
                "session_id": "ws-private-echo-error",
            }
        )
        ws.receive_json()
        error = ws.receive_json()

    assert error["content"] == "Echo safety layer is unavailable; request was not executed"
    assert private_detail not in str(error)


def test_ws_stream_echo_on_fails_closed_when_begin_errors(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)
    agent = _agent(settings)
    run_echo_turn = AsyncMock(
        side_effect=EchoUnavailableError("Echo safety layer unavailable before model execution")
    )
    app = _wire(monkeypatch, settings=settings, agent=agent, run_echo_turn=run_echo_turn)

    with _client(app).websocket_connect("/ws", headers=_WIRED_WS_HEADERS) as ws:
        ws.send_json(
            {
                "type": "stream",
                "content": "hello",
                "session_id": "ws-stream-begin-fail",
            }
        )
        status = ws.receive_json()
        error = ws.receive_json()

    _assert_identified_frame(status, {"type": "status", "content": "streaming..."})
    assert error["type"] == "error"
    assert "safety layer" in error["content"]
    run_echo_turn.assert_awaited_once()
    agent.run.assert_not_awaited()


def test_ws_message_echo_on_does_not_send_response_before_finalize_error(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)
    agent = _agent(settings)
    run_echo_turn = AsyncMock(
        side_effect=EchoUnavailableError("Echo safety layer failed to finalize model turn")
    )
    app = _wire(monkeypatch, settings=settings, agent=agent, run_echo_turn=run_echo_turn)

    with _client(app).websocket_connect("/ws", headers=_WIRED_WS_HEADERS) as ws:
        ws.send_json(
            {
                "type": "message",
                "content": "hello",
                "session_id": "ws-finish-fail",
            }
        )
        status = ws.receive_json()
        first_terminal = ws.receive_json()

    _assert_identified_frame(status, {"type": "status", "content": "thinking..."})
    assert first_terminal["type"] == "error"
    assert "safety layer" in first_terminal["content"]
    # Single terminal frame: no response/done after finalize failure.
    run_echo_turn.assert_awaited_once()
    agent.run.assert_not_awaited()


def test_ws_stream_echo_on_does_not_send_done_before_finalize_error(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)
    agent = _agent(settings)

    async def _runtime(*_args: Any, stream_callback: Any = None, **_kwargs: Any) -> Any:
        if stream_callback is not None:
            await stream_callback("partial")
        raise EchoUnavailableError("Echo safety layer failed to finalize model turn")

    run_echo_turn = AsyncMock(side_effect=_runtime)
    app = _wire(monkeypatch, settings=settings, agent=agent, run_echo_turn=run_echo_turn)

    with _client(app).websocket_connect("/ws", headers=_WIRED_WS_HEADERS) as ws:
        ws.send_json(
            {
                "type": "stream",
                "content": "hello",
                "session_id": "ws-stream-finish-fail",
            }
        )
        frames = [ws.receive_json() for _ in range(3)]

    assert [frame["type"] for frame in frames] == ["status", "token", "error"]
    assert frames[1]["provisional"] is True
    assert "safety layer" in frames[-1]["content"]
    # Finalize failure must not emit done after provisional tokens.
    assert "done" not in [frame["type"] for frame in frames]
    run_echo_turn.assert_awaited_once()
    agent.run.assert_not_awaited()
