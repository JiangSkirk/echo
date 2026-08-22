"""F-05: real /ws overload E2E — close 1008, cancel, no leftover turns."""

from __future__ import annotations

import asyncio
import threading
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from js.config import JSSettings, SecurityConfig
from js.web import ws_inbox as ws_inbox_mod
from js.web.auth import AuthManager


class TinyInbox(ws_inbox_mod.BoundedWebSocketInbox):
    """Force a tiny per-connection budget regardless of endpoint defaults."""

    def __init__(self, *, max_messages: int = 32, max_bytes: int = 4 * 1024 * 1024) -> None:
        del max_messages, max_bytes
        super().__init__(max_messages=3, max_bytes=10_000)


class _SlowAgent:
    """Agent double that counts Echo turns and supports cancel tokens."""

    def __init__(self, settings: JSSettings) -> None:
        self.settings = settings
        self.echo_turn_calls = 0
        self._cancel_tokens: dict[str, tuple[asyncio.Event, str, str | None]] = {}
        self.audit = MagicMock()
        self.logger = MagicMock()
        self._active_run_tasks: dict[str, Any] = {}
        self.router = MagicMock()
        self.router.get_model_config.return_value = None

    def bind_cancel_token(
        self,
        session_id: str,
        token: asyncio.Event,
        *,
        owner_key_hash: str | None = None,
        run_id: str | None = None,
    ) -> None:
        from js.echo.turn_context import runtime_partition_key

        key = runtime_partition_key(
            getattr(self.settings, "product_id", "js-agent"),
            owner_key_hash,
            session_id,
        )
        self._cancel_tokens[key] = (token, run_id or "conn", owner_key_hash)

    def unbind_cancel_token(
        self,
        session_id: str,
        token: asyncio.Event,
        *,
        owner_key_hash: str | None = None,
    ) -> None:
        from js.echo.turn_context import runtime_partition_key

        key = runtime_partition_key(
            getattr(self.settings, "product_id", "js-agent"),
            owner_key_hash,
            session_id,
        )
        entry = self._cancel_tokens.get(key)
        if entry is not None and entry[0] is token:
            self._cancel_tokens.pop(key, None)

    def request_cancel(self, session_id: str, owner_key_hash: str | None = None) -> bool:
        from js.echo.turn_context import runtime_partition_key

        key = runtime_partition_key(
            getattr(self.settings, "product_id", "js-agent"),
            owner_key_hash,
            session_id,
        )
        entry = self._cancel_tokens.get(key)
        if entry is None:
            return False
        entry[0].set()
        return True


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


def test_ws_inbox_overload_closes_1008_and_cancels_turn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = JSSettings(
        workspace=tmp_path / "workspace",
        state_dir=tmp_path / "state",
        security=SecurityConfig(api_key_required=False),
        echo_engine="on",
    )
    (tmp_path / "workspace").mkdir(parents=True, exist_ok=True)
    (tmp_path / "state").mkdir(parents=True, exist_ok=True)
    agent = _SlowAgent(settings)
    started = threading.Event()
    cancel_tokens: list[Any] = []

    async def slow_turn(*_args: Any, **kwargs: Any) -> Any:
        agent.echo_turn_calls += 1
        cancel = kwargs.get("cancel_token")
        cancel_tokens.append(cancel)
        started.set()
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            if cancel is not None and cancel.is_set():
                raise asyncio.CancelledError
            try:
                await asyncio.sleep(0.01)
            except asyncio.CancelledError:
                # Endpoint may task.cancel() when request_cancel misses; still OK.
                raise
        raise TimeoutError("turn was not cancelled by overload")

    # Force tiny inbox budgets even if the endpoint passes larger defaults.
    _orig_init = ws_inbox_mod.BoundedWebSocketInbox.__init__

    def _tiny_init(
        self: Any,
        *,
        max_messages: int = 32,
        max_bytes: int = 4 * 1024 * 1024,
    ) -> None:
        del max_messages, max_bytes
        _orig_init(self, max_messages=3, max_bytes=10_000)

    monkeypatch.setattr(ws_inbox_mod.BoundedWebSocketInbox, "__init__", _tiny_init)
    monkeypatch.setattr(ws_inbox_mod, "BoundedWebSocketInbox", TinyInbox)
    app = _build_app(monkeypatch)
    from js.web.deps import set_globals

    set_globals(agent, settings)  # type: ignore[arg-type]
    monkeypatch.setattr("js.web.server._settings", settings)
    monkeypatch.setattr("js.web.server._agent", agent)
    monkeypatch.setattr("js.web.server.get_agent", lambda: agent)
    monkeypatch.setattr("js.web.deps._agent", agent)
    monkeypatch.setattr("js.web.deps._settings", settings)
    monkeypatch.setattr("js.web.server.run_echo_turn", slow_turn)

    user_key = AuthManager(settings.state_dir).create_key("ws-overload", role="user")
    client = TestClient(
        app,
        base_url="http://localhost",
        headers={"Origin": "http://localhost", "X-API-Key": user_key},
    )
    before = agent.echo_turn_calls
    close_code: int | None = None

    with (
        pytest.raises(WebSocketDisconnect) as exc_info,
        client.websocket_connect("/ws") as ws,
    ):
        ws.send_json(
            {
                "type": "message",
                "content": "hold the lane",
                "session_id": "overload-sess-1",
            }
        )
        status = ws.receive_json()
        assert status["type"] == "status"
        assert started.wait(timeout=2.0), "first turn never started"
        for i in range(12):
            ws.send_json(
                {
                    "type": "message",
                    "content": f"flood-{i}",
                    "session_id": "overload-sess-1",
                }
            )
        # Drain until the policy close surfaces to the client.
        deadline = time.time() + 3.0
        while time.time() < deadline:
            ws.receive_json()

    close_code = exc_info.value.code
    assert close_code == 1008
    assert started.is_set()
    assert cancel_tokens, "turn never received a cancel token"
    assert cancel_tokens[0] is not None and cancel_tokens[0].is_set()
    # Exactly the in-flight first turn; flooded messages must not become extra turns.
    assert agent.echo_turn_calls - before == 1
    # Connection cleanup must drop cancel registrations (no delayed lane leftovers).
    assert agent._cancel_tokens == {}
    assert agent._active_run_tasks == {}


def test_ws_inbox_overload_cancels_turn_task_when_request_cancel_misses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When request_cancel returns False, endpoint must still turn_task.cancel()."""
    settings = JSSettings(
        workspace=tmp_path / "workspace",
        state_dir=tmp_path / "state",
        security=SecurityConfig(api_key_required=False),
        echo_engine="on",
    )
    (tmp_path / "workspace").mkdir(parents=True, exist_ok=True)
    (tmp_path / "state").mkdir(parents=True, exist_ok=True)
    agent = _SlowAgent(settings)
    started = threading.Event()
    cancelled_via_task = threading.Event()
    # Force the miss branch — token registration must not make request_cancel succeed.
    agent.request_cancel = MagicMock(return_value=False)  # type: ignore[method-assign]

    async def stubborn_turn(*_args: Any, **kwargs: Any) -> Any:
        """Ignore cancel_token; only asyncio.CancelledError from turn_task.cancel() stops us."""
        del kwargs
        agent.echo_turn_calls += 1
        started.set()
        try:
            await asyncio.sleep(5.0)
        except asyncio.CancelledError:
            cancelled_via_task.set()
            raise
        raise TimeoutError("turn was not cancelled via turn_task.cancel()")

    _orig_init = ws_inbox_mod.BoundedWebSocketInbox.__init__

    def _tiny_init(
        self: Any,
        *,
        max_messages: int = 32,
        max_bytes: int = 4 * 1024 * 1024,
    ) -> None:
        del max_messages, max_bytes
        _orig_init(self, max_messages=3, max_bytes=10_000)

    monkeypatch.setattr(ws_inbox_mod.BoundedWebSocketInbox, "__init__", _tiny_init)
    monkeypatch.setattr(ws_inbox_mod, "BoundedWebSocketInbox", TinyInbox)
    app = _build_app(monkeypatch)
    from js.web.deps import set_globals

    set_globals(agent, settings)  # type: ignore[arg-type]
    monkeypatch.setattr("js.web.server._settings", settings)
    monkeypatch.setattr("js.web.server._agent", agent)
    monkeypatch.setattr("js.web.server.get_agent", lambda: agent)
    monkeypatch.setattr("js.web.deps._agent", agent)
    monkeypatch.setattr("js.web.deps._settings", settings)
    monkeypatch.setattr("js.web.server.run_echo_turn", stubborn_turn)

    user_key = AuthManager(settings.state_dir).create_key("ws-overload", role="user")
    client = TestClient(
        app,
        base_url="http://localhost",
        headers={"Origin": "http://localhost", "X-API-Key": user_key},
    )
    before = agent.echo_turn_calls

    with (
        pytest.raises(WebSocketDisconnect) as exc_info,
        client.websocket_connect("/ws") as ws,
    ):
        ws.send_json(
            {
                "type": "message",
                "content": "hold the lane",
                "session_id": "overload-sess-miss",
            }
        )
        status = ws.receive_json()
        assert status["type"] == "status"
        assert started.wait(timeout=2.0), "first turn never started"
        for i in range(12):
            ws.send_json(
                {
                    "type": "message",
                    "content": f"flood-{i}",
                    "session_id": "overload-sess-miss",
                }
            )
        deadline = time.time() + 3.0
        while time.time() < deadline:
            ws.receive_json()

    assert exc_info.value.code == 1008
    assert agent.request_cancel.called
    assert cancelled_via_task.wait(timeout=1.0), "turn_task.cancel() did not stop the turn"
    assert agent.echo_turn_calls - before == 1
    assert agent._cancel_tokens == {}
    assert agent._active_run_tasks == {}
