from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from js.agent import JSAgent, OwnedCancelResult
from js.config import JSSettings, SecurityConfig
from js.web.runtime_context import WebRuntime, bind_web_runtime

if TYPE_CHECKING:
    import pytest


def _app(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    runtime: Any,
) -> tuple[Any, Any, dict[str, str]]:
    monkeypatch.setenv("JS_ALLOWED_ORIGINS", "http://localhost")
    import js.web.auth as auth_mod

    monkeypatch.setattr(auth_mod, "_ALLOWED_ORIGINS", None)

    @asynccontextmanager
    async def _noop(_app: Any) -> AsyncIterator[None]:
        yield

    settings = JSSettings(
        workspace=tmp_path / "workspace",
        state_dir=tmp_path / "state",
        security=SecurityConfig(api_key_required=False),
        echo_engine="on",
    )
    agent = MagicMock()
    agent.settings = settings
    agent._cancel_tokens = {}
    agent.router.get_model_config.return_value = None
    agent.request_cancel.return_value = False

    with patch("js.web.server.lifespan", _noop):
        from js.web.server import create_app

        app = create_app()
    monkeypatch.setattr("js.web.server._settings", settings)
    monkeypatch.setattr("js.web.server._agent", agent)
    monkeypatch.setattr("js.web.server.get_agent", lambda: agent)
    monkeypatch.setattr("js.web.server.run_echo_turn", runtime)
    bind_web_runtime(app, WebRuntime(settings=settings, agent=agent))
    from js.web.auth import AuthManager

    user_key = AuthManager(settings.state_dir).create_key("lifecycle", role="user")
    headers = {"Origin": "http://localhost", "X-API-Key": user_key}
    return app, agent, headers


def _state(session_id: str, run_id: str, content: str) -> MagicMock:
    state = MagicMock()
    state.session_id = session_id
    state.run_id = run_id
    state.turn_count = 1
    state.total_tokens = {"input": 1, "output": 1}
    state.status = "completed"
    state.cost_estimate = 0.0
    state.model = "fake"
    state.error_message = None
    state.compression_stats = {}
    state.messages = [MagicMock(role="assistant", content=content)]
    return state


def test_stream_frames_carry_closed_turn_identity(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    async def runtime(*_args: Any, **kwargs: Any) -> Any:
        await kwargs["stream_callback"]("hello")
        await kwargs["event_callback"]({"kind": "thinking_delta", "text": "think"})
        await kwargs["event_callback"](
            {"kind": "tool_call_delta", "tool_call": {"index": 0, "name": "noop"}}
        )
        return _state("session-a", "agent-run-a", "hello")

    app, _agent, headers = _app(monkeypatch, tmp_path, runtime)
    client = TestClient(app, base_url="http://localhost")
    with client.websocket_connect("/ws", headers=headers) as ws:
        ws.send_json(
            {
                "type": "stream",
                "content": "go",
                "session_id": "session-a",
                "request_id": "request-a",
            }
        )
        frames = [ws.receive_json() for _ in range(5)]

    assert [frame["type"] for frame in frames] == [
        "status",
        "token",
        "thinking",
        "tool_call",
        "done",
    ]
    identities = {
        (frame["request_id"], frame["turn_id"], frame["run_id"], frame["session_id"])
        for frame in frames
    }
    assert len(identities) == 1
    request_id, turn_id, run_id, session_id = identities.pop()
    assert request_id == "request-a"
    assert turn_id
    assert run_id
    assert session_id == "session-a"


def test_each_websocket_turn_gets_a_fresh_cancel_event(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    cancel_tokens: list[Any] = []

    async def runtime(*_args: Any, **kwargs: Any) -> Any:
        cancel_tokens.append(kwargs["cancel_token"])
        turn = len(cancel_tokens)
        await kwargs["stream_callback"](str(turn))
        return _state("same-session", f"agent-run-{turn}", str(turn))

    app, _agent, headers = _app(monkeypatch, tmp_path, runtime)
    client = TestClient(app, base_url="http://localhost")
    with client.websocket_connect("/ws", headers=headers) as ws:
        for request_id in ("request-1", "request-2"):
            ws.send_json(
                {
                    "type": "stream",
                    "content": request_id,
                    "session_id": "same-session",
                    "request_id": request_id,
                }
            )
            assert [ws.receive_json()["type"] for _ in range(3)] == ["status", "token", "done"]

    assert len(cancel_tokens) == 2
    assert cancel_tokens[0] is not cancel_tokens[1]
    assert not cancel_tokens[1].is_set()


def test_late_cancel_identity_cannot_cancel_successor_turn() -> None:
    agent = JSAgent.__new__(JSAgent)
    agent.settings = SimpleNamespace(product_id="js-agent")
    agent._cancel_tokens = {}
    agent._cancel_client_identity = {}
    agent._active_run_tasks = {}
    agent.audit = MagicMock()
    agent.logger = MagicMock()

    old = asyncio.Event()
    agent.bind_cancel_token(
        "same-session",
        old,
        owner_key_hash="owner",
        run_id="logical-old",
        request_id="request-old",
    )
    successor = asyncio.Event()
    agent.bind_cancel_token(
        "same-session",
        successor,
        owner_key_hash="owner",
        run_id="logical-new",
        request_id="request-new",
    )

    assert not agent.request_cancel(
        "same-session",
        owner_key_hash="owner",
        expected_run_id="logical-old",
        expected_request_id="request-old",
    )
    assert not successor.is_set()
    assert agent.request_cancel(
        "same-session",
        owner_key_hash="owner",
        expected_run_id="logical-new",
        expected_request_id="request-new",
    )
    assert successor.is_set()


def test_owned_cancel_uses_current_client_identity_for_matching_owner() -> None:
    agent = JSAgent.__new__(JSAgent)
    agent.settings = SimpleNamespace(product_id="js-agent")
    agent._cancel_tokens = {}
    agent._cancel_client_identity = {}
    agent._active_run_tasks = {}
    agent.audit = MagicMock()
    agent.logger = MagicMock()

    token = asyncio.Event()
    agent.bind_cancel_token(
        "same-session",
        token,
        owner_key_hash="owner",
        run_id="logical-run",
        request_id="request-1",
    )

    assert (
        agent.request_owned_cancel("same-session", owner_key_hash="wrong-owner")
        == OwnedCancelResult.DENIED
    )
    assert not token.is_set()
    assert (
        agent.request_owned_cancel("same-session", owner_key_hash="owner")
        == OwnedCancelResult.CANCELLED
    )
    assert token.is_set()


def test_owned_cancel_snapshot_cannot_cancel_successor_turn() -> None:
    agent = JSAgent.__new__(JSAgent)
    agent.settings = SimpleNamespace(product_id="js-agent")
    agent._cancel_tokens = {}
    agent._cancel_client_identity = {}
    agent._active_run_tasks = {}
    agent.audit = MagicMock()
    agent.logger = MagicMock()

    old = asyncio.Event()
    agent.bind_cancel_token(
        "same-session",
        old,
        owner_key_hash="owner",
        run_id="logical-old",
        request_id="request-old",
    )
    successor = asyncio.Event()
    real_request_cancel = agent.request_cancel

    def replace_before_cancel(
        session_id: str,
        owner_key_hash: str | None = None,
        *,
        expected_run_id: str,
        expected_request_id: str,
    ) -> bool:
        agent.bind_cancel_token(
            "same-session",
            successor,
            owner_key_hash="owner",
            run_id="logical-new",
            request_id="request-new",
        )
        return real_request_cancel(
            session_id,
            owner_key_hash=owner_key_hash,
            expected_run_id=expected_run_id,
            expected_request_id=expected_request_id,
        )

    agent.request_cancel = replace_before_cancel  # type: ignore[method-assign]

    assert (
        agent.request_owned_cancel("same-session", owner_key_hash="owner")
        == OwnedCancelResult.IDLE
    )
    assert not old.is_set()
    assert not successor.is_set()


def test_owned_cancel_legacy_snapshot_cannot_cancel_successor_turn() -> None:
    agent = JSAgent.__new__(JSAgent)
    agent.settings = SimpleNamespace(product_id="js-agent")
    agent._cancel_tokens = {}
    agent._cancel_client_identity = {}
    agent._active_run_tasks = {}
    agent.audit = MagicMock()
    agent.logger = MagicMock()

    old = asyncio.Event()
    agent.bind_cancel_token(
        "same-session",
        old,
        owner_key_hash="owner",
        run_id="logical-old",
    )
    successor = asyncio.Event()
    real_request_cancel = agent.request_cancel

    def replace_before_cancel(
        session_id: str,
        owner_key_hash: str | None = None,
        *,
        expected_run_id: str,
        expected_request_id: str | None = None,
    ) -> bool:
        agent.bind_cancel_token(
            "same-session",
            successor,
            owner_key_hash="owner",
            run_id="logical-new",
        )
        return real_request_cancel(
            session_id,
            owner_key_hash=owner_key_hash,
            expected_run_id=expected_run_id,
            expected_request_id=expected_request_id,
        )

    agent.request_cancel = replace_before_cancel  # type: ignore[method-assign]

    assert (
        agent.request_owned_cancel("same-session", owner_key_hash="owner")
        == OwnedCancelResult.IDLE
    )
    assert not old.is_set()
    assert not successor.is_set()


def test_owned_cancel_malformed_identity_registry_is_fail_closed() -> None:
    agent = JSAgent.__new__(JSAgent)
    agent.settings = SimpleNamespace(product_id="js-agent")
    agent._cancel_tokens = {}
    agent._cancel_client_identity = {}
    agent._active_run_tasks = {}
    agent.audit = MagicMock()
    agent.logger = MagicMock()

    token = asyncio.Event()
    agent.bind_cancel_token(
        "same-session",
        token,
        owner_key_hash="owner",
        run_id="logical-run",
        request_id="request-1",
    )
    agent._cancel_client_identity = []  # type: ignore[assignment]

    assert (
        agent.request_owned_cancel("same-session", owner_key_hash="owner")
        == OwnedCancelResult.IDLE
    )
    assert not token.is_set()


def test_request_cancel_malformed_identity_registry_is_fail_closed() -> None:
    agent = JSAgent.__new__(JSAgent)
    agent.settings = SimpleNamespace(product_id="js-agent")
    agent._cancel_tokens = {}
    agent._cancel_client_identity = {}
    agent._active_run_tasks = {}
    agent.audit = MagicMock()
    agent.logger = MagicMock()

    token = asyncio.Event()
    agent.bind_cancel_token(
        "same-session",
        token,
        owner_key_hash="owner",
        run_id="logical-run",
    )
    agent._cancel_client_identity = []  # type: ignore[assignment]

    assert agent.request_cancel("same-session", owner_key_hash="owner") is False
    assert not token.is_set()


def test_request_cancel_missing_or_none_identity_registry_keeps_legacy_compatibility() -> None:
    for registry_state in ("missing", "none"):
        agent = JSAgent.__new__(JSAgent)
        agent.settings = SimpleNamespace(product_id="js-agent")
        agent._cancel_tokens = {}
        agent._cancel_client_identity = {}
        agent._active_run_tasks = {}
        agent.audit = MagicMock()
        agent.logger = MagicMock()

        token = asyncio.Event()
        agent.bind_cancel_token(
            f"legacy-{registry_state}",
            token,
            owner_key_hash="owner",
            run_id=f"run-{registry_state}",
        )
        if registry_state == "missing":
            del agent._cancel_client_identity
        else:
            agent._cancel_client_identity = None  # type: ignore[assignment]

        assert agent.request_cancel(f"legacy-{registry_state}", "owner") is True
        assert token.is_set()


def test_empty_legacy_client_identity_is_fail_closed() -> None:
    agent = JSAgent.__new__(JSAgent)
    agent.settings = SimpleNamespace(product_id="js-agent")
    agent._cancel_tokens = {}
    agent._cancel_client_identity = {}
    agent._active_run_tasks = {}
    agent.audit = MagicMock()
    agent.logger = MagicMock()

    successor = asyncio.Event()
    agent.bind_cancel_token(
        "same-session",
        successor,
        owner_key_hash="owner",
        run_id="successor-run",
    )
    from js.echo.turn_context import runtime_partition_key

    partition = runtime_partition_key("js-agent", "owner", "same-session")
    agent._cancel_client_identity[partition] = ()  # type: ignore[assignment]

    assert agent.request_cancel("same-session", owner_key_hash="owner") is False
    assert not successor.is_set()
