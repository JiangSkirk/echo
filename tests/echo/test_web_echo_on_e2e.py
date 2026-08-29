"""Echo endpoint-level E2E coverage for local ``JS_ECHO_ENGINE=on`` mode.

These tests intentionally drive the real FastAPI ``/api/chat`` router through
an actual ``JSAgent`` instance and a deterministic fake provider. They close
the gap left by router-only mock tests: Echo context metrics must be produced
by the real agent prompt path, not pre-filled on a mocked ``AgentState``.
"""

from __future__ import annotations

import asyncio
import os
import threading
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Literal
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.websockets import WebSocket

from js.agent import JSAgent
from js.config import EchoBudgetConfig, JSSettings, SecurityConfig
from js.echo.context_runtime import (
    get_context_runtime_snapshot_for_tests,
    reset_context_runtime_for_tests,
)
from js.echo.ledger.journal import FileEchoLedger
from js.models.permit import ModelPermitError, ModelPermitIssuer
from js.models.providers import ChatMessage, ChatResponse, ModelProvider
from js.models.router import ModelRouter
from js.models.stream_events import StreamEvent
from js.web.routers.chat import router as chat_router


class RecordingProvider(ModelProvider):
    def __init__(self, *, content: str = "Echo endpoint response") -> None:
        self.content = content
        self.calls: list[tuple[list[ChatMessage], list[dict[str, Any]] | None]] = []

    async def chat(
        self,
        messages: list[ChatMessage],
        model: str,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> ChatResponse:
        self.calls.append((messages, tools))
        return ChatResponse(
            content=self.content,
            tool_calls=[],
            model="mock",
            usage={"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18},
            finish_reason="stop",
        )

    def chat_stream(
        self,
        messages: list[ChatMessage],
        model: str,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> AsyncIterator[str]:
        async def _gen() -> AsyncIterator[str]:
            yield self.content

        return _gen()

    async def health_check(self) -> bool:
        return True

    async def close(self) -> None:
        pass


class DisconnectAwareProvider(RecordingProvider):
    def __init__(self) -> None:
        super().__init__(content="late response")
        self.started = threading.Event()
        self.cancelled = threading.Event()

    async def chat(
        self,
        messages: list[ChatMessage],
        model: str,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> ChatResponse:
        self.started.set()
        try:
            await asyncio.sleep(0.5)
        except asyncio.CancelledError:
            self.cancelled.set()
            raise
        return await super().chat(messages, model, tools, temperature, max_tokens)


class ScriptedStreamProvider(RecordingProvider):
    def __init__(self, events: list[StreamEvent]) -> None:
        super().__init__()
        self.events = events

    async def chat_stream_events(
        self,
        messages: list[ChatMessage],
        model: str,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> AsyncIterator[StreamEvent]:
        del messages, model, tools, temperature, max_tokens
        for event in self.events:
            yield event


class RecordingRouter(ModelRouter):
    def __init__(
        self,
        provider: RecordingProvider,
        *,
        permit_verifier: ModelPermitIssuer | None = None,
    ) -> None:
        self.settings = JSSettings()
        self._providers: dict[str, ModelProvider] = {"mock": provider}
        self._model_map: dict[str, str] = {}
        self._permit_verifier = permit_verifier or ModelPermitIssuer()

    async def select_model(
        self, task_complexity: str = "medium", preferred: str | None = None
    ) -> Any:
        from js.models.router import RoutingDecision

        return RoutingDecision(
            provider=self._providers["mock"],
            model="mock",
            provider_name="mock",
            reason="mock",
        )

    async def chat(
        self,
        messages: list[ChatMessage],
        model: str | None = None,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
        before_model_call: Any = None,
        after_model_call: Any = None,
        permit_grant: Any = None,
    ) -> ChatResponse:
        if before_model_call is None or after_model_call is None or permit_grant is None:
            raise RuntimeError(
                "Echo requires before_model_call/after_model_call callbacks and "
                "a runtime-issued permit_grant for ModelRouter.chat(); direct "
                "provider chat is only available through the Echo turn runtime."
            )
        if self._permit_verifier is None:
            raise ModelPermitError(
                "ModelRouter has no Echo permit verifier; direct provider calls "
                "are only available through the Echo turn runtime."
            )
        provider = self._providers["mock"]
        decision = await self.select_model(preferred=model)
        self._consume_model_permit(permit_grant, decision, messages, tools)
        context = await before_model_call(decision, messages, tools)
        try:
            response = await provider.chat(
                messages=messages,
                model=decision.model,
                tools=tools,
                temperature=temperature,
                max_tokens=max_tokens,
            )
        except BaseException as exc:
            await after_model_call(context, None, exc)
            raise
        await after_model_call(context, response, None)
        return response


class CapturingAgent:
    """Small proxy that preserves the real JSAgent path and exposes last state."""

    def __init__(self, agent: JSAgent) -> None:
        self._agent = agent
        self.last_state: Any = None
        outer = self
        runtime = agent.echo_runtime
        delegate_factory = runtime._turn_loop_factory

        class _CapturingLoop:
            def __init__(self, delegate: Any) -> None:
                self._delegate = delegate

            async def execute(self) -> Any:
                state = await self._delegate.execute()
                outer.last_state = state
                return state

        runtime._turn_loop_factory = lambda current_agent, request: _CapturingLoop(
            delegate_factory(current_agent, request)
        )
        self.echo_runtime = runtime

    async def run(self, *args: Any, **kwargs: Any) -> Any:
        raise AssertionError("web paths must use EchoRuntime instead of JSAgent.run")

    def __getattr__(self, name: str) -> Any:
        return getattr(self._agent, name)


@pytest.fixture(autouse=True)
def _reset_echo_runtime() -> None:
    reset_context_runtime_for_tests()


def _settings(tmp_path: Path) -> JSSettings:
    return JSSettings(
        workspace=tmp_path / "workspace",
        state_dir=tmp_path / "state",
        max_turns=3,
        security=SecurityConfig(api_key_required=False),
    )


def _make_client(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    agent: CapturingAgent,
) -> TestClient:
    settings = _settings(tmp_path)
    app = FastAPI()
    app.include_router(chat_router)

    monkeypatch.setattr("js.web.server._settings", settings, raising=False)
    monkeypatch.setattr("js.web.deps._settings", settings, raising=False)
    monkeypatch.setattr("js.web.routers.chat.get_agent", lambda: agent)
    monkeypatch.setattr("js.web.routers.chat.get_stats_store", lambda: None)
    # Anonymous guests are read-only; authenticate as a regular user.
    from js.web.auth import AuthManager

    user_key = AuthManager(settings.state_dir).create_key("echo-e2e", role="user")
    return TestClient(
        app,
        base_url="http://localhost",
        headers={"Origin": "http://localhost", "X-API-Key": user_key},
    )


def _make_agent(tmp_path: Path, provider: RecordingProvider) -> CapturingAgent:
    agent = JSAgent(_settings(tmp_path))
    agent.router = RecordingRouter(provider, permit_verifier=agent._model_permit_issuer)
    return CapturingAgent(agent)


def _ledger_records(
    agent: CapturingAgent,
    owner_key_hash: str,
    session_id: str,
) -> list[Any]:
    service = agent._agent.echo_safety_service
    return FileEchoLedger(
        service.journal_path_for_scope(
            owner_key_hash,
            product_id="js-agent",
            session_id=session_id,
        ),
        mac_key=service.journal_key_for_scope(
            owner_key_hash,
            product_id="js-agent",
            session_id=session_id,
        ),
    ).records


def _make_ws_app(monkeypatch: pytest.MonkeyPatch) -> Any:
    monkeypatch.setenv("JS_ALLOWED_ORIGINS", "http://localhost")
    import js.web.auth as auth_mod

    monkeypatch.setattr(auth_mod, "_ALLOWED_ORIGINS", None)

    @asynccontextmanager
    async def _noop_lifespan(_app: Any) -> AsyncIterator[None]:
        yield

    with patch("js.web.server.lifespan", _noop_lifespan):
        from js.web.server import create_app

        return create_app()


def test_make_ws_app_origin_overrides_are_scoped(monkeypatch: pytest.MonkeyPatch) -> None:
    import js.web.auth as auth_mod

    original_cache = ("http://before.example",)
    monkeypatch.setenv("JS_ALLOWED_ORIGINS", "http://before.example")
    monkeypatch.setattr(auth_mod, "_ALLOWED_ORIGINS", original_cache)

    with pytest.MonkeyPatch.context() as ws_monkeypatch:
        _make_ws_app(ws_monkeypatch)
        assert os.environ["JS_ALLOWED_ORIGINS"] == "http://localhost"
        assert auth_mod._ALLOWED_ORIGINS in {None, frozenset({"http://localhost"})}

    assert os.environ["JS_ALLOWED_ORIGINS"] == "http://before.example"
    assert auth_mod._ALLOWED_ORIGINS is original_cache


def _make_ws_client(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    agent: CapturingAgent,
) -> TestClient:
    settings = _settings(tmp_path)
    app = _make_ws_app(monkeypatch)
    agent.settings = settings
    if not hasattr(agent, "_dream_scheduler") or agent._dream_scheduler is None:
        agent._dream_scheduler = MagicMock()

    monkeypatch.setattr("js.web.server._settings", settings)
    monkeypatch.setattr("js.web.server._agent", agent)
    monkeypatch.setattr("js.web.server.get_agent", lambda: agent)
    monkeypatch.setattr("js.web.deps._settings", settings)
    monkeypatch.setattr("js.web.deps._agent", agent)
    from js.web.auth import AuthManager

    user_key = AuthManager(settings.state_dir).create_key("echo-ws-e2e", role="user")
    return TestClient(
        app,
        base_url="http://localhost",
        headers={"Origin": "http://localhost", "X-API-Key": user_key},
    )


def test_api_chat_on_mode_produces_real_echo_metrics_from_agent_path(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("JS_ECHO_ENGINE", "on")
    provider = RecordingProvider()
    agent = _make_agent(tmp_path, provider)
    client = _make_client(monkeypatch, tmp_path, agent)

    response = client.post(
        "/api/chat",
        json={"message": "inspect this tool-heavy prompt", "session_id": "web-on-session"},
    )

    assert response.status_code == 200
    assert response.json()["response"] == "Echo endpoint response"
    assert len(provider.calls) == 1
    snapshot = get_context_runtime_snapshot_for_tests()
    assert snapshot.observation_count == 1
    assert snapshot.last_observation is not None
    assert snapshot.last_observation.mode == "on"
    assert snapshot.last_observation.channel == "agent_turn"
    assert snapshot.last_observation.session_id == "web-on-session"
    assert snapshot.last_observation.naive_tokens > 0
    assert snapshot.last_observation.new_cas_tokens > 0
    assert agent.last_state is not None
    echo_stats = agent.last_state.compression_stats["echo_context_savings"]
    assert echo_stats["mode"] == "on"
    assert echo_stats["channel"] == "agent_turn"
    assert echo_stats["naive_tokens"] == snapshot.last_observation.naive_tokens


def test_api_chat_on_mode_echo_failure_fails_open(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("JS_ECHO_ENGINE", "on")
    provider = RecordingProvider(content="Legacy provider still wins")
    agent = _make_agent(tmp_path, provider)
    client = _make_client(monkeypatch, tmp_path, agent)

    def boom(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("endpoint observer exploded")

    monkeypatch.setattr("js.echo.turn_loop.loop.observe_prompt_context", boom)

    response = client.post(
        "/api/chat",
        json={"message": "this request must still succeed", "session_id": "web-safety-unavailable"},
    )

    assert response.status_code == 200
    assert response.json()["response"] == "Legacy provider still wins"
    assert len(provider.calls) == 1
    assert agent.last_state is not None
    echo_stats = agent.last_state.compression_stats["echo_context_savings"]
    assert echo_stats["mode"] == "on"
    assert echo_stats["channel"] == "agent_turn"
    assert echo_stats["error"] == "RuntimeError: endpoint observer exploded"


def test_api_chat_on_mode_keeps_session_scopes_isolated(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("JS_ECHO_ENGINE", "on")
    provider = RecordingProvider()
    agent = _make_agent(tmp_path, provider)
    client = _make_client(monkeypatch, tmp_path, agent)

    first = client.post("/api/chat", json={"message": "same prompt", "session_id": "session-a"})
    second = client.post("/api/chat", json={"message": "same prompt", "session_id": "session-b"})

    assert first.status_code == 200
    assert second.status_code == 200
    assert len(provider.calls) == 2
    snapshot = get_context_runtime_snapshot_for_tests()
    assert snapshot.observation_count == 2
    assert snapshot.scope_count == 2
    assert snapshot.last_observation is not None
    assert snapshot.last_observation.session_id == "session-b"
    assert snapshot.last_observation.new_cas_tokens > 0


def test_ws_message_on_mode_produces_real_echo_metrics_from_agent_path(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("JS_ECHO_ENGINE", "on")
    provider = RecordingProvider(content="Echo WS endpoint response")
    agent = _make_agent(tmp_path, provider)
    client = _make_ws_client(monkeypatch, tmp_path, agent)

    with client.websocket_connect("/ws") as ws:
        ws.send_json(
            {
                "type": "message",
                "content": "inspect websocket prompt",
                "session_id": "ws-on-session",
            }
        )
        status = ws.receive_json()
        response = ws.receive_json()

    assert status["type"] == "status"
    assert status["content"] == "thinking..."
    assert all(status.get(key) for key in ("request_id", "turn_id", "run_id", "session_id"))
    assert response["type"] == "response"
    assert response["content"] == "Echo WS endpoint response"
    assert response["session_id"] == "ws-on-session"
    assert len(provider.calls) == 1
    snapshot = get_context_runtime_snapshot_for_tests()
    assert snapshot.observation_count == 1
    assert snapshot.last_observation is not None
    assert snapshot.last_observation.mode == "on"
    assert snapshot.last_observation.channel == "agent_turn"
    assert snapshot.last_observation.session_id == "ws-on-session"
    assert snapshot.last_observation.naive_tokens > 0
    assert agent.last_state is not None
    echo_stats = agent.last_state.compression_stats["echo_context_savings"]
    assert (
        response["compression"]["echo_context_savings"]["naive_tokens"]
        == echo_stats["naive_tokens"]
    )


def test_ws_message_on_mode_echo_failure_fails_open(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("JS_ECHO_ENGINE", "on")
    provider = RecordingProvider(content="WS legacy response survives")
    agent = _make_agent(tmp_path, provider)
    client = _make_ws_client(monkeypatch, tmp_path, agent)

    def boom(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("ws observer exploded")

    monkeypatch.setattr("js.echo.turn_loop.loop.observe_prompt_context", boom)

    with client.websocket_connect("/ws") as ws:
        ws.send_json(
            {
                "type": "message",
                "content": "this websocket turn must still succeed",
                "session_id": "ws-safety-unavailable",
            }
        )
        status = ws.receive_json()
        response = ws.receive_json()

    assert status["type"] == "status"
    assert status["content"] == "thinking..."
    assert all(status.get(key) for key in ("request_id", "turn_id", "run_id", "session_id"))
    assert response["type"] == "response"
    assert response["content"] == "WS legacy response survives"
    assert len(provider.calls) == 1
    assert response["compression"]["echo_context_savings"]["error"] == (
        "RuntimeError: ws observer exploded"
    )


@pytest.mark.parametrize(
    ("case", "events", "completion_budget", "expected_terminal_type"),
    [
        pytest.param(
            "success",
            [
                StreamEvent(kind="text_delta", text="ok"),
                StreamEvent(kind="done", finish_reason="stop"),
            ],
            8,
            "done",
            id="success",
        ),
        pytest.param(
            "budget-failure",
            [
                StreamEvent(kind="text_delta", text="abcdefgh"),
                StreamEvent(kind="done", finish_reason="stop"),
            ],
            1,
            "error",
            id="budget-failure",
        ),
        pytest.param(
            "provider-error",
            [StreamEvent(kind="error", error="provider failed")],
            8,
            "error",
            id="provider-error",
        ),
    ],
)
def test_ws_stream_connected_outcome_emits_exactly_one_terminal_frame(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    case: str,
    events: list[StreamEvent],
    completion_budget: int,
    expected_terminal_type: str,
) -> None:
    sent_frames: list[dict[str, Any]] = []
    pong_sent = threading.Event()
    real_send_json = WebSocket.send_json

    async def probe_send_json(
        websocket: WebSocket,
        data: Any,
        mode: Literal["text", "binary"] = "text",
    ) -> None:
        await real_send_json(websocket, data, mode=mode)
        if not isinstance(data, dict):
            return
        frame = dict(data)
        sent_frames.append(frame)
        if frame.get("type") == "pong":
            pong_sent.set()

    monkeypatch.setattr(WebSocket, "send_json", probe_send_json)
    provider = ScriptedStreamProvider(events)
    agent = _make_agent(tmp_path, provider)
    client = _make_ws_client(monkeypatch, tmp_path, agent)
    agent._agent.settings.echo_budget = EchoBudgetConfig(max_completion_tokens=completion_budget)
    frames: list[dict[str, Any]] = []

    with client.websocket_connect("/ws") as ws:
        ws.send_json(
            {
                "type": "stream",
                "content": f"exercise {case} terminal delivery",
                "session_id": f"ws-terminal-{case}",
                "enable_tools": False,
            }
        )
        while True:
            frame = ws.receive_json()
            frames.append(frame)
            if frame.get("terminal") is True:
                break
        ws.send_json({"type": "ping"})
        assert pong_sent.wait(timeout=1.0), {
            "client_frames": frames,
            "sent_frames": sent_frames,
        }

    turn_frames: list[dict[str, Any]] = []
    for frame in sent_frames:
        if frame.get("type") == "pong":
            break
        turn_frames.append(frame)
    terminal_frames = [frame for frame in turn_frames if frame.get("terminal") is True]
    assert len(terminal_frames) == 1, turn_frames
    assert terminal_frames[0]["type"] == expected_terminal_type
    assert all(frame.get("terminal") is not True for frame in turn_frames[:-1])
    diagnostics = [frame for frame in turn_frames if frame.get("type") == "stream_diagnostic"]
    assert all(frame.get("terminal") is not True for frame in diagnostics)


def test_ws_disconnect_cancels_inflight_echo_turn(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    provider = DisconnectAwareProvider()
    agent = _make_agent(tmp_path, provider)
    cancel_requests: list[tuple[str, str | None]] = []
    real_request_cancel = agent._agent.request_cancel

    def record_cancel(session_id: str, owner_key_hash: str | None = None) -> bool:
        cancel_requests.append((session_id, owner_key_hash))
        return real_request_cancel(session_id, owner_key_hash)

    agent._agent.request_cancel = record_cancel  # type: ignore[method-assign]
    client = _make_ws_client(monkeypatch, tmp_path, agent)

    with client.websocket_connect("/ws") as ws:
        ws.send_json(
            {
                "type": "message",
                "content": "start a slow turn",
                "session_id": "ws-disconnect",
            }
        )
        status = ws.receive_json()
        assert status["type"] == "status"
        assert status["content"] == "thinking..."
        assert all(status.get(key) for key in ("request_id", "turn_id", "run_id", "session_id"))
        assert provider.started.wait(timeout=1.0)
        ws.close()

    assert provider.cancelled.wait(timeout=1.0)
    assert len(cancel_requests) == 1
    assert cancel_requests[0][0] == "ws-disconnect"
    assert isinstance(cancel_requests[0][1], str) and cancel_requests[0][1]
    assert cancel_requests[0][1] != "local-user"
    owner_key_hash = cancel_requests[0][1]
    deadline = time.monotonic() + 1.0
    receipts: list[Any] = []
    merges: list[Any] = []
    while time.monotonic() < deadline:
        records = _ledger_records(agent, owner_key_hash, "ws-disconnect")
        receipts = [record for record in records if record.record_type == "receipt"]
        merges = [record for record in records if record.record_type == "merge"]
        if len(receipts) == 1 and len(merges) == 1:
            break
        time.sleep(0.01)

    assert len(receipts) == 1
    assert receipts[0].payload["status"] == "cancelled"
    assert len(merges) == 1
    assert merges[0].payload["status"] == "cancelled"
    assert agent._agent.echo_safety_service.health().claimed_effect_count == 0
