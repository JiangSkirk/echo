"""Tests for memory-context fence and streaming scrubber."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from js.agent.finalizer import FinalizerMixin
from js.agent.state import AgentState
from js.echo.turn_context import (
    RuntimeContext,
    reset_current_owner_key_hash,
    reset_runtime_context,
    set_current_owner_key_hash,
    set_runtime_context,
)
from js.echo.turn_loop import EchoTurnLoop
from js.models.providers import ChatMessage, ChatResponse
from js.security.secrets import SecretManager

_SECRET = "sk-test12345678901234567890"


class _DummyFinalizer(FinalizerMixin):
    async def _summarize_context(self, messages: list[ChatMessage]) -> str:
        return f"capsule summary with {_SECRET}"


def _make_finalizer(tmp_path):
    obj = _DummyFinalizer()
    obj.secrets = SecretManager(tmp_path / "state")
    obj.settings = MagicMock()
    obj.settings.memory.capsule_enabled = True
    obj.settings.memory.capsule_token_threshold = 10
    obj.memory = MagicMock()
    obj.memory.store_messages = MagicMock()
    obj.memory.store_episode = MagicMock()
    obj.memory.store_capsule = MagicMock()
    obj._dream_scheduler = MagicMock()
    obj._quality_scorer = None
    obj.learner = MagicMock()
    obj.compression_feedback = MagicMock()
    obj.optimizer = MagicMock()
    obj.metacognition = MagicMock()
    obj.curator = MagicMock()
    obj.curator.should_run.return_value = False
    obj.evolver = None
    obj.skills = MagicMock()
    obj.guard = MagicMock()
    obj.logger = MagicMock()
    return obj


@pytest.mark.asyncio
async def test_store_messages_are_redacted(tmp_path):
    finalizer = _make_finalizer(tmp_path)
    state = AgentState(session_id="s1", run_id="r1")
    state.messages = [
        ChatMessage(role="system", content="sys"),
        ChatMessage(role="user", content=f"my key is {_SECRET}"),
        ChatMessage(role="assistant", content=f"use {_SECRET}"),
    ]
    state.status = "completed"
    state.total_tokens = {"input": 10, "output": 10}

    token = set_current_owner_key_hash("owner_a")
    try:
        await finalizer._finalize_run(state, "s1", "r1", f"my key is {_SECRET}", 0)
    finally:
        reset_current_owner_key_hash(token)

    stored = finalizer.memory.store_messages.call_args[0][1]
    assert stored[0]["role"] == "user"
    assert _SECRET not in stored[0]["content"]
    assert "[REDACTED" in stored[0]["content"]
    assert stored[1]["role"] == "assistant"
    assert _SECRET not in stored[1]["content"]
    assert finalizer.memory.store_messages.call_args[0][2] == "owner_a"


@pytest.mark.asyncio
async def test_episode_summary_is_redacted(tmp_path):
    finalizer = _make_finalizer(tmp_path)
    state = AgentState(session_id="s1", run_id="r1")
    state.messages = [ChatMessage(role="assistant", content=f"ok {_SECRET}")]
    state.status = "completed"
    state.total_tokens = {"input": 5, "output": 5}

    await finalizer._finalize_run(state, "s1", "r1", f"user {_SECRET}", 0)

    summary = finalizer.memory.store_episode.call_args.kwargs["summary"]
    assert _SECRET not in summary
    assert "[REDACTED" in summary


@pytest.mark.asyncio
async def test_capsule_text_is_redacted(tmp_path):
    finalizer = _make_finalizer(tmp_path)
    state = AgentState(session_id="s1", run_id="r1")
    state.messages = [ChatMessage(role="assistant", content="hello")]
    state.status = "completed"
    state.total_tokens = {"input": 20, "output": 20}

    await finalizer._finalize_run(state, "s1", "r1", "hi", 0)

    capsule = finalizer.memory.store_capsule.call_args[0][1]
    assert _SECRET not in capsule
    assert "[REDACTED" in capsule


@pytest.mark.asyncio
async def test_streaming_callback_receives_redacted_tokens(tmp_path):
    from js.config import EchoBudgetConfig

    agent = MagicMock()
    agent.settings.echo_budget = EchoBudgetConfig()
    agent.secrets = SecretManager.__new__(SecretManager)
    agent.secrets.PATTERNS = SecretManager.PATTERNS
    agent.secrets.detect_and_redact = SecretManager.detect_and_redact.__get__(
        agent.secrets, SecretManager
    )
    agent.secrets._redaction_cache = set()
    agent.secrets._log_detection = MagicMock()

    async def fake_stream(*args, **kwargs):
        yield f"token {_SECRET}"

    # PR-4.3: EchoTurnLoop now consumes chat_stream_events(). The structured
    # equivalent of yielding "token <SECRET>" is a single text_delta event,
    # which the loop then redacts and forwards to stream_callback.
    from js.models.stream_events import StreamEvent

    async def fake_stream_events(*args, **kwargs):
        yield StreamEvent(kind="text_delta", text=f"token {_SECRET}")

    provider = MagicMock()
    provider.chat_stream = fake_stream
    provider.chat_stream_events = fake_stream_events
    provider._last_stream_usage = None
    decision = MagicMock()
    decision.provider = provider
    decision.model = "m"
    agent.router = MagicMock()
    agent.router.select_model = AsyncMock(return_value=decision)

    class _EchoRuntime:
        async def execute_model_stream_effect(self, *_args, **_kwargs):
            async for event in fake_stream_events():
                yield event

    agent.echo_runtime = _EchoRuntime()

    received: list[str] = []

    async def callback(token: str) -> None:
        received.append(token)

    executor = EchoTurnLoop(
        agent=agent,
        user_input="hi",
        session_id="s1",
        model=None,
        attachments=None,
        resume_state=None,
        stream_callback=callback,
        progress_callback=None,
    )
    executor.state = AgentState(session_id="s1", run_id="r1")

    runtime_context = RuntimeContext(
        product_id="js-agent",
        channel="test",
        owner_key_hash="owner-a",
        session_id="s1",
        run_id="r1",
        role="local-user",
        profile="default",
        capabilities=(),
        workspace=tmp_path / "workspace",
        state_dir=tmp_path / "state",
    )
    token = set_runtime_context(runtime_context)
    try:
        response = await executor._get_response([], None)
    finally:
        reset_runtime_context(token)
    assert isinstance(response, ChatResponse)
    assert _SECRET not in response.content
    assert "[REDACTED" in response.content
    assert len(received) == 1
    assert _SECRET not in received[0]
    assert "[REDACTED" in received[0]
