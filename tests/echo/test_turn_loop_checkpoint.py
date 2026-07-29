from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from js.config import JSSettings
from js.echo.effect_interpreter import ToolEffect
from js.echo.ledger.service import EchoUnavailableError
from js.echo.state import AgentState
from js.echo.turn_context import RuntimeContext, reset_runtime_context, set_runtime_context
from js.echo.turn_loop import EchoTurnLoop
from js.models.providers import ChatMessage, ChatResponse
from js.tools.registry import ToolResult


class _EventStore:
    def __init__(self) -> None:
        self.events: list[Any] = []

    def emit(self, event: Any) -> None:
        self.events.append(event)


class _Audit:
    def log(self, *_args: Any, **_kwargs: Any) -> None:
        pass


class _EchoRuntime:
    def __init__(self) -> None:
        self.executed_tool_call_ids: list[str] = []

    def derive_context(self, context: RuntimeContext, **_kwargs: Any) -> RuntimeContext:
        return context

    async def execute_tool_effect(
        self,
        effect: ToolEffect,
        *_args: Any,
        **_kwargs: Any,
    ) -> tuple[ChatMessage, ToolResult]:
        self.executed_tool_call_ids.append(effect.tool_call_id)
        return (
            ChatMessage(
                role="tool",
                content="contents",
                tool_call_id=effect.tool_call_id,
                name=effect.tool_name,
            ),
            ToolResult(success=True, output="contents"),
        )


class _CheckpointAgent:
    def __init__(self, tmp_path: Path, checkpoint_error: Exception | None = None) -> None:
        self.settings = JSSettings(
            workspace=tmp_path / "workspace",
            state_dir=tmp_path / "state",
            echo_engine="on",
        )
        self.logger = logging.getLogger("tests.echo.turn_loop_checkpoint")
        self.echo_runtime = _EchoRuntime()
        self.registry = SimpleNamespace(
            get=lambda name: SimpleNamespace(read_only=name == "file_read")
        )
        self.event_store = _EventStore()
        self.audit = _Audit()
        self._quality_scorer = None
        self.checkpoint_started = asyncio.Event()
        self.checkpoint_release = asyncio.Event()
        self.checkpoint_error = checkpoint_error

    async def save_checkpoint(self, _state: AgentState) -> None:
        self.checkpoint_started.set()
        await self.checkpoint_release.wait()
        if self.checkpoint_error is not None:
            raise self.checkpoint_error


def _new_loop(agent: _CheckpointAgent, response: ChatResponse) -> EchoTurnLoop:
    loop = EchoTurnLoop(
        agent,
        "read a file",
        "session-1",
        None,
        None,
        None,
        None,
        None,
    )
    loop.run_id = "run-1"
    loop.state = AgentState(session_id="session-1", run_id="run-1", turn_count=1)
    loop.state.messages = [
        ChatMessage(role="system", content="initial-system"),
        ChatMessage(role="user", content="read a file"),
        ChatMessage(role="assistant", content="", tool_calls=response.tool_calls),
    ]
    loop.allowed_tools = {"file_read", "shell"}
    return loop


def _tool_response() -> ChatResponse:
    return ChatResponse(
        content="",
        tool_calls=[
            {
                "id": "call-1",
                "function": {"name": "file_read", "arguments": "{}"},
            }
        ],
        model="test-model",
        usage={},
        finish_reason="tool_calls",
    )


def _sequential_tool_response() -> ChatResponse:
    return ChatResponse(
        content="",
        tool_calls=[
            {
                "id": f"call-{index}",
                "function": {"name": "shell", "arguments": "{}"},
            }
            for index in range(1, 3)
        ],
        model="test-model",
        usage={},
        finish_reason="tool_calls",
    )


def _checkpoint_events(agent: _CheckpointAgent) -> list[Any]:
    return [event for event in agent.event_store.events if event.event_type == "checkpoint_saved"]


def _runtime_context(tmp_path: Path) -> RuntimeContext:
    return RuntimeContext(
        product_id="js-agent",
        channel="test",
        owner_key_hash="owner-1",
        session_id="session-1",
        run_id="run-1",
        role="local-user",
        profile="default",
        capabilities=("file_read",),
        workspace=tmp_path / "workspace",
        state_dir=tmp_path / "state",
    )


@pytest.mark.asyncio
async def test_tool_batch_waits_for_checkpoint_before_emitting_success(tmp_path: Path) -> None:
    agent = _CheckpointAgent(tmp_path)
    response = _tool_response()
    loop = _new_loop(agent, response)
    context_token = set_runtime_context(_runtime_context(tmp_path))
    try:
        batch_task = asyncio.create_task(loop._run_tools(response, []))
        await asyncio.wait_for(agent.checkpoint_started.wait(), timeout=1)

        assert not batch_task.done()
        assert _checkpoint_events(agent) == []

        agent.checkpoint_release.set()
        await batch_task
    finally:
        reset_runtime_context(context_token)

    assert len(_checkpoint_events(agent)) == 1


@pytest.mark.asyncio
async def test_tool_batch_checkpoint_failure_warns_without_success_event(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    agent = _CheckpointAgent(tmp_path, checkpoint_error=OSError("checkpoint unavailable"))
    agent.checkpoint_release.set()
    response = _sequential_tool_response()
    loop = _new_loop(agent, response)
    context_token = set_runtime_context(_runtime_context(tmp_path))
    try:
        with (
            caplog.at_level(logging.WARNING, logger=agent.logger.name),
            pytest.raises(EchoUnavailableError, match="checkpoint persistence failed"),
        ):
            await loop._run_tools(response, [])
    finally:
        reset_runtime_context(context_token)

    assert "Checkpoint auto-save failed" in caplog.text
    assert _checkpoint_events(agent) == []
    assert agent.echo_runtime.executed_tool_call_ids == ["call-1"]
