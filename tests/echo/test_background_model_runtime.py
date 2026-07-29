from __future__ import annotations

import ast
import asyncio
import sqlite3
import threading
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from js.agent import JSAgent
from js.agent.state import AgentState
from js.config import JSSettings, SecurityConfig
from js.echo.effect_interpreter import ModelEffect, ToolEffect
from js.echo.model_budget import EchoBudgetExceededError
from js.echo.state import AgentState as EchoAgentState
from js.echo.turn_context import RuntimeContext, reset_runtime_context, set_runtime_context
from js.echo.turn_loop import EchoTurnLoop, _tool_quality_score, _tool_result_event
from js.evolution.quality_scorer import QualityScorer
from js.models.providers import ChatMessage, ChatResponse
from js.models.stream_events import StreamEvent
from js.tools.registry import ToolResult

ROOT = Path(__file__).resolve().parents[2]
BACKGROUND_METHODS = {
    "_memory_extraction_model_chat": "memory_extraction",
    "_auto_update_profiles": "profile_update",
    "_run_skill_evolution_for": "skill_evolution",
    "_run_dreaming": "dreaming",
}


@pytest.mark.asyncio
async def test_quality_metric_write_failure_does_not_fail_completed_turn() -> None:
    loop = object.__new__(EchoTurnLoop)
    scorer = MagicMock()
    scorer.record_turn.side_effect = sqlite3.OperationalError("database is locked")
    logger = MagicMock()
    loop.agent = SimpleNamespace(_quality_scorer=scorer, logger=logger)
    loop.state = SimpleNamespace(
        status="completed",
        turn_count=1,
        model="mock",
        total_tokens={"input": 1, "output": 2},
    )
    loop.session_id = "session-a"
    loop.run_id = "run-a"
    loop.owner_key_hash = "owner-a"

    await loop._record_turn_metrics(time.perf_counter(), [])

    scorer.record_turn.assert_called_once()
    logger.warning.assert_called()
    assert loop.state.status == "completed"


@pytest.mark.asyncio
async def test_quality_metric_write_does_not_block_echo_event_loop(
    tmp_path: Path,
) -> None:
    scorer = QualityScorer(tmp_path)
    lock_ready = threading.Event()

    def hold_write_lock() -> None:
        with sqlite3.connect(scorer.db_path) as conn:
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("BEGIN IMMEDIATE")
            lock_ready.set()
            threading.Event().wait(0.25)
            conn.rollback()

    holder = threading.Thread(target=hold_write_lock)
    holder.start()
    assert await asyncio.to_thread(lock_ready.wait, 1.0)

    loop = object.__new__(EchoTurnLoop)
    loop.agent = SimpleNamespace(_quality_scorer=scorer, logger=MagicMock())
    loop.state = SimpleNamespace(
        turn_count=1,
        model="mock",
        total_tokens={"input": 1, "output": 2},
    )
    loop.session_id = "session-a"
    loop.run_id = "run-a"
    loop.owner_key_hash = "owner-a"
    event_loop_ticked = asyncio.Event()

    async def tick() -> None:
        await asyncio.sleep(0.05)
        event_loop_ticked.set()

    ticker = asyncio.create_task(tick())
    await loop._record_turn_metrics(time.perf_counter(), [])
    responsive_before_return = event_loop_ticked.is_set()
    await ticker
    await asyncio.to_thread(holder.join, 1.0)

    assert responsive_before_return


@pytest.mark.asyncio
async def test_quality_metric_write_is_skipped_when_turn_is_already_cancelling(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    loop = object.__new__(EchoTurnLoop)
    scorer = MagicMock()
    loop.agent = SimpleNamespace(_quality_scorer=scorer, logger=MagicMock())
    loop.state = SimpleNamespace(
        status="cancelled",
        turn_count=1,
        model="mock",
        total_tokens={"input": 1, "output": 2},
    )
    loop.session_id = "session-a"
    loop.run_id = "run-a"
    loop.owner_key_hash = "owner-a"
    cancelling_task = SimpleNamespace(cancelling=lambda: 1)
    monkeypatch.setattr(asyncio, "current_task", lambda: cancelling_task)

    await loop._record_turn_metrics(time.perf_counter(), [])

    scorer.record_turn.assert_not_called()
    assert loop.state.status == "cancelled"


def test_failed_tool_quality_uses_called_tool_name() -> None:
    score = _tool_quality_score(
        ChatMessage(
            role="tool",
            content="denied",
            name="file_read",
            tool_call_id="call-a",
        ),
        ToolResult(success=False, error="Security: path denied"),
    )

    assert score.tool_name == "file_read"
    assert score.error_pattern == "Security: path denied"


@pytest.mark.parametrize(
    ("result", "expected_preview"),
    [
        (ToolResult(success=True, output="done"), "done"),
        (ToolResult(success=False, error="Security: path denied"), "Security: path denied"),
    ],
)
def test_tool_result_event_uses_called_tool_name(
    result: ToolResult,
    expected_preview: str,
) -> None:
    event = _tool_result_event(
        "session-a",
        "run-a",
        ChatMessage(
            role="tool",
            content=expected_preview,
            name="file_read",
            tool_call_id="call-a",
        ),
        result,
    )

    assert event.payload == {
        "tool_name": "file_read",
        "success": result.success,
        "output_preview": expected_preview,
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "detector_mode",
    ["standard", "raises", "invalid"],
)
async def test_non_stream_provider_exception_is_safe_in_every_terminal_sink(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    detector_mode: str,
) -> None:
    agent = JSAgent(
        JSSettings(
            workspace=tmp_path / "workspace",
            state_dir=tmp_path / "state",
            max_turns=1,
        )
    )
    secret = "sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"
    audit_records: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
    emitted_events: list[Any] = []
    finalized_states: list[dict[str, Any]] = []
    checkpoint_states: list[dict[str, Any]] = []
    redaction_sources: list[str] = []
    original_redact = agent.secrets.detect_and_redact

    def detect_and_redact(text: str, source: str = "unknown") -> Any:
        if source == "provider_exception":
            redaction_sources.append(source)
            if detector_mode == "raises":
                raise OSError("secret detector unavailable")
            if detector_mode == "invalid":
                return None
        return original_redact(text, source)

    def audit_log(*args: Any, **kwargs: Any) -> None:
        audit_records.append((args, kwargs))

    async def model_effect(
        _effect: ModelEffect,
        _context: RuntimeContext,
    ) -> ChatResponse:
        raise RuntimeError(f"provider failed with {secret}")

    async def save_checkpoint(state: EchoAgentState) -> None:
        checkpoint_states.append(state.to_dict())

    async def finalize_run(
        state: EchoAgentState,
        _session_id: str,
        _run_id: str,
        _user_input: str,
        _history_ua_count: int,
    ) -> None:
        finalized_states.append(state.to_dict())
        await agent.save_checkpoint(state)

    agent.secrets.detect_and_redact = detect_and_redact  # type: ignore[method-assign]
    agent.audit.log = audit_log  # type: ignore[method-assign]
    agent.event_store.emit = emitted_events.append  # type: ignore[method-assign]
    agent.echo_runtime.execute_model_effect = model_effect  # type: ignore[assignment]
    agent.save_checkpoint = save_checkpoint  # type: ignore[method-assign]
    agent._finalize_run = finalize_run  # type: ignore[method-assign]
    agent._check_degraded = AsyncMock()  # type: ignore[method-assign]
    loop = EchoTurnLoop(agent, "hello", "session-a", None, None, None, None, None)
    context_token = set_runtime_context(
        agent.echo_runtime.build_context(
            channel="test",
            owner_key_hash="owner-a",
            session_id="session-a",
            run_id="run-a",
            capabilities=(),
        )
    )
    try:
        state = await loop.execute()
    finally:
        reset_runtime_context(context_token)
        await agent.close()
    captured_logs = capsys.readouterr()

    sink_values = {
        "state": repr(state.to_dict()),
        "finalized": repr(finalized_states),
        "checkpoint": repr(checkpoint_states),
        "audit": repr(audit_records),
        "events": repr(emitted_events),
        "logs": captured_logs.out + captured_logs.err,
    }
    assert [name for name, value in sink_values.items() if secret in value] == []
    assert redaction_sources == ["provider_exception"]
    assert state.status == "error"
    assert state.error_message.startswith("RuntimeError:")
    assert finalized_states == checkpoint_states
    assert len(finalized_states) == 1
    assert any(args[4] == "exception" for args, _kwargs in audit_records)
    assert any(event.event_type == "error" for event in emitted_events)
    assert "run-a" in sink_values["logs"]
    assert "RuntimeError" in sink_values["logs"]
    assert "Traceback" not in sink_values["logs"]
    if detector_mode == "standard":
        assert "[REDACTED:openai_key]" in state.error_message
    else:
        assert state.error_message == "RuntimeError: error details unavailable"


@pytest.mark.asyncio
async def test_setup_failure_is_safe_before_terminal_persistence(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    agent = JSAgent(
        JSSettings(workspace=tmp_path / "workspace", state_dir=tmp_path / "state")
    )
    secret = "sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"
    finalized_states: list[dict[str, Any]] = []
    checkpoint_states: list[dict[str, Any]] = []
    redaction_sources: list[str] = []
    original_redact = agent.secrets.detect_and_redact
    loop = EchoTurnLoop(agent, "hello", "session-a", None, None, None, None, None)

    def detect_and_redact(text: str, source: str = "unknown") -> str:
        if source == "setup_exception":
            redaction_sources.append(source)
        return original_redact(text, source)

    async def fail_setup() -> None:
        loop.run_id = "run-a"
        loop.state = EchoAgentState(session_id="session-a", run_id="run-a")
        loop.state.messages = [
            ChatMessage(role="system", content="initial-system"),
            ChatMessage(role="user", content="hello"),
        ]
        raise RuntimeError(f"setup failed with {secret}")

    async def save_checkpoint(state: EchoAgentState) -> None:
        checkpoint_states.append(state.to_dict())

    async def finalize_run(
        state: EchoAgentState,
        _session_id: str,
        _run_id: str,
        _user_input: str,
        _history_ua_count: int,
    ) -> None:
        finalized_states.append(state.to_dict())
        await agent.save_checkpoint(state)

    agent.secrets.detect_and_redact = detect_and_redact  # type: ignore[method-assign]
    agent.save_checkpoint = save_checkpoint  # type: ignore[method-assign]
    agent._finalize_run = finalize_run  # type: ignore[method-assign]
    loop._setup = fail_setup  # type: ignore[method-assign]
    try:
        with pytest.raises(RuntimeError):
            await loop.execute()
    finally:
        await agent.close()
    captured_logs = capsys.readouterr()

    assert redaction_sources == ["setup_exception"]
    assert secret not in loop.state.error_message
    assert secret not in repr(finalized_states)
    assert secret not in repr(checkpoint_states)
    assert secret not in captured_logs.out + captured_logs.err
    assert "[REDACTED:openai_key]" in loop.state.error_message
    assert finalized_states == checkpoint_states


def test_message_limit_is_hard_cap_without_duplicating_system_messages() -> None:
    loop = object.__new__(EchoTurnLoop)
    main_system = ChatMessage(role="system", content="main-system")
    recent_system = ChatMessage(role="system", content="recent-system")
    messages = [main_system]
    messages.extend(
        ChatMessage(role="user", content=f"message-{index}")
        for index in range(198)
    )
    messages.append(recent_system)
    loop.agent = SimpleNamespace(
        settings=SimpleNamespace(
            security=SimpleNamespace(max_messages_hard_limit=100)
        ),
        logger=MagicMock(),
    )
    loop.state = SimpleNamespace(messages=messages)

    loop._enforce_message_limit()

    assert loop.state.messages.count(main_system) == 1
    assert loop.state.messages.count(recent_system) == 1
    assert len(loop.state.messages) == 100


def test_message_limit_caps_system_only_history() -> None:
    loop = object.__new__(EchoTurnLoop)
    messages = [
        ChatMessage(role="system", content=f"system-{index}")
        for index in range(150)
    ]
    loop.agent = SimpleNamespace(
        settings=SimpleNamespace(
            security=SimpleNamespace(max_messages_hard_limit=100)
        ),
        logger=MagicMock(),
    )
    loop.state = SimpleNamespace(messages=messages)

    loop._enforce_message_limit()

    assert len(loop.state.messages) == 100
    assert loop.state.messages[0] == messages[0]
    assert loop.state.messages[1:] == messages[-99:]


def test_message_limit_of_one_preserves_initial_system_message() -> None:
    loop = object.__new__(EchoTurnLoop)
    messages = [
        ChatMessage(role="system", content="initial-system"),
        ChatMessage(role="user", content="user"),
        ChatMessage(role="system", content="recent-system"),
    ]
    loop.agent = SimpleNamespace(
        settings=SimpleNamespace(security=SimpleNamespace(max_messages_hard_limit=1)),
        logger=MagicMock(),
    )
    loop.state = SimpleNamespace(messages=messages)

    loop._enforce_message_limit()

    assert loop.state.messages == messages[:1]


def _assert_complete_tool_call_groups(messages: list[ChatMessage] | tuple[ChatMessage, ...]) -> None:
    grouped_tool_indices: set[int] = set()
    for index, message in enumerate(messages):
        if message.role != "assistant" or not message.tool_calls:
            continue
        expected_ids = [str(call["id"]) for call in message.tool_calls]
        result_ids: list[str] = []
        cursor = index + 1
        while cursor < len(messages) and messages[cursor].role == "tool":
            grouped_tool_indices.add(cursor)
            result_ids.append(str(messages[cursor].tool_call_id))
            cursor += 1
        assert result_ids == expected_ids

    for index, message in enumerate(messages):
        if message.role == "tool":
            assert index in grouped_tool_indices


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("tool_name", "tool_success"),
    [("file_read", True), ("shell", False)],
    ids=["parallel-success", "sequential-failure"],
)
async def test_turn_loop_bounds_large_tool_batch_without_orphaning_history(
    tmp_path: Path,
    tool_name: str,
    tool_success: bool,
) -> None:
    agent = JSAgent(
        JSSettings(
            workspace=tmp_path / "workspace",
            state_dir=tmp_path / "state",
            max_turns=2,
            security=SecurityConfig(max_messages_hard_limit=10),
        )
    )
    initial_system = ChatMessage(role="system", content="initial-system")
    resume_state = EchoAgentState(session_id="session-a", run_id="run-a")
    resume_state.messages = [initial_system] + [
        ChatMessage(role="user", content=f"history-{index}") for index in range(9)
    ]
    current_user = resume_state.messages[-1]
    loop = EchoTurnLoop(
        agent,
        "continue",
        "session-a",
        None,
        None,
        resume_state,
        None,
        None,
    )
    model_effects: list[tuple[ChatMessage, ...]] = []
    checkpoint_messages: list[list[ChatMessage]] = []
    executed_tool_call_ids: list[str] = []

    async def model_effect(effect: ModelEffect, _context: RuntimeContext) -> ChatResponse:
        model_effects.append(effect.messages)
        if len(model_effects) == 1:
            return ChatResponse(
                content="",
                tool_calls=[
                    {
                        "id": f"tool-{index}",
                        "function": {"name": tool_name, "arguments": "{}"},
                    }
                    for index in range(12)
                ],
                model="mock",
                usage={},
                finish_reason="tool_calls",
            )
        return ChatResponse(
            content="final answer",
            tool_calls=[],
            model="mock",
            usage={},
            finish_reason="stop",
        )

    async def tool_effect(
        effect: ToolEffect,
        _context: RuntimeContext,
        _progress: Callable[[str, ToolResult], Awaitable[None]] | None,
    ) -> tuple[ChatMessage, ToolResult]:
        executed_tool_call_ids.append(effect.tool_call_id)
        return (
            ChatMessage(
                role="tool",
                content=f"result-{effect.tool_call_id}",
                name=effect.tool_name,
                tool_call_id=effect.tool_call_id,
            ),
            ToolResult(
                success=tool_success,
                output="ok" if tool_success else "",
                error="denied" if not tool_success else "",
            ),
        )

    async def save_checkpoint(state: EchoAgentState) -> None:
        checkpoint_messages.append(list(state.messages))

    agent.echo_runtime.execute_model_effect = model_effect  # type: ignore[assignment]
    agent.echo_runtime.execute_tool_effect = tool_effect  # type: ignore[assignment]
    agent.save_checkpoint = save_checkpoint  # type: ignore[method-assign]
    context_token = set_runtime_context(
        agent.echo_runtime.build_context(
            channel="test",
            owner_key_hash="owner-a",
            session_id="session-a",
            run_id="run-a",
        )
    )
    try:
        state = await loop.execute()
    finally:
        reset_runtime_context(context_token)
        await agent.close()

    expected_ids = [f"tool-{index}" for index in range(6)]
    assert executed_tool_call_ids == expected_ids
    assert all(len(messages) <= 10 for messages in model_effects)
    assert all(len(messages) <= 10 for messages in checkpoint_messages)
    assert len(state.messages) <= 10
    assert state.messages[0] == initial_system
    assert state.messages[-1].content == "final answer"
    assert all(current_user in messages for messages in model_effects)
    assert all(current_user in messages for messages in checkpoint_messages)
    assert state.messages.count(current_user) == 1
    for messages in [*model_effects, *checkpoint_messages, state.messages]:
        assert messages.count(initial_system) == 1
        assert messages.count(current_user) == 1
        assert messages.index(initial_system) < messages.index(current_user)
        _assert_complete_tool_call_groups(messages)
    for messages in checkpoint_messages:
        assert any(message.role == "assistant" and message.tool_calls for message in messages)
        controls = [
            message
            for message in messages
            if message.role == "system"
            and ("not executed" in str(message.content) or "STOP calling tools" in str(message.content))
        ]
        assert len(controls) <= 1
    checkpoint_prefix_lengths = [
        len(
            next(
                message.tool_calls or []
                for message in messages
                if message.role == "assistant" and message.tool_calls
            )
        )
        for messages in checkpoint_messages
    ]
    assert checkpoint_prefix_lengths == ([4, 6] if tool_success else [1, 2, 3, 4, 5, 6])
    provider_tool_groups = [
        message for message in model_effects[1] if message.role == "assistant" and message.tool_calls
    ]
    assert len(provider_tool_groups) == 1
    assert [str(call["id"]) for call in provider_tool_groups[0].tool_calls or []] == expected_ids
    control_messages = [
        str(message.content)
        for message in model_effects[1]
        if message.role == "system"
        and ("not executed" in str(message.content) or "STOP calling tools" in str(message.content))
    ]
    assert len(control_messages) == 1
    assert "not executed" in control_messages[0]
    if not tool_success:
        assert "STOP calling tools" in control_messages[0]


async def _run_tool_id_loop(
    tmp_path: Path,
    tool_calls: list[dict[str, Any]],
    *,
    first_response_content: str = "",
) -> tuple[
    EchoAgentState,
    list[tuple[ChatMessage, ...]],
    list[list[ChatMessage]],
    list[str],
    ChatMessage,
    ChatMessage,
]:
    agent = JSAgent(
        JSSettings(
            workspace=tmp_path / "workspace",
            state_dir=tmp_path / "state",
            max_turns=2,
            security=SecurityConfig(max_messages_hard_limit=10),
        )
    )
    initial_system = ChatMessage(role="system", content="initial-system")
    current_user = ChatMessage(role="user", content="current-user")
    resume_state = EchoAgentState(session_id="session-a", run_id="run-a")
    resume_state.messages = [initial_system, current_user]
    loop = EchoTurnLoop(
        agent,
        "continue",
        "session-a",
        None,
        None,
        resume_state,
        None,
        None,
    )
    model_effects: list[tuple[ChatMessage, ...]] = []
    checkpoint_messages: list[list[ChatMessage]] = []
    executed_tool_call_ids: list[str] = []

    async def model_effect(effect: ModelEffect, _context: RuntimeContext) -> ChatResponse:
        model_effects.append(effect.messages)
        if len(model_effects) == 1:
            return ChatResponse(
                content=first_response_content,
                tool_calls=tool_calls,
                model="mock",
                usage={},
                finish_reason="tool_calls",
            )
        return ChatResponse(
            content="final answer",
            tool_calls=[],
            model="mock",
            usage={},
            finish_reason="stop",
        )

    async def tool_effect(
        effect: ToolEffect,
        _context: RuntimeContext,
        _progress: Callable[[str, ToolResult], Awaitable[None]] | None,
    ) -> tuple[ChatMessage, ToolResult]:
        executed_tool_call_ids.append(effect.tool_call_id)
        return (
            ChatMessage(
                role="tool",
                content=f"result-{effect.tool_call_id}",
                name=effect.tool_name,
                tool_call_id=effect.tool_call_id,
            ),
            ToolResult(success=True, output="ok"),
        )

    async def save_checkpoint(state: EchoAgentState) -> None:
        checkpoint_messages.append(list(state.messages))

    agent.echo_runtime.execute_model_effect = model_effect  # type: ignore[assignment]
    agent.echo_runtime.execute_tool_effect = tool_effect  # type: ignore[assignment]
    agent.save_checkpoint = save_checkpoint  # type: ignore[method-assign]
    context_token = set_runtime_context(
        agent.echo_runtime.build_context(
            channel="test",
            owner_key_hash="owner-a",
            session_id="session-a",
            run_id="run-a",
        )
    )
    try:
        state = await loop.execute()
    finally:
        reset_runtime_context(context_token)
        await agent.close()
    return (
        state,
        model_effects,
        checkpoint_messages,
        executed_tool_call_ids,
        initial_system,
        current_user,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "invalid_id",
    [None, 7, "", " \t"],
    ids=["none", "non-string", "empty", "blank"],
)
async def test_turn_loop_rejects_invalid_tool_call_id_with_bounding_notice(
    tmp_path: Path,
    invalid_id: Any,
) -> None:
    tool_calls = [
        {
            "id": invalid_id,
            "function": {"name": "file_read", "arguments": "{}"},
        }
    ]

    state, model_effects, checkpoints, executed_ids, initial_system, current_user = (
        await _run_tool_id_loop(tmp_path, tool_calls)
    )

    assert executed_ids == []
    assert checkpoints == []
    assert len(model_effects) == 2
    control_messages = [
        str(message.content)
        for message in model_effects[1]
        if message.role == "system" and "Tool-call batch was bounded" in str(message.content)
    ]
    assert len(control_messages) == 1
    assert "accepted 0 of 1 calls" in control_messages[0]
    for messages in [*model_effects, state.messages]:
        assert len(messages) <= 10
        assert messages.count(initial_system) == 1
        assert messages.count(current_user) == 1
        assert not any(message.role == "tool" for message in messages)
        assert not any(message.role == "assistant" and message.tool_calls for message in messages)
        _assert_complete_tool_call_groups(messages)
    assert state.messages[-1].content == "final answer"


@pytest.mark.asyncio
async def test_turn_loop_reports_zero_accepted_calls_before_completing_text(
    tmp_path: Path,
) -> None:
    tool_calls = [
        {
            "id": None,
            "function": {"name": "file_read", "arguments": "{}"},
        }
    ]

    state, model_effects, checkpoints, executed_ids, initial_system, current_user = (
        await _run_tool_id_loop(
            tmp_path,
            tool_calls,
            first_response_content="draft answer",
        )
    )

    assert executed_ids == []
    assert checkpoints == []
    assert len(model_effects) == 2
    assert any(
        message.role == "system" and "accepted 0 of 1 calls" in str(message.content)
        for message in model_effects[1]
    )
    assert state.messages.count(initial_system) == 1
    assert state.messages.count(current_user) == 1
    assert state.messages[-1].content == "final answer"
    _assert_complete_tool_call_groups(state.messages)


@pytest.mark.asyncio
async def test_turn_loop_executes_only_unique_valid_tool_call_ids(tmp_path: Path) -> None:
    tool_calls = [
        {"id": None, "function": {"name": "file_read", "arguments": "{}"}},
        {"id": 7, "function": {"name": "file_read", "arguments": "{}"}},
        {"id": "", "function": {"name": "file_read", "arguments": "{}"}},
        {"id": "   ", "function": {"name": "file_read", "arguments": "{}"}},
        {"id": "tool-valid", "function": {"name": "file_read", "arguments": "{}"}},
        {"id": "tool-valid", "function": {"name": "file_read", "arguments": "{}"}},
    ]

    state, model_effects, checkpoints, executed_ids, initial_system, current_user = (
        await _run_tool_id_loop(tmp_path, tool_calls)
    )

    assert executed_ids == ["tool-valid"]
    histories = [*model_effects, *checkpoints, state.messages]
    for messages in histories:
        assert len(messages) <= 10
        assert messages.count(initial_system) == 1
        assert messages.count(current_user) == 1
        _assert_complete_tool_call_groups(messages)
        for message in messages:
            if message.role == "assistant" and message.tool_calls:
                assert [call["id"] for call in message.tool_calls] == ["tool-valid"]
    control_messages = [
        str(message.content)
        for message in model_effects[1]
        if message.role == "system" and "Tool-call batch was bounded" in str(message.content)
    ]
    assert len(control_messages) == 1
    assert "accepted 1 of 6 calls" in control_messages[0]
    assert state.messages[-1].content == "final answer"


async def _run_stream_tool_loop(
    tmp_path: Path,
    tool_call_deltas: list[dict[str, Any]],
    *,
    hard_limit: int,
) -> tuple[
    EchoAgentState,
    list[tuple[ChatMessage, ...]],
    list[list[ChatMessage]],
    list[str],
    ChatMessage,
    ChatMessage,
]:
    agent = JSAgent(
        JSSettings(
            workspace=tmp_path / "workspace",
            state_dir=tmp_path / "state",
            max_turns=2,
            security=SecurityConfig(max_messages_hard_limit=hard_limit),
        )
    )
    initial_system = ChatMessage(role="system", content="initial-system")
    current_user = ChatMessage(role="user", content="current-user")
    resume_state = EchoAgentState(session_id="session-a", run_id="run-a")
    resume_state.messages = [initial_system, current_user]

    async def stream_callback(_token: str) -> None:
        pass

    loop = EchoTurnLoop(
        agent=agent,
        user_input="continue",
        session_id="session-a",
        model=None,
        attachments=None,
        resume_state=resume_state,
        stream_callback=stream_callback,
        progress_callback=None,
    )
    model_effects: list[tuple[ChatMessage, ...]] = []
    checkpoint_messages: list[list[ChatMessage]] = []
    executed_tool_call_ids: list[str] = []

    async def stream_effect(
        effect: ModelEffect,
        _context: RuntimeContext,
        **_kwargs: Any,
    ) -> AsyncIterator[StreamEvent]:
        model_effects.append(effect.messages)
        if len(model_effects) == 1:
            for delta in tool_call_deltas:
                yield StreamEvent(kind="tool_call_delta", tool_call=delta)
            yield StreamEvent(kind="done", finish_reason="tool_calls")
            return
        yield StreamEvent(kind="text_delta", text="final answer")
        yield StreamEvent(kind="done", finish_reason="stop")

    async def tool_effect(
        effect: ToolEffect,
        _context: RuntimeContext,
        _progress: Callable[[str, ToolResult], Awaitable[None]] | None,
    ) -> tuple[ChatMessage, ToolResult]:
        executed_tool_call_ids.append(effect.tool_call_id)
        return (
            ChatMessage(
                role="tool",
                content=f"result-{effect.tool_call_id}",
                name=effect.tool_name,
                tool_call_id=effect.tool_call_id,
            ),
            ToolResult(success=True, output="ok"),
        )

    async def save_checkpoint(state: EchoAgentState) -> None:
        checkpoint_messages.append(list(state.messages))

    agent.echo_runtime.execute_model_stream_effect = stream_effect  # type: ignore[assignment]
    agent.echo_runtime.execute_tool_effect = tool_effect  # type: ignore[assignment]
    agent.save_checkpoint = save_checkpoint  # type: ignore[method-assign]
    context_token = set_runtime_context(
        agent.echo_runtime.build_context(
            channel="test",
            owner_key_hash="owner-a",
            session_id="session-a",
            run_id="run-a",
        )
    )
    try:
        state = await loop.execute()
    finally:
        reset_runtime_context(context_token)
        await agent.close()
    return (
        state,
        model_effects,
        checkpoint_messages,
        executed_tool_call_ids,
        initial_system,
        current_user,
    )


@pytest.mark.asyncio
async def test_streamed_malformed_tool_id_is_bounded_without_execution(tmp_path: Path) -> None:
    state, model_effects, checkpoints, executed_ids, initial_system, current_user = (
        await _run_stream_tool_loop(
            tmp_path,
            [
                {
                    "index": 0,
                    "id": 7,
                    "name": "file_read",
                    "arguments_delta": "{}",
                }
            ],
            hard_limit=10,
        )
    )

    assert executed_ids == []
    assert checkpoints == []
    assert len(model_effects) == 2
    assert any(
        message.role == "system" and "accepted 0 of 1 calls" in str(message.content)
        for message in model_effects[1]
    )
    for messages in [*model_effects, state.messages]:
        assert len(messages) <= 10
        assert messages.count(initial_system) == 1
        assert messages.count(current_user) == 1
        _assert_complete_tool_call_groups(messages)
    assert state.messages[-1].content == "final answer"


@pytest.mark.asyncio
async def test_streamed_sequential_tools_execute_in_numeric_index_order(tmp_path: Path) -> None:
    expected_ids = [f"tool-{index}" for index in range(12)]
    state, model_effects, checkpoints, executed_ids, initial_system, current_user = (
        await _run_stream_tool_loop(
            tmp_path,
            [
                {
                    "index": index,
                    "id": call_id,
                    "name": "shell",
                    "arguments_delta": "{}",
                }
                for index, call_id in enumerate(expected_ids)
            ],
            hard_limit=30,
        )
    )

    assert executed_ids == expected_ids
    assert len(checkpoints) == 12
    histories = [*model_effects, *checkpoints, state.messages]
    for messages in histories:
        assert len(messages) <= 30
        assert messages.count(initial_system) == 1
        assert messages.count(current_user) == 1
        _assert_complete_tool_call_groups(messages)
    provider_group = next(
        message
        for message in model_effects[1]
        if message.role == "assistant" and message.tool_calls
    )
    assert [call["id"] for call in provider_group.tool_calls or []] == expected_ids
    assert state.messages[-1].content == "final answer"


def _recorded_sequential_tool_loop(
    agent: JSAgent,
    *,
    call_count: int = 2,
) -> tuple[EchoTurnLoop, ChatResponse]:
    response = ChatResponse(
        content="",
        tool_calls=[
            {
                "id": f"tool-{index}",
                "function": {"name": "shell", "arguments": "{}"},
            }
            for index in range(call_count)
        ],
        model="mock",
        usage={},
        finish_reason="tool_calls",
    )
    loop = EchoTurnLoop(agent, "run tools", "session-a", None, None, None, None, None)
    loop.run_id = "run-a"
    loop.state = EchoAgentState(session_id="session-a", run_id="run-a", turn_count=1)
    loop.state.messages = [
        ChatMessage(role="system", content="initial-system"),
        ChatMessage(role="user", content="current-user"),
        ChatMessage(role="assistant", content="", tool_calls=response.tool_calls),
    ]
    loop.allowed_tools = {"shell"}
    return loop, response


def _tool_test_context(agent: JSAgent) -> RuntimeContext:
    return agent.echo_runtime.build_context(
        channel="test",
        owner_key_hash="owner-a",
        session_id="session-a",
        run_id="run-a",
        capabilities=("shell",),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("redaction_fails", [False, True], ids=["redacted", "fallback"])
async def test_tool_effect_exception_secret_is_absent_from_state_checkpoint_and_events(
    tmp_path: Path,
    redaction_fails: bool,
) -> None:
    agent = JSAgent(
        JSSettings(
            workspace=tmp_path / "workspace",
            state_dir=tmp_path / "state",
            security=SecurityConfig(max_messages_hard_limit=10),
        )
    )
    loop, response = _recorded_sequential_tool_loop(agent, call_count=1)
    secret = "sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"
    checkpoint_states: list[EchoAgentState] = []
    emitted_events: list[Any] = []
    redaction_sources: list[str] = []
    original_redact = agent.secrets.detect_and_redact

    def redact_tool_error(text: str, source: str = "unknown") -> str:
        redaction_sources.append(source)
        if redaction_fails:
            raise OSError("secret detector unavailable")
        return original_redact(text, source)

    async def tool_effect(
        _effect: ToolEffect,
        _context: RuntimeContext,
        _progress: Callable[[str, ToolResult], Awaitable[None]] | None,
    ) -> tuple[ChatMessage, ToolResult]:
        raise RuntimeError(f"provider failed with {secret}")

    async def save_checkpoint(state: EchoAgentState) -> None:
        checkpoint_states.append(state)

    agent.secrets.detect_and_redact = redact_tool_error  # type: ignore[method-assign]
    agent.echo_runtime.execute_tool_effect = tool_effect  # type: ignore[assignment]
    agent.save_checkpoint = save_checkpoint  # type: ignore[method-assign]
    agent.event_store.emit = emitted_events.append  # type: ignore[method-assign]
    context_token = set_runtime_context(_tool_test_context(agent))
    try:
        await loop._run_tools(response, [])
    finally:
        reset_runtime_context(context_token)
        await agent.close()

    serialized_artifacts = repr(
        [
            loop.state.messages,
            loop.state.tool_results,
            checkpoint_states,
            emitted_events,
        ]
    )
    assert redaction_sources == ["tool_error"]
    assert secret not in serialized_artifacts
    assert len(checkpoint_states) == 1
    assert any(event.event_type == "tool_result" for event in emitted_events)
    if redaction_fails:
        assert loop.state.tool_results[-1].error == "Tool execution error"
    else:
        assert "[REDACTED:openai_key]" in serialized_artifacts


@pytest.mark.asyncio
async def test_sequential_tool_batch_checkpoints_completed_prefix_before_cancel(
    tmp_path: Path,
) -> None:
    agent = JSAgent(
        JSSettings(
            workspace=tmp_path / "workspace",
            state_dir=tmp_path / "state",
            security=SecurityConfig(max_messages_hard_limit=10),
        )
    )
    loop, response = _recorded_sequential_tool_loop(agent)
    second_started = asyncio.Event()
    second_release = asyncio.Event()
    checkpoint_messages: list[list[ChatMessage]] = []

    async def tool_effect(
        effect: ToolEffect,
        _context: RuntimeContext,
        _progress: Callable[[str, ToolResult], Awaitable[None]] | None,
    ) -> tuple[ChatMessage, ToolResult]:
        if effect.tool_call_id == "tool-1":
            second_started.set()
            await second_release.wait()
        return (
            ChatMessage(
                role="tool",
                content=f"result-{effect.tool_call_id}",
                name=effect.tool_name,
                tool_call_id=effect.tool_call_id,
            ),
            ToolResult(success=True, output="ok"),
        )

    async def save_checkpoint(state: EchoAgentState) -> None:
        checkpoint_messages.append(list(state.messages))

    agent.echo_runtime.execute_tool_effect = tool_effect  # type: ignore[assignment]
    agent.save_checkpoint = save_checkpoint  # type: ignore[method-assign]
    context_token = set_runtime_context(_tool_test_context(agent))
    task = asyncio.create_task(loop._run_tools(response, []))
    try:
        await asyncio.wait_for(second_started.wait(), timeout=1.0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    finally:
        second_release.set()
        if not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        reset_runtime_context(context_token)
        await agent.close()

    assert len(checkpoint_messages) == 1
    snapshot = checkpoint_messages[0]
    _assert_complete_tool_call_groups(snapshot)
    assistant = next(message for message in snapshot if message.role == "assistant")
    assert [str(call["id"]) for call in assistant.tool_calls or []] == ["tool-0"]
    assert [message.tool_call_id for message in snapshot if message.role == "tool"] == ["tool-0"]


@pytest.mark.asyncio
async def test_sequential_tool_checkpoint_finishes_when_cancelled_during_save(
    tmp_path: Path,
) -> None:
    agent = JSAgent(
        JSSettings(
            workspace=tmp_path / "workspace",
            state_dir=tmp_path / "state",
            security=SecurityConfig(max_messages_hard_limit=10),
        )
    )
    loop, response = _recorded_sequential_tool_loop(agent)
    checkpoint_started = asyncio.Event()
    checkpoint_release = asyncio.Event()
    second_started = asyncio.Event()
    checkpoint_messages: list[list[ChatMessage]] = []

    async def tool_effect(
        effect: ToolEffect,
        _context: RuntimeContext,
        _progress: Callable[[str, ToolResult], Awaitable[None]] | None,
    ) -> tuple[ChatMessage, ToolResult]:
        if effect.tool_call_id == "tool-1":
            second_started.set()
        return (
            ChatMessage(
                role="tool",
                content=f"result-{effect.tool_call_id}",
                name=effect.tool_name,
                tool_call_id=effect.tool_call_id,
            ),
            ToolResult(success=True, output="ok"),
        )

    async def save_checkpoint(state: EchoAgentState) -> None:
        checkpoint_started.set()
        await checkpoint_release.wait()
        checkpoint_messages.append(list(state.messages))

    agent.echo_runtime.execute_tool_effect = tool_effect  # type: ignore[assignment]
    agent.save_checkpoint = save_checkpoint  # type: ignore[method-assign]
    context_token = set_runtime_context(_tool_test_context(agent))
    task = asyncio.create_task(loop._run_tools(response, []))
    try:
        await asyncio.wait_for(checkpoint_started.wait(), timeout=1.0)
        task.cancel()
        checkpoint_release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
    finally:
        checkpoint_release.set()
        if not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        reset_runtime_context(context_token)
        await agent.close()

    assert not second_started.is_set()
    assert len(checkpoint_messages) == 1
    snapshot = checkpoint_messages[0]
    _assert_complete_tool_call_groups(snapshot)
    assistant = next(message for message in snapshot if message.role == "assistant")
    assert [str(call["id"]) for call in assistant.tool_calls or []] == ["tool-0"]


@pytest.mark.asyncio
async def test_sequential_tool_checkpoint_failure_during_cancel_preserves_cancellation(
    tmp_path: Path,
) -> None:
    agent = JSAgent(
        JSSettings(
            workspace=tmp_path / "workspace",
            state_dir=tmp_path / "state",
            security=SecurityConfig(max_messages_hard_limit=10),
        )
    )
    loop, response = _recorded_sequential_tool_loop(agent)
    checkpoint_started = asyncio.Event()
    checkpoint_release = asyncio.Event()
    second_started = asyncio.Event()
    executed_tool_call_ids: list[str] = []
    checkpoint_messages: list[list[ChatMessage]] = []

    async def tool_effect(
        effect: ToolEffect,
        _context: RuntimeContext,
        _progress: Callable[[str, ToolResult], Awaitable[None]] | None,
    ) -> tuple[ChatMessage, ToolResult]:
        executed_tool_call_ids.append(effect.tool_call_id)
        if effect.tool_call_id == "tool-1":
            second_started.set()
        return (
            ChatMessage(
                role="tool",
                content=f"result-{effect.tool_call_id}",
                name=effect.tool_name,
                tool_call_id=effect.tool_call_id,
            ),
            ToolResult(success=True, output="ok"),
        )

    async def save_checkpoint(state: EchoAgentState) -> None:
        checkpoint_messages.append(list(state.messages))
        checkpoint_started.set()
        await checkpoint_release.wait()
        raise OSError("checkpoint unavailable")

    agent.echo_runtime.execute_tool_effect = tool_effect  # type: ignore[assignment]
    agent.save_checkpoint = save_checkpoint  # type: ignore[method-assign]
    context_token = set_runtime_context(_tool_test_context(agent))
    task = asyncio.create_task(loop._run_tools(response, []))
    try:
        await asyncio.wait_for(checkpoint_started.wait(), timeout=1.0)
        task.cancel("cancel during checkpoint")
        checkpoint_release.set()
        with pytest.raises(asyncio.CancelledError, match="cancel during checkpoint"):
            await task
    finally:
        checkpoint_release.set()
        if not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        reset_runtime_context(context_token)
        await agent.close()

    assert executed_tool_call_ids == ["tool-0"]
    assert not second_started.is_set()
    assert len(checkpoint_messages) == 1
    snapshot = checkpoint_messages[0]
    _assert_complete_tool_call_groups(snapshot)
    assistant = next(message for message in snapshot if message.role == "assistant")
    assert [str(call["id"]) for call in assistant.tool_calls or []] == ["tool-0"]
    assert [message.tool_call_id for message in snapshot if message.role == "tool"] == ["tool-0"]


@pytest.mark.asyncio
async def test_lifecycle_heartbeat_does_not_block_event_loop() -> None:
    loop = object.__new__(EchoTurnLoop)

    def blocking_heartbeat(_session: str, _owner: str, _run: str) -> None:
        time.sleep(0.2)

    loop.agent = SimpleNamespace(
        lifecycle_store=SimpleNamespace(heartbeat=blocking_heartbeat),
        logger=MagicMock(),
    )
    loop.session_id = "session-a"
    loop.owner_key_hash = "owner-a"
    loop.run_id = "run-a"
    event_loop_ticked = asyncio.Event()

    async def tick() -> None:
        await asyncio.sleep(0.05)
        event_loop_ticked.set()

    ticker = asyncio.create_task(tick())
    await loop._heartbeat()
    responsive_before_return = event_loop_ticked.is_set()
    await ticker

    assert responsive_before_return


@pytest.mark.asyncio
async def test_memory_extraction_executes_through_echo_runtime(tmp_path: Path) -> None:
    agent = JSAgent(
        JSSettings(workspace=tmp_path / "workspace", state_dir=tmp_path / "state")
    )
    runtime = AsyncMock(
        return_value=ChatResponse(
            content='{"facts": [], "summary": "ok"}',
            tool_calls=[],
            model="mock",
            usage={},
            finish_reason="stop",
        )
    )
    agent.echo_runtime.execute_model_effect = runtime  # type: ignore[method-assign]

    try:
        report = await agent._organizer.extract(
            [{"user": "hello", "assistant": "hi"}],
            session_id="session-a",
            owner_key_hash="owner-a",
        )
    finally:
        await agent.close()

    assert report["ok"] is True
    assert runtime.await_count == 1
    effect, context = runtime.await_args.args
    assert context.channel == "memory_extraction"
    assert context.owner_key_hash == "owner-a"
    assert context.session_id == "session-a"
    assert context.run_id == "memory:session-a"
    assert effect.temperature == 0.2


def _attribute_name(node: ast.AST) -> str | None:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def test_background_model_entries_use_echo_runtime_without_direct_adapter_calls() -> None:
    tree = ast.parse((ROOT / "js" / "agent" / "__init__.py").read_text(encoding="utf-8"))
    methods = {
        node.name: node
        for node in ast.walk(tree)
        if isinstance(node, ast.AsyncFunctionDef) and node.name in BACKGROUND_METHODS
    }

    assert methods.keys() == BACKGROUND_METHODS.keys()
    for method_name, channel in BACKGROUND_METHODS.items():
        calls = {
            name
            for call in ast.walk(methods[method_name])
            if isinstance(call, ast.Call)
            if (name := _attribute_name(call.func)) is not None
        }
        assert "self.authorized_model_chat" not in calls
        assert "self.echo_runtime.build_context" in calls
        assert "self.echo_runtime.execute_model_effect" in calls
        assert any(
            isinstance(constant, ast.Constant) and constant.value == channel
            for constant in ast.walk(methods[method_name])
        )


@pytest.mark.asyncio
async def test_skill_evolution_executes_model_effect_with_complete_context(tmp_path: Path) -> None:
    agent = JSAgent(
        JSSettings(workspace=tmp_path / "workspace", state_dir=tmp_path / "state")
    )
    observed: dict[str, Any] = {}

    class Evolver:
        async def evolve_skill(
            self,
            *,
            skill_id: str,
            current_code: str,
            llm_caller: Any,
            propagate_llm_errors: bool,
        ) -> None:
            assert propagate_llm_errors is True
            observed["skill_id"] = skill_id
            observed["current_code"] = current_code
            observed["model_output"] = await llm_caller("rewrite this skill")

    runtime = AsyncMock(
        return_value=ChatResponse(
            content="rewritten skill",
            tool_calls=[],
            model="mock",
            usage={},
            finish_reason="stop",
        )
    )
    forbidden_adapter = AsyncMock(side_effect=AssertionError("background entry bypassed EchoRuntime"))
    agent.evolver = Evolver()  # type: ignore[assignment]
    agent.echo_runtime.execute_model_effect = runtime  # type: ignore[method-assign]
    agent.authorized_model_chat = forbidden_adapter  # type: ignore[method-assign]

    try:
        await agent._run_skill_evolution_for(
            "skill-a",
            SimpleNamespace(full_content="current skill"),
        )
    finally:
        await agent.close()

    assert observed == {
        "skill_id": "skill-a",
        "current_code": "current skill",
        "model_output": "rewritten skill",
    }
    assert runtime.await_count == 1
    assert forbidden_adapter.await_count == 0
    effect, context = runtime.await_args.args
    assert context.product_id == "js-agent"
    assert context.channel == "skill_evolution"
    assert context.owner_key_hash == "local"
    assert context.session_id == "skill-a"
    assert context.run_id == "skill-evolution:skill-a"
    assert context.role == "local-user"
    assert context.profile == "default"
    assert context.capabilities == ()
    assert context.workspace == agent.settings.workspace
    assert context.state_dir == agent.settings.state_dir
    assert effect.before_model_attempt is not None
    assert effect.completion_budget_callback is not None
    assert effect.max_tokens == agent.settings.echo_budget.max_completion_tokens


@pytest.mark.asyncio
async def test_evolution_cycle_reports_profile_model_effect_failure_and_continues(
    tmp_path: Path,
) -> None:
    agent = JSAgent(
        JSSettings(workspace=tmp_path / "workspace", state_dir=tmp_path / "state")
    )
    agent._maybe_bootstrap_memory = AsyncMock()  # type: ignore[method-assign]
    agent._extract_memories = AsyncMock(  # type: ignore[method-assign]
        return_value={"ok": True, "skipped": False, "error": None}
    )
    agent._run_dreaming = AsyncMock()  # type: ignore[method-assign]
    agent._run_skill_evolution = AsyncMock(return_value=[])  # type: ignore[method-assign]
    agent.echo_runtime.execute_model_effect = AsyncMock(  # type: ignore[method-assign]
        side_effect=RuntimeError("provider unavailable")
    )

    try:
        report = await agent._run_evolution_cycle(
            [{"user": "hello", "assistant": "hi", "session_id": "session-a"}]
        )
    finally:
        await agent.close()

    assert report["profile_update"] == {
        "ok": False,
        "skipped": False,
        "error": "provider unavailable",
    }
    agent._extract_memories.assert_awaited_once()
    agent._run_dreaming.assert_awaited_once()
    agent._run_skill_evolution.assert_awaited_once()


@pytest.mark.asyncio
async def test_evolution_cycle_reports_dream_model_budget_failure_and_continues(
    tmp_path: Path,
) -> None:
    agent = JSAgent(
        JSSettings(workspace=tmp_path / "workspace", state_dir=tmp_path / "state")
    )
    agent._maybe_bootstrap_memory = AsyncMock()  # type: ignore[method-assign]
    agent._auto_update_profiles = AsyncMock()  # type: ignore[method-assign]
    agent._extract_memories = AsyncMock(  # type: ignore[method-assign]
        return_value={"ok": True, "skipped": False, "error": None}
    )
    agent._run_skill_evolution = AsyncMock(return_value=[])  # type: ignore[method-assign]
    agent.memory.store_working(
        "session-a",
        "fact-a",
        "important memory",
        importance=9,
        owner_key_hash="owner-a",
    )
    agent.echo_runtime.execute_model_effect = AsyncMock(  # type: ignore[method-assign]
        side_effect=EchoBudgetExceededError("Echo budget exceeded: prompt_tokens_exceeded")
    )

    try:
        report = await agent._run_evolution_cycle(
            [{"user": "hello", "assistant": "hi", "session_id": "session-a"}]
        )
    finally:
        await agent.close()

    assert report["dreaming"] == {
        "ok": False,
        "error": "Echo budget exceeded: prompt_tokens_exceeded",
    }
    agent._auto_update_profiles.assert_awaited_once()
    agent._extract_memories.assert_awaited_once()
    agent._run_skill_evolution.assert_awaited_once()


@pytest.mark.asyncio
async def test_evolution_cycle_reports_skill_model_gate_failure_and_continues(
    tmp_path: Path,
) -> None:
    agent = JSAgent(
        JSSettings(workspace=tmp_path / "workspace", state_dir=tmp_path / "state")
    )
    agent._maybe_bootstrap_memory = AsyncMock()  # type: ignore[method-assign]
    agent._auto_update_profiles = AsyncMock()  # type: ignore[method-assign]
    agent._extract_memories = AsyncMock(  # type: ignore[method-assign]
        return_value={"ok": True, "skipped": False, "error": None}
    )
    agent._run_dreaming = AsyncMock()  # type: ignore[method-assign]

    class Skills:
        def get_all(self) -> dict[str, Any]:
            return {"skill-a": SimpleNamespace(full_content="current skill")}

    class Evolver:
        def should_evolve(self, skill_id: str) -> bool:
            return skill_id == "skill-a"

        async def evolve_skill(
            self,
            *,
            skill_id: str,
            current_code: str,
            llm_caller: Any,
            propagate_llm_errors: bool,
        ) -> None:
            assert skill_id == "skill-a"
            assert current_code == "current skill"
            assert propagate_llm_errors is True
            await llm_caller("rewrite this skill")

    agent.skills = Skills()  # type: ignore[assignment]
    agent.evolver = Evolver()  # type: ignore[assignment]
    agent.echo_runtime.execute_model_effect = AsyncMock(  # type: ignore[method-assign]
        side_effect=PermissionError("model gate denied")
    )

    try:
        report = await agent._run_evolution_cycle(
            [{"user": "hello", "assistant": "hi", "session_id": "session-a"}]
        )
    finally:
        await agent.close()

    assert report["skill_evolution"] == {
        "ok": False,
        "error": "model gate denied",
        "evolved": [],
    }
    agent._auto_update_profiles.assert_awaited_once()
    agent._extract_memories.assert_awaited_once()
    agent._run_dreaming.assert_awaited_once()


def _configure_blocked_finalizer_evolution(
    agent: JSAgent,
    *,
    started: asyncio.Event,
    release: asyncio.Event,
) -> None:
    class Skills:
        def get_all(self) -> dict[str, Any]:
            return {"skill-a": SimpleNamespace(full_content="current skill")}

    class Evolver:
        def should_evolve_many(self, _skill_ids: tuple[str, ...]) -> set[str]:
            return {"skill-a"}

    async def blocked_evolution(_skill_id: str, _spec: Any) -> None:
        started.set()
        await release.wait()

    agent.skills = Skills()  # type: ignore[assignment]
    agent.evolver = Evolver()  # type: ignore[assignment]
    agent._quality_scorer = None
    agent.learner = None
    agent.optimizer = None
    agent.metacognition = None
    agent.curator = None
    agent._run_skill_evolution_for = blocked_evolution  # type: ignore[method-assign]


def _completed_state() -> AgentState:
    state = AgentState(session_id="session-a", run_id="run-a")
    state.messages = [
        ChatMessage(role="user", content="hello"),
        ChatMessage(role="assistant", content="done"),
    ]
    state.status = "completed"
    return state


@pytest.mark.asyncio
async def test_finalizer_discards_completed_skill_evolution_task(tmp_path: Path) -> None:
    agent = JSAgent(
        JSSettings(workspace=tmp_path / "workspace", state_dir=tmp_path / "state")
    )
    started = asyncio.Event()
    release = asyncio.Event()
    _configure_blocked_finalizer_evolution(agent, started=started, release=release)

    try:
        await agent._finalize_run(_completed_state(), "session-a", "run-a", "hello", 0)
        await asyncio.wait_for(started.wait(), timeout=1.0)
        task = next(iter(agent._background_model_tasks))

        release.set()
        await asyncio.wait_for(task, timeout=1.0)
        await asyncio.sleep(0)

        assert task not in agent._background_model_tasks
    finally:
        release.set()
        await agent.close()


@pytest.mark.asyncio
async def test_agent_close_cancels_and_reaps_finalizer_evolution_task(tmp_path: Path) -> None:
    agent = JSAgent(
        JSSettings(workspace=tmp_path / "workspace", state_dir=tmp_path / "state")
    )
    started = asyncio.Event()
    release = asyncio.Event()
    _configure_blocked_finalizer_evolution(agent, started=started, release=release)

    await agent._finalize_run(_completed_state(), "session-a", "run-a", "hello", 0)
    await asyncio.wait_for(started.wait(), timeout=1.0)
    task = next(iter(agent._background_model_tasks))

    await asyncio.wait_for(agent.close(), timeout=2.0)

    assert task.cancelled()
    assert task not in agent._background_model_tasks


@pytest.mark.asyncio
async def test_finalizer_does_not_start_evolution_after_close(tmp_path: Path) -> None:
    import threading

    agent = JSAgent(
        JSSettings(workspace=tmp_path / "workspace", state_dir=tmp_path / "state")
    )
    selection_started = threading.Event()
    selection_release = threading.Event()
    evolution_started = asyncio.Event()
    evolution_release = asyncio.Event()

    class Skills:
        def get_all(self) -> dict[str, Any]:
            return {"skill-a": SimpleNamespace(full_content="current skill")}

    class Evolver:
        def should_evolve_many(self, _skill_ids: tuple[str, ...]) -> set[str]:
            selection_started.set()
            assert selection_release.wait(timeout=2.0)
            return {"skill-a"}

    async def blocked_evolution(_skill_id: str, _spec: Any) -> None:
        evolution_started.set()
        await evolution_release.wait()

    agent.skills = Skills()  # type: ignore[assignment]
    agent.evolver = Evolver()  # type: ignore[assignment]
    agent._quality_scorer = None
    agent.learner = None
    agent.optimizer = None
    agent.metacognition = None
    agent.curator = None
    agent._run_skill_evolution_for = blocked_evolution  # type: ignore[method-assign]

    finalize_task = asyncio.create_task(
        agent._finalize_run(_completed_state(), "session-a", "run-a", "hello", 0)
    )
    try:
        assert await asyncio.wait_for(
            asyncio.to_thread(selection_started.wait, 1.0),
            timeout=2.0,
        )
        await asyncio.wait_for(agent.close(), timeout=2.0)
        selection_release.set()
        await asyncio.wait_for(finalize_task, timeout=2.0)
        await asyncio.sleep(0)

        assert not evolution_started.is_set()
        assert not agent._background_model_tasks
    finally:
        selection_release.set()
        evolution_release.set()
        if not finalize_task.done():
            finalize_task.cancel()
            await asyncio.gather(finalize_task, return_exceptions=True)
        await agent.close()


@pytest.mark.asyncio
async def test_finalizer_throttles_skill_evolution_database_sweeps(
    tmp_path: Path,
) -> None:
    agent = JSAgent(
        JSSettings(workspace=tmp_path / "workspace", state_dir=tmp_path / "state")
    )
    agent._quality_scorer = None
    agent.learner = None
    agent.optimizer = None
    agent.metacognition = None
    agent.curator = None
    agent.skills = SimpleNamespace(get_all=MagicMock(return_value={}))  # type: ignore[assignment]

    class Evolver:
        should_evolve_many = MagicMock(return_value=set())

    agent.evolver = Evolver()  # type: ignore[assignment]

    try:
        await agent._finalize_run(_completed_state(), "session-a", "run-a", "hello", 0)
        await agent._finalize_run(_completed_state(), "session-b", "run-b", "hello", 0)
    finally:
        await agent.close()

    Evolver.should_evolve_many.assert_called_once()


@pytest.mark.asyncio
async def test_finalizer_deduplicates_concurrent_skill_evolution_sweeps(
    tmp_path: Path,
) -> None:
    agent = JSAgent(
        JSSettings(workspace=tmp_path / "workspace", state_dir=tmp_path / "state")
    )
    agent._quality_scorer = None
    agent.learner = None
    agent.optimizer = None
    agent.metacognition = None
    agent.curator = None
    agent.skills = SimpleNamespace(get_all=MagicMock(return_value={}))  # type: ignore[assignment]

    class Evolver:
        should_evolve_many = MagicMock(return_value=set())

    agent.evolver = Evolver()  # type: ignore[assignment]
    state_a = _completed_state()
    state_b = _completed_state()
    state_b.session_id = "session-b"
    state_b.run_id = "run-b"

    try:
        await asyncio.gather(
            agent._finalize_run(state_a, "session-a", "run-a", "hello", 0),
            agent._finalize_run(state_b, "session-b", "run-b", "hello", 0),
        )
    finally:
        await agent.close()

    Evolver.should_evolve_many.assert_called_once()
