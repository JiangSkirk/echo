"""Tests for post-tool telemetry events and metrics."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from js.agent.state import AgentState
from js.echo.turn_loop import EchoTurnLoop
from js.models.providers import ChatMessage
from js.security.audit import AuditEventType
from js.tools.registry import ToolResult


def _make_executor(session_id: str = "s-1", run_id: str = "r-1") -> EchoTurnLoop:
    agent = MagicMock()
    agent.settings.max_turns = 10
    executor = EchoTurnLoop(
        agent=agent,
        user_input="hi",
        session_id=session_id,
        model=None,
        attachments=None,
        resume_state=None,
        stream_callback=None,
        progress_callback=None,
    )
    executor.run_id = run_id
    executor.state = AgentState(session_id=session_id, run_id=run_id)
    executor.state.turn_count = 2
    return executor


@patch("js.echo.turn_loop.get_metrics")
def test_telemetry_logs_batch_details(mock_get_metrics: MagicMock) -> None:
    executor = _make_executor()
    batch = [
        (
            ChatMessage(role="tool", name="echo", content="ok"),
            ToolResult(success=True, output="ok"),
        ),
        (
            ChatMessage(role="tool", name="fail", content="err"),
            ToolResult(success=False, error="boom"),
        ),
    ]

    executor._emit_tool_telemetry(executor.state, batch, "owner_a")

    executor.agent.audit.log.assert_called_once()
    args, kwargs = executor.agent.audit.log.call_args
    assert args[0] == AuditEventType.TOOL_BATCH
    assert args[1] == "s-1"
    assert args[2] == "r-1"
    assert args[3] == "agent"
    assert args[4] == "tool_batch"
    details = kwargs.get("details") or args[5]
    assert details["turn"] == 2
    assert details["tool_names"] == ["echo", "fail"]
    assert details["all_failed"] is False
    assert details["batch_size"] == 2
    assert details["total_output_chars"] == 2  # "ok" + ""
    assert details["owner_key_hash"] == "owner_a"

    mock_get_metrics.return_value.tool_batches_total.labels.assert_called_once_with(
        all_failed="false", tool_count="2"
    )
    mock_get_metrics.return_value.tool_batches_total.labels.return_value.inc.assert_called_once()


@patch("js.echo.turn_loop.get_metrics")
def test_telemetry_all_failed_true(mock_get_metrics: MagicMock) -> None:
    executor = _make_executor()
    batch = [
        (ChatMessage(role="tool", name="f1", content="e1"), ToolResult(success=False, error="e1")),
        (ChatMessage(role="tool", name="f2", content="e2"), ToolResult(success=False, error="e2")),
    ]

    executor._emit_tool_telemetry(executor.state, batch, "owner_b")

    details = (
        executor.agent.audit.log.call_args.kwargs.get("details")
        or executor.agent.audit.log.call_args[0][5]
    )
    assert details["all_failed"] is True
    mock_get_metrics.return_value.tool_batches_total.labels.assert_called_once_with(
        all_failed="true", tool_count="2"
    )


@patch("js.echo.turn_loop.get_metrics")
def test_telemetry_empty_batch(mock_get_metrics: MagicMock) -> None:
    executor = _make_executor()
    executor._emit_tool_telemetry(executor.state, [], None)

    details = (
        executor.agent.audit.log.call_args.kwargs.get("details")
        or executor.agent.audit.log.call_args[0][5]
    )
    assert details["tool_names"] == []
    assert details["all_failed"] is False
    assert details["batch_size"] == 0
    assert details["owner_key_hash"] == ""
    mock_get_metrics.return_value.tool_batches_total.labels.assert_called_once_with(
        all_failed="false", tool_count="0"
    )
