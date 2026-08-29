"""Tool-call quality scoring and result events for the Echo turn loop."""

from __future__ import annotations

from typing import TYPE_CHECKING

from js.evolution.quality_scorer import ToolCallScore
from js.models.providers import ChatMessage
from js.tools.registry import ToolResult

if TYPE_CHECKING:
    from js.events.models import AgentEvent


def _tool_quality_score(message: ChatMessage, result: ToolResult) -> ToolCallScore:
    """Map a tool result to learning data without confusing errors with identity."""
    from js.evolution.quality_scorer import ToolCallScore

    return ToolCallScore(
        tool_name=message.name or "unknown",
        success=result.success,
        error_pattern=result.error or "",
    )


def _tool_result_event(
    session_id: str,
    run_id: str,
    message: ChatMessage,
    result: ToolResult,
) -> AgentEvent:
    from js.events.models import AgentEvent

    return AgentEvent.tool_result(
        session_id=session_id,
        run_id=run_id,
        tool_name=message.name or "unknown",
        success=result.success,
        output_preview=result.output or result.error or "",
    )
