"""Simplified fleet collaboration tool."""
# noqa: N806 (intentional UPPER_CASE for constants)

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from js.tools.registry import ToolParam, ToolResult, ToolSpec
from js.utils.log import get_logger

logger = get_logger("js.tools.fleet")


class FleetCollaborateTool:
    """Tool that delegates complex tasks to a team of agents for parallel execution."""

    # Rate limiting: max 3 fleet calls per 60s window to prevent abuse
    _MAX_CALLS_PER_WINDOW = 3
    _WINDOW_SECONDS = 60.0
    _call_timestamps: list[float] = []

    def __init__(self, fleet_factory: Callable[[], Any]) -> None:
        self._fleet_factory = fleet_factory

    def get_spec(self) -> ToolSpec:
        return ToolSpec(
            name="fleet_collaborate",
            description=(
                "当一个任务可以拆分成多个独立部分并行执行时使用此工具。"
                "例如：'写一个完整的 Web 应用（前端 + 后端 + 测试）'、"
                "'调研三个不同的技术方案并对比'、"
                "'同时处理多个文件的分析任务'。"
                "系统会自动组建团队、分配任务、并行执行并合成最终答案。"
            ),
            parameters=[
                ToolParam(
                    "task",
                    "string",
                    "主任务描述。描述越清晰，分解效果越好。",
                ),
                ToolParam(
                    "subtasks",
                    "array",
                    "（可选）如果你已经想好了如何拆分任务，可以直接提供子任务列表。"
                    "如果不提供，系统会自动拆分。",
                    required=False,
                ),
            ],
        )

    def register(self, registry: Any) -> None:
        registry.register(self.get_spec(), self.collaborate)

    async def collaborate(self, task: str, subtasks: list[str] | None = None) -> ToolResult:
        """Execute a task via the AgentFleet."""
        # Sanitize inputs to prevent prompt injection into sub-agent system prompts.
        # Subtask strings are injected directly into agent instructions; strip
        # common injection markers and enforce length limits.
        _injection_markers = [
            "ignore previous instructions",
            "disregard all prior",
            "system prompt:",
            "new instructions:",
            "you are now",
            "developer mode",
            "dan mode",
        ]
        _max_subtask_len = 2000

        def _sanitize(text: str) -> str:
            text_lower = text.lower()
            for marker in _injection_markers:
                if marker in text_lower:
                    text = text[:200] + " ... [content trimmed for security]"
                    logger.warning(f"Potential prompt injection in fleet subtask: '{marker}'")
                    break
            return text[:_max_subtask_len]

        sanitized_subtasks: list[str] | None = None
        if subtasks:
            sanitized_subtasks = [_sanitize(s) for s in subtasks]

        # Rate limit: prevent excessive fleet calls in a short window
        import time as _time
        now = _time.time()
        FleetCollaborateTool._call_timestamps = [
            t for t in FleetCollaborateTool._call_timestamps
            if now - t < FleetCollaborateTool._WINDOW_SECONDS
        ]
        if len(FleetCollaborateTool._call_timestamps) >= FleetCollaborateTool._MAX_CALLS_PER_WINDOW:
            return ToolResult(
                success=False,
                error=(
                    f"Fleet collaboration rate limit reached "
                    f"({FleetCollaborateTool._MAX_CALLS_PER_WINDOW} calls per "
                    f"{FleetCollaborateTool._WINDOW_SECONDS:.0f}s). "
                    "Please wait before delegating again."
                ),
            )
        FleetCollaborateTool._call_timestamps.append(now)

        try:
            fleet = self._fleet_factory()
        except Exception as e:
            return ToolResult(success=False, error=f"Fleet not available: {e}")

        try:
            result = await fleet.collaborate(main_task=_sanitize(task), subtasks=sanitized_subtasks)
            final = result.get("final", "")
            review = result.get("review")
            meta: dict[str, Any] = {
                "subtask_count": len(result.get("subtasks", {})),
                "subtask_results": result.get("subtasks", {}),
            }
            if review:
                meta["review"] = review
            return ToolResult(success=True, output=final, metadata=meta)
        except Exception as e:
            logger.error(f"Fleet collaboration failed: {e}", exc_info=True)
            return ToolResult(success=False, error=f"Collaboration failed: {e}")
