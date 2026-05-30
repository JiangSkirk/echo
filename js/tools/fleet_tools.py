"""Simplified fleet collaboration tool."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from js.tools.registry import ToolParam, ToolResult, ToolSpec
from js.utils.log import get_logger

logger = get_logger("js.tools.fleet")


class FleetCollaborateTool:
    """Tool that delegates complex tasks to a team of agents for parallel execution."""

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
        try:
            fleet = self._fleet_factory()
        except Exception as e:
            return ToolResult(success=False, error=f"Fleet not available: {e}")

        try:
            result = await fleet.collaborate(main_task=task, subtasks=subtasks)
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
