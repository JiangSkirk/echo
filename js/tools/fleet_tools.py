"""Simplified fleet collaboration tool."""
# noqa: N806 (intentional UPPER_CASE for constants)

from __future__ import annotations

import threading
from collections import OrderedDict
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
    _MAX_RATE_LIMIT_SCOPES = 1024
    _rate_limit_lock = threading.Lock()
    _call_timestamps_by_scope: OrderedDict[str, list[float]] = OrderedDict()

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
                ToolParam(
                    "session_id",
                    "string",
                    "Optional safe Fleet session identifier.",
                    required=False,
                ),
                ToolParam(
                    "role_mapping",
                    "object",
                    "Optional subtask-index to safe role-name mapping.",
                    required=False,
                ),
                ToolParam(
                    "mode",
                    "string",
                    "Collaboration strategy.",
                    required=False,
                    enum=["auto", "debate", "sequential", "manager"],
                ),
            ],
        )

    def register(self, registry: Any) -> None:
        registry.register(self.get_spec(), self.collaborate)

    async def collaborate(
        self,
        task: str,
        subtasks: list[str] | None = None,
        session_id: str | None = None,
        role_mapping: dict[int | str, str] | None = None,
        mode: str = "auto",
    ) -> ToolResult:
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

        from js.orchestration.fleet import AgentFleet

        try:
            (
                normalized_task,
                normalized_subtasks,
                normalized_session_id,
                normalized_role_mapping,
                normalized_mode,
            ) = AgentFleet._validate_collaboration_request(
                task,
                subtasks,
                session_id,
                role_mapping,
                mode,
            )
        except (TypeError, ValueError):
            return ToolResult(
                success=False,
                error="Invalid Fleet collaboration request",
                metadata={"status_code": 400},
            )

        sanitized_subtasks = (
            [_sanitize(subtask) for subtask in normalized_subtasks]
            if normalized_subtasks is not None
            else None
        )

        # Rate limit: prevent excessive fleet calls in a short window
        import time as _time

        from js.echo.turn_context import current_owner_key_hash, current_runtime_context

        now = _time.time()
        runtime_context = current_runtime_context()
        product_id = runtime_context.product_id if runtime_context is not None else "js-agent"
        owner = current_owner_key_hash("local-user") or "local-user"
        scope = f"{product_id}:{owner}"
        with FleetCollaborateTool._rate_limit_lock:
            timestamps = FleetCollaborateTool._call_timestamps_by_scope.get(scope, [])
            timestamps = [
                timestamp
                for timestamp in timestamps
                if now - timestamp < FleetCollaborateTool._WINDOW_SECONDS
            ]
            FleetCollaborateTool._call_timestamps_by_scope[scope] = timestamps
            FleetCollaborateTool._call_timestamps_by_scope.move_to_end(scope)
            while (
                len(FleetCollaborateTool._call_timestamps_by_scope)
                > FleetCollaborateTool._MAX_RATE_LIMIT_SCOPES
            ):
                FleetCollaborateTool._call_timestamps_by_scope.popitem(last=False)
            rate_limited = len(timestamps) >= FleetCollaborateTool._MAX_CALLS_PER_WINDOW
            if not rate_limited:
                timestamps.append(now)
        if rate_limited:
            return ToolResult(
                success=False,
                error=(
                    f"Fleet collaboration rate limit reached "
                    f"({FleetCollaborateTool._MAX_CALLS_PER_WINDOW} calls per "
                    f"{FleetCollaborateTool._WINDOW_SECONDS:.0f}s). "
                    "Please wait before delegating again."
                ),
            )

        try:
            fleet = self._fleet_factory()
        except Exception:
            logger.error("Fleet factory failed", exc_info=True)
            return ToolResult(
                success=False,
                error="Fleet is unavailable",
                metadata={"status_code": 503},
            )

        try:
            result = await fleet.collaborate(
                main_task=_sanitize(normalized_task),
                subtasks=sanitized_subtasks,
                session_id=normalized_session_id,
                role_mapping=normalized_role_mapping,
                mode=normalized_mode,
            )
            final = str(result.get("final", ""))
            review = result.get("review")
            raw_subtasks = result.get("subtasks", {})
            bounded_subtasks = (
                {
                    str(key)[:500]: str(value)[:1000]
                    for key, value in list(raw_subtasks.items())[:20]
                }
                if isinstance(raw_subtasks, dict)
                else {}
            )
            meta: dict[str, Any] = {
                "session_id": str(result.get("session_id", normalized_session_id or ""))[:128],
                "mode": str(result.get("mode", normalized_mode)),
                "subtask_count": len(bounded_subtasks),
                "subtasks": bounded_subtasks,
            }
            if review:
                meta["review"] = str(review)[:2000]
            return ToolResult(success=True, output=final, metadata=meta)
        except Exception as exc:
            from js.orchestration.fleet import FleetCapacityError

            logger.error("Fleet collaboration failed", exc_info=True)
            status_code = 503 if isinstance(exc, FleetCapacityError) else 500
            error = (
                "Fleet capacity is exhausted"
                if status_code == 503
                else "Fleet collaboration failed"
            )
            return ToolResult(
                success=False,
                error=error,
                metadata={"status_code": status_code},
            )
