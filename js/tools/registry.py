"""Tool registry with schema validation and execution."""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from js.config import ToolLimits
from js.security.guard import BehaviorGuard, SecurityDecisionType
from js.utils.log import get_logger
from js.utils.metrics import get_metrics, start_span


@dataclass(frozen=True)
class ToolParam:
    name: str
    type: str
    description: str
    required: bool = True
    enum: list[str] | None = None


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    parameters: list[ToolParam]
    dangerous: bool = False  # Requires extra confirmation
    read_only: bool = False  # Safe to retry

    def to_openai_schema(self) -> dict[str, Any]:
        """Convert to OpenAI function calling schema."""
        properties: dict[str, Any] = {}
        required: list[str] = []
        for p in self.parameters:
            prop: dict[str, Any] = {"type": p.type, "description": p.description}
            if p.enum:
                prop["enum"] = p.enum
            properties[p.name] = prop
            if p.required:
                required.append(p.name)

        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": properties,
                    "required": required,
                },
            },
        }


@dataclass
class ToolResult:
    success: bool
    output: str = ""
    error: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_text(self) -> str:
        if self.success:
            return self.output
        return f"Error: {self.error}"


ToolHandler = Callable[..., Awaitable[ToolResult]]


class ToolRegistry:
    """Central registry for all available tools."""

    def __init__(self, limits: ToolLimits, guard: BehaviorGuard) -> None:
        self.limits = limits
        self.guard = guard
        self._tools: dict[str, ToolSpec] = {}
        self._handlers: dict[str, ToolHandler] = {}
        self._call_counts: dict[str, int] = {}
        self._semaphore = asyncio.Semaphore(limits.max_concurrent_tools)
        self.logger = get_logger("js.tools.registry")

    def register(self, spec: ToolSpec, handler: ToolHandler) -> None:
        """Register a tool with its specification and handler."""
        self._tools[spec.name] = spec
        self._handlers[spec.name] = handler
        self._call_counts[spec.name] = 0

    def unregister(self, name: str) -> None:
        self._tools.pop(name, None)
        self._handlers.pop(name, None)
        self._call_counts.pop(name, None)

    def get(self, name: str) -> ToolSpec | None:
        return self._tools.get(name)

    def get_handler(self, name: str) -> ToolHandler | None:
        return self._handlers.get(name)

    def list_tools(self) -> list[ToolSpec]:
        return list(self._tools.values())

    def to_openai_schemas(self) -> list[dict[str, Any]]:
        return [t.to_openai_schema() for t in self._tools.values()]

    async def execute(
        self,
        run_id: str,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> ToolResult:
        """Execute a tool with security checks and limits."""
        spec = self._tools.get(tool_name)
        if not spec:
            return ToolResult(success=False, error=f"Unknown tool: {tool_name}")

        handler = self._handlers.get(tool_name)
        if not handler:
            return ToolResult(success=False, error=f"No handler for tool: {tool_name}")

        # Security: loop detection
        args_key = json.dumps(arguments, sort_keys=True)
        loop_decision = self.guard.check_loop(run_id, tool_name, args_key)
        if loop_decision.decision == SecurityDecisionType.BLOCK:
            return ToolResult(success=False, error=f"Security: {loop_decision.reason}")

        async with self._semaphore:
            try:
                try:
                    get_metrics().tool_calls_total.labels(tool_name=tool_name).inc()
                except Exception:
                    self.logger.debug("Suppressed error", exc_info=True)
                start = time.perf_counter()
                with start_span("tool.execute", {"tool_name": tool_name}):
                    try:
                        result = await handler(**arguments)
                        self._call_counts[tool_name] += 1

                        # Scan tool result
                        if result.output:
                            scan = self.guard.check_tool_result(result.output)
                            if scan.decision == SecurityDecisionType.WARN:
                                result.output = f"[Security Warning: {scan.reason}]\n{result.output}"

                        latency = time.perf_counter() - start
                        try:
                            get_metrics().tool_latency_seconds.labels(
                                tool_name=tool_name
                            ).observe(latency)
                        except Exception:
                            self.logger.debug("Suppressed error", exc_info=True)
                        return result
                    except Exception as e:
                        latency = time.perf_counter() - start
                        try:
                            get_metrics().tool_latency_seconds.labels(
                                tool_name=tool_name
                            ).observe(latency)
                            get_metrics().tool_errors_total.labels(
                                tool_name=tool_name
                            ).inc()
                        except Exception:
                            self.logger.debug("Suppressed error", exc_info=True)
                        return ToolResult(success=False, error=f"Tool execution failed: {e}")
            except Exception as e:
                # Metrics/span machinery failed; still report the error
                return ToolResult(success=False, error=f"Tool execution failed: {e}")

    def get_stats(self) -> dict[str, int]:
        return dict(self._call_counts)
