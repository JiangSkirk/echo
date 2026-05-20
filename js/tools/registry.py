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
    """Central registry for all available tools.

    Features:
    - Self-registration of tool schemas and handlers
    - Concurrent execution limiting via semaphore
    - Result caching for idempotent read-only tools
    - Security guard integration (loop detection, result scanning)
    """

    def __init__(self, limits: ToolLimits, guard: BehaviorGuard) -> None:
        self.limits = limits
        self.guard = guard
        self._tools: dict[str, ToolSpec] = {}
        self._handlers: dict[str, ToolHandler] = {}
        self._call_counts: dict[str, int] = {}
        self._semaphore = asyncio.Semaphore(limits.max_concurrent_tools)
        self.logger = get_logger("js.tools.registry")
        # Simple LRU cache for tool results: (tool_name, args_key) -> ToolResult
        self._result_cache: dict[tuple[str, str], tuple[ToolResult, float]] = {}
        self._cache_ttl_seconds = 30.0
        self._cache_max_size = 128

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

    def _cache_key(self, tool_name: str, arguments: dict[str, Any]) -> tuple[str, str]:
        """Build a cache key for a tool call."""
        return (tool_name, json.dumps(arguments, sort_keys=True))

    def _get_cached(self, key: tuple[str, str]) -> ToolResult | None:
        """Get a cached result if fresh."""
        entry = self._result_cache.get(key)
        if not entry:
            return None
        result, timestamp = entry
        if time.time() - timestamp > self._cache_ttl_seconds:
            del self._result_cache[key]
            return None
        return result

    def _set_cached(self, key: tuple[str, str], result: ToolResult) -> None:
        """Cache a tool result, evicting oldest if at capacity."""
        if len(self._result_cache) >= self._cache_max_size:
            # Evict oldest entry
            oldest = min(self._result_cache, key=lambda k: self._result_cache[k][1])
            del self._result_cache[oldest]
        self._result_cache[key] = (result, time.time())

    def _is_cacheable(self, tool_name: str) -> bool:
        """Determine if a tool's results can be safely cached."""
        spec = self._tools.get(tool_name)
        if not spec:
            return False
        # Cache read-only tools (file_read, browser_fetch, etc.)
        if getattr(spec, "read_only", False):
            return True
        # Cache safe built-ins by name heuristic
        cacheable_names = {"file_read", "file_list", "file_search", "browser_fetch", "web_search"}
        return tool_name in cacheable_names or tool_name.replace("skill_", "") in cacheable_names

    async def execute(
        self,
        run_id: str,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> ToolResult:
        """Execute a tool with security checks, caching, and limits."""
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

        # Check cache for idempotent tools
        cache_key = self._cache_key(tool_name, arguments)
        if self._is_cacheable(tool_name):
            cached = self._get_cached(cache_key)
            if cached is not None:
                self.logger.debug(f"Cache hit for {tool_name}")
                return cached

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

                        # Cache successful results for cacheable tools
                        if result.success and self._is_cacheable(tool_name):
                            self._set_cached(cache_key, result)

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
