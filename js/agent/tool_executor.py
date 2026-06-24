"""Tool layer for the agent: schema selection, tool registration, and execution.

Owns the tool schema trimming/degradation logic, the per-call execution path
(permissions, defense strategies, approval, audit, secret redaction), and tool
registration helpers.
"""

from __future__ import annotations

import asyncio
import json
from typing import TYPE_CHECKING, Any

from js.agent.base import AgentBase
from js.models.providers import ChatMessage
from js.security.audit import AuditEventType
from js.tools.registry import ToolResult

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable


class ToolExecutorMixin(AgentBase):
    """Tool schema selection, registration, and execution."""

    def _get_tools_schema(self, model: str | None = None) -> list[dict[str, Any]] | None:
        """Return tool schemas, filtering network tools when degraded.

        If the selected model does not support function calling, returns None
        so the provider receives a plain text completion instead of tools.

        Trimming strategy:
        - Cloud models: keep all tools (they have large context windows).
        - Local models: aggressively trim to ~8 essentials to avoid context
          overflow and reduce reasoning burden on weak FC models.
        """
        # Check model capability first
        if model:
            cfg = self.router.get_model_config(model)
            if cfg and not cfg.supports_tools:
                return None

        schemas = self.registry.to_openai_schemas()

        context_window = 128_000
        is_local = False
        if model:
            cfg = self.router.get_model_config(model)
            if cfg:
                context_window = cfg.context_window
            is_local = self.router.is_local_model(model)

        # Local models: aggressively trim to avoid prompt > context errors
        # AND to reduce reasoning burden (weak FC models drown in too many tools).
        if is_local and len(schemas) > 7:
            # Local models struggle with browser_fetch (SPA sites, redirects)
            # and multi-step WebBridge workflows.  Keep only the essentials.
            _local_core = {
                "web_search",
                "file_read",
                "file_write",
                "file_edit",
                "file_view",
                "shell",
                "python",
            }
            trimmed = [s for s in schemas if s.get("function", {}).get("name", "") in _local_core]
            self.logger.info(
                f"Local-model tool trim {model or 'default'}: {len(schemas)} -> {len(trimmed)}"
            )
            schemas = trimmed
        elif context_window < 32_000 and len(schemas) > 15:
            # Small-context cloud models: trim skills/office but keep browser tools
            _cloud_core = {
                "web_search",
                "browser_fetch",
                "file_read",
                "file_write",
                "file_edit",
                "file_view",
                "file_list",
                "code_search",
                "shell",
                "python",
                "web_navigate",
                "web_snapshot",
                "web_click",
                "web_fill",
                "web_screenshot",
                "web_evaluate",
                "web_extract_text",
                "web_find_tab",
                "web_list_tabs",
            }
            trimmed = [s for s in schemas if s.get("function", {}).get("name", "") in _cloud_core]
            self.logger.debug(
                f"Cloud tool trim {model or 'default'}: {len(schemas)} -> {len(trimmed)}"
            )
            schemas = trimmed

        if not self._degraded:
            return schemas
        filtered = []
        for s in schemas or []:
            name = s.get("function", {}).get("name", "")
            if name in ("web_search", "browser_fetch", "browser_open", "fetch_url"):
                continue
            if name.startswith("web_"):
                continue
            filtered.append(s)
        return filtered

    def _setup_tools(self) -> None:
        from js.tools.browser import BrowserTool
        from js.tools.code import CodeTool
        from js.tools.files import FileTools
        from js.tools.office import OfficeTools
        from js.tools.shell import ShellTool

        file_tools = FileTools(self.settings.workspace, self.settings.tools, self.guard)
        file_tools.register_all(self.registry)

        shell_tool = ShellTool(self.settings.workspace, self.settings.tools, self.guard)
        shell_tool.register(self.registry)

        code_tool = CodeTool(self.settings.workspace, self.settings.tools, self.guard)
        code_tool.register(self.registry)

        self._browser_tool = BrowserTool(self.settings.tools, self.guard)
        self._browser_tool.register_all(self.registry)

        # Kimi WebBridge — real browser control (navigate, click, screenshot, etc.)
        try:
            from js.tools.webbridge import WebBridgeTool

            self._webbridge_tool = WebBridgeTool(state_dir=self.settings.state_dir)
            self._webbridge_tool.register_all(self.registry)
        except Exception:
            self.logger.warning(
                "WebBridge tools not available (daemon may not be running)", exc_info=True
            )

        office_tools = OfficeTools(self.settings.workspace, self.settings.tools, self.guard)
        office_tools.register_all(self.registry)

        # Register search as a tool
        self._register_search_tool()

        # TODO: Register code-type skills as tools (requires async handler wrapper)

    async def _execute_tool_call(
        self,
        tc: dict[str, Any],
        session_id: str,
        run_id: str,
        user_input: str,
        progress_callback: Callable[[str, ToolResult], Awaitable[None]] | None = None,
    ) -> tuple[ChatMessage, ToolResult]:
        """Execute a single tool call and return the tool message plus raw result."""
        func = tc.get("function", {}) if isinstance(tc, dict) else {}
        tool_name = func.get("name", "") if isinstance(func, dict) else ""
        raw_args = func.get("arguments", "{}") if isinstance(func, dict) else "{}"
        raw_tool_call_id = tc.get("id", "") if isinstance(tc, dict) else ""
        # Deterministic fallback for prompt-cache consistency
        # (Hermes-style: same args → same ID across restarts)
        if not raw_tool_call_id:
            from js.utils.ids import tool_call_id as _det_tool_call_id

            raw_tool_call_id = _det_tool_call_id(
                tool_name=tool_name,
                arguments=raw_args,
                turn_idx=0,
                session_id=session_id,
            )
        tool_call_id = raw_tool_call_id
        if not tool_name:
            err_result = ToolResult(success=False, error="Tool call missing name")
            return (
                ChatMessage(
                    role="tool",
                    content=err_result.to_text(),
                    tool_call_id=tool_call_id,
                    name="unknown",
                ),
                err_result,
            )

        # Hard block: model called a tool that is not in its allowed schema.
        # This catches hallucinated tool calls from weak FC models (e.g. local
        # models that infer tool names from the system prompt even when the
        # tool was trimmed from their schema).
        if self._current_allowed_tools and tool_name not in self._current_allowed_tools:
            err_result = ToolResult(
                success=False,
                error=f"Tool '{tool_name}' is not available for this model. "
                f"Available tools: {', '.join(sorted(self._current_allowed_tools))}. "
                "Use one of the available tools or answer directly.",
            )
            return (
                ChatMessage(
                    role="tool",
                    content=err_result.to_text(),
                    tool_call_id=tool_call_id,
                    name=tool_name,
                ),
                err_result,
            )

        try:
            arguments = (
                json.loads(raw_args)
                if isinstance(raw_args, str)
                else (raw_args if isinstance(raw_args, dict) else {})
            )
        except json.JSONDecodeError as e:
            err_result = ToolResult(success=False, error=f"Invalid tool arguments JSON: {e}")
            return (
                ChatMessage(
                    role="tool",
                    content=err_result.to_text(),
                    tool_call_id=tool_call_id,
                    name=tool_name,
                ),
                err_result,
            )

        # Role-based tool permissions (least privilege)
        _role_tool_whitelist: dict[str, set[str]] = {
            "orchestrator": {
                "web_search",
                "browser_fetch",
                "file_read",
                "file_view",
                "web_navigate",
                "web_snapshot",
                "web_extract_text",
            },
            "coder": {
                "file_read",
                "file_write",
                "file_edit",
                "code_search",
                "shell",
                "python",
                "file_view",
                "file_list",
            },
            "reviewer": {"file_read", "code_search", "file_view", "file_list"},
            "researcher": {
                "web_search",
                "browser_fetch",
                "file_read",
                "file_view",
                "web_navigate",
                "web_snapshot",
                "web_click",
                "web_fill",
                "web_extract_text",
            },
            "tester": {"shell", "python", "file_read", "file_view", "code_search"},
            "generalist": {
                "file_read",
                "file_write",
                "file_edit",
                "shell",
                "python",
                "web_search",
                "code_search",
                "file_view",
                "file_list",
                "web_navigate",
                "web_snapshot",
                "web_click",
                "web_fill",
                "web_extract_text",
            },
            "architect": {"file_read", "code_search", "file_view", "file_list"},
            "designer": {"file_read", "file_view", "file_list"},
            "doc_writer": {"file_read", "file_write", "file_edit", "file_view", "file_list"},
            "security": {
                "file_read",
                "shell",
                "code_search",
                "file_view",
                "file_list",
                "web_navigate",
                "web_snapshot",
                "web_extract_text",
            },
            "performance": {
                "file_read",
                "shell",
                "python",
                "code_search",
                "file_view",
                "file_list",
            },
        }
        if self._role and tool_name not in _role_tool_whitelist.get(self._role, set()):
            denied_result = ToolResult(
                success=False,
                error=f"Permission denied: role '{self._role}' is not allowed to use tool '{tool_name}'",
            )
            return (
                ChatMessage(
                    role="tool",
                    content=denied_result.to_text(),
                    tool_call_id=tool_call_id,
                    name=tool_name,
                ),
                denied_result,
            )

        # Strategy-based defense
        from js.security.strategies import DefenseContext

        defense_ctx = DefenseContext(
            tool_name=tool_name,
            arguments=arguments,
            session_id=session_id,
            run_id=run_id,
            user_input=user_input,
            config=self.settings.security,
        )
        defense_result = self.defense_strategies.evaluate(defense_ctx)
        if defense_result.blocked:
            blocked_result = ToolResult(
                success=False, error=f"Security blocked: {defense_result.reason}"
            )
            return (
                ChatMessage(
                    role="tool",
                    content=blocked_result.to_text(),
                    tool_call_id=tool_call_id,
                    name=tool_name,
                ),
                blocked_result,
            )

        # Approval check for dangerous tools (must be awaited, so runs inline)
        spec = self.registry.get(tool_name)
        if spec and spec.dangerous:
            from js.events.models import AgentEvent

            self.event_store.emit(
                AgentEvent.approval_requested(
                    session_id=session_id,
                    run_id=run_id,
                    tool_name=tool_name,
                    arguments=arguments,
                )
            )
            approved = await asyncio.to_thread(
                self.approvals.request,
                tool_name=tool_name,
                arguments=arguments,
                context=getattr(self, "_run_context", None) or "unknown",
            )
            if not approved:
                self.event_store.emit(
                    AgentEvent.approval_denied(
                        session_id=session_id,
                        run_id=run_id,
                        tool_name=tool_name,
                        reason="approval required but not granted",
                    )
                )
                denied_result = ToolResult(
                    success=False, error="Operation denied: approval required but not granted"
                )
                return (
                    ChatMessage(
                        role="tool",
                        content=denied_result.to_text(),
                        tool_call_id=tool_call_id,
                        name=tool_name,
                    ),
                    denied_result,
                )
            self.event_store.emit(
                AgentEvent.approval_granted(
                    session_id=session_id,
                    run_id=run_id,
                    tool_name=tool_name,
                )
            )

        self.audit.log(
            AuditEventType.TOOL_CALL,
            session_id,
            run_id,
            "agent",
            tool_name,
            {"arguments": arguments},
        )
        from js.events.models import AgentEvent

        self.event_store.emit(
            AgentEvent.tool_called(
                session_id=session_id,
                run_id=run_id,
                tool_name=tool_name,
                arguments=arguments,
            )
        )

        result = await self.registry.execute(run_id, tool_name, arguments)

        # Redact secrets in output BEFORE any downstream consumer (progress
        # callback, repeated-failure guard, model context) sees it. Previously
        # progress_callback received the raw output, so a WebSocket preview
        # could leak the first ~200 chars of a secret-bearing tool result.
        if result.output:
            result.output = self.secrets.detect_and_redact(result.output, f"tool:{tool_name}")

        # Notify progress callback (e.g. WebSocket frontend)
        if progress_callback:
            try:
                await progress_callback(tool_name, result)
            except Exception:
                self.logger.debug("Progress callback failed", exc_info=True)

        # Repeated failure guard (Hermes-style)
        fail_check = self.guard.check_repeated_failure(run_id, tool_name, result.success)
        if fail_check.decision == "block":
            result = ToolResult(success=False, error=f"Security: {fail_check.reason}")

        return (
            ChatMessage(
                role="tool",
                content=result.to_text(),
                tool_call_id=tool_call_id,
                name=tool_name,
            ),
            result,
        )

    def _register_search_tool(self) -> None:
        """Register web search as a tool."""
        from js.tools.registry import ToolParam, ToolResult, ToolSpec

        async def search_handler(query: str, max_results: int = 5) -> ToolResult:
            results = await self.search.search(query, max_results)
            if not results:
                return ToolResult(success=False, error="Search returned no results")
            output = "\n\n".join(
                f"[{i + 1}] {r.title}\nURL: {r.url}\n{r.snippet}" for i, r in enumerate(results)
            )
            return ToolResult(success=True, output=output)

        spec = ToolSpec(
            name="web_search",
            description="Search the web for current information. Returns top results with snippets.",
            parameters=[
                ToolParam("query", "string", "Search query"),
                ToolParam("max_results", "integer", "Max results (1-10)", required=False),
            ],
        )
        self.registry.register(spec, search_handler)
