"""Tool layer for the agent: schema selection, tool registration, and execution.

Owns the tool schema trimming/degradation logic, the per-call execution path
(permissions, defense strategies, approval, audit, secret redaction), and tool
registration helpers.
"""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, cast

from js.echo import stable_payload_hash
from js.echo.capability import (
    LeaseAuthority,
    LeaseDenied,
    sign_tool_execution_context,
)
from js.echo.durable_thread import claim_to_thread, durable_to_thread
from js.echo.turn_context import current_runtime_context
from js.models.providers import ChatMessage
from js.orin.client import OrinLeaseClientAdapter
from js.security.approvals import ApprovalDecision, ApprovalDecisionType
from js.security.audit import AuditEventType
from js.security.untrusted import is_untrusted_tool_name, wrap_untrusted_for_model
from js.tools.registry import (
    EchoToolExecutionContext,
    ToolResult,
    network_authorization_error,
    required_network_hosts,
    tool_requires_network,
)

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from js.echo.execution_contract import ReplayClass


from js.agent.tool_executor_constants import (
    CONTROL_CLAWHUB_DISCOVER_TOOL as CONTROL_CLAWHUB_DISCOVER_TOOL,
)
from js.agent.tool_executor_constants import (
    CONTROL_CLAWHUB_INSTALL_TOOL as CONTROL_CLAWHUB_INSTALL_TOOL,
)
from js.agent.tool_executor_constants import (
    CONTROL_CRON_MUTATE_TOOL as CONTROL_CRON_MUTATE_TOOL,
)
from js.agent.tool_executor_constants import (
    CONTROL_DESKTOP_STATE_TOOL as CONTROL_DESKTOP_STATE_TOOL,
)
from js.agent.tool_executor_constants import (
    CONTROL_EVOLUTION_ACTION_TOOL as CONTROL_EVOLUTION_ACTION_TOOL,
)
from js.agent.tool_executor_constants import (
    CONTROL_FLEET_CONFIGURE_TOOL as CONTROL_FLEET_CONFIGURE_TOOL,
)
from js.agent.tool_executor_constants import (
    CONTROL_FLEET_CONTINUE_TOOL as CONTROL_FLEET_CONTINUE_TOOL,
)
from js.agent.tool_executor_constants import (
    CONTROL_FLEET_SESSION_DELETE_TOOL as CONTROL_FLEET_SESSION_DELETE_TOOL,
)
from js.agent.tool_executor_constants import (
    CONTROL_GATEWAY_PUSH_TOOL as CONTROL_GATEWAY_PUSH_TOOL,
)
from js.agent.tool_executor_constants import (
    CONTROL_MEMORY_MUTATE_TOOL as CONTROL_MEMORY_MUTATE_TOOL,
)
from js.agent.tool_executor_constants import (
    CONTROL_MODEL_SWITCH_TOOL as CONTROL_MODEL_SWITCH_TOOL,
)
from js.agent.tool_executor_constants import (
    CONTROL_PLANE_TOOL_NAMES as CONTROL_PLANE_TOOL_NAMES,
)
from js.agent.tool_executor_constants import (
    CONTROL_PROVIDER_DISCOVER_TOOL as CONTROL_PROVIDER_DISCOVER_TOOL,
)
from js.agent.tool_executor_constants import (
    CONTROL_PROVIDER_MUTATE_TOOL as CONTROL_PROVIDER_MUTATE_TOOL,
)
from js.agent.tool_executor_constants import (
    CONTROL_SESSION_MUTATE_TOOL as CONTROL_SESSION_MUTATE_TOOL,
)
from js.agent.tool_executor_constants import (
    CONTROL_SETUP_STATE_TOOL as CONTROL_SETUP_STATE_TOOL,
)
from js.agent.tool_executor_constants import (
    CONTROL_SKILL_INSTALL_TOOL as CONTROL_SKILL_INSTALL_TOOL,
)
from js.agent.tool_executor_constants import (
    CONTROL_SKILL_MUTATE_TOOL as CONTROL_SKILL_MUTATE_TOOL,
)
from js.agent.tool_executor_constants import (
    CONTROL_TASK_MUTATE_TOOL as CONTROL_TASK_MUTATE_TOOL,
)
from js.agent.tool_executor_constants import (
    CONTROL_UPLOAD_MUTATE_TOOL as CONTROL_UPLOAD_MUTATE_TOOL,
)
from js.agent.tool_executor_constants import (
    DESKTOP_WIZARD_ACTION_TOOL as DESKTOP_WIZARD_ACTION_TOOL,
)
from js.agent.tool_executor_constants import (
    DESKTOP_WIZARD_ACTIONS as DESKTOP_WIZARD_ACTIONS,
)
from js.agent.tool_executor_control_plane import ControlPlaneMixin
from js.agent.tool_executor_handoffs import ToolHandoffMixin
from js.agent.tool_executor_lease import (
    _load_or_create_tool_lease_key as _load_or_create_tool_lease_key,
)
from js.agent.tool_executor_lease import (
    _read_tool_lease_key_strict as _read_tool_lease_key_strict,
)


def _approval_context_from_channel(channel: str) -> str:
    normalized = channel.strip().lower()
    if normalized == "cli" or normalized.endswith("_cli"):
        return "cli"
    if "cron" in normalized or "routine" in normalized:
        return "cron"
    if (
        normalized in {"api_chat", "ws_message", "ws_stream"}
        or "web" in normalized
        or normalized.startswith("ws_")
    ):
        return "web"
    return "unknown"


class ToolExecutorMixin(ControlPlaneMixin, ToolHandoffMixin):
    """Tool schema selection, registration, and execution."""

    _approval_poll_interval = 0.1

    def _effective_tool_role(self, session_id: str, run_id: str) -> str | None:
        """Use the immutable per-turn role instead of shared mutable agent state."""
        runtime_context = current_runtime_context()
        if runtime_context is None:
            return getattr(self, "_role", None)
        if runtime_context.session_id != session_id or runtime_context.run_id != run_id:
            return "echo-context-mismatch"
        return runtime_context.role

    async def _await_pending_approval(
        self,
        request_id: str,
        *,
        owner_key_hash: str,
    ) -> ApprovalDecision:
        take_decision = getattr(self.approvals, "take_decision", None)
        get_pending_request = getattr(self.approvals, "get_pending_request", None)
        if not callable(take_decision) or not callable(get_pending_request):
            return ApprovalDecision(
                ApprovalDecisionType.PENDING,
                request_id=request_id,
                reason="approval queue does not support asynchronous resolution",
            )

        decision = await asyncio.to_thread(
            take_decision,
            request_id,
            owner_key_hash=owner_key_hash,
        )
        if decision is not None:
            return cast("ApprovalDecision", decision)
        pending_request = await asyncio.to_thread(
            get_pending_request,
            request_id,
            owner_key_hash=owner_key_hash,
        )
        if pending_request is None:
            decision = await asyncio.to_thread(
                take_decision,
                request_id,
                owner_key_hash=owner_key_hash,
            )
            if decision is not None:
                return cast("ApprovalDecision", decision)
            return ApprovalDecision(
                ApprovalDecisionType.REJECT,
                request_id=request_id,
                reason="approval request is no longer pending",
            )
        timeout_seconds = max(0.1, float(pending_request.timeout_seconds))
        deadline = time.monotonic() + timeout_seconds
        try:
            while time.monotonic() < deadline:
                decision = await asyncio.to_thread(
                    take_decision,
                    request_id,
                    owner_key_hash=owner_key_hash,
                )
                if decision is not None:
                    return cast("ApprovalDecision", decision)
                await asyncio.sleep(max(0.0, float(self._approval_poll_interval)))
        except asyncio.CancelledError:
            decide = getattr(self.approvals, "decide", None)
            if callable(decide):
                await asyncio.to_thread(
                    decide,
                    request_id,
                    ApprovalDecisionType.REJECT,
                    reason="turn_cancelled",
                )
                await asyncio.to_thread(
                    take_decision,
                    request_id,
                    owner_key_hash=owner_key_hash,
                )
            raise

        decide = getattr(self.approvals, "decide", None)
        if callable(decide):
            await asyncio.to_thread(
                decide,
                request_id,
                ApprovalDecisionType.REJECT,
                reason="timeout",
            )
            decision = await asyncio.to_thread(
                take_decision,
                request_id,
                owner_key_hash=owner_key_hash,
            )
            if decision is not None:
                return cast("ApprovalDecision", decision)
        return ApprovalDecision(
            ApprovalDecisionType.REJECT,
            request_id=request_id,
            reason="timeout",
        )

    async def _request_echo_approval(
        self,
        *,
        tool_name: str,
        arguments: dict[str, Any],
        tool_call_id: str,
        session_id: str,
        run_id: str,
        owner_key_hash: str,
    ) -> tuple[Any, dict[str, str]]:
        """Resolve one dangerous-tool approval as its own durable Echo effect.

        Returns the decision plus a durable reference (request id, approval
        effect id) so the approved execution can be atomically linked back to
        this approval in the EchoLedger (approval_execution_claimed /
        approval_finalized).
        """
        echo_service = getattr(self, "echo_safety_service", None)
        if echo_service is None:
            raise RuntimeError("Echo approval requires an initialized EchoSafetyService")
        runtime_context = current_runtime_context()
        product_id = str(getattr(self.settings, "product_id", "js-agent"))
        channel = ""
        if (
            runtime_context is not None
            and runtime_context.session_id == session_id
            and runtime_context.run_id == run_id
        ):
            product_id = runtime_context.product_id
            channel = runtime_context.channel
        binding_hash = stable_payload_hash(
            {
                "product_id": product_id,
                "owner_key_hash": owner_key_hash,
                "session_id": session_id,
                "run_id": run_id,
                "tool_name": tool_name,
                "tool_call_id": tool_call_id,
                "arguments": arguments,
            }
        )
        # P0-1 fix: issue a real CapabilityLease and consume it to prove authenticity
        authority = self._get_echo_tool_lease_authority()
        approval_lease = authority.issue(
            owner_key_hash=owner_key_hash,
            run_id=run_id,
            tool_name="echo_approval",
            args_schema=binding_hash,
            resource_scope="approval",
            max_bytes=0,
            max_duration_ms=300000,
            ttl_ms=300000,
            product_id=product_id,
            session_id=session_id,
        )
        # Verify and consume the lease to prove it is a real CapabilityLease
        now = authority._now()
        authority.verify(
            approval_lease,
            expected_owner=owner_key_hash,
            expected_tool="echo_approval",
            expected_scope="approval",
            now=now,
        )
        authority.consume(approval_lease, now=now)
        lease_id = approval_lease.lease_id

        def finish_cancelled(effect: Any) -> None:
            echo_service.finish_tool_effect(
                effect,
                status="cancelled",
                output_hash=stable_payload_hash(
                    {"status": "cancelled", "approval_binding": binding_hash}
                ),
            )

        claimed = await claim_to_thread(
            lambda: echo_service.begin_tool_effect(
                tenant_id=owner_key_hash,
                product_id=product_id,
                session_id=session_id,
                run_id=run_id,
                tool_name="echo_approval",
                tool_call_id=f"approval:{tool_call_id}",
                args_hash=binding_hash,
                lease_id=lease_id,
                replay_class="non_idempotent",
            ),
            on_cancel=finish_cancelled,
            executor=self._echo_durable_executor,
        )
        approval_effect = claimed.value
        try:
            from js.events.models import AgentEvent

            self.event_store.emit(
                AgentEvent.approval_requested(
                    session_id=session_id,
                    run_id=run_id,
                    tool_name=tool_name,
                    arguments=arguments,
                )
            )
            run_context = _approval_context_from_channel(channel)
            if hasattr(self.approvals, "request_decision"):
                decision = await asyncio.to_thread(
                    self.approvals.request_decision,
                    tool_name=tool_name,
                    arguments=arguments,
                    context=run_context,
                    session_id=session_id,
                    run_id=run_id,
                    owner_key_hash=owner_key_hash,
                    queue_if_unhandled=run_context == "web",
                )
            else:
                approved = await asyncio.to_thread(
                    self.approvals.request,
                    tool_name=tool_name,
                    arguments=arguments,
                    context=run_context,
                    session_id=session_id,
                )
                decision = type(
                    "_ApprovalDecisionCompat",
                    (),
                    {
                        "action": ApprovalDecisionType.APPROVE
                        if approved
                        else ApprovalDecisionType.REJECT,
                        "approved": approved,
                        "edited_arguments": None,
                        "response": "",
                        "reason": "legacy approval",
                        "request_id": "",
                    },
                )()
            if decision.action == ApprovalDecisionType.PENDING:
                decision = await self._await_pending_approval(
                    decision.request_id,
                    owner_key_hash=owner_key_hash,
                )
        except asyncio.CancelledError:
            await durable_to_thread(
                lambda: finish_cancelled(approval_effect),
                claim=claimed,
            )
            raise
        except Exception as exc:
            exception_type = type(exc).__name__
            await durable_to_thread(
                lambda: echo_service.finish_tool_effect(
                    approval_effect,
                    status="failed",
                    output_hash=stable_payload_hash(
                        {
                            "status": "failed",
                            "approval_binding": binding_hash,
                            "exception_type": exception_type,
                        }
                    ),
                ),
                claim=claimed,
            )
            raise

        await durable_to_thread(
            lambda: echo_service.finish_tool_effect(
                approval_effect,
                status="ok",
                output_hash=stable_payload_hash(
                    {
                        "status": "ok",
                        "approval_binding": binding_hash,
                        "action": str(decision.action),
                        "request_id": str(getattr(decision, "request_id", "")),
                        "edited_arguments_hash": stable_payload_hash(decision.edited_arguments)
                        if isinstance(decision.edited_arguments, dict)
                        else None,
                        "response_hash": stable_payload_hash(decision.response)
                        if getattr(decision, "response", "")
                        else None,
                        "reason_hash": stable_payload_hash(decision.reason)
                        if getattr(decision, "reason", "")
                        else None,
                    }
                ),
            ),
            claim=claimed,
        )
        approval_ref = {
            "request_id": str(getattr(decision, "request_id", "")),
            "approval_effect_id": str(getattr(approval_effect, "effect_id", "")),
            "tenant_id": owner_key_hash,
        }
        return decision, approval_ref

    def _get_tools_schema(self, model: str | None = None) -> list[dict[str, Any]] | None:
        """Return tool schemas, filtering network tools when degraded.

        If the selected model does not support function calling, returns None
        so the provider receives a plain text completion instead of tools.

        Trimming strategy:
        - Cloud models: keep all tools (they have large context windows).
        - Local models: aggressively trim to ~8 essentials to avoid context
          overflow and reduce reasoning burden on weak FC models.
        """
        skills = getattr(self, "skills", None)
        ensure_loaded = getattr(skills, "ensure_loaded", None)
        if callable(ensure_loaded):
            ensure_loaded()

        # Check model capability first
        if model:
            cfg = self.router.get_model_config(model)
            if cfg and not cfg.supports_tools:
                return None

        schemas = self.registry.to_openai_schemas()
        agent_attributes = getattr(self, "__dict__", {})
        if "_echo_capability_ceiling" in agent_attributes:
            capability_ceiling = {
                str(name) for name in agent_attributes["_echo_capability_ceiling"]
            }
            schemas = [
                schema
                for schema in schemas
                if str(schema.get("function", {}).get("name", "")) in capability_ceiling
            ]
        security = getattr(self.settings, "security", None)
        if not (
            bool(getattr(security, "network_enabled", False))
            and tuple(getattr(security, "network_allowlist", ()))
        ):
            schemas = [
                schema
                for schema in schemas
                if not tool_requires_network(
                    str(schema.get("function", {}).get("name", "")),
                    {},
                )
            ]

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
        from js.orin.stage_c import product_enforce_enabled, should_register_product_tool
        from js.tools.browser import BrowserTool
        from js.tools.code import CodeTool
        from js.tools.files import FileTools
        from js.tools.office import OfficeTools
        from js.tools.shell import ShellTool

        enforce = product_enforce_enabled(getattr(self.settings, "orin", None))
        file_tools = FileTools(
            self.settings.workspace,
            self.settings.tools,
            self.guard,
            cell_backend=self._file_cell_backend(),
        )
        file_tools.register_all(self.registry)

        shell_tool = ShellTool(self.settings.workspace, self.settings.tools, self.guard)
        shell_tool.register(self.registry)

        code_tool = CodeTool(self.settings.workspace, self.settings.tools, self.guard)
        code_tool.register(self.registry)

        cell_backend = self._build_cell_backend()
        if cell_backend is not None:
            from js.orind.cells.build import build_cell_private_staging

            shell_tool.cell_backend = cell_backend  # type: ignore[attr-defined]
            code_tool.cell_backend = cell_backend  # type: ignore[attr-defined]
            code_tool.staging_root = build_cell_private_staging(Path(self.settings.state_dir))

        if not enforce or getattr(getattr(self.settings, "orin", None), "cell_net", False) is True:
            self._browser_tool = BrowserTool(
                self.settings.tools,
                self.guard,
                cell_backend=self._network_cell_backend(),
            )
            self._browser_tool.register_all(self.registry)

        # Kimi WebBridge — real browser control (navigate, click, screenshot, etc.)
        if should_register_product_tool("web_navigate", enforce=enforce):
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
        if should_register_product_tool("web_search", enforce=enforce):
            self._register_search_tool()
        if should_register_product_tool("control_memory_mutate", enforce=enforce):
            self._register_control_plane_tools()
        if should_register_product_tool("mcp_placeholder", enforce=enforce):
            self._register_controlled_mcp_tools()
        if should_register_product_tool("desktop_wizard_action", enforce=enforce):
            self._register_desktop_wizard_action_tool()
        from js.bots.tools import register_bots_tools

        register_bots_tools(self.registry, self)
        self._apply_enforce_tool_inventory(enforce=enforce)

        # TODO: Register code-type skills as tools (requires async handler wrapper)

    def _apply_enforce_tool_inventory(self, *, enforce: bool) -> None:
        """Drop C0 disabled-in-enforce tools and fail closed on unknown names."""

        if not enforce:
            return
        from js.orin.inventory import require_no_unclassified_exits, should_register_product_tool

        for spec in list(self.registry.list_tools()):
            if not should_register_product_tool(spec.name, enforce=True):
                self.registry.unregister(spec.name)
        require_no_unclassified_exits(spec.name for spec in self.registry.list_tools())

    def _register_controlled_mcp_tools(self) -> None:
        manifest_path = getattr(self.settings, "mcp_manifest", None)
        if not manifest_path:
            return
        try:
            from js.mcp.controlled import ControlledMCPConnector, load_mcp_manifest

            manifest = load_mcp_manifest(Path(manifest_path))
            ControlledMCPConnector(manifest).register_tools(self.registry)
        except Exception as exc:
            raise RuntimeError(
                f"Controlled MCP manifest could not be registered: {manifest_path}"
            ) from exc

    def _register_desktop_wizard_action_tool(self) -> None:
        """Register the admin-confirmed desktop setup action behind Echo leases."""
        from js.tools.registry import ToolParam, ToolSpec

        async def wizard_action_handler(action_type: str) -> ToolResult:
            if not isinstance(action_type, str) or action_type not in DESKTOP_WIZARD_ACTIONS:
                return ToolResult(success=False, error="Unsupported desktop wizard action")

            from js.tools.desktop.wizard import execute_action

            result = await asyncio.to_thread(execute_action, action_type)
            if not isinstance(result, dict):
                return ToolResult(
                    success=False, error="Desktop wizard action returned invalid result"
                )
            if result.get("success"):
                return ToolResult(success=True, output=json.dumps(result, ensure_ascii=True))
            return ToolResult(
                success=False,
                error=str(
                    result.get("error") or result.get("message") or "Desktop wizard action failed"
                ),
            )

        self.registry.register(
            ToolSpec(
                name=DESKTOP_WIZARD_ACTION_TOOL,
                description="Internal desktop setup wizard action.",
                parameters=[
                    ToolParam(
                        "action_type",
                        "string",
                        "Desktop wizard action",
                        enum=sorted(DESKTOP_WIZARD_ACTIONS),
                    )
                ],
                # An authenticated admin POST is the explicit confirmation for
                # this narrowly scoped wizard action; do not enqueue approval.
                dangerous=False,
                model_visible=False,
            ),
            wizard_action_handler,
        )

    async def _execute_tool_call(
        self,
        tc: dict[str, Any],
        session_id: str,
        run_id: str,
        user_input: str,
        progress_callback: Callable[[str, ToolResult], Awaitable[None]] | None = None,
        *,
        allowed_tools: set[str] | None = None,
        owner_key_hash: str | None = None,
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

        from js.echo.plan_commit.narrowing import is_write_or_egress_tool, write_egress_blocked

        if write_egress_blocked() and is_write_or_egress_tool(tool_name):
            err_result = ToolResult(
                success=False,
                error=f"Tool '{tool_name}' is blocked after mid-turn dirty context.",
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

        # Hard block: model called a tool that is not in its allowed schema.
        # This catches hallucinated tool calls from weak FC models (e.g. local
        # models that infer tool names from the system prompt even when the
        # tool was trimmed from their schema).
        active_allowed_tools = (
            set(allowed_tools)
            if allowed_tools is not None
            else set(getattr(self, "_current_allowed_tools", set()))
        )
        if active_allowed_tools and tool_name not in active_allowed_tools:
            err_result = ToolResult(
                success=False,
                error=f"Tool '{tool_name}' is not available for this model. "
                f"Available tools: {', '.join(sorted(active_allowed_tools))}. "
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
            loaded_args = (
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
        arguments: dict[str, Any] = loaded_args if isinstance(loaded_args, dict) else {}

        from js.echo.plan_commit.assembler import apply_assembled_arguments

        assembled_error, arguments = apply_assembled_arguments(tool_name, arguments)
        if assembled_error is not None:
            err_result = ToolResult(success=False, error=assembled_error)
            return (
                ChatMessage(
                    role="tool",
                    content=err_result.to_text(),
                    tool_call_id=tool_call_id,
                    name=tool_name,
                ),
                err_result,
            )

        if tool_name == CONTROL_SKILL_INSTALL_TOOL:
            source_error, arguments = self._normalize_control_skill_install_arguments(arguments)
            if source_error is not None:
                err_result = ToolResult(success=False, error=source_error)
                return (
                    ChatMessage(
                        role="tool",
                        content=err_result.to_text(),
                        tool_call_id=tool_call_id,
                        name=tool_name,
                    ),
                    err_result,
                )

        argument_security_error = self._tool_argument_security_error(arguments)
        if argument_security_error is not None:
            denied_result = ToolResult(success=False, error=argument_security_error)
            return (
                ChatMessage(
                    role="tool",
                    content=denied_result.to_text(),
                    tool_call_id=tool_call_id,
                    name=tool_name,
                ),
                denied_result,
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
        _runtime_capability_roles = {"admin", "local-user", "user"}
        effective_role = self._effective_tool_role(session_id, run_id)
        if (
            effective_role
            and effective_role not in _runtime_capability_roles
            and tool_name not in CONTROL_PLANE_TOOL_NAMES
            and tool_name not in _role_tool_whitelist.get(effective_role, set())
        ):
            denied_result = ToolResult(
                success=False,
                error=(
                    f"Permission denied: role '{effective_role}' is not allowed "
                    f"to use tool '{tool_name}'"
                ),
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

        defense_error = self._tool_defense_error(
            tool_name=tool_name,
            arguments=arguments,
            session_id=session_id,
            run_id=run_id,
            user_input=user_input,
        )
        if defense_error is not None:
            blocked_result = ToolResult(success=False, error=defense_error)
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
        approval_ref: dict[str, str] | None = None
        spec = self.registry.get(tool_name)
        if spec and spec.dangerous:
            from js.events.models import AgentEvent

            approval_owner_key_hash = self._current_echo_owner(owner_key_hash)
            decision, approval_ref = await self._request_echo_approval(
                tool_name=tool_name,
                arguments=arguments,
                tool_call_id=tool_call_id,
                session_id=session_id,
                run_id=run_id,
                owner_key_hash=approval_owner_key_hash,
            )
            if decision.action == ApprovalDecisionType.PENDING:
                self.event_store.emit(
                    AgentEvent.approval_denied(
                        session_id=session_id,
                        run_id=run_id,
                        tool_name=tool_name,
                        reason="pending approval",
                    )
                )
                pending_result = ToolResult(
                    success=False,
                    error="Operation pending approval in Echo approval queue",
                    metadata={"echo_approval": "pending"},
                )
                return (
                    ChatMessage(
                        role="tool",
                        content=pending_result.to_text(),
                        tool_call_id=tool_call_id,
                        name=tool_name,
                    ),
                    pending_result,
                )
            if decision.action == ApprovalDecisionType.RESPOND:
                try:
                    safe_response = self.secrets.detect_and_redact(
                        decision.response,
                        "approval_response",
                    )
                except Exception:
                    safe_response = "Approval response suppressed because it could not be inspected"
                response_result = ToolResult(
                    success=True,
                    output=safe_response,
                    metadata={"echo_approval": "respond"},
                )
                return (
                    ChatMessage(
                        role="tool",
                        content=response_result.to_text(),
                        tool_call_id=tool_call_id,
                        name=tool_name,
                    ),
                    response_result,
                )
            if decision.action == ApprovalDecisionType.EDIT:
                edited_arguments = decision.edited_arguments
                if not isinstance(edited_arguments, dict):
                    denied_result = ToolResult(
                        success=False,
                        error="Operation denied: edited approval did not include arguments",
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
                arguments = edited_arguments
                argument_security_error = self._tool_argument_security_error(arguments)
                if argument_security_error is not None:
                    denied_result = ToolResult(success=False, error=argument_security_error)
                    return (
                        ChatMessage(
                            role="tool",
                            content=denied_result.to_text(),
                            tool_call_id=tool_call_id,
                            name=tool_name,
                        ),
                        denied_result,
                    )
                defense_error = self._tool_defense_error(
                    tool_name=tool_name,
                    arguments=arguments,
                    session_id=session_id,
                    run_id=run_id,
                    user_input=user_input,
                )
                if defense_error is not None:
                    denied_result = ToolResult(success=False, error=defense_error)
                    return (
                        ChatMessage(
                            role="tool",
                            content=denied_result.to_text(),
                            tool_call_id=tool_call_id,
                            name=tool_name,
                        ),
                        denied_result,
                    )
            if not decision.approved:
                self.event_store.emit(
                    AgentEvent.approval_denied(
                        session_id=session_id,
                        run_id=run_id,
                        tool_name=tool_name,
                        reason=decision.reason or "approval rejected",
                    )
                )
                denied_result = ToolResult(
                    success=False,
                    error=(
                        "Operation denied: approval rejected"
                        + (f" ({decision.reason})" if decision.reason else "")
                    ),
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

        lease_error, echo_context = self._authorize_echo_tool_lease(
            tool_name=tool_name,
            arguments=arguments,
            session_id=session_id,
            run_id=run_id,
            owner_key_hash=owner_key_hash,
        )
        if lease_error is not None:
            denied_result = ToolResult(success=False, error=lease_error)
            return (
                ChatMessage(
                    role="tool",
                    content=denied_result.to_text(),
                    tool_call_id=tool_call_id,
                    name=tool_name,
                ),
                denied_result,
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

        if echo_context is None:
            raise RuntimeError("Echo tool execution requires a signed CapabilityLease context")
        echo_service = getattr(self, "echo_safety_service", None)
        if echo_service is None:
            raise RuntimeError("Echo tool execution requires an initialized EchoSafetyService")
        runtime_context = current_runtime_context()
        product_id = str(getattr(self.settings, "product_id", "js-agent"))
        effect_workspace: str | None = None
        if (
            runtime_context is not None
            and runtime_context.session_id == session_id
            and runtime_context.run_id == run_id
        ):
            product_id = runtime_context.product_id
            task_ref = runtime_context.task_ref
            if task_ref is not None:
                if (
                    task_ref.owner != echo_context.owner_key_hash
                    or task_ref.session != session_id
                    or task_ref.run != run_id
                    or task_ref.legacy_product_id != product_id
                ):
                    raise RuntimeError("Echo TaskRef does not match tool effect authority")
                effect_workspace = task_ref.workspace
        replay_class: ReplayClass = (
            "idempotent" if spec is not None and spec.read_only else "non_idempotent"
        )

        def _finish_cancelled_tool_effect(effect: Any) -> None:
            echo_service.finish_tool_effect(
                effect,
                status="cancelled",
                output_hash=stable_payload_hash(
                    {
                        "status": "cancelled",
                        "tool_name": tool_name,
                        "tool_call_id": tool_call_id,
                    }
                ),
            )

        claimed_effect = await claim_to_thread(
            lambda: echo_service.begin_tool_effect(
                tenant_id=echo_context.owner_key_hash,
                product_id=product_id,
                session_id=session_id,
                run_id=run_id,
                tool_name=tool_name,
                tool_call_id=tool_call_id,
                args_hash=echo_context.args_hash,
                lease_id=echo_context.lease_id,
                replay_class=replay_class,
                workspace=effect_workspace,
            ),
            on_cancel=_finish_cancelled_tool_effect,
            executor=self._echo_durable_executor,
        )
        tool_effect = claimed_effect.value

        def _record_approval_finalized(final_status: str) -> None:
            if approval_ref is None:
                return
            echo_service.record_approval_event(
                tenant_id=approval_ref["tenant_id"],
                product_id=product_id,
                session_id=session_id,
                run_id=run_id,
                event_type="approval_finalized",
                request_id=approval_ref["request_id"],
                tool_name=tool_name,
                arguments_hash=echo_context.args_hash,
                extra={
                    "approval_effect_id": approval_ref["approval_effect_id"],
                    "execution_effect_id": tool_effect.effect_id,
                    "status": final_status,
                },
            )

        try:
            if approval_ref is not None:
                # Link the approved execution back to its approval in the
                # authoritative EchoLedger (claim is exactly-once via the
                # outbox).  This must stay inside the try: if journaling fails,
                # the except handlers below release the claim by finishing the
                # tool effect instead of leaking it.
                await asyncio.to_thread(
                    lambda: echo_service.record_approval_event(
                        tenant_id=approval_ref["tenant_id"],
                        product_id=product_id,
                        session_id=session_id,
                        run_id=run_id,
                        event_type="approval_execution_claimed",
                        request_id=approval_ref["request_id"],
                        tool_name=tool_name,
                        arguments_hash=echo_context.args_hash,
                        extra={
                            "approval_effect_id": approval_ref["approval_effect_id"],
                            "execution_effect_id": tool_effect.effect_id,
                        },
                    )
                )
            result = await self.registry.execute(
                run_id,
                tool_name,
                arguments,
                echo_mode=self._echo_tool_execution_mode(),
                execution_context=echo_context,
            )
            if not isinstance(result, ToolResult):
                raise TypeError("ToolRegistry.execute returned an invalid result")
            result, result_was_redacted = self._sanitize_tool_result(
                result,
                tool_name=tool_name,
            )
            if result_was_redacted:
                # ToolRegistry caches a defensive copy before this Echo-level
                # redaction boundary.  Remove any pre-redaction cached copy.
                self.registry.invalidate_cache(tool_name)
        except asyncio.CancelledError:
            await durable_to_thread(
                lambda: _finish_cancelled_tool_effect(tool_effect),
                claim=claimed_effect,
            )
            await asyncio.to_thread(_record_approval_finalized, "cancelled")
            raise
        except Exception as exc:
            exception_type = exc.__class__.__name__
            await durable_to_thread(
                lambda: echo_service.finish_tool_effect(
                    tool_effect,
                    status="failed",
                    output_hash=stable_payload_hash(
                        {
                            "status": "failed",
                            "exception_type": exception_type,
                            "exception": "internal error details withheld",
                        }
                    ),
                ),
                claim=claimed_effect,
            )
            await asyncio.to_thread(_record_approval_finalized, "failed")
            raise
        receipt_status: Literal["ok", "failed"] = "ok" if result.success else "failed"
        durable_output_hash = stable_payload_hash(
            {
                "status": receipt_status,
                "success": result.success,
                "output": result.output,
                "error": result.error,
                "metadata": result.metadata,
            }
        )
        # Prefer excel_write's content digest. Work result policy rewrites
        # metadata.path to a public handle, so path-based hashing is unreliable.
        artifact_refs: tuple[Any, ...] = ()
        if tool_name == "excel_write" and result.success and isinstance(result.metadata, dict):
            content_digest = result.metadata.get("content_sha256")
            if (
                isinstance(content_digest, str)
                and len(content_digest) == 64
                and all(char in "0123456789abcdef" for char in content_digest.lower())
            ):
                durable_output_hash = f"sha256:{content_digest.lower()}"
                # Build verified ArtifactRefV1 for excel_write results
                from js.echo.mode_contract import AppMode, ArtifactRefV1

                eff_mode = AppMode.WORK if product_id == "js-work" else AppMode.PERSONAL
                eff_owner = owner_key_hash or "local-user"
                if not eff_owner or len(eff_owner) < 1:
                    eff_owner = "0" * 16
                eff_workspace: str | None = tool_effect.workspace
                # Only build artifact ref if workspace is valid for the mode
                if eff_mode is AppMode.WORK and not eff_workspace:
                    # Work mode requires non-empty workspace for ArtifactRefV1
                    # Skip artifact ref if binding doesn't have workspace
                    artifact_refs = ()
                else:
                    artifact_ref = ArtifactRefV1(
                        mode=eff_mode,
                        owner=eff_owner,
                        session=session_id,
                        workspace=eff_workspace,
                        kind="spreadsheet",
                        uri=f"echo://artifact/excel_write/{content_digest.lower()}",
                        digest=f"sha256:{content_digest.lower()}",
                        acl="owner",
                        created_by_run=run_id,
                    )
                    artifact_refs = (artifact_ref,)
        await durable_to_thread(
            lambda: echo_service.finish_tool_effect(
                tool_effect,
                status=receipt_status,
                output_hash=durable_output_hash,
                artifact_refs=artifact_refs,
            ),
            claim=claimed_effect,
        )
        await asyncio.to_thread(_record_approval_finalized, receipt_status)

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

        content = result.to_text()
        if is_untrusted_tool_name(tool_name):
            content = wrap_untrusted_for_model(content)

        return (
            ChatMessage(
                role="tool",
                content=content,
                tool_call_id=tool_call_id,
                name=tool_name,
            ),
            result,
        )

    def _sanitize_tool_result(
        self,
        result: ToolResult,
        *,
        tool_name: str,
    ) -> tuple[ToolResult, bool]:
        """Redact and bound every public ToolResult field before journaling."""
        output_budget = int(
            getattr(getattr(self.settings, "tools", None), "tool_output_budget_chars", 20_000)
        )
        output, output_changed = self._sanitize_tool_result_text(
            result.output,
            scope=f"tool:{tool_name}:output",
            limit=max(1, output_budget),
        )
        error, error_changed = self._sanitize_tool_result_text(
            result.error,
            scope=f"tool:{tool_name}:error",
            limit=4_000,
        )
        metadata, metadata_changed = self._sanitize_tool_metadata(
            result.metadata,
            scope=f"tool:{tool_name}:metadata",
        )
        result.output = output
        result.error = error
        result.metadata = metadata
        return result, output_changed or error_changed or metadata_changed

    def _sanitize_tool_result_text(
        self,
        value: Any,
        *,
        scope: str,
        limit: int,
    ) -> tuple[str, bool]:
        if not isinstance(value, str):
            return "", value not in (None, "")
        original = value
        value = value[:limit]
        try:
            value = self.secrets.detect_and_redact(value, scope)
        except Exception:
            return "Tool result could not be safely inspected", True
        private_roots: list[tuple[str, str]] = []
        for attribute, replacement in (
            ("workspace", "<workspace>"),
            ("state_dir", "<state>"),
        ):
            raw_path = getattr(self.settings, attribute, None)
            if raw_path is None:
                continue
            try:
                private_roots.append((str(Path(raw_path).expanduser().resolve()), replacement))
            except (OSError, RuntimeError, ValueError):
                continue
        try:
            private_roots.append((str(Path.home().resolve()), "<home>"))
        except (OSError, RuntimeError):
            pass
        for private_root, replacement in private_roots:
            if private_root and private_root != str(Path(private_root).anchor):
                value = value.replace(private_root, replacement)
        return value, value != original

    def _sanitize_tool_metadata(
        self,
        metadata: Any,
        *,
        scope: str,
    ) -> tuple[dict[str, Any], bool]:
        nodes_left = [512]

        def sanitize(value: Any, depth: int) -> tuple[Any, bool]:
            nodes_left[0] -= 1
            if nodes_left[0] < 0 or depth > 8:
                return "[metadata truncated]", True
            if isinstance(value, str):
                return self._sanitize_tool_result_text(
                    value,
                    scope=scope,
                    limit=4_000,
                )
            if isinstance(value, Path):
                text, _changed = self._sanitize_tool_result_text(
                    str(value),
                    scope=scope,
                    limit=4_000,
                )
                return text, True
            if value is None or isinstance(value, (bool, int, float)):
                return value, False
            if isinstance(value, dict):
                changed = len(value) > 128
                sanitized: dict[str, Any] = {}
                for index, (key, item) in enumerate(value.items()):
                    if index >= 128:
                        break
                    safe_key, key_changed = self._sanitize_tool_result_text(
                        key if isinstance(key, str) else "metadata",
                        scope=scope,
                        limit=128,
                    )
                    safe_item, item_changed = sanitize(item, depth + 1)
                    sanitized[safe_key] = safe_item
                    changed = changed or key_changed or item_changed or not isinstance(key, str)
                return sanitized, changed
            if isinstance(value, (list, tuple)):
                changed = isinstance(value, tuple) or len(value) > 128
                sanitized_items: list[Any] = []
                for item in value[:128]:
                    safe_item, item_changed = sanitize(item, depth + 1)
                    sanitized_items.append(safe_item)
                    changed = changed or item_changed
                return sanitized_items, changed
            return f"<{type(value).__name__}>", True

        if not isinstance(metadata, dict):
            return {}, metadata not in (None, {})
        sanitized, changed = sanitize(metadata, 0)
        return sanitized if isinstance(sanitized, dict) else {}, changed

    def _tool_argument_security_error(self, arguments: dict[str, Any]) -> str | None:
        """Reject uninspectable or secret-bearing arguments before side effects."""
        try:
            payload = json.dumps(
                arguments,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            redacted = self.secrets.detect_and_redact(payload, "tool_arguments")
        except Exception:
            return "Security blocked: tool arguments could not be safely inspected"
        if redacted != payload:
            return "Security blocked: secret material detected in tool arguments"
        return None

    def _tool_defense_error(
        self,
        *,
        tool_name: str,
        arguments: dict[str, Any],
        session_id: str,
        run_id: str,
        user_input: str,
    ) -> str | None:
        """Evaluate the full behavior policy for the exact arguments to execute."""
        from js.security.strategies import DefenseContext

        defense_result = self.defense_strategies.evaluate(
            DefenseContext(
                tool_name=tool_name,
                arguments=arguments,
                session_id=session_id,
                run_id=run_id,
                user_input=user_input,
                config=self.settings.security,
            )
        )
        if defense_result.blocked:
            return f"Security blocked: {defense_result.reason}"
        return None

    def _authorize_echo_tool_lease(
        self,
        *,
        tool_name: str,
        arguments: dict[str, Any],
        session_id: str,
        run_id: str,
        owner_key_hash: str | None = None,
    ) -> tuple[str | None, EchoToolExecutionContext | None]:
        if self._echo_tool_execution_mode() != "on":
            return None, None
        try:
            authority = self._get_echo_tool_lease_authority()
            owner = self._current_echo_owner(owner_key_hash)
            args_hash = stable_payload_hash(arguments)
            runtime_context = current_runtime_context()
            product_id = str(getattr(self.settings, "product_id", "js-agent"))
            profile = str(getattr(self.settings, "work_profile", "default"))
            network_allowlist: tuple[str, ...] = ()
            if (
                runtime_context is not None
                and runtime_context.session_id == session_id
                and runtime_context.run_id == run_id
            ):
                product_id = runtime_context.product_id
                profile = runtime_context.profile
                network_allowlist = tuple(runtime_context.network_allowlist)
            session_scope = "product-session:" + stable_payload_hash(
                {"product_id": product_id, "session_id": session_id}
            )
            tool_limits = getattr(self.settings, "tools", None)
            output_budget = int(getattr(tool_limits, "tool_output_budget_chars", 20_000))
            timeout_seconds = float(getattr(tool_limits, "shell_timeout", 300.0))
            network_error = network_authorization_error(
                tool_name,
                arguments,
                network_allowlist,
            )
            if network_error is not None:
                raise LeaseDenied(network_error)
            network_hosts = required_network_hosts(tool_name, arguments)
            network_policy = "allow" if network_hosts else "deny"
            workspace = str(getattr(self.settings, "workspace", ""))
            bounded_roots: tuple[str, ...] = (workspace,) if workspace else ()
            if (
                runtime_context is not None
                and runtime_context.session_id == session_id
                and runtime_context.run_id == run_id
                and runtime_context.fs_roots
            ):
                bounded_roots = tuple(str(root) for root in runtime_context.fs_roots)
            if tool_name == CONTROL_SKILL_INSTALL_TOOL and network_policy == "deny":
                source_error, normalized_arguments = (
                    self._normalize_control_skill_install_arguments(arguments)
                )
                if source_error is not None:
                    raise LeaseDenied(source_error)
                source = normalized_arguments["source"]
                bounded_roots = (source,)
            elif tool_name in CONTROL_PLANE_TOOL_NAMES:
                bounded_roots = ()
            lease = self._issue_echo_tool_lease(
                authority,
                product_id=product_id,
                session_id=session_id,
                owner_key_hash=owner,
                run_id=run_id,
                tool_name=tool_name,
                arguments=arguments,
                args_schema=args_hash,
                resource_scope=session_scope,
                fs_roots=bounded_roots,
                network_policy=network_policy,
                network_hosts=network_hosts,
                max_bytes=output_budget,
                max_duration_ms=int(timeout_seconds * 1000),
                ttl_ms=60_000,
                max_invocations=1,
                profile=profile,
            )
            if lease.run_id != run_id:
                raise LeaseDenied("lease run_id does not match current run")
            if lease.args_schema != args_hash:
                raise LeaseDenied("lease args_schema does not match current arguments")
            now_fn = getattr(authority, "_now", None)
            now = int(now_fn()) if callable(now_fn) else int(time.time() * 1000)
            authority.verify(
                lease,
                expected_owner=owner,
                expected_tool=tool_name,
                expected_scope=session_scope,
                now=now,
            )
            context = EchoToolExecutionContext(
                product_id=product_id,
                session_id=session_id,
                profile=profile,
                owner_key_hash=owner,
                run_id=run_id,
                tool_name=tool_name,
                args_hash=args_hash,
                resource_scope=session_scope,
                fs_roots=tuple(lease.fs_roots),
                network_policy=network_policy,
                network_hosts=network_hosts,
                max_bytes=output_budget,
                max_duration_ms=int(timeout_seconds * 1000),
            )
            signed_context = sign_tool_execution_context(
                context,
                lease=lease,
                authority=authority,
                now=now,
            )
            self._install_echo_tool_context_verifier(authority)
            return (
                None,
                cast("EchoToolExecutionContext", signed_context),
            )
        except LeaseDenied as exc:
            return f"Echo CapabilityLease denied tool execution: {type(exc).__name__}", None
        except Exception as exc:  # noqa: BLE001 - tool side effects must fail closed in Echo on-mode
            return (
                f"Echo CapabilityLease unavailable for tool execution: {type(exc).__name__}",
                None,
            )

    def _issue_echo_tool_lease(
        self,
        authority: Any,
        *,
        tool_name: str,
        arguments: dict[str, Any],
        profile: str,
        **kwargs: Any,
    ) -> Any:
        """Issue a lease; Orin handles also pre-sign the execution context.

        The in-process ``LeaseAuthority`` path is byte-identical to the
        pre-Orin call. The Orin adapter path rides ``issue_with_context``:
        orind signs the context server-side and evaluates the policy table
        against the turn's taint snapshot (context bits + argument overlap).
        """

        issue_with_context = getattr(authority, "issue_with_context", None)
        if not callable(issue_with_context):
            return authority.issue(tool_name=tool_name, **kwargs)
        from js.orin import taint as orin_taint

        snapshot = orin_taint.current_tool_taint_snapshot()
        if snapshot is not None:
            kwargs.setdefault("context_taint", snapshot.context_taint)
            kwargs.setdefault("clearance", snapshot.clearance)
            try:
                args_text = json.dumps(arguments, ensure_ascii=False, default=str)
            except (TypeError, ValueError):
                args_text = str(arguments)
            arg_bits = (
                orin_taint.arg_taint(args_text, list(snapshot.dirty_samples))
                if snapshot.dirty_samples
                else 0
            )
            kwargs.setdefault("arg_taint", arg_bits)
        return issue_with_context(profile=profile, tool_name=tool_name, **kwargs)

    def _normalize_control_skill_install_arguments(
        self,
        arguments: dict[str, Any],
    ) -> tuple[str | None, dict[str, Any]]:
        """Resolve an approved local source without expanding its filesystem authority."""
        source = arguments.get("source")
        if not isinstance(source, str) or not source.strip():
            return "source is required", arguments

        source = source.strip()
        if tool_requires_network(CONTROL_SKILL_INSTALL_TOOL, {"source": source}):
            from js.skills.manager import SkillManager

            if SkillManager._github_repo_name(source) is None:
                return (
                    "Invalid remote skill source: expected an exact "
                    "https://github.com/<owner>/<repo>.git URL",
                    arguments,
                )
            return None, {**arguments, "source": source}

        path = Path(source).expanduser()
        if ".." in path.parts:
            return "Invalid local skill source: path traversal is not allowed", arguments
        if not path.is_absolute():
            path = Path(self.settings.workspace) / path
        try:
            resolved = path.resolve(strict=True)
        except OSError:
            return "Invalid local skill source: path does not exist", arguments
        return None, {**arguments, "source": str(resolved)}

    def _echo_tool_execution_mode(self) -> str:
        return self.settings.echo_engine

    def _get_echo_tool_lease_authority(self) -> Any:
        """Return the lease authority handle (Orin adapter or in-process).

        ``orin_enabled=false`` (default) keeps the original in-process
        ``LeaseAuthority`` path byte-for-byte. When Orin is enabled the
        handle is an :class:`OrinLeaseClientAdapter`: it holds no MAC key
        and never subclasses ``LeaseAuthority`` (the handle check rejects
        subclasses). After enabling Orin the main process must never read
        the adopted ``echo_tool_lease.key`` again — that key lives only
        in the orind KeyBox.
        """

        authority = getattr(self, "_tool_lease_authority", None)
        if authority is not None:
            return authority
        orin_config = getattr(self.settings, "orin", None)
        if orin_config is not None and getattr(orin_config, "enabled", False):
            socket_path = orin_config.socket_path or (
                Path(self.settings.state_dir) / "orin" / "orind.sock"
            )
            authority = OrinLeaseClientAdapter(
                socket_path=Path(socket_path),
                state_dir=Path(self.settings.state_dir),
                fail_mode=str(getattr(orin_config, "fail_mode", "closed")),
                readonly_tool_classifier=self._orin_readonly_tool_classifier(),
                stage_b=bool(getattr(orin_config, "stage_b", False)),
            )
        else:
            key = _load_or_create_tool_lease_key(
                Path(self.settings.state_dir) / "echo_tool_lease.key"
            )
            authority = LeaseAuthority(
                mac_key=key,
                now_fn=lambda: int(time.time() * 1000),
                ledger_path=Path(self.settings.state_dir) / "echo_tool_lease.jsonl",
            )
        self._tool_lease_authority = authority
        return authority

    def _orin_readonly_tool_classifier(self) -> Any:
        """Classify tools as read-only for orind's readonly fail-mode."""

        registry = getattr(self, "registry", None)

        def classify(tool_name: str) -> bool:
            if registry is None:
                return False
            spec = registry.get(tool_name)
            return bool(spec is not None and spec.read_only)

        return classify

    def _desktop_cell_backend(self) -> Any:
        """Return the C2 Desktop Cell adapter only on the enforce product path."""

        from js.orin.stage_c import product_desktop_cell_required

        orin_config = getattr(self.settings, "orin", None)
        if not product_desktop_cell_required(orin_config):
            return None

        def backend(payload: dict[str, Any]) -> dict[str, Any]:
            from js.echo.capability import LeaseDenied
            from js.echo.turn_context import current_runtime_context
            from js.orin.client import OrinUnavailable

            context = current_runtime_context()
            if context is None:
                raise LeaseDenied("Desktop Cell requires an Echo runtime context")
            run_id = str(context.run_id or "")
            task_id = run_id if run_id.startswith("task:") else f"task:{run_id}"
            authority = self._get_echo_tool_lease_authority()
            factory = getattr(authority, "desktop_cell_backend", None)
            if factory is None:
                raise OrinUnavailable("Desktop Cell is unavailable on this authority")
            cell = factory(task_id)
            result: dict[str, Any] = cell(payload)
            return result

        return backend

    def _memory_cell_backend(self) -> Any:
        """Return the Memory Cell adapter only on the enforce product path."""

        from js.orin.stage_c import product_memory_cell_required

        orin_config = getattr(self.settings, "orin", None)
        if not product_memory_cell_required(orin_config):
            return None

        def backend() -> Any:
            from js.echo.capability import LeaseDenied
            from js.echo.turn_context import current_runtime_context
            from js.orin.client import OrinUnavailable

            context = current_runtime_context()
            if context is None:
                raise LeaseDenied("Memory Cell requires an Echo runtime context")
            run_id = str(context.run_id or "")
            task_id = run_id if run_id.startswith("task:") else f"task:{run_id}"
            authority = self._get_echo_tool_lease_authority()
            factory = getattr(authority, "memory_cell_backend", None)
            if factory is None:
                raise OrinUnavailable("Memory Cell is unavailable on this authority")
            return factory(task_id)

        return backend

    def _build_cell_backend(self) -> Any:
        """Return the Build Cell dispatch callable, or ``None`` when disabled.

        Enabled only when orin.enabled ∧ stage_b ∧ cell_build. The returned
        callable sends ``consume(mode="cell")`` through the SAME adapter
        connection; orind re-runs its policy table and proxies into the
        sandboxed cell subprocess. No license ever comes back here.
        """

        orin_config = getattr(self.settings, "orin", None)
        if not (
            getattr(orin_config, "enabled", False)
            and getattr(orin_config, "stage_b", False)
            and getattr(orin_config, "cell_build", False)
        ):
            return None

        def backend(payload: dict[str, Any]) -> dict[str, Any]:
            authority = self._get_echo_tool_lease_authority()
            runner = getattr(authority, "run_in_build_cell", None)
            if runner is None:
                from js.orin.client import OrinUnavailable

                raise OrinUnavailable("stage B is disabled on this authority")
            result: dict[str, Any] = runner(payload)
            return result

        return backend

    def _network_cell_backend(self) -> Any:
        """Return the narrow R0 Network Cell fetch adapter when enabled.

        Browser arguments stay data-only.  Orind reconstructs the signed
        EndpointHandle, strict CellPackage, StateWitness, and CommitPermit;
        this process receives only the bounded fetch result.  Cell failure is
        allowed to propagate so :class:`BrowserTool` can fail closed without
        falling back to in-process HTTP.
        """

        orin_config = getattr(self.settings, "orin", None)
        if not (
            getattr(orin_config, "enabled", False)
            and getattr(orin_config, "stage_b", False)
            and getattr(orin_config, "cell_net", False)
        ):
            return None

        def backend(payload: dict[str, Any]) -> dict[str, Any]:
            if set(payload) != {"tool", "url", "max_chars"}:
                raise ValueError("Network Cell fetch payload shape is invalid")
            if payload.get("tool") != "net.fetch":
                raise ValueError("Network Cell adapter accepts net.fetch only")
            authority = self._get_echo_tool_lease_authority()
            runner = getattr(authority, "run_in_cell", None)
            if runner is None:
                from js.orin.client import OrinUnavailable

                raise OrinUnavailable("WP8 Network Cell is disabled on this authority")
            result: dict[str, Any] = runner(
                "cell.net",
                payload,
            )
            return result

        return backend

    def _file_cell_backend(self) -> Any:
        """Return the strict File Cell adapter when all WP9 gates are enabled.

        The model-facing file tool contributes only one normalized relative
        path and the exact final text.  Task and DirectoryHandle selection
        remain inside the Orin authority; a missing binding or Cell failure
        propagates to :class:`FileTools`, which fails closed without a local
        filesystem fallback.
        """

        orin_config = getattr(self.settings, "orin", None)
        if not (
            getattr(orin_config, "enabled", False)
            and getattr(orin_config, "stage_b", False)
            and getattr(orin_config, "cell_file", False)
        ):
            return None

        def backend(change: dict[str, Any]) -> dict[str, Any]:
            if set(change) != {"path", "content"}:
                raise ValueError("File Cell change payload shape is invalid")
            if not isinstance(change.get("path"), str) or not isinstance(
                change.get("content"), str
            ):
                raise ValueError("File Cell path and content must be strings")
            authority = self._get_echo_tool_lease_authority()
            runner = getattr(authority, "run_file_change", None)
            if runner is None:
                from js.orin.client import OrinUnavailable

                raise OrinUnavailable("WP9 File Cell task binding is unavailable")
            result: dict[str, Any] = runner(change)
            return result

        return backend

    def _install_echo_tool_context_verifier(self, authority: Any) -> None:
        existing = getattr(self, "_echo_tool_verifier_installed", None)
        if existing is authority:
            return

        def _verify(context: EchoToolExecutionContext) -> str | None:
            now_fn = getattr(authority, "_now", None)
            now = int(now_fn()) if callable(now_fn) else int(time.time() * 1000)
            try:
                authority.consume_execution_context(context, now=now)
            except LeaseDenied as exc:
                return f"Echo execution context lease denied: {type(exc).__name__}"
            except Exception as exc:  # noqa: BLE001 - fail closed inside registry boundary
                return f"Echo execution context lease unavailable: {type(exc).__name__}"
            return None

        installer = getattr(self.registry, "install_echo_context_verifier", None)
        if installer is not None:
            installer(_verify)
        else:  # pragma: no cover - registry contract enforced by tests
            self.registry.echo_context_verifier = _verify  # type: ignore[misc]
        self._echo_tool_verifier_installed = authority

    def _current_echo_owner(self, owner_key_hash: str | None = None) -> str:
        if owner_key_hash:
            return owner_key_hash
        runtime_context = current_runtime_context()
        if runtime_context is not None and runtime_context.owner_key_hash:
            return runtime_context.owner_key_hash
        from js.echo.turn_context import current_owner_key_hash

        owner = current_owner_key_hash()
        return owner or "local"

    def _register_search_tool(self) -> None:
        """Register web search as a tool."""
        from js.tools.registry import ToolParam, ToolResult, ToolSpec

        async def search_handler(query: str, max_results: int = 5) -> ToolResult:
            from js.search.engines import validate_search_max_results, validate_search_query

            try:
                query = validate_search_query(query)
                max_results = validate_search_max_results(max_results)
            except ValueError as exc:
                return ToolResult(success=False, error=str(exc))
            results = await self.search.search(query, max_results)
            structured_results = [
                {
                    "title": result.title,
                    "url": result.url,
                    "snippet": result.snippet,
                    "source": result.source,
                }
                for result in results
            ]
            if not results:
                return ToolResult(
                    success=False,
                    error="Search returned no results",
                    metadata={"results": structured_results},
                )
            output = "\n\n".join(
                f"[{i + 1}] {r.title}\nURL: {r.url}\n{r.snippet}" for i, r in enumerate(results)
            )
            return ToolResult(
                success=True,
                output=output,
                metadata={"results": structured_results},
            )

        spec = ToolSpec(
            name="web_search",
            description="Search the web for current information. Returns top results with snippets.",
            parameters=[
                ToolParam("query", "string", "Search query"),
                ToolParam("max_results", "integer", "Max results (1-10)", required=False),
            ],
            read_only=True,
        )
        self.registry.register(spec, search_handler)
