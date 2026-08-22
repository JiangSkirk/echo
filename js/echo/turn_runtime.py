"""Authoritative Echo runtime boundary for every agent turn."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import secrets
import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol, cast

from js.appshell.principal import AppShellOperationV1, current_appshell_epoch_binding
from js.connectors.contracts import ConnectorExecutionRequestV1, ConnectorRunOutcomeV1
from js.connectors.manager import build_production_connector_manager
from js.echo.attachment_gate import AttachmentGateError, validate_chat_attachments
from js.echo.effect_interpreter import EffectInterpreter, ModelEffect, ToolEffect
from js.echo.private_handoff import PrivateHandoffVault
from js.echo.runtime import EchoPulseRuntime, get_pulse_runtime

if TYPE_CHECKING:
    from js.models.providers import ChatMessage, ChatResponse
    from js.models.stream_events import StreamEvent
    from js.tools.registry import ToolResult
from js.echo.mode_contract import AppMode, TaskRef, mode_from_product_id
from js.echo.turn_context import (
    RuntimeContext,
    current_owner_key_hash,
    current_runtime_context,
    reset_current_owner_key_hash,
    reset_runtime_context,
    runtime_channel_key,
    runtime_context_error,
    runtime_partition_key,
    set_current_owner_key_hash,
    set_runtime_context,
)

_WORKSPACE_HANDLE_DOMAIN: bytes = b"js-agent:workspace-handle:v1\0"


def _workspace_handle(workspace: Path) -> str:
    """Derive a deterministic opaque pseudo-name from a trusted resolved workspace path.

    The output is ``ws-<64 lowercase hex>`` and satisfies ``_WORKSPACE_RE``.
    This is a path pseudo-name, not a cryptographic commitment.
    """
    import unicodedata

    path_text = unicodedata.normalize("NFC", str(workspace))
    path_bytes = path_text.encode("utf-8")
    payload = _WORKSPACE_HANDLE_DOMAIN + len(path_bytes).to_bytes(4, "big") + path_bytes
    return "ws-" + hashlib.sha256(payload).hexdigest()


class EchoBackpressureError(RuntimeError):
    """Raised when the deterministic Echo kernel rejects a turn."""


class TurnLoop(Protocol):
    async def execute(self) -> Any: ...


TurnLoopFactory = Callable[[Any, "TurnRequest"], TurnLoop]
EventSink = Callable[[dict[str, Any]], Awaitable[None]]


@dataclass(frozen=True)
class TurnRequest:
    """Complete immutable input to one Echo runtime invocation."""

    message: str
    context: RuntimeContext
    model: str | None = None
    attachments: tuple[str, ...] = ()
    resume_state: Any | None = None
    stream_callback: Callable[[str], Awaitable[None]] | None = None
    progress_callback: Callable[[str, Any], Awaitable[None]] | None = None
    event_callback: EventSink | None = None
    disable_tools: bool = False


def _default_turn_loop_factory(agent: Any, request: TurnRequest) -> TurnLoop:
    from js.echo.turn_loop import EchoTurnLoop

    return EchoTurnLoop(
        agent,
        request.message,
        request.context.session_id or None,
        request.model,
        list(request.attachments),
        request.resume_state,
        request.stream_callback,
        request.progress_callback,
        request.event_callback,
        request.disable_tools,
    )


class EchoRuntime:
    """Single authority that admits, binds and executes agent turns."""

    def __init__(
        self,
        agent: Any,
        *,
        pulse_runtime: EchoPulseRuntime | None = None,
        turn_loop_factory: TurnLoopFactory | None = None,
    ) -> None:
        self._agent = agent
        product_id = str(getattr(getattr(agent, "settings", None), "product_id", "js-agent"))
        self._pulse = pulse_runtime or get_pulse_runtime(product_id)
        self._turn_loop_factory = turn_loop_factory or _default_turn_loop_factory
        # Create the connector artifact store from the agent's state_dir
        _state_dir = getattr(getattr(agent, "settings", None), "state_dir", None)
        _artifact_store = None
        if _state_dir is not None:
            from js.connectors.artifact_store import ConnectorArtifactStore

            _artifact_store = ConnectorArtifactStore(state_dir=Path(str(_state_dir)) / "echo")
        self._connector_manager = build_production_connector_manager(
            artifact_store=_artifact_store,
        )
        self._dispatch_issuer = self._connector_manager._create_dispatch_issuer()
        self.effects = EffectInterpreter(
            agent,
            runtime_authority=self,
            connector_manager=self._connector_manager,
            dispatch_issuer=self._dispatch_issuer,
        )
        self._admission_tasks: dict[asyncio.Task[Any], int] = {}
        self._issued_control_contexts: PrivateHandoffVault[str] = PrivateHandoffVault(
            max_entries=128,
            ttl_seconds=300.0,
        )
        self._context_mac_key = secrets.token_bytes(32)

    @property
    def active_turn_tasks(self) -> tuple[asyncio.Task[Any], ...]:
        """Return turns admitted before shutdown, including tasks still in setup."""
        return tuple(self._admission_tasks)

    def _registered_capabilities(self) -> set[str]:
        current_tools = {
            str(name)
            for name in (getattr(self._agent, "_current_allowed_tools", set()) or ())
            if str(name)
        }
        if not current_tools:
            registry = getattr(self._agent, "registry", None)
            list_tools = getattr(registry, "list_tools", None)
            if callable(list_tools):
                current_tools = {
                    tool.name
                    for tool in list_tools()
                    if isinstance(getattr(tool, "name", None), str) and tool.name
                }
        attributes = getattr(self._agent, "__dict__", {})
        if "_echo_capability_ceiling" in attributes:
            current_tools &= {
                str(name) for name in attributes["_echo_capability_ceiling"] if str(name)
            }
        return current_tools

    def _context_scope(
        self,
        owner_key_hash: str,
        session_id: str,
    ) -> tuple[str, Path, Path, tuple[Path, ...], tuple[str, ...]]:
        settings = self._agent.settings
        product_id = str(getattr(settings, "product_id", "js-agent"))
        workspace = Path(settings.workspace).expanduser().resolve()
        state_dir = Path(settings.state_dir).expanduser().resolve()
        agent_attributes = getattr(self._agent, "__dict__", {})
        fs_roots_resolver = agent_attributes.get("_echo_fs_roots_resolver")
        if callable(fs_roots_resolver):
            fs_roots = tuple(
                Path(root).expanduser().resolve()
                for root in fs_roots_resolver(owner_key_hash, session_id)
            )
        else:
            fs_roots = (workspace,)
        if not fs_roots:
            raise PermissionError("Echo context scope requires at least one filesystem root")
        security = getattr(settings, "security", None)
        network_allowlist = (
            tuple(str(host) for host in getattr(security, "network_allowlist", ()))
            if bool(getattr(security, "network_enabled", False))
            else ()
        )
        if "_echo_network_allowlist_ceiling" in agent_attributes:
            network_ceiling = {
                str(host) for host in agent_attributes["_echo_network_allowlist_ceiling"]
            }
            network_allowlist = tuple(host for host in network_allowlist if host in network_ceiling)
        return product_id, workspace, state_dir, fs_roots, network_allowlist

    @staticmethod
    def _context_fingerprint(context: RuntimeContext) -> str:
        task_ref_hash = ""
        if context.task_ref is not None:
            task_ref_hash = context.task_ref.canonical_hash()
        appshell_binding = context.appshell_epoch_binding
        appshell_binding_scope = (
            (
                appshell_binding.owner,
                appshell_binding.session,
                appshell_binding.active_mode,
                appshell_binding.workspace,
                appshell_binding.epoch,
            )
            if appshell_binding is not None
            else None
        )
        payload = (
            context.product_id,
            context.channel,
            context.owner_key_hash,
            context.session_id,
            context.run_id,
            context.role,
            context.profile,
            tuple(context.capabilities),
            str(context.workspace),
            str(context.state_dir),
            tuple(str(root) for root in context.fs_roots),
            tuple(context.network_allowlist),
            context.deadline_ms,
            id(context.cancel_token),
            context.control_scope,
            task_ref_hash,
            appshell_binding_scope,
        )
        return hashlib.sha256(repr(payload).encode("utf-8")).hexdigest()

    def _sign_context(self, context: RuntimeContext) -> RuntimeContext:
        context_error = runtime_context_error(context)
        if context_error is not None:
            raise PermissionError(f"Echo context scope is invalid: {context_error}")
        if context.task_ref is not None:
            tr = context.task_ref
            if tr.legacy_product_id != context.product_id:
                raise PermissionError("Echo context task_ref product_id mismatch")
            if tr.owner != context.owner_key_hash:
                raise PermissionError("Echo context task_ref owner mismatch")
            if tr.session != context.session_id:
                raise PermissionError("Echo context task_ref session mismatch")
            if tr.run != context.run_id:
                raise PermissionError("Echo context task_ref run mismatch")
            mode = mode_from_product_id(context.product_id)
            if mode is AppMode.PERSONAL and tr.workspace is not None:
                raise PermissionError("Echo context task_ref must not carry workspace in personal mode")
            if mode is AppMode.WORK and tr.workspace is None:
                raise PermissionError("Echo context task_ref must carry workspace in work mode")
        signature = hmac.new(
            self._context_mac_key,
            self._context_fingerprint(context).encode("ascii"),
            hashlib.sha256,
        ).hexdigest()
        return replace(context, authority_mac=signature)

    def derive_context(
        self,
        context: RuntimeContext,
        *,
        capabilities: tuple[str, ...],
    ) -> RuntimeContext:
        """Narrow and re-sign an already authorized runtime context."""
        self._validate_context_scope(context)
        if context.control_scope:
            raise PermissionError("Ephemeral Echo control contexts cannot be derived")
        requested = tuple(sorted({str(name) for name in capabilities if str(name)}))
        if not set(requested).issubset(set(context.capabilities)):
            raise PermissionError("Derived Echo context expands runtime capabilities")
        return self._sign_context(replace(context, capabilities=requested, authority_mac=""))

    def validate_effect_context(
        self,
        context: RuntimeContext,
        *,
        effect_kind: str,
    ) -> None:
        """Authenticate a context at the final model/tool adapter boundary."""
        if effect_kind not in {"model", "tool", "connector"}:
            raise PermissionError("Unknown Echo effect kind")
        self._validate_context_scope(
            context,
            consume_control_context=effect_kind == "tool",
        )

    def begin_effect_operation(
        self,
        context: RuntimeContext,
        *,
        effect_kind: str,
    ) -> AppShellOperationV1 | None:
        binding = context.appshell_epoch_binding
        if binding is None:
            return None
        store = getattr(self._agent, "_appshell_operation_store", None)
        begin = getattr(store, "begin_operation", None)
        if not callable(begin):
            raise PermissionError("AppShell effect operation authority is unavailable")
        return cast(
            "AppShellOperationV1",
            begin(binding, operation_kind=f"echo_{effect_kind}"),
        )

    def finish_effect_operation(self, operation: AppShellOperationV1 | None) -> None:
        if operation is None:
            return
        store = getattr(self._agent, "_appshell_operation_store", None)
        release = getattr(store, "release_operation", None)
        if not callable(release) or not release(operation):
            raise RuntimeError("AppShell effect operation release failed")

    def _validate_context_scope(
        self,
        context: RuntimeContext,
        *,
        consume_control_context: bool = False,
    ) -> None:
        context_error = runtime_context_error(context)
        if context_error is not None:
            raise PermissionError(f"Echo context scope is invalid: {context_error}")
        expected_mac = hmac.new(
            self._context_mac_key,
            self._context_fingerprint(context).encode("ascii"),
            hashlib.sha256,
        ).hexdigest()
        if not context.authority_mac or not hmac.compare_digest(
            context.authority_mac,
            expected_mac,
        ):
            raise PermissionError("Echo context scope authority signature is invalid")
        product_id, workspace, state_dir, fs_roots, network_allowlist = self._context_scope(
            context.owner_key_hash,
            context.session_id,
        )
        supplied_roots = tuple(Path(root).expanduser().resolve() for root in context.fs_roots)
        scope_matches = (
            context.product_id == product_id
            and Path(context.workspace).expanduser().resolve() == workspace
            and Path(context.state_dir).expanduser().resolve() == state_dir
            and supplied_roots == fs_roots
            and tuple(context.network_allowlist) == network_allowlist
        )
        if context.control_scope:
            if context.control_scope != "provider_discovery":
                raise PermissionError("Echo control context scope is invalid")
            supplied_fingerprint = self._context_fingerprint(context)
            expected_fingerprint = (
                self._issued_control_contexts.take(
                    context.run_id,
                    context.owner_key_hash,
                )
                if consume_control_context
                else self._issued_control_contexts.peek(
                    context.run_id,
                    context.owner_key_hash,
                )
            )
            if expected_fingerprint != supplied_fingerprint:
                raise PermissionError("Echo context scope does not match its owning agent")
        elif not scope_matches:
            raise PermissionError("Echo context scope does not match its owning agent")
        unknown = set(context.capabilities) - self._registered_capabilities()
        if unknown:
            raise PermissionError("Echo context scope capabilities exceed the owning agent")
        self._validate_appshell_epoch(context)

    def _validate_appshell_epoch(self, context: RuntimeContext) -> None:
        managed = bool(getattr(self._agent.settings, "_appshell_managed", False))
        binding = context.appshell_epoch_binding
        if not managed:
            if binding is not None:
                raise PermissionError("Standalone Echo context cannot carry AppShell authority")
            return
        if binding is None:
            raise PermissionError("AppShell-managed Echo effect requires a parent epoch binding")
        validator = getattr(self._agent, "_appshell_epoch_validator", None)
        if not callable(validator):
            raise PermissionError("AppShell epoch validator is unavailable")
        validator(binding)

    def build_context(
        self,
        *,
        channel: str,
        owner_key_hash: str,
        session_id: str = "",
        run_id: str | None = None,
        role: str | None = None,
        profile: str | None = None,
        capabilities: tuple[str, ...] | None = None,
        control_arguments: Mapping[str, Any] | None = None,
        cancel_token: Any | None = None,
    ) -> RuntimeContext:
        """Build a complete context for non-chat Echo effects."""
        settings = self._agent.settings
        current_tools = self._registered_capabilities()
        if capabilities is None:
            resolved_capabilities = tuple(sorted(current_tools))
        else:
            requested_capabilities = set(capabilities)
            unknown = requested_capabilities - current_tools
            if unknown:
                raise PermissionError(
                    "Echo context capabilities exceed the owning agent: "
                    + ", ".join(sorted(unknown))
                )
            resolved_capabilities = tuple(sorted(requested_capabilities))
        resolved_session_id = session_id or str(uuid.uuid4())
        product_id, workspace, state_dir, fs_roots, network_allowlist = self._context_scope(
            owner_key_hash,
            resolved_session_id,
        )
        agent_attributes = getattr(self._agent, "__dict__", {})
        if control_arguments is not None:
            if resolved_capabilities != ("control_provider_discover",):
                raise PermissionError(
                    "Dynamic Echo network scope is restricted to exact provider discovery"
                )
            from js.tools.registry import (
                network_authorization_error,
                required_network_hosts,
            )

            network_allowlist = required_network_hosts(
                resolved_capabilities[0],
                dict(control_arguments),
            )
            network_error = network_authorization_error(
                resolved_capabilities[0],
                dict(control_arguments),
                network_allowlist,
            )
            if network_error is not None:
                raise PermissionError(network_error)
            network_ceiling = agent_attributes.get("_echo_network_allowlist_ceiling")
            if network_ceiling is not None and not set(network_allowlist).issubset(
                {str(host) for host in network_ceiling}
            ):
                raise PermissionError("Echo control network scope exceeds its parent ceiling")
        resolved_role = role or str(getattr(self._agent, "_role", None) or "local-user")
        resolved_profile = profile or str(
            getattr(
                self._agent,
                "_work_profile",
                getattr(settings, "work_profile", "default"),
            )
        )
        role_ceiling = agent_attributes.get("_echo_role_ceiling")
        if role_ceiling is not None and resolved_role != role_ceiling:
            raise PermissionError("Echo context role exceeds the owning agent")
        profile_ceiling = agent_attributes.get("_echo_profile_ceiling")
        if profile_ceiling is not None and resolved_profile != profile_ceiling:
            raise PermissionError("Echo context profile exceeds the owning agent")

        deadline_ms = int(time.monotonic() * 1000) + int(
            getattr(getattr(settings, "echo_budget", None), "max_elapsed_ms", 900_000)
        )
        deadline_ceiling = agent_attributes.get("_echo_deadline_ceiling_ms")
        if isinstance(deadline_ceiling, int) and not isinstance(deadline_ceiling, bool):
            deadline_ms = min(deadline_ms, deadline_ceiling)
        inherited_cancel_token = agent_attributes.get("_echo_cancel_token")
        if callable(getattr(cancel_token, "is_set", None)):
            resolved_cancel_token = cancel_token
        elif callable(getattr(inherited_cancel_token, "is_set", None)):
            resolved_cancel_token = inherited_cancel_token
        else:
            resolved_cancel_token = asyncio.Event()
        cancel_token = resolved_cancel_token
        resolved_run_id = run_id or str(uuid.uuid4())
        mode = mode_from_product_id(product_id)
        ws_handle = None if mode is AppMode.PERSONAL else _workspace_handle(workspace)
        appshell_binding = current_appshell_epoch_binding()
        if bool(getattr(settings, "_appshell_managed", False)):
            if appshell_binding is None:
                raise PermissionError(
                    "AppShell-managed Echo context requires an admitted parent request"
                )
            if (
                appshell_binding.owner != owner_key_hash
                or appshell_binding.active_mode != mode.value
                or appshell_binding.workspace != ws_handle
            ):
                raise PermissionError(
                    "AppShell parent binding does not match the Echo product authority"
                )
        elif appshell_binding is not None:
            raise PermissionError("Standalone Echo context cannot inherit AppShell authority")
        task_ref = TaskRef(
            mode=mode,
            owner=owner_key_hash,
            session=resolved_session_id,
            run=resolved_run_id,
            workspace=ws_handle,
        )
        context = self._sign_context(
            RuntimeContext(
                product_id=product_id,
                channel=channel,
                owner_key_hash=owner_key_hash,
                session_id=resolved_session_id,
                run_id=resolved_run_id,
                role=resolved_role,
                profile=resolved_profile,
                capabilities=resolved_capabilities,
                workspace=workspace,
                state_dir=state_dir,
                fs_roots=fs_roots,
                network_allowlist=network_allowlist,
                deadline_ms=deadline_ms,
                cancel_token=cancel_token,
                control_scope=("provider_discovery" if control_arguments is not None else ""),
                task_ref=task_ref,
                appshell_epoch_binding=appshell_binding,
            )
        )
        if control_arguments is not None:
            reference = self._issued_control_contexts.stage(
                context.owner_key_hash,
                self._context_fingerprint(context),
                reference=context.run_id,
            )
            if not reference:
                raise EchoBackpressureError("Echo control context capacity is exhausted")
        return context

    async def execute_model_effect(
        self,
        effect: ModelEffect,
        context: RuntimeContext,
    ) -> ChatResponse:
        return await self.effects.execute_model(effect, context)

    async def execute_model_stream_effect(
        self,
        effect: ModelEffect,
        context: RuntimeContext,
        *,
        before_model_call: Callable[..., Awaitable[Any]],
        after_model_call: Callable[..., Awaitable[None]],
    ) -> AsyncIterator[StreamEvent]:
        async for event in self.effects.execute_model_stream(
            effect,
            context,
            before_model_call=before_model_call,
            after_model_call=after_model_call,
        ):
            yield event

    async def execute_tool_effect(
        self,
        effect: ToolEffect,
        context: RuntimeContext,
        progress_callback: Callable[[str, ToolResult], Awaitable[None]] | None = None,
    ) -> tuple[ChatMessage, ToolResult]:
        return await self.effects.execute_tool(effect, context, progress_callback)

    async def execute_connector_effect(
        self,
        request: ConnectorExecutionRequestV1,
        *,
        params: Mapping[str, Any],
        context: RuntimeContext,
    ) -> ConnectorRunOutcomeV1:
        return await self.effects.execute_connector(
            request,
            params=params,
            context=context,
        )

    async def run_turn(
        self,
        request: TurnRequest,
        emit: EventSink | None = None,
    ) -> Any:
        """Atomically reject shutdown races or track the admitted caller to completion."""
        if getattr(self._agent, "_shutdown_requested", False):
            from js.echo.ledger.service import EchoUnavailableError

            raise EchoUnavailableError("JSAgent is shutting down")
        task = asyncio.current_task()
        if task is None:
            raise RuntimeError("Echo runtime requires an active asyncio task")
        self._admission_tasks[task] = self._admission_tasks.get(task, 0) + 1
        try:
            return await self._run_turn_admitted(request, emit)
        finally:
            depth = self._admission_tasks.get(task, 0)
            if depth <= 1:
                self._admission_tasks.pop(task, None)
            else:
                self._admission_tasks[task] = depth - 1

    async def _run_turn_admitted(
        self,
        request: TurnRequest,
        emit: EventSink | None = None,
    ) -> Any:
        """Admit and execute one turn without calling ``JSAgent.run``."""
        context = request.context
        self._validate_context_scope(context)

        attachments = list(request.attachments)
        if attachments:
            validate_chat_attachments(
                workspace=context.workspace,
                attachments=attachments,
                owner_key_hash=context.owner_key_hash,
                session_id=context.session_id or None,
            )

        payload_hash = hashlib.sha256(request.message.encode("utf-8")).hexdigest()
        observation = self._pulse.observe(
            channel=runtime_channel_key(
                context.product_id,
                context.owner_key_hash,
                context.channel,
            ),
            request_id=context.run_id,
            payload_hash=payload_hash,
            now_ms=int(time.time() * 1000),
            owner_key_hash=context.owner_key_hash,
            session_id=context.session_id,
            source=context.channel,
        )
        if not observation.admitted:
            raise EchoBackpressureError("Echo runtime rejected the turn due to backpressure")

        effective_request = request
        if emit is not None and request.event_callback is None:
            effective_request = TurnRequest(
                message=request.message,
                context=request.context,
                model=request.model,
                attachments=request.attachments,
                resume_state=request.resume_state,
                stream_callback=request.stream_callback,
                progress_callback=request.progress_callback,
                event_callback=emit,
                disable_tools=request.disable_tools,
            )

        lane = getattr(self._agent, "_lane_executor", None)
        if lane is not None:
            return await lane.submit(
                session_id=runtime_partition_key(
                    context.product_id,
                    context.owner_key_hash,
                    context.session_id or "default",
                ),
                coro=lambda: self._execute_bound(effective_request),
                task_id=f"echo_{context.run_id}",
                name="echo_turn",
            )
        return await self._execute_bound(effective_request)

    async def _execute_bound(self, request: TurnRequest) -> Any:
        owner_token = set_current_owner_key_hash(request.context.owner_key_hash)
        context_token = set_runtime_context(request.context)
        summary_token = None
        push_summary = getattr(self._agent, "_push_summary_tenant", None)
        if push_summary is not None:
            summary_token = push_summary(request.context.owner_key_hash)
        try:
            loop = self._turn_loop_factory(self._agent, request)
            return await loop.execute()
        finally:
            if summary_token is not None:
                self._agent._reset_summary_tenant(summary_token)
            reset_runtime_context(context_token)
            reset_current_owner_key_hash(owner_token)

    async def run_agent_turn(
        self,
        message: str,
        *,
        channel: str,
        owner_key_hash: str | None = None,
        session_id: str | None = None,
        model: str | None = None,
        attachments: list[str] | None = None,
        _resume_state: Any | None = None,
        stream_callback: Callable[[str], Awaitable[None]] | None = None,
        progress_callback: Callable[[str, Any], Awaitable[None]] | None = None,
        event_callback: EventSink | None = None,
        disable_tools: bool = False,
        cancel_token: Any | None = None,
    ) -> Any:
        """Translate the historical public call shape into ``TurnRequest``."""
        parent_context = current_runtime_context()
        if (
            parent_context is not None
            and owner_key_hash
            and owner_key_hash != parent_context.owner_key_hash
        ):
            raise PermissionError("Nested Echo turn owner exceeds its parent context")
        owner = owner_key_hash or current_owner_key_hash("local-user") or "local-user"
        resume_session = str(getattr(_resume_state, "session_id", "") or "")
        resume_run = str(getattr(_resume_state, "run_id", "") or "")
        if session_id and resume_session and session_id != resume_session:
            raise ValueError("resume state session does not match the requested session")
        resolved_session = session_id or resume_session or str(uuid.uuid4())
        resolved_run = resume_run or str(uuid.uuid4())
        context = self.build_context(
            channel=channel,
            owner_key_hash=owner,
            session_id=resolved_session,
            run_id=resolved_run,
            cancel_token=cancel_token,
        )
        return await EchoRuntime.run_turn(
            self,
            TurnRequest(
                message=message,
                context=context,
                model=model,
                attachments=tuple(attachments or ()),
                resume_state=_resume_state,
                stream_callback=stream_callback,
                progress_callback=progress_callback,
                event_callback=event_callback,
                disable_tools=disable_tools,
            ),
        )


def authoritative_runtime(agent: Any) -> EchoRuntime:
    """Return the one initialized runtime or fail closed on replacement/shims."""
    runtime = getattr(agent, "echo_runtime", None)
    if type(runtime) is not EchoRuntime:
        from js.echo.ledger.service import EchoUnavailableError

        raise EchoUnavailableError("agent does not own the authoritative EchoRuntime instance")
    return runtime


async def run_echo_turn(
    agent: Any,
    message: str,
    *,
    channel: str,
    owner_key_hash: str | None = None,
    session_id: str | None = None,
    model: str | None = None,
    attachments: list[str] | None = None,
    **run_kwargs: Any,
) -> Any:
    """Run one turn through the Echo runtime boundary.

    This boundary centralizes owner/session propagation and attachment scope
    checks so web, WebSocket, and future direct callers share the same Echo
    safety preconditions before delegating to the agent loop.
    """
    if attachments is None:
        normalized_attachments: list[str] = []
    elif isinstance(attachments, list):
        normalized_attachments = attachments
    else:
        raise AttachmentGateError(400, "attachments must be a list")

    runtime = authoritative_runtime(agent)
    return await EchoRuntime.run_agent_turn(
        runtime,
        message,
        channel=channel,
        owner_key_hash=owner_key_hash,
        session_id=session_id,
        model=model,
        attachments=normalized_attachments,
        **run_kwargs,
    )


__all__ = [
    "EchoBackpressureError",
    "EchoRuntime",
    "ModelEffect",
    "RuntimeContext",
    "ToolEffect",
    "TurnRequest",
    "authoritative_runtime",
    "run_echo_turn",
]
