"""Trusted adapters for side effects emitted inside an Echo runtime context."""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from js.connectors.contracts import (
    ConnectorExecutionRequestV1,
    ConnectorRunOutcomeV1,
    canonical_params_digest,
)
from js.connectors.manager import ConnectorManager
from js.echo.capability import is_lease_authority_handle
from js.echo.turn_context import (
    RuntimeContext,
    reset_current_owner_key_hash,
    reset_runtime_context,
    runtime_context_error,
    set_current_owner_key_hash,
    set_runtime_context,
)
from js.models.providers import ChatMessage, ChatResponse
from js.security.approvals import ApprovalQueue
from js.tools.registry import ToolResult
from js.utils.log import get_logger

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Awaitable, Callable

    from js.models.stream_events import StreamEvent

logger = get_logger("js.echo.effect_interpreter")


@dataclass(frozen=True)
class ModelEffect:
    """One authorized model invocation."""

    messages: tuple[ChatMessage, ...]
    model: str | None = None
    tools_schema: tuple[dict[str, Any], ...] = ()
    attachment_manifest: tuple[dict[str, Any], ...] = ()
    temperature: float = 0.7
    max_tokens: int | None = None
    before_model_attempt: Callable[[], None] | None = None
    completion_budget_callback: Callable[[int], None] | None = None


@dataclass(frozen=True)
class ToolEffect:
    """One authorized tool invocation with a stable serialized input."""

    tool_name: str
    arguments_json: str
    tool_call_id: str = ""
    user_input: str = ""
    allowed_tools: tuple[str, ...] = ()

    @classmethod
    def from_arguments(
        cls,
        tool_name: str,
        arguments: Mapping[str, Any],
        *,
        tool_call_id: str = "",
        user_input: str = "",
        allowed_tools: tuple[str, ...] = (),
    ) -> ToolEffect:
        return cls(
            tool_name=tool_name,
            arguments_json=json.dumps(
                dict(arguments),
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ),
            tool_call_id=tool_call_id,
            user_input=user_input,
            allowed_tools=allowed_tools,
        )


class EffectInterpreter:
    """The only adapter allowed to invoke model and tool side effects."""

    def __init__(
        self,
        agent: Any,
        *,
        runtime_authority: Any | None = None,
        connector_manager: ConnectorManager | None = None,
        dispatch_issuer: Any | None = None,
    ) -> None:
        self._agent = agent
        self._runtime_authority = runtime_authority
        self._connector_manager = connector_manager
        self._dispatch_issuer = dispatch_issuer

    async def execute_model(
        self,
        effect: ModelEffect,
        context: RuntimeContext,
    ) -> ChatResponse:
        self._validate_context(context, effect_kind="model")
        operation = self._begin_effect_operation(context, effect_kind="model")
        try:
            return await self._execute_model_admitted(effect, context)
        finally:
            self._finish_effect_operation(operation)

    async def _execute_model_admitted(
        self,
        effect: ModelEffect,
        context: RuntimeContext,
    ) -> ChatResponse:
        authorized_chat = getattr(self._agent, "authorized_model_chat", None)
        if not callable(authorized_chat):
            raise RuntimeError("Echo model effect requires authorized_model_chat")

        owner_token = set_current_owner_key_hash(context.owner_key_hash)
        context_token = set_runtime_context(context)
        try:
            response = await self._call_before_deadline(
                lambda: authorized_chat(
                    messages=list(effect.messages),
                    tenant_id=context.owner_key_hash,
                    run_id=context.run_id,
                    session_id=context.session_id or "",
                    model=effect.model,
                    tools=list(effect.tools_schema) or None,
                    attachment_manifest=effect.attachment_manifest,
                    temperature=effect.temperature,
                    max_tokens=effect.max_tokens,
                    budget_callback=effect.before_model_attempt,
                    completion_budget_callback=effect.completion_budget_callback,
                ),
                context,
            )
            if not isinstance(response, ChatResponse):
                raise TypeError("authorized model adapter returned an invalid response")
            return response
        finally:
            reset_runtime_context(context_token)
            reset_current_owner_key_hash(owner_token)

    async def execute_model_stream(
        self,
        effect: ModelEffect,
        context: RuntimeContext,
        *,
        before_model_call: Callable[..., Awaitable[Any]],
        after_model_call: Callable[..., Awaitable[None]],
    ) -> AsyncIterator[StreamEvent]:
        """Stream one model effect through the router under a bound runtime context.

        This is the sole call site allowed to invoke
        ``agent.router.chat_stream_events``. Context is restored in ``finally``
        even when the consumer stops early or the generator raises.
        """
        self._validate_context(context, effect_kind="model")
        operation = self._begin_effect_operation(context, effect_kind="model_stream")
        try:
            async for event in self._execute_model_stream_admitted(
                effect,
                context,
                before_model_call=before_model_call,
                after_model_call=after_model_call,
            ):
                yield event
        finally:
            self._finish_effect_operation(operation)

    async def _execute_model_stream_admitted(
        self,
        effect: ModelEffect,
        context: RuntimeContext,
        *,
        before_model_call: Callable[..., Awaitable[Any]],
        after_model_call: Callable[..., Awaitable[None]],
    ) -> AsyncIterator[StreamEvent]:
        router = getattr(self._agent, "router", None)
        chat_stream_events = getattr(router, "chat_stream_events", None)
        if not callable(chat_stream_events):
            raise RuntimeError("Echo model stream effect requires router.chat_stream_events")

        # The router must be gated by unforgeable single-use permits issued by
        # this runtime; a rebindable callback API is rejected outright.
        if getattr(router, "bind_echo_callbacks", None) is not None:
            raise RuntimeError(
                "router exposes a rebindable callback API; refusing to run the "
                "Echo model stream gate without unforgeable permits"
            )
        issuer = getattr(self._agent, "_model_permit_issuer", None)
        if issuer is None:
            # The verifier installed on the router is the same runtime-owned
            # issuer (the unforgeability lives in the HMAC key, not in where
            # the object is referenced from).  Accept it as the permit source.
            issuer = getattr(router, "_permit_verifier", None)
        if issuer is None or not callable(getattr(issuer, "issue", None)):
            raise RuntimeError("Echo model stream effect requires the runtime permit issuer")

        def _permit_grant(
            decision: Any,
            call_messages: list[ChatMessage],
            call_tools: Any,
        ) -> Any:
            return issuer.issue(
                provider_name=str(getattr(decision, "provider_name", "")),
                model=str(getattr(decision, "model", effect.model or "default")),
                messages=call_messages,
                tools=call_tools,
                owner_key_hash=context.owner_key_hash,
                session_id=context.session_id or "",
                run_id=context.run_id,
            )

        stream = chat_stream_events(
            messages=list(effect.messages),
            model=effect.model,
            tools=list(effect.tools_schema) or None,
            temperature=effect.temperature,
            max_tokens=effect.max_tokens,
            before_model_call=before_model_call,
            after_model_call=after_model_call,
            permit_grant=_permit_grant,
        )
        iterator = aiter(stream)
        try:
            while True:
                owner_token = set_current_owner_key_hash(context.owner_key_hash)
                context_token = set_runtime_context(context)
                try:
                    event = await self._call_before_deadline(
                        lambda: anext(iterator),
                        context,
                    )
                except StopAsyncIteration:
                    return
                finally:
                    reset_runtime_context(context_token)
                    reset_current_owner_key_hash(owner_token)
                yield event
        finally:
            # Close the provider stream directly.  Routing the close through
            # ``_call_before_deadline`` meant that on cancellation or an
            # exceeded deadline the guard raised before ``close`` ever ran,
            # leaking the provider connection.  Closing is best-effort: a
            # failure here must never mask the in-flight exception.  This also
            # runs when the consumer stops early and GeneratorExit is thrown in
            # at the ``yield`` above — awaiting in a generator's finally during
            # aclose() is legal as long as nothing is yielded.
            close = getattr(stream, "aclose", None)
            if callable(close):
                owner_token = set_current_owner_key_hash(context.owner_key_hash)
                context_token = set_runtime_context(context)
                try:
                    try:
                        await close()
                    except Exception:
                        logger.debug("Echo provider stream close failed", exc_info=True)
                finally:
                    reset_runtime_context(context_token)
                    reset_current_owner_key_hash(owner_token)

    async def execute_tool(
        self,
        effect: ToolEffect,
        context: RuntimeContext,
        progress_callback: Callable[[str, ToolResult], Awaitable[None]] | None = None,
    ) -> tuple[ChatMessage, ToolResult]:
        self._validate_context(context, effect_kind="tool")
        operation = self._begin_effect_operation(context, effect_kind="tool")
        try:
            return await self._execute_tool_admitted(effect, context, progress_callback)
        finally:
            self._finish_effect_operation(operation)

    async def _execute_tool_admitted(
        self,
        effect: ToolEffect,
        context: RuntimeContext,
        progress_callback: Callable[[str, ToolResult], Awaitable[None]] | None = None,
    ) -> tuple[ChatMessage, ToolResult]:
        if not effect.tool_name:
            raise ValueError("Echo tool effect requires a tool name")

        from js.echo.plan_commit.narrowing import deny_write_egress_if_blocked

        deny_write_egress_if_blocked(effect.tool_name)

        context_tools = set(context.capabilities)
        effect_tools = set(effect.allowed_tools)
        allowed_tools = context_tools & effect_tools
        if not allowed_tools or effect.tool_name not in allowed_tools:
            raise PermissionError("Echo tool effect is outside the runtime capability set")

        execute = getattr(self._agent, "_execute_tool_call", None)
        if not callable(execute):
            raise RuntimeError("Echo tool effect requires the leased tool executor")

        tool_call = {
            "id": effect.tool_call_id,
            "type": "function",
            "function": {
                "name": effect.tool_name,
                "arguments": effect.arguments_json,
            },
        }
        owner_token = set_current_owner_key_hash(context.owner_key_hash)
        context_token = set_runtime_context(context)
        try:
            result = await self._call_before_deadline(
                lambda: execute(
                    tool_call,
                    context.session_id or "default",
                    context.run_id,
                    effect.user_input,
                    progress_callback,
                    allowed_tools=allowed_tools,
                    owner_key_hash=context.owner_key_hash,
                ),
                context,
            )
            if (
                not isinstance(result, tuple)
                or len(result) != 2
                or not isinstance(result[0], ChatMessage)
                or not isinstance(result[1], ToolResult)
            ):
                raise TypeError("leased tool adapter returned an invalid result")
            return result
        finally:
            reset_runtime_context(context_token)
            reset_current_owner_key_hash(owner_token)

    async def execute_connector(
        self,
        request: ConnectorExecutionRequestV1,
        *,
        params: Mapping[str, Any],
        context: RuntimeContext,
    ) -> ConnectorRunOutcomeV1:
        """Execute one connector only under the owning signed Echo runtime."""

        self._validate_context(context, effect_kind="connector")
        operation = self._begin_effect_operation(context, effect_kind="connector")
        try:
            return await self._execute_connector_admitted(
                request,
                params=params,
                context=context,
                operation=operation,
            )
        finally:
            self._finish_effect_operation(operation)

    async def _execute_connector_admitted(
        self,
        request: ConnectorExecutionRequestV1,
        *,
        params: Mapping[str, Any],
        context: RuntimeContext,
        operation: Any = None,
    ) -> ConnectorRunOutcomeV1:
        if type(request) is not ConnectorExecutionRequestV1:
            raise TypeError("connector request must be exact ConnectorExecutionRequestV1")
        if not isinstance(params, Mapping) or isinstance(params, (str, bytes, bytearray)):
            raise TypeError("connector params must be a mapping")
        manager = self._connector_manager
        if type(manager) is not ConnectorManager:
            raise RuntimeError("Echo connector manager authority is unavailable")
        task_ref = context.task_ref
        if task_ref is None or task_ref != request.task_ref:
            raise PermissionError("connector task_ref does not match signed runtime context")
        if (
            request.task_ref.legacy_product_id != context.product_id
            or request.task_ref.owner != context.owner_key_hash
            or request.task_ref.session != context.session_id
            or request.task_ref.run != context.run_id
        ):
            raise PermissionError("connector task_ref exceeds signed runtime identity")

        actual_params = dict(params)
        if canonical_params_digest(actual_params) != request.params_digest:
            raise PermissionError("connector params do not match authority binding")
        grant = request.directory_grant
        if request.connection.ref.connector_type in {"local_import", "local_publish"}:
            if grant is None:
                raise PermissionError("local connector requires a directory grant")
            if grant.root == "/":
                raise PermissionError("connector directory grant cannot be filesystem root")
            grant_path = Path(grant.root)
            runtime_roots = tuple(Path(root).resolve(strict=False) for root in context.fs_roots)
            if not any(
                grant_path == root or grant_path.is_relative_to(root) for root in runtime_roots
            ):
                raise PermissionError("connector directory grant exceeds runtime filesystem roots")

        authority_getter = getattr(self._agent, "_get_echo_tool_lease_authority", None)
        if not callable(authority_getter):
            raise RuntimeError("Echo connector lease authority is unavailable")
        lease_authority = authority_getter()
        if not is_lease_authority_handle(lease_authority):
            raise RuntimeError("Echo connector lease authority is invalid")
        now_fn = getattr(lease_authority, "_now", None)
        if not callable(now_fn):
            raise RuntimeError("Echo connector lease authority clock is unavailable")
        now = int(now_fn())
        expected_tool = f"connector.{request.connection.ref.connector_type}.{request.operation}"
        expected_scope = f"connection:{request.connection.ref.connection_id}:{request.scope}"
        expected_fs_roots = () if grant is None else (grant.root,)
        approvals: ApprovalQueue | None = None
        approval_kwargs: dict[str, Any] | None = None
        if request.operation == "write":
            approvals = getattr(self._agent, "approvals", None)
            if type(approvals) is not ApprovalQueue or request.approval_id is None:
                raise PermissionError("connector write approval authority is unavailable")
            approval_arguments = {
                "authority_binding_hash": request.authority_binding_hash(),
                "scope": request.scope,
            }
            approval_kwargs = {
                "owner_key_hash": request.task_ref.owner,
                "session_id": request.task_ref.session,
                "run_id": request.task_ref.run,
                "tool_name": expected_tool,
                "arguments_hash": approvals.arguments_hash(approval_arguments),
                "require_manual": True,
            }
            approvals.validate_approved_binding(request.approval_id, **approval_kwargs)

        lease_authority.verify_bound(
            request.lease,
            expected_product_id=request.task_ref.legacy_product_id,
            expected_owner=request.task_ref.owner,
            expected_session=request.task_ref.session,
            expected_run=request.task_ref.run,
            expected_tool=expected_tool,
            expected_args_schema=request.authority_binding_hash(),
            expected_resource_scope=expected_scope,
            expected_fs_roots=expected_fs_roots,
            expected_network_policy="deny",
            expected_network_hosts=(),
            expected_max_bytes=10 * 1024 * 1024,
            expected_max_duration_ms=30_000,
            now=now,
            require_single_use=True,
        )

        # Task 5 inserts the durable connector outbox/claim at this exact point.
        # R4-A has no production I/O implementation, so consuming authority here
        # can only reach the fail-closed local declarations or the isolated Fake.
        if approvals is not None and approval_kwargs is not None:
            assert request.approval_id is not None
            approvals.consume_approved_binding(request.approval_id, **approval_kwargs)

        # Two-phase Echo anchor: record pending intent before consume.
        # First, check if Echo already has a finalized anchor for this lease
        # (detects valid-prefix rollback of the lease ledger alone).
        # Echo must be available -- fail closed if it is not.
        echo_service = getattr(self._agent, "_echo_safety_service", None)
        if echo_service is None:
            return ConnectorRunOutcomeV1(
                success=False,
                connector_type=request.connection.ref.connector_type,
                effects=(),
                artifact_refs=(),
                attention_items=(),
                receipt_id="",
                error_code="echo_safety_service_unavailable",
            )
        existing_anchor = echo_service.lookup_lease_consume_anchor(
            tenant_id=request.task_ref.owner,
            product_id=request.task_ref.legacy_product_id,
            session_id=request.task_ref.session,
            lease_id=request.lease.lease_id,
            nonce=request.lease.nonce,
        )
        if existing_anchor is not None:
            raise PermissionError("lease consume anchor detects valid-prefix rollback")
        echo_service.record_lease_consume_pending(
            tenant_id=request.task_ref.owner,
            product_id=request.task_ref.legacy_product_id,
            session_id=request.task_ref.session,
            run_id=request.task_ref.run,
            lease_id=request.lease.lease_id,
            nonce=request.lease.nonce,
        )

        consume_receipt = lease_authority.consume_bound(
            request.lease,
            expected_product_id=request.task_ref.legacy_product_id,
            expected_owner=request.task_ref.owner,
            expected_session=request.task_ref.session,
            expected_run=request.task_ref.run,
            expected_tool=expected_tool,
            expected_args_schema=request.authority_binding_hash(),
            expected_resource_scope=expected_scope,
            expected_fs_roots=expected_fs_roots,
            expected_network_policy="deny",
            expected_network_hosts=(),
            expected_max_bytes=10 * 1024 * 1024,
            expected_max_duration_ms=30_000,
            now=now,
            require_single_use=True,
        )

        # Phase 2: finalize the Echo anchor with the consume receipt hash
        echo_service.record_lease_consume_finalized(
            tenant_id=request.task_ref.owner,
            product_id=request.task_ref.legacy_product_id,
            session_id=request.task_ref.session,
            run_id=request.task_ref.run,
            lease_id=request.lease.lease_id,
            nonce=request.lease.nonce,
            consume_receipt_hash=consume_receipt.ledger_record_hash,
        )

        # Issue per-execution dispatch capability (R4A-I3)
        if self._dispatch_issuer is None:
            return ConnectorRunOutcomeV1(
                success=False,
                connector_type=request.connection.ref.connector_type,
                effects=(),
                artifact_refs=(),
                attention_items=(),
                receipt_id="",
                error_code="connector_runtime_authority_required",
            )
        context_fingerprint = ""
        if self._runtime_authority is not None:
            context_fingerprint = self._runtime_authority._context_fingerprint(context)
        capability = self._dispatch_issuer.issue(
            authority_hash=request.authority_binding_hash(),
            context_fingerprint=context_fingerprint,
            appshell_operation_id=(operation.operation_id if operation else None),
            approval_claim_receipt_hash=None,  # R4-B will bind approval receipt
            lease_consume_receipt_hash=consume_receipt.ledger_record_hash,
            connector_type=request.connection.ref.connector_type,
            operation=request.operation,
        )
        result = await manager._dispatch_authorized(
            request,
            params=actual_params,
            capability=capability,
        )
        error_code = None if result.success else (result.error or "connector_failed")
        return ConnectorRunOutcomeV1(
            success=result.success,
            connector_type=result.connector_type,
            effects=result.effects,
            artifact_refs=result.artifact_refs,
            attention_items=(),
            # Task 5 supplies the real EchoLedger receipt. Empty is deliberate
            # here and never misrepresented as a durable receipt identifier.
            receipt_id="",
            error_code=error_code,
        )

    @staticmethod
    async def _call_before_deadline(
        call: Callable[[], Awaitable[Any]],
        context: RuntimeContext,
    ) -> Any:
        error = runtime_context_error(context)
        if error is not None:
            if "cancelled" in error:
                raise asyncio.CancelledError("Echo runtime context is cancelled")
            if "deadline" in error:
                raise TimeoutError("Echo runtime context deadline exceeded")
            raise ValueError(error)

        assert context.deadline_ms is not None
        remaining = (context.deadline_ms - time.monotonic() * 1000) / 1000
        if remaining <= 0:
            raise TimeoutError("Echo runtime context deadline exceeded")

        timeout = asyncio.timeout(remaining)
        try:
            async with timeout:
                return await call()
        except TimeoutError as exc:
            if timeout.expired():
                raise TimeoutError("Echo runtime context deadline exceeded") from exc
            raise

    def _validate_context(
        self,
        context: RuntimeContext,
        *,
        effect_kind: str,
    ) -> None:
        authority = self._runtime_authority
        validate = getattr(authority, "validate_effect_context", None)
        if (
            authority is None
            or getattr(self._agent, "echo_runtime", None) is not authority
            or not callable(validate)
        ):
            raise RuntimeError("Echo effect runtime authority is unavailable")
        validate(context, effect_kind=effect_kind)
        error = runtime_context_error(context)
        if error is not None:
            raise ValueError(error)
        try:
            from js.utils.metrics import bind_effect_ids

            bind_effect_ids(
                kind=effect_kind,
                effect_id=context.run_id,
                outbox_id=context.session_id,
                lease_id=context.owner_key_hash,
            )
        except Exception:
            pass

    def _begin_effect_operation(
        self,
        context: RuntimeContext,
        *,
        effect_kind: str,
    ) -> Any | None:
        if context.appshell_epoch_binding is None:
            return None
        begin = getattr(self._runtime_authority, "begin_effect_operation", None)
        if not callable(begin):
            raise RuntimeError("AppShell effect operation authority is unavailable")
        return begin(context, effect_kind=effect_kind)

    def _finish_effect_operation(self, operation: Any | None) -> None:
        if operation is None:
            return
        finish = getattr(self._runtime_authority, "finish_effect_operation", None)
        if not callable(finish):
            raise RuntimeError("AppShell effect operation authority is unavailable")
        finish(operation)


__all__ = ["EffectInterpreter", "ModelEffect", "ToolEffect"]
