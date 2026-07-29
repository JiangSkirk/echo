"""Trusted adapters for side effects emitted inside an Echo runtime context."""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from js.echo.turn_context import (
    RuntimeContext,
    reset_current_owner_key_hash,
    reset_runtime_context,
    runtime_context_error,
    set_current_owner_key_hash,
    set_runtime_context,
)
from js.models.providers import ChatMessage, ChatResponse
from js.tools.registry import ToolResult

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Awaitable, Callable, Mapping

    from js.models.stream_events import StreamEvent


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

    def __init__(self, agent: Any, *, runtime_authority: Any | None = None) -> None:
        self._agent = agent
        self._runtime_authority = runtime_authority

    async def execute_model(
        self,
        effect: ModelEffect,
        context: RuntimeContext,
    ) -> ChatResponse:
        self._validate_context(context, effect_kind="model")
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
        primary_failure = False
        deadline_failure = False
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
        except BaseException as exc:
            primary_failure = True
            deadline_failure = isinstance(exc, TimeoutError) and "deadline" in str(exc)
            raise
        finally:
            close = getattr(stream, "aclose", None)
            if callable(close) and not deadline_failure:
                owner_token = set_current_owner_key_hash(context.owner_key_hash)
                context_token = set_runtime_context(context)
                try:
                    try:
                        await self._call_before_deadline(close, context)
                    except (TimeoutError, asyncio.CancelledError):
                        if not primary_failure:
                            raise
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
        if not effect.tool_name:
            raise ValueError("Echo tool effect requires a tool name")

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


__all__ = ["EffectInterpreter", "ModelEffect", "ToolEffect"]
