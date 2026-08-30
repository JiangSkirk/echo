"""Echo model-call authorize / finish gate used by the turn loop."""

from __future__ import annotations

import asyncio
import inspect
from typing import Any, cast

from js.echo.ledger.service import (
    EchoBlockedError,
    EchoTurnContext,
    EchoUnavailableError,
)
from js.echo.turn_context import current_runtime_context
from js.models.cascade import current_cascade_intent, decision_is_local
from js.models.providers import ChatMessage


def _enforce_cascade_model_policy(
    agent: Any,
    *,
    provider_id: str,
    model_id: str,
) -> None:
    """Fail closed if a heavy-path call would use a local model while cloud exists.

    This check is not a routing-table flag and cannot be disabled by
    ``model_cascade.enabled``.
    """

    intent = current_cascade_intent()
    if intent is None or not intent.forbid_local:
        return
    router = getattr(agent, "router", None)
    if router is None:
        return
    if decision_is_local(router, provider_id=provider_id, model_id=model_id):
        raise EchoBlockedError(
            "plan-commit and mid-turn dirty model calls cannot use a local model"
        )


def _model_terminal_status(error: BaseException | None) -> str:
    """Map user/task cancellation to the ledger's distinct terminal state."""
    return "cancelled" if isinstance(error, asyncio.CancelledError) else "failed"


def _authorize_echo_model_call(
    agent: Any,
    *,
    tenant_id: str,
    run_id: str,
    provider_id: str,
    model_id: str,
    messages: list[ChatMessage],
    tools_schema: list[dict[str, Any]] | None,
    session_id: str | None = None,
    product_id: str | None = None,
    attachments_manifest: tuple[dict[str, Any], ...] = (),
) -> EchoTurnContext:
    runtime_context = current_runtime_context()
    resolved_session_id = session_id or (
        runtime_context.session_id if runtime_context is not None else run_id
    )
    resolved_product_id = product_id or (
        runtime_context.product_id
        if runtime_context is not None
        else str(getattr(getattr(agent, "settings", None), "product_id", "js-agent"))
    )
    try:
        _enforce_cascade_model_policy(agent, provider_id=provider_id, model_id=model_id)
        return cast(
            "EchoTurnContext",
            agent.echo_safety_service.authorize_model_call(
                tenant_id=tenant_id,
                session_id=resolved_session_id,
                run_id=run_id,
                product_id=resolved_product_id,
                provider_id=provider_id,
                model_id=model_id,
                messages=messages,
                tools_schema=tools_schema,
                attachments_manifest=attachments_manifest,
            ),
        )
    except EchoBlockedError:
        raise
    except PermissionError as exc:
        raise EchoBlockedError(str(exc)) from exc
    except Exception as exc:
        raise EchoUnavailableError("Echo safety layer unavailable before model execution") from exc


def _finish_echo_model_call(
    agent: Any,
    context: EchoTurnContext | None,
    *,
    assistant_text: str,
    status: str,
    token_totals: dict[str, int],
    token_source: str = "unavailable",
) -> None:
    if context is None:
        raise EchoUnavailableError("Echo safety context missing during model finalization")
    try:
        agent.echo_safety_service.finish_chat_turn(
            context,
            assistant_text=assistant_text,
            status=status,
            token_totals=token_totals,
            token_source=token_source,
        )
    except Exception as exc:
        raise EchoUnavailableError("Echo safety layer failed to finalize model turn") from exc


def _router_supports_model_gate_callbacks(router: Any) -> bool:
    try:
        parameters = inspect.signature(router.chat).parameters
    except (AttributeError, TypeError, ValueError):
        return False
    return all(
        name in parameters
        for name in ("before_model_call", "after_model_call", "max_tokens", "permit_grant")
    )
