"""Chat API router."""

from __future__ import annotations

import asyncio
import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from js.echo.ledger.service import EchoBlockedError, EchoUnavailableError
from js.echo.turn_runtime import run_echo_turn
from js.utils.log import get_logger
from js.web.auth import require_user_write, runtime_owner
from js.web.deps import coerce_body_session_id, get_agent, get_stats_store
from js.web.messages import humanize_error
from js.web.runtime_context import prepare_web_message, web_channel
from js.web.schemas import ChatRequest

logger = get_logger("js.web")

router = APIRouter(tags=["chat"])

# Concurrency floor: must be >= SLO concurrency_workers (50) so the 50×3
# probe is not throttled by an artificial semaphore.  Real rate limiting
# is the job of the reverse proxy / auth layer, not this in-process gate.
_MAX_CONCURRENT_CHATS = 64
_chat_semaphore = asyncio.Semaphore(_MAX_CONCURRENT_CHATS)

# Per-session locks to prevent duplicate concurrent requests on the same session
# Maximum request payload size (256 KiB)
_MAX_PAYLOAD_BYTES = 256 * 1024


def _bots_binding_id() -> str:
    try:
        from js.bots.persona import current_bot_binding

        binding = current_bot_binding()
    except Exception:
        return ""
    return binding.bot_id if binding is not None else ""


def _exclude_first_write(buckets: dict[str, Any]) -> bool:
    return (
        int(buckets.get("cache_write", 0) or 0) > 0 and int(buckets.get("cache_read", 0) or 0) == 0
    )


@router.post("/api/chat")
async def chat(
    payload: ChatRequest,
    auth: dict[str, Any] = Depends(require_user_write),
) -> dict[str, Any]:

    # Match typical client JSON spacing so the 256 KiB cap is on wire-sized bytes.
    payload_size = len(json.dumps(payload.model_dump(exclude_unset=True)).encode("utf-8"))
    if payload_size > _MAX_PAYLOAD_BYTES:
        raise HTTPException(
            413, f"Request payload too large: {payload_size} bytes (max {_MAX_PAYLOAD_BYTES})"
        )

    agent = get_agent()
    message = payload.message
    session_id = coerce_body_session_id(payload.session_id)
    model = payload.model
    attachments = list(payload.attachments)
    from js.web.session_locks import get_session_lock
    from js.web.uploads import validate_chat_attachments

    owner = runtime_owner(auth)
    validate_chat_attachments(
        workspace=agent.settings.workspace,
        attachments=attachments,
        owner_key_hash=owner,
        session_id=session_id,
    )

    # Concurrency limit: global + per-session
    async with _chat_semaphore:
        session_lock = await get_session_lock(session_id, owner)
        async with session_lock:
            try:
                state = await run_echo_turn(
                    agent,
                    prepare_web_message(agent.settings, message),
                    channel=web_channel(agent.settings, "api_chat"),
                    owner_key_hash=owner,
                    session_id=session_id,
                    model=model,
                    attachments=attachments,
                )
            except asyncio.CancelledError:
                raise
            except EchoBlockedError as exc:
                raise HTTPException(
                    400,
                    "Echo blocked sensitive input before model execution",
                ) from exc
            except EchoUnavailableError as exc:
                raise HTTPException(503, humanize_error(str(exc))) from exc
            except PermissionError as exc:
                raise HTTPException(400, humanize_error(str(exc))) from exc
            except HTTPException:
                raise
            except Exception as e:
                logger.error(f"Chat error: {e}", exc_info=True)
                # Return a user-friendly Chinese message — never leak raw Python
                # exceptions. The full traceback is logged server-side for debugging.
                raise HTTPException(500, humanize_error(str(e))) from e

    state_status = str(getattr(state, "status", "") or "")
    if state_status == "cancelled":
        raise HTTPException(409, humanize_error("Run cancelled by user request"))
    if state_status != "completed":
        raise HTTPException(
            500,
            humanize_error(str(getattr(state, "error_message", "") or "Agent run failed")),
        )

    assistant_msg = ""
    for msg in reversed(state.messages):
        if msg.role == "assistant" and isinstance(msg.content, str) and msg.content:
            assistant_msg = msg.content
            break

    # Record token usage
    stats_store = get_stats_store()
    total_in = state.total_tokens.get("input", 0)
    total_out = state.total_tokens.get("output", 0)
    if stats_store and total_in + total_out > 0:
        model_id = getattr(state, "model", None)
        if not isinstance(model_id, str):
            model_id = None
        model_id = model_id or model or "unknown"
        cfg = agent.router.get_model_config(model_id)
        provider = (
            cfg.provider
            if cfg and hasattr(cfg, "provider") and isinstance(cfg.provider, str)
            else ""
        )
        cached_tokens = getattr(state, "cached_tokens", 0)
        if not isinstance(cached_tokens, int):
            cached_tokens = 0
        buckets = getattr(state, "usage_buckets", {}) or {}
        try:
            stats_store.record(
                model=model_id,
                provider=provider,
                prompt_tokens=total_in,
                completion_tokens=total_out,
                cost=state.cost_estimate,
                cached_tokens=cached_tokens,
                session_id=getattr(state, "session_id", ""),
                run_id=getattr(state, "run_id", ""),
                uncached_input=int(buckets.get("uncached_input", max(total_in - cached_tokens, 0))),
                cache_read=int(buckets.get("cache_read", cached_tokens)),
                cache_write=int(buckets.get("cache_write", 0)),
                output=int(buckets.get("output", total_out)),
                reasoning=int(buckets.get("reasoning", 0)),
                input_total=int(buckets.get("input_total", total_in)),
                usage_source=str(getattr(state, "usage_source", "unavailable") or "unavailable"),
                prefix_id=str(getattr(state, "prefix_id", "") or ""),
                bot_id=_bots_binding_id(),
                exclude_from_hit_rate=_exclude_first_write(buckets),
            )
        except Exception as exc:
            logger.warning(
                "Token usage telemetry degraded after successful HTTP chat",
                error_type=type(exc).__name__,
                exc_info=True,
            )

    return {
        "response": assistant_msg,
        "session_id": state.session_id,
        "turns": state.turn_count,
        "tokens": state.total_tokens,
        "cost": round(state.cost_estimate, 6),
        "status": state.status,
    }
