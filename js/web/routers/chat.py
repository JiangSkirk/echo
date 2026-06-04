"""Chat API router."""

from __future__ import annotations

import asyncio
import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from js.utils.log import get_logger
from js.web.auth import require_auth_dep
from js.web.deps import get_agent, get_stats_store

logger = get_logger("js.web")

router = APIRouter(tags=["chat"])

# Rate limiting: max concurrent chat requests globally
_MAX_CONCURRENT_CHATS = 10
_chat_semaphore = asyncio.Semaphore(_MAX_CONCURRENT_CHATS)

# Per-session locks to prevent duplicate concurrent requests on the same session
_session_locks: dict[str, asyncio.Lock] = {}
_session_locks_lock = asyncio.Lock()

# Maximum request payload size (256 KiB)
_MAX_PAYLOAD_BYTES = 256 * 1024


async def _get_session_lock(session_id: str | None) -> asyncio.Lock:
    if session_id is None:
        return asyncio.Lock()  # ephemeral lock for requests without session
    async with _session_locks_lock:
        if session_id not in _session_locks:
            _session_locks[session_id] = asyncio.Lock()
        return _session_locks[session_id]


@router.post("/api/chat")
async def chat(
    payload: dict[str, Any],
    auth: dict[str, Any] = Depends(require_auth_dep),
) -> dict[str, Any]:
    # Size limit
    payload_size = len(json.dumps(payload).encode("utf-8"))
    if payload_size > _MAX_PAYLOAD_BYTES:
        raise HTTPException(413, f"Request payload too large: {payload_size} bytes (max {_MAX_PAYLOAD_BYTES})")

    agent = get_agent()
    message = payload.get("message", "")
    session_id = payload.get("session_id")
    model = payload.get("model")
    attachments = payload.get("attachments", [])

    # Concurrency limit: global + per-session
    async with _chat_semaphore:
        session_lock = await _get_session_lock(session_id)
        async with session_lock:
            try:
                from js.web.auth import _session_owner_hash, memory_owner
                owner = memory_owner(auth)
                token = _session_owner_hash.set(owner)
                try:
                    agent._session_owner = owner  # type: ignore[attr-defined]
                    state = await agent.run(message, session_id=session_id, model=model, attachments=attachments)
                finally:
                    _session_owner_hash.reset(token)
            except asyncio.CancelledError:
                raise
            except HTTPException:
                raise
            except Exception as e:
                logger.error(f"Chat error: {e}", exc_info=True)
                # Return a user-friendly message — never leak raw Python exceptions.
                # The full traceback is logged server-side for debugging.
                raise HTTPException(
                    500,
                    "The agent encountered an error processing your request. "
                    "Please try again or check the server logs for details.",
                ) from e

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
        provider = cfg.provider if cfg and hasattr(cfg, "provider") and isinstance(cfg.provider, str) else ""
        cached_tokens = getattr(state, "cached_tokens", 0)
        if not isinstance(cached_tokens, int):
            cached_tokens = 0
        stats_store.record(
            model=model_id,
            provider=provider,
            prompt_tokens=total_in,
            completion_tokens=total_out,
            cost=state.cost_estimate,
            cached_tokens=cached_tokens,
            session_id=getattr(state, "session_id", ""),
            run_id=getattr(state, "run_id", ""),
        )

    return {
        "response": assistant_msg,
        "session_id": state.session_id,
        "turns": state.turn_count,
        "tokens": state.total_tokens,
        "cost": round(state.cost_estimate, 6),
        "status": state.status,
    }
