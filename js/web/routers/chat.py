"""Chat API router."""

from __future__ import annotations

import asyncio
import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect

from js.utils.log import get_logger
from js.web.auth import require_auth_dep
from js.web.deps import get_active_model, get_agent, get_stats_store

logger = get_logger("js.web")

router = APIRouter(tags=["chat"])


@router.post("/api/chat")
async def chat(
    payload: dict[str, Any],
    auth: dict[str, Any] = Depends(require_auth_dep),
) -> dict[str, Any]:
    agent = get_agent()
    message = payload.get("message", "")
    session_id = payload.get("session_id")
    model = payload.get("model")
    attachments = payload.get("attachments", [])

    try:
        state = await agent.run(message, session_id=session_id, model=model, attachments=attachments)
    except Exception as e:
        logger.error(f"Chat error: {e}", exc_info=True)
        raise HTTPException(500, f"Agent run failed: {e}") from e

    assistant_msg = ""
    for msg in reversed(state.messages):
        if msg.role == "assistant" and isinstance(msg.content, str) and msg.content:
            assistant_msg = msg.content
            break

    return {
        "response": assistant_msg,
        "session_id": state.session_id,
        "turns": state.turn_count,
        "tokens": state.total_tokens,
        "status": state.status,
    }


@router.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket,
    auth: dict[str, Any] = Depends(require_auth_dep),
) -> None:
    await websocket.accept()
    agent = get_agent()
    session_id: str | None = None
    max_msg_bytes = 1024 * 1024  # 1MB
    ping_interval = 30.0

    async def _receive_with_limit() -> dict[str, Any]:
        raw = await websocket.receive()
        if isinstance(raw, str):
            if len(raw.encode("utf-8")) > max_msg_bytes:
                raise ValueError("Message too large")
            return json.loads(raw)
        if isinstance(raw, bytes):
            if len(raw) > max_msg_bytes:
                raise ValueError("Message too large")
            return json.loads(raw.decode("utf-8"))
        # WebSocket text frame from Starlette
        data = raw.get("text") or raw.get("bytes", b"").decode("utf-8")
        if len(data.encode("utf-8")) > max_msg_bytes:
            raise ValueError("Message too large")
        result: dict[str, Any] = json.loads(data)
        return result

    try:
        while True:
            # Receive with timeout to allow periodic ping checks
            try:
                data = await asyncio.wait_for(_receive_with_limit(), timeout=ping_interval)
            except TimeoutError:
                try:
                    await websocket.send_json({"type": "ping"})
                except Exception:
                    break
                continue

            msg_type = data.get("type", "message")

            if msg_type == "message":
                user_msg = data.get("content", "")
                session_id = data.get("session_id") or session_id
                model = data.get("model") or get_active_model() or None
                attachments = data.get("attachments", [])

                await websocket.send_json({"type": "status", "content": "thinking..."})

                state = await agent.run(user_msg, session_id=session_id, model=model, attachments=attachments)
                session_id = state.session_id

                assistant_msg = ""
                for msg in reversed(state.messages):
                    if msg.role == "assistant" and isinstance(msg.content, str) and msg.content:
                        assistant_msg = msg.content
                        break

                # Record token usage
                stats_store = get_stats_store()
                if stats_store and state.total_tokens["input"] + state.total_tokens["output"] > 0:
                    stats_store.record(
                        model=model or state.messages[-1].role or "unknown",
                        provider="",
                        prompt_tokens=state.total_tokens["input"],
                        completion_tokens=state.total_tokens["output"],
                        cost=state.cost_estimate,
                        session_id=session_id,
                        run_id=state.run_id,
                    )

                await websocket.send_json(
                    {
                        "type": "response",
                        "content": assistant_msg,
                        "session_id": session_id,
                        "turns": state.turn_count,
                        "tokens": state.total_tokens,
                        "cost": round(state.cost_estimate, 6),
                        "status": state.status,
                        "compression": state.compression_stats,
                    }
                )

            elif msg_type == "stream":
                user_msg = data.get("content", "")
                session_id = data.get("session_id") or session_id
                model = data.get("model")
                attachments = data.get("attachments", [])

                await websocket.send_json({"type": "status", "content": "streaming..."})

                # Native token-level streaming for the final assistant response.
                # Tool-calling turns remain non-streaming (parsed atomically).
                streamed = False

                async def _send_token(token: str) -> None:
                    nonlocal streamed
                    streamed = True
                    await websocket.send_json({"type": "token", "content": token})

                state = await agent.run(
                    user_msg,
                    session_id=session_id,
                    model=model,
                    attachments=attachments,
                    stream_callback=_send_token,
                )
                session_id = state.session_id

                assistant_msg = ""
                for msg in reversed(state.messages):
                    if msg.role == "assistant" and isinstance(msg.content, str) and msg.content:
                        assistant_msg = msg.content
                        break

                # Fallback: if streaming never fired (all tool turns or provider
                # doesn't support streaming), send the full response in one go.
                if not streamed and assistant_msg:
                    await websocket.send_json({"type": "response", "content": assistant_msg})

                await websocket.send_json({
                    "type": "done",
                    "session_id": session_id,
                    "turns": state.turn_count,
                    "tokens": state.total_tokens,
                    "cost": round(state.cost_estimate, 6),
                    "status": state.status,
                    "compression": state.compression_stats,
                })

                # Store memories for stream path (same as run() path)
                try:
                    redacted_msg = agent.secrets.detect_and_redact(user_msg, "user_input")
                    await asyncio.to_thread(
                        agent.memory.store_working,
                        session_id=session_id,
                        key="user_input",
                        value=redacted_msg[:500],
                        category="interaction",
                        importance=5,
                    )
                    await asyncio.to_thread(
                        agent.memory.store_episode,
                        session_id=session_id,
                        summary=f"User: {redacted_msg[:80]}... → Assistant: {assistant_msg[:80]}...",
                        topics=list({
                            word.lower() for word in (redacted_msg + " " + assistant_msg).split()
                            if len(word) > 4 and word.isalpha()
                        })[:5],
                        importance=5,
                    )
                    # Persist conversation messages
                    await asyncio.to_thread(
                        agent.memory.store_messages,
                        session_id,
                        [
                            {"role": "user", "content": redacted_msg},
                            {"role": "assistant", "content": assistant_msg},
                        ],
                    )
                    agent._dream_scheduler.notify_activity(user_msg, assistant_msg)
                except Exception:
                    logger.debug("Stream memory storage failed", exc_info=True)

            elif msg_type == "ping":
                await websocket.send_json({"type": "pong"})

    except WebSocketDisconnect:
        logger.info("WebSocket disconnected")
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        try:
            await websocket.send_json({"type": "error", "content": str(e)})
        except Exception:
            logger.debug("Failed to send error to websocket", exc_info=True)
