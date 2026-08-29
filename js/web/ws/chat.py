"""Chat WebSocket endpoint."""

from __future__ import annotations

import asyncio
import json
from contextlib import suppress
from typing import Any

from fastapi import HTTPException, WebSocket, WebSocketDisconnect
from pydantic import ValidationError

from js.echo.ledger.service import EchoBlockedError, EchoUnavailableError
from js.utils.log import get_logger
from js.web.auth import runtime_owner, websocket_presented_api_key
from js.web.deps import coerce_ws_session_id as _coerce_ws_session_id
from js.web.deps import get_active_model
from js.web.messages import humanize_error
from js.web.runtime_context import prepare_web_message, web_channel
from js.web.schemas import ChatWsFrame
from js.web.session_locks import get_session_lock
from js.web.uploads import validate_chat_attachments
from js.web.ws_inbox import BoundedWebSocketInbox, InboxOverloadError

logger = get_logger("js.web")


def _ws_frame_error(exc: ValidationError) -> str:
    for err in exc.errors():
        loc = err.get("loc") or ()
        if "attachments" in loc:
            return "attachments must be a list"
    return "Invalid WebSocket frame"


async def websocket_endpoint(websocket: WebSocket) -> None:
    # Authenticate WebSocket connection via X-API-Key header + Origin check.
    # Bootstrap anonymous access is REMOVED — all connections require a
    # valid key (or auth-optional mode with Origin whitelist).
    from js.exceptions import AuthRequiredError
    from js.web.auth import AuthManager, check_origin
    from js.web.server import (
        _assistant_text_from_state,
        _record_usage,
        get_agent,
        run_echo_turn,
        secrets,
    )

    # Origin check first — reject cross-origin WebSocket upgrades
    try:
        check_origin(websocket)
    except HTTPException as exc:
        await websocket.close(code=1008, reason=exc.detail)
        return

    # Browsers authenticate WebSockets with the same-site HttpOnly session
    # cookie; native clients may use the X-API-Key header. The legacy
    # ``x-api-key`` cookie is rejected. Query-string credentials are
    # unsupported because URLs leak into proxy/access logs and history.
    from js.web.auth import resolve_session_cookie

    agent = get_agent()
    settings = agent.settings
    ws_owner_hash: str | None = None
    auth_ctx: dict[str, Any] = {"name": "anonymous", "role": "guest"}
    ws_can_turn = False

    from js.appshell.principal import appshell_auth_context_from_scope

    managed, injected_auth = appshell_auth_context_from_scope(websocket.scope)
    if managed:
        if injected_auth is None:
            await websocket.close(code=1008, reason="Authentication failed")
            return
        auth_ctx = injected_auth
        ws_owner_hash = auth_ctx.get("key_hash")
        ws_can_turn = auth_ctx.get("role") != "guest"
    else:
        try:
            api_key = websocket_presented_api_key(websocket)
        except AuthRequiredError:
            await websocket.close(code=1008, reason="x-api-key cookie is no longer accepted")
            return
        session_token = (
            resolve_session_cookie(
                websocket.cookies,
                str(getattr(settings, "product_id", "js-agent") or "js-agent"),
            )
            or ""
        )
        if settings.security.api_key_required or api_key or session_token:
            # Standalone compatibility keeps the legacy child auth path.
            auth_mgr = AuthManager(settings.state_dir)
            try:
                if api_key:
                    auth_ctx = auth_mgr.verify(api_key)
                else:
                    auth_ctx = auth_mgr.verify_session(session_token)
                ws_owner_hash = auth_ctx.get("key_hash")
                ws_can_turn = auth_ctx.get("role") != "guest"
            except AuthRequiredError:
                await websocket.close(code=1008, reason="Authentication failed")
                return

    ws_owner_hash = ws_owner_hash or runtime_owner(auth_ctx)

    await websocket.accept()
    # The socket may carry many turns; cancellation and routing identity
    # are turn-owned, never connection-owned.
    session_id: str | None = f"ws-{secrets.token_hex(16)}"
    connection_closed = asyncio.Event()
    turn_task: asyncio.Task[Any] | None = None
    active_turn: dict[str, Any] | None = None
    max_msg_bytes = 1024 * 1024  # 1MB
    ping_interval = 30.0
    # Per-connection pending budget (independent of the 1MB single-frame cap).
    max_inbox_messages = 32
    max_inbox_bytes = 4 * 1024 * 1024

    def _bind_turn_cancel(
        target_session: str,
        cancel_event: asyncio.Event,
        *,
        run_id: str,
        request_id: str,
    ) -> None:
        bind = getattr(agent, "bind_cancel_token", None)
        if callable(bind):
            try:
                bind(
                    target_session,
                    cancel_event,
                    owner_key_hash=ws_owner_hash,
                    run_id=run_id,
                    request_id=request_id,
                )
            except TypeError:
                # Compatibility for narrow test/extension doubles. Real
                # JSAgent always binds client identity fail-closed.
                bind(
                    target_session,
                    cancel_event,
                    owner_key_hash=ws_owner_hash,
                    run_id=run_id,
                )
            return
        # Test doubles without bind helpers still expose the cancel map.
        from js.echo.turn_context import runtime_partition_key

        partition_key = runtime_partition_key(
            getattr(agent.settings, "product_id", "js-agent"),
            ws_owner_hash,
            target_session,
        )
        tokens = getattr(agent, "_cancel_tokens", None)
        if isinstance(tokens, dict):
            tokens[partition_key] = (
                cancel_event,
                run_id,
                ws_owner_hash,
                target_session,
            )

    def _unbind_turn_cancel(
        target_session: str | None,
        cancel_event: asyncio.Event | None,
    ) -> None:
        if not target_session or cancel_event is None:
            return
        unbind = getattr(agent, "unbind_cancel_token", None)
        if callable(unbind):
            unbind(
                target_session,
                cancel_event,
                owner_key_hash=ws_owner_hash,
            )
            return
        from js.echo.turn_context import runtime_partition_key

        partition_key = runtime_partition_key(
            getattr(agent.settings, "product_id", "js-agent"),
            ws_owner_hash,
            target_session,
        )
        tokens = getattr(agent, "_cancel_tokens", None)
        if isinstance(tokens, dict):
            entry = tokens.get(partition_key)
            if entry is not None and entry[0] is cancel_event:
                tokens.pop(partition_key, None)

    def _cancel_active_turn(expected: dict[str, Any] | None = None) -> bool:
        turn = active_turn
        if turn is None:
            return False
        if expected is not None and any(
            expected.get(key) != turn.get(key)
            for key in ("request_id", "turn_id", "run_id", "session_id")
        ):
            return False
        cancel_event = turn["cancel_event"]
        cancel_event.set()
        cancelled = False
        target_session = turn["session_id"]
        if target_session:
            try:
                try:
                    cancelled = bool(
                        agent.request_cancel(
                            target_session,
                            owner_key_hash=ws_owner_hash,
                            expected_run_id=turn["run_id"],
                            expected_request_id=turn["request_id"],
                        )
                    )
                except TypeError:
                    if expected is not None:
                        raise
                    cancelled = bool(
                        agent.request_cancel(
                            target_session,
                            owner_key_hash=ws_owner_hash,
                        )
                    )
            except (PermissionError, RuntimeError):
                logger.warning(
                    "Failed to cancel WebSocket turn via request_cancel",
                    exc_info=True,
                )
        if not cancelled:
            task = turn_task
            if task is not None and not task.done():
                task.cancel()
        return True

    def _cancel_connection_work() -> None:
        """Cancel the active turn when the socket itself is lost."""
        connection_closed.set()
        _cancel_active_turn()

    def _adopt_session_id(next_session: str) -> None:
        nonlocal session_id
        session_id = next_session

    async def _run_ws_turn(
        agent: Any,
        message: str,
        *,
        cancel_event: asyncio.Event | None = None,
        **turn_kwargs: Any,
    ) -> Any:
        """Run one Echo turn as a cancellable child task.

        The turn must be a distinct Task so ``turn_task.cancel()`` (used when
        ``request_cancel`` returns False) does not cancel the WebSocket
        endpoint itself — that would deadlock Starlette TestClient drains.
        """
        nonlocal turn_task

        async def _execute() -> Any:
            effective_cancel = cancel_event or asyncio.Event()
            return await run_echo_turn(
                agent,
                message,
                cancel_token=effective_cancel,
                **turn_kwargs,
            )

        turn_task = asyncio.create_task(_execute(), name="echo-ws-turn")
        try:
            return await turn_task
        finally:
            turn_task = None

    seen_request_ids: set[str] = set()

    def _start_turn(payload: dict[str, Any], target_session: str) -> dict[str, Any]:
        nonlocal active_turn
        raw_request_id = payload.get("request_id")
        request_id = (
            raw_request_id.strip()
            if isinstance(raw_request_id, str) and raw_request_id.strip()
            else f"request-{secrets.token_hex(16)}"
        )
        if len(request_id) > 128:
            raise ValueError("invalid request_id")
        if request_id in seen_request_ids:
            raise ValueError("duplicate request_id")
        seen_request_ids.add(request_id)
        if len(seen_request_ids) > 512:
            seen_request_ids.pop()
        raw_turn_id = payload.get("turn_id")
        turn_id = (
            raw_turn_id.strip()
            if isinstance(raw_turn_id, str) and raw_turn_id.strip()
            else f"turn-{secrets.token_hex(16)}"
        )
        if len(turn_id) > 128:
            raise ValueError("invalid turn_id")
        turn: dict[str, Any] = {
            "request_id": request_id,
            "turn_id": turn_id,
            "run_id": f"ws-run-{secrets.token_hex(16)}",
            "session_id": target_session,
            "cancel_event": asyncio.Event(),
        }
        active_turn = turn
        _bind_turn_cancel(
            target_session,
            turn["cancel_event"],
            run_id=turn["run_id"],
            request_id=request_id,
        )
        return turn

    def _turn_frame(turn: dict[str, Any], **payload: Any) -> dict[str, Any]:
        return {
            **payload,
            "request_id": turn["request_id"],
            "turn_id": turn["turn_id"],
            "run_id": turn["run_id"],
            "session_id": turn["session_id"],
        }

    def _finish_turn(turn: dict[str, Any]) -> None:
        nonlocal active_turn
        _unbind_turn_cancel(turn["session_id"], turn["cancel_event"])
        if active_turn is turn:
            active_turn = None

    async def _receive_with_limit() -> tuple[dict[str, Any], int]:
        raw = await websocket.receive()
        if isinstance(raw, str):
            nbytes = len(raw.encode("utf-8"))
            if nbytes > max_msg_bytes:
                raise ValueError("Message too large")
            return json.loads(raw), nbytes
        if isinstance(raw, bytes):
            nbytes = len(raw)
            if nbytes > max_msg_bytes:
                raise ValueError("Message too large")
            return json.loads(raw.decode("utf-8")), nbytes
        # WebSocket text frame from Starlette
        if raw.get("type") == "websocket.disconnect":
            raise WebSocketDisconnect(
                code=raw.get("code", 1000),
                reason=raw.get("reason"),
            )
        data = raw.get("text") or raw.get("bytes", b"").decode("utf-8")
        nbytes = len(data.encode("utf-8")) if isinstance(data, str) else len(data)
        if nbytes > max_msg_bytes:
            raise ValueError("Message too large")
        result: dict[str, Any] = json.loads(data)
        return result, nbytes

    inbox = BoundedWebSocketInbox(
        max_messages=max_inbox_messages,
        max_bytes=max_inbox_bytes,
    )

    async def _read_websocket() -> None:
        """Own all receive calls so disconnects can cancel an in-flight turn."""
        try:
            while True:
                payload, nbytes = await _receive_with_limit()
                if not isinstance(payload, dict):
                    raise ValueError("WebSocket frame must be an object")
                if payload.get("type") == "cancel":
                    cancelled = _cancel_active_turn(payload)
                    await websocket.send_json(
                        {
                            "type": "cancelled" if cancelled else "cancel_rejected",
                            "request_id": payload.get("request_id"),
                            "turn_id": payload.get("turn_id"),
                            "run_id": payload.get("run_id"),
                            "session_id": payload.get("session_id"),
                        }
                    )
                    continue
                try:
                    await inbox.put_data(payload, nbytes=nbytes)
                except InboxOverloadError as overload:
                    _cancel_connection_work()
                    await inbox.put_control(overload)
                    try:
                        await websocket.close(
                            code=1008,
                            reason="WebSocket inbox overload policy",
                        )
                    except Exception:
                        logger.warning(
                            "Failed to close overloaded WebSocket",
                            exc_info=True,
                        )
                    return
        except BaseException as exc:  # noqa: BLE001 - forwarded to the endpoint task
            # Any reader failure (disconnect, decode, etc.) closes the connection
            # and cancels in-flight work before the control signal is delivered.
            _cancel_connection_work()
            await inbox.put_control(exc)

    reader_task = asyncio.create_task(_read_websocket(), name="echo-ws-reader")

    try:
        while True:
            # Receive with timeout to allow periodic ping checks
            try:
                incoming = await asyncio.wait_for(inbox.get(), timeout=ping_interval)
            except TimeoutError:
                try:
                    await websocket.send_json({"type": "ping"})
                except Exception:
                    break
                continue
            if isinstance(incoming, InboxOverloadError):
                raise incoming
            if isinstance(incoming, BaseException):
                raise incoming
            data = incoming
            if not isinstance(data, dict):
                await websocket.send_json({"type": "error", "content": "Invalid WebSocket frame"})
                continue
            try:
                data = ChatWsFrame.model_validate(data).model_dump()
            except ValidationError as exc:
                await websocket.send_json(
                    {
                        "type": "error",
                        "content": _ws_frame_error(exc),
                        "session_id": incoming.get("session_id")
                        if isinstance(incoming, dict)
                        else None,
                    }
                )
                continue

            msg_type = data.get("type", "message")

            if msg_type in ("message", "stream") and not ws_can_turn:
                await websocket.send_json(
                    {
                        "type": "error",
                        "content": ("Guest role is read-only; authenticate to send chat turns"),
                        "session_id": session_id,
                    }
                )
                continue

            if msg_type == "message":
                user_msg = data.get("content", "")
                if not isinstance(user_msg, str):
                    await websocket.send_json(
                        {
                            "type": "error",
                            "content": "content must be a string",
                            "session_id": session_id,
                        }
                    )
                    continue
                try:
                    _adopt_session_id(
                        _coerce_ws_session_id(data.get("session_id"), current=session_id)
                    )
                except ValueError as exc:
                    await websocket.send_json(
                        {
                            "type": "error",
                            "content": str(exc),
                        }
                    )
                    await websocket.close(code=1008, reason="invalid session_id")
                    return
                assert session_id is not None
                try:
                    turn = _start_turn(data, session_id)
                except ValueError as exc:
                    await websocket.send_json(
                        {"type": "error", "content": str(exc), "session_id": session_id}
                    )
                    continue
                model = data.get("model") or get_active_model() or None
                attachments = data.get("attachments", [])

                if connection_closed.is_set():
                    raise WebSocketDisconnect(code=1001, reason="client disconnected")

                try:
                    validate_chat_attachments(
                        workspace=agent.settings.workspace,
                        attachments=attachments,
                        owner_key_hash=ws_owner_hash,
                        session_id=session_id,
                    )
                except HTTPException as exc:
                    await websocket.send_json(
                        _turn_frame(
                            turn,
                            type="error",
                            terminal=True,
                            content=str(exc.detail),
                        )
                    )
                    _finish_turn(turn)
                    continue

                await websocket.send_json(_turn_frame(turn, type="status", content="thinking..."))

                # Progress callback: notify frontend of each tool execution
                async def _progress(
                    tool_name: str,
                    result: Any,
                    _turn: dict[str, Any] = turn,
                ) -> None:
                    try:
                        output_preview = (
                            result.output[:200] if getattr(result, "output", None) else ""
                        )
                        await websocket.send_json(
                            _turn_frame(
                                _turn,
                                type="progress",
                                tool=tool_name,
                                success=getattr(result, "success", False),
                                preview=output_preview,
                            )
                        )
                    except Exception:
                        pass

                if connection_closed.is_set():
                    raise WebSocketDisconnect(code=1001, reason="client disconnected")

                session_lock = await get_session_lock(session_id, ws_owner_hash)
                async with session_lock:
                    if connection_closed.is_set():
                        raise WebSocketDisconnect(code=1001, reason="client disconnected")
                    try:
                        state = await _run_ws_turn(
                            agent,
                            prepare_web_message(settings, user_msg),
                            cancel_event=turn["cancel_event"],
                            channel=web_channel(settings, "ws_message"),
                            owner_key_hash=ws_owner_hash,
                            session_id=session_id,
                            model=model,
                            attachments=attachments,
                            progress_callback=_progress,
                        )
                    except asyncio.CancelledError:
                        if connection_closed.is_set():
                            raise WebSocketDisconnect(
                                code=1001, reason="client disconnected"
                            ) from None
                        if turn["cancel_event"].is_set():
                            await websocket.send_json(
                                _turn_frame(
                                    turn,
                                    type="cancelled",
                                    terminal=True,
                                    content="Run cancelled",
                                )
                            )
                            _finish_turn(turn)
                            continue
                        raise
                    except EchoBlockedError:
                        await websocket.send_json(
                            _turn_frame(
                                turn,
                                type="error",
                                terminal=True,
                                content=("Echo blocked sensitive input before model execution"),
                            )
                        )
                        _finish_turn(turn)
                        continue
                    except EchoUnavailableError:
                        await websocket.send_json(
                            _turn_frame(
                                turn,
                                type="error",
                                terminal=True,
                                content=(
                                    "Echo safety layer is unavailable; request was not executed"
                                ),
                            )
                        )
                        _finish_turn(turn)
                        continue
                    except PermissionError as exc:
                        await websocket.send_json(
                            _turn_frame(
                                turn,
                                type="error",
                                terminal=True,
                                content=humanize_error(str(exc)),
                            )
                        )
                        _finish_turn(turn)
                        continue
                session_id = state.session_id
                turn["session_id"] = session_id

                if connection_closed.is_set():
                    raise WebSocketDisconnect(code=1001, reason="client disconnected")

                # Record token usage
                _record_usage(state, explicit_model=model)
                assistant_msg = _assistant_text_from_state(state)

                if state.status != "completed":
                    await websocket.send_json(
                        _turn_frame(
                            turn,
                            type="error",
                            terminal=True,
                            content=humanize_error(state.error_message),
                            turns=state.turn_count,
                            tokens=state.total_tokens,
                            cost=round(state.cost_estimate, 6),
                            model=state.model or model or "unknown",
                        )
                    )
                else:
                    await websocket.send_json(
                        _turn_frame(
                            turn,
                            type="response",
                            terminal=True,
                            content=assistant_msg,
                            turns=state.turn_count,
                            tokens=state.total_tokens,
                            cost=round(state.cost_estimate, 6),
                            status=state.status,
                            compression=state.compression_stats,
                            model=state.model or model or "unknown",
                        )
                    )
                _finish_turn(turn)

            elif msg_type == "stream":
                user_msg = data.get("content", "")
                if not isinstance(user_msg, str):
                    await websocket.send_json(
                        {
                            "type": "error",
                            "content": "content must be a string",
                            "session_id": session_id,
                        }
                    )
                    continue
                try:
                    _adopt_session_id(
                        _coerce_ws_session_id(data.get("session_id"), current=session_id)
                    )
                except ValueError as exc:
                    await websocket.send_json(
                        {
                            "type": "error",
                            "content": str(exc),
                        }
                    )
                    await websocket.close(code=1008, reason="invalid session_id")
                    return
                assert session_id is not None
                try:
                    turn = _start_turn(data, session_id)
                except ValueError as exc:
                    await websocket.send_json(
                        {"type": "error", "content": str(exc), "session_id": session_id}
                    )
                    continue
                model = data.get("model")
                attachments = data.get("attachments", [])
                raw_enable_tools = data.get("enable_tools", True)
                if isinstance(raw_enable_tools, bool):
                    enable_tools = raw_enable_tools
                elif isinstance(raw_enable_tools, str):
                    enable_tools = raw_enable_tools.strip().lower() in ("true", "1", "yes")
                elif isinstance(raw_enable_tools, (int, float)):
                    enable_tools = bool(raw_enable_tools)
                else:
                    enable_tools = True

                if connection_closed.is_set():
                    raise WebSocketDisconnect(code=1001, reason="client disconnected")

                try:
                    validate_chat_attachments(
                        workspace=agent.settings.workspace,
                        attachments=attachments,
                        owner_key_hash=ws_owner_hash,
                        session_id=session_id,
                    )
                except HTTPException as exc:
                    await websocket.send_json(
                        _turn_frame(
                            turn,
                            type="error",
                            terminal=True,
                            content=str(exc.detail),
                        )
                    )
                    _finish_turn(turn)
                    continue

                await websocket.send_json(_turn_frame(turn, type="status", content="streaming..."))

                # Native token-level streaming for the final assistant response.
                # Tool-calling turns remain non-streaming (parsed atomically).
                streamed = False

                async def _send_token(
                    token: str,
                    _turn: dict[str, Any] = turn,
                ) -> None:
                    nonlocal streamed
                    streamed = True
                    await websocket.send_json(
                        _turn_frame(
                            _turn,
                            type="token",
                            content=token,
                            provisional=True,
                        )
                    )

                async def _send_event(
                    payload: dict[str, Any],
                    _turn: dict[str, Any] = turn,
                ) -> None:
                    """PR-4.3 side-channel: structured StreamEvent → WS frame.

                    Maps:
                      thinking_delta  → {type:"thinking", content:<text>}
                      tool_call_delta → {type:"tool_call", tool_call:<dict>}
                      usage           → {type:"usage", usage:<dict>}
                      error           → {type:"stream_diagnostic", content:<str>}
                    Empty/unknown kinds are dropped silently so the
                    legacy frontend ({type:"token"}) keeps working.
                    """
                    kind = payload.get("kind")
                    try:
                        if kind == "thinking_delta":
                            text = payload.get("text") or ""
                            if text:
                                await websocket.send_json(
                                    _turn_frame(_turn, type="thinking", content=text)
                                )
                        elif kind == "tool_call_delta":
                            tc = payload.get("tool_call") or {}
                            if tc:
                                await websocket.send_json(
                                    _turn_frame(_turn, type="tool_call", tool_call=tc)
                                )
                        elif kind == "usage":
                            usage = payload.get("usage") or {}
                            if usage:
                                await websocket.send_json(
                                    _turn_frame(_turn, type="usage", usage=usage)
                                )
                        elif kind == "error":
                            err = payload.get("error") or ""
                            if err:
                                await websocket.send_json(
                                    _turn_frame(
                                        _turn,
                                        type="stream_diagnostic",
                                        content=humanize_error(str(err)),
                                    )
                                )
                    except Exception:
                        # Never let the side-channel kill the main turn.
                        logger.warning("WebSocket event-channel send failed", exc_info=True)

                if connection_closed.is_set():
                    raise WebSocketDisconnect(code=1001, reason="client disconnected")

                session_lock = await get_session_lock(session_id, ws_owner_hash)
                async with session_lock:
                    if connection_closed.is_set():
                        raise WebSocketDisconnect(code=1001, reason="client disconnected")
                    try:
                        state = await _run_ws_turn(
                            agent,
                            prepare_web_message(settings, user_msg),
                            cancel_event=turn["cancel_event"],
                            channel=web_channel(settings, "ws_stream"),
                            owner_key_hash=ws_owner_hash,
                            session_id=session_id,
                            model=model,
                            attachments=attachments,
                            stream_callback=_send_token,
                            event_callback=_send_event,
                            disable_tools=not enable_tools,
                        )
                    except asyncio.CancelledError:
                        if connection_closed.is_set():
                            raise WebSocketDisconnect(
                                code=1001, reason="client disconnected"
                            ) from None
                        if turn["cancel_event"].is_set():
                            await websocket.send_json(
                                _turn_frame(
                                    turn,
                                    type="cancelled",
                                    terminal=True,
                                    content="Run cancelled",
                                )
                            )
                            _finish_turn(turn)
                            continue
                        raise
                    except EchoBlockedError:
                        await websocket.send_json(
                            _turn_frame(
                                turn,
                                type="error",
                                terminal=True,
                                content=("Echo blocked sensitive input before model execution"),
                            )
                        )
                        _finish_turn(turn)
                        continue
                    except EchoUnavailableError:
                        await websocket.send_json(
                            _turn_frame(
                                turn,
                                type="error",
                                terminal=True,
                                content=(
                                    "Echo safety layer is unavailable; request was not executed"
                                ),
                            )
                        )
                        _finish_turn(turn)
                        continue
                    except PermissionError as exc:
                        await websocket.send_json(
                            _turn_frame(
                                turn,
                                type="error",
                                terminal=True,
                                content=humanize_error(str(exc)),
                            )
                        )
                        _finish_turn(turn)
                        continue
                session_id = state.session_id
                turn["session_id"] = session_id
                if connection_closed.is_set():
                    raise WebSocketDisconnect(code=1001, reason="client disconnected")
                _record_usage(state, explicit_model=model)
                assistant_msg = _assistant_text_from_state(state)

                if state.status != "completed":
                    await websocket.send_json(
                        _turn_frame(
                            turn,
                            type="error",
                            terminal=True,
                            content=humanize_error(state.error_message),
                            turns=state.turn_count,
                            tokens=state.total_tokens,
                            cost=round(state.cost_estimate, 6),
                            model=state.model or model or "unknown",
                        )
                    )
                else:
                    # Fallback: if streaming never fired (all tool turns or provider
                    # doesn't support streaming), send the full response in one go.
                    if not streamed and assistant_msg:
                        await websocket.send_json(
                            _turn_frame(turn, type="response", content=assistant_msg)
                        )

                    await websocket.send_json(
                        _turn_frame(
                            turn,
                            type="done",
                            terminal=True,
                            turns=state.turn_count,
                            tokens=state.total_tokens,
                            cost=round(state.cost_estimate, 6),
                            status=state.status,
                            compression=state.compression_stats,
                        )
                    )
                _finish_turn(turn)

            elif msg_type == "ping":
                await websocket.send_json({"type": "pong"})

    except WebSocketDisconnect:
        pass
    except InboxOverloadError:
        logger.warning("WebSocket closed by inbox overload policy")
    except Exception as exc:
        logger.error("WebSocket error: %s", type(exc).__name__)
        try:
            await websocket.send_json(
                {"type": "error", "content": "An internal error occurred. Please try again."}
            )
        except Exception:
            logger.warning("Failed to send error to websocket", exc_info=True)
    finally:
        connection_closed.set()
        if active_turn is not None:
            active_turn["cancel_event"].set()
        reader_task.cancel()
        with suppress(asyncio.CancelledError):
            await reader_task
        with suppress(Exception):
            await inbox.close()
        if active_turn is not None:
            _finish_turn(active_turn)
