"""Fleet dashboard WebSocket endpoint."""

from __future__ import annotations

import asyncio
import json
from typing import Any

from fastapi import HTTPException, WebSocket, WebSocketDisconnect

from js.utils.log import get_logger

logger = get_logger("js.web")


async def fleet_websocket_endpoint(websocket: WebSocket) -> None:
    """Real-time fleet dashboard WebSocket."""
    from js.exceptions import AuthRequiredError
    from js.orchestration.fleet import (
        AgentFleet,
        bind_fleet_event_identity,
        validate_fleet_event_identity,
    )
    from js.web.auth import (
        _ADMIN_ROLE,
        AuthManager,
        check_origin,
        memory_owner,
        websocket_presented_api_key,
    )
    from js.web.routers.fleet import get_fleet
    from js.web.server import _execute_web_tool_effect, get_agent

    # Origin check first — reject cross-origin WebSocket upgrades
    try:
        check_origin(websocket)
    except HTTPException as exc:
        await websocket.close(code=1008, reason=exc.detail)
        return

    # Keep credentials out of URLs. Browsers use the same-site HttpOnly
    # session cookie; native clients may send X-API-Key during the upgrade.
    # The legacy ``x-api-key`` cookie is rejected.
    from js.web.auth import resolve_session_cookie

    settings = get_agent().settings
    from js.appshell.principal import appshell_auth_context_from_scope

    managed, injected_auth = appshell_auth_context_from_scope(websocket.scope)
    if managed:
        if injected_auth is None:
            await websocket.close(code=1008, reason="Authentication failed")
            return
        auth_ctx = injected_auth
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
        auth_mgr = AuthManager(settings.state_dir)
        try:
            if api_key:
                auth_ctx = auth_mgr.verify(api_key)
            else:
                auth_ctx = auth_mgr.verify_session(session_token)
        except AuthRequiredError:
            await websocket.close(code=1008, reason="Authentication failed")
            return
    if auth_ctx.get("role") != _ADMIN_ROLE:
        await websocket.close(code=1008, reason="Admin role required")
        return
    owner_key_hash = memory_owner(auth_ctx) or "local-user"
    product_id = str(getattr(settings, "product_id", "js-agent"))
    await websocket.accept()

    fleet = get_fleet()
    event_queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=500)
    background_tasks: set[asyncio.Task[None]] = set()
    fleet_effect_tasks: dict[tuple[str, str, str], asyncio.Task[None]] = {}
    dropped_events = 0
    queue_overloaded = False

    def _enqueue_event(event: dict[str, Any]) -> None:
        nonlocal dropped_events, queue_overloaded
        try:
            event_queue.put_nowait(event)
        except asyncio.QueueFull:
            dropped_events += 1
            queue_overloaded = True
            logger.warning(
                "Fleet WebSocket event queue full; dropping event",
                dropped=dropped_events,
                event_type=event.get("type"),
            )

    async def _on_event(event: dict[str, Any]) -> None:
        try:
            request_id, turn_id, session_id = validate_fleet_event_identity(
                event.get("request_id"),
                event.get("turn_id"),
                event.get("session_id"),
            )
        except (TypeError, ValueError):
            logger.warning("Dropped Fleet event without a valid runtime identity")
            return
        validated_event = dict(event)
        validated_event.update(
            {
                "request_id": request_id,
                "turn_id": turn_id,
                "session_id": session_id,
            }
        )
        _enqueue_event(validated_event)

    async def _run_fleet_effect(
        *,
        tool_name: str,
        arguments: dict[str, Any],
        action: str,
        request_id: str,
        turn_id: str,
        session_id: str,
    ) -> None:
        with bind_fleet_event_identity(request_id, turn_id, session_id):
            try:
                result = await _execute_web_tool_effect(
                    get_agent(),
                    auth_ctx,
                    channel=f"fleet_ws_{action}",
                    tool_name=tool_name,
                    arguments=arguments,
                    user_input=f"Run an administrator-approved Fleet {action} request",
                )
                if result.success:
                    return
                logger.warning(
                    "Fleet WebSocket effect failed",
                    action=action,
                    status_code=result.metadata.get("status_code"),
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.warning(
                    "Fleet WebSocket effect failed",
                    action=action,
                    exc_info=True,
                )
            _enqueue_event(
                {
                    "type": "error",
                    "message": f"Fleet {action} failed",
                    "request_id": request_id,
                    "turn_id": turn_id,
                    "session_id": session_id,
                }
            )

    def _start_fleet_effect(
        *,
        tool_name: str,
        arguments: dict[str, Any],
        action: str,
        request_id: str,
        turn_id: str,
        session_id: str,
    ) -> None:
        request_id, turn_id, session_id = validate_fleet_event_identity(
            request_id, turn_id, session_id
        )
        key = (request_id, turn_id, session_id)
        existing = fleet_effect_tasks.get(key)
        if existing is not None and not existing.done():
            return
        task = asyncio.create_task(
            _run_fleet_effect(
                tool_name=tool_name,
                arguments=arguments,
                action=action,
                request_id=request_id,
                turn_id=turn_id,
                session_id=session_id,
            )
        )
        background_tasks.add(task)
        fleet_effect_tasks[key] = task

        def _discard(done: asyncio.Task[None]) -> None:
            background_tasks.discard(done)
            if fleet_effect_tasks.get(key) is done:
                fleet_effect_tasks.pop(key, None)

        task.add_done_callback(_discard)

    subscription = fleet.on_event(
        _on_event,
        product_id=product_id,
        owner_key_hash=owner_key_hash,
    )

    # Send initial status
    try:
        await websocket.send_json(
            {
                "type": "status",
                "data": fleet.get_status(owner_key_hash=owner_key_hash),
            }
        )
    except Exception:
        pass

    async def _handle_client_raw(raw: dict[str, Any]) -> None:
        if raw.get("type") == "websocket.disconnect":
            raise WebSocketDisconnect(
                code=raw.get("code", 1000),
                reason=raw.get("reason"),
            )
        payload = raw.get("text")
        if payload is None:
            raw_bytes = raw.get("bytes") or b""
            if not isinstance(raw_bytes, bytes) or len(raw_bytes) > 262_144:
                raise ValueError("invalid Fleet WebSocket message")
            payload = raw_bytes.decode("utf-8")
        if not isinstance(payload, str) or len(payload.encode("utf-8")) > 262_144:
            raise ValueError("invalid Fleet WebSocket message")
        data = json.loads(payload)
        if not isinstance(data, dict):
            raise ValueError("invalid Fleet WebSocket message")

        msg_type = data.get("type", "")
        if not isinstance(msg_type, str):
            raise ValueError("invalid Fleet WebSocket message type")
        if msg_type == "cancel":
            request_id, turn_id, session_id = validate_fleet_event_identity(
                data.get("request_id"),
                data.get("turn_id"),
                data.get("session_id"),
            )
            background_task = fleet_effect_tasks.get((request_id, turn_id, session_id))
            if background_task is None:
                await websocket.send_json(
                    {
                        "type": "cancel_rejected",
                        "request_id": request_id,
                        "turn_id": turn_id,
                        "session_id": session_id,
                    }
                )
                return
            background_task.cancel()
            await asyncio.gather(background_task, return_exceptions=True)
            await websocket.send_json(
                {
                    "type": "cancelled",
                    "request_id": request_id,
                    "turn_id": turn_id,
                    "session_id": session_id,
                }
            )
            return
        if msg_type == "status":
            await websocket.send_json(
                {
                    "type": "status",
                    "data": fleet.get_status(owner_key_hash=owner_key_hash),
                }
            )
            return
        if msg_type == "collaborate":
            request_id, turn_id, requested_session_id = validate_fleet_event_identity(
                data.get("request_id"),
                data.get("turn_id"),
                data.get("session_id"),
            )
            raw_subtasks = data.get("subtasks")
            normalized_subtasks: list[str] | None = None
            if raw_subtasks is not None:
                if not isinstance(raw_subtasks, list):
                    raise ValueError("invalid Fleet subtasks")
                normalized_subtasks = []
                for raw_subtask in raw_subtasks:
                    if isinstance(raw_subtask, str):
                        normalized_subtasks.append(raw_subtask)
                    elif isinstance(raw_subtask, dict) and isinstance(
                        raw_subtask.get("description"), str
                    ):
                        normalized_subtasks.append(raw_subtask["description"])
                    else:
                        raise ValueError("invalid Fleet subtask")
            (
                task,
                subtasks,
                validated_session_id,
                role_mapping,
                mode,
            ) = AgentFleet._validate_collaboration_request(
                data.get("task", ""),
                normalized_subtasks,
                requested_session_id,
                data.get("role_mapping"),
                data.get("mode", "auto"),
            )
            await websocket.send_json({"type": "ack", "action": "collaborate"})
            _start_fleet_effect(
                tool_name="fleet_collaborate",
                arguments={
                    "task": task,
                    "subtasks": subtasks,
                    "session_id": validated_session_id,
                    "role_mapping": role_mapping,
                    "mode": mode,
                },
                action="collaborate",
                request_id=request_id,
                turn_id=turn_id,
                session_id=requested_session_id,
            )
            return
        if msg_type == "continue":
            request_id, turn_id, requested_session_id = validate_fleet_event_identity(
                data.get("request_id"),
                data.get("turn_id"),
                data.get("session_id"),
            )
            (
                follow_up,
                _subtasks,
                validated_session_id,
                _role_mapping,
                _mode,
            ) = AgentFleet._validate_collaboration_request(
                data.get("task", ""),
                None,
                requested_session_id,
                None,
                "auto",
            )
            assert validated_session_id is not None
            await websocket.send_json({"type": "ack", "action": "continue"})
            _start_fleet_effect(
                tool_name="control_fleet_continue",
                arguments={
                    "session_id": validated_session_id,
                    "follow_up": follow_up,
                },
                action="continue",
                request_id=request_id,
                turn_id=turn_id,
                session_id=requested_session_id,
            )
            return
        if msg_type == "spawn":
            await websocket.send_json(
                {
                    "type": "ack",
                    "action": "spawn",
                    "warning": "Spawn is deprecated. Agents are created automatically.",
                }
            )
            return
        if msg_type == "ping":
            await websocket.send_json({"type": "pong"})
            return
        await websocket.send_json({"type": "error", "message": "Unsupported Fleet message type"})

    try:
        queue_get: asyncio.Task[dict[str, Any]] = asyncio.create_task(event_queue.get())
        ws_recv: asyncio.Task[Any] = asyncio.create_task(websocket.receive())
        try:
            while True:
                done, _pending = await asyncio.wait(
                    {queue_get, ws_recv},
                    return_when=asyncio.FIRST_COMPLETED,
                )
                if queue_get in done:
                    try:
                        event = queue_get.result()
                    except RuntimeError as exc:
                        if "disconnect" in str(exc).lower():
                            break
                        raise
                    queue_get = asyncio.create_task(event_queue.get())
                    if queue_overloaded:
                        queue_overloaded = False
                        await websocket.send_json(
                            {"type": "overloaded", "dropped": dropped_events}
                        )
                    await websocket.send_json(event)
                if ws_recv not in done:
                    continue
                try:
                    raw = ws_recv.result()
                except WebSocketDisconnect:
                    break
                ws_recv = asyncio.create_task(websocket.receive())
                try:
                    await _handle_client_raw(raw)
                except WebSocketDisconnect:
                    break
                except RuntimeError as exc:
                    if "disconnect" in str(exc).lower():
                        break
                    raise
                except (TypeError, ValueError, json.JSONDecodeError, UnicodeDecodeError):
                    logger.warning("Invalid Fleet WebSocket client message")
                    await websocket.send_json(
                        {"type": "error", "message": "Invalid Fleet request"}
                    )
                except Exception:
                    logger.warning("Fleet WebSocket client message failed", exc_info=True)
                    await websocket.send_json(
                        {"type": "error", "message": "Fleet request failed"}
                    )
        finally:
            queue_get.cancel()
            ws_recv.cancel()
            await asyncio.gather(queue_get, ws_recv, return_exceptions=True)
    except WebSocketDisconnect:
        logger.info("Fleet WebSocket disconnected")
    except Exception as exc:
        logger.error("Fleet WebSocket error: %s", type(exc).__name__)
    finally:
        for background_task in tuple(background_tasks):
            background_task.cancel()
        if background_tasks:
            await asyncio.gather(*background_tasks, return_exceptions=True)
        fleet.off_event(subscription)
