"""Bots room event stream. Projections only — no MAC or handle seals."""

from __future__ import annotations

from typing import Any

from fastapi import HTTPException, WebSocket, WebSocketDisconnect

from js.bots.models import BOTS_PRODUCT_ID
from js.bots.service import bot_store_for


async def bots_websocket_endpoint(websocket: WebSocket) -> None:
    from js.exceptions import AuthRequiredError
    from js.web.auth import (
        AuthManager,
        check_origin,
        resolve_session_cookie,
        runtime_owner,
        websocket_presented_api_key,
    )
    from js.web.deps import get_agent

    try:
        check_origin(websocket)
    except HTTPException as exc:
        await websocket.close(code=1008, reason=exc.detail)
        return

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

    owner = runtime_owner(auth_ctx)
    await websocket.accept()
    try:
        payload = await websocket.receive_json()
        room_id = str(payload.get("room_id") or "")
        if not room_id:
            await websocket.send_json({"error": "room_id required"})
            return
        agent = get_agent()
        store = getattr(agent, "_bot_store", None) or bot_store_for(agent.settings.state_dir)
        room = store.get_room(room_id, owner_key_hash=owner, product_id=BOTS_PRODUCT_ID)
        if room is None:
            await websocket.send_json({"error": "room not visible"})
            return
        messages = store.list_messages(room_id, owner_key_hash=owner, product_id=BOTS_PRODUCT_ID)
        await websocket.send_json(
            {
                "type": "snapshot",
                "room": room.to_public_dict(),
                "messages": [item.to_public_dict() for item in messages],
            }
        )
        while True:
            incoming = await websocket.receive_json()
            if incoming.get("type") == "ping":
                await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        return


def room_event(message: dict[str, Any]) -> dict[str, Any]:
    return {"type": "message", "message": message}
