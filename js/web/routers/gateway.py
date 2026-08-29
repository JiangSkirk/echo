"""Host webhook surface. HMAC authenticates the caller; Echo still owns turns."""

from __future__ import annotations

import time
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

from js.web.deps import get_agent, get_settings

router = APIRouter(prefix="/api/gateway", tags=["gateway"])


@router.post("/webhook")
async def inbound_webhook(request: Request) -> JSONResponse:
    settings = get_settings()
    if not bool(getattr(settings.gateway, "enabled", False)):
        raise HTTPException(status_code=404, detail="gateway disabled")
    from js.security.posture import require_untrusted_surface

    try:
        require_untrusted_surface(settings, "webhook")
    except RuntimeError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    from js.gateway.channels.webhook import (
        SIGNATURE_HEADER,
        TIMESTAMP_HEADER,
        WebhookAuthError,
        parse_webhook_body,
        verify_webhook,
    )

    body = await request.body()
    timestamp = request.headers.get(TIMESTAMP_HEADER, "")
    signature = request.headers.get(SIGNATURE_HEADER, "")
    replay = getattr(request.app.state, "gateway_webhook_replay", None)
    if replay is None:
        from js.gateway.channels.webhook import WebhookReplayCache

        replay = WebhookReplayCache()
        request.app.state.gateway_webhook_replay = replay
    try:
        verify_webhook(
            secret=settings.gateway.webhook_secret,
            timestamp=timestamp,
            signature=signature,
            body=body,
            max_skew_seconds=settings.gateway.webhook_max_skew_seconds,
            replay=replay,
        )
        envelope = parse_webhook_body(body, received_at=time.time())
    except WebhookAuthError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc

    from js.gateway.attach import attach_gateway_service

    agent = get_agent()
    service = attach_gateway_service(agent)
    request.app.state.gateway_service = service
    decision = await service.dispatch_echo(agent, envelope)
    payload: dict[str, Any] = {
        "accepted": decision.accepted,
        "reason": decision.reason,
        "owner": decision.owner,
    }
    status = 202 if decision.accepted else 202
    if decision.reason in {"unpaired", "bad_pairing_code", "unrouted", "owner_mismatch"}:
        status = 202
    return JSONResponse(payload, status_code=status)
