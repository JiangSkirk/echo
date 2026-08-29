"""Friends v1 HTTP surface. Mounted only when friends_enabled=true."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from js.friends.service import (
    RECIPIENT_HEADER,
    FriendsError,
    FriendService,
)
from js.security.secrets import SecretManager
from js.web.auth import require_user_write, runtime_owner
from js.web.deps import get_agent, get_settings, require_auth_dep

router = APIRouter(prefix="/api/friends", tags=["friends"])


class InviteAcceptBody(BaseModel):
    invite_card: str = Field(min_length=8)
    display_name: str = Field(default="Friend", max_length=64)
    endpoint: str = Field(default="", max_length=512)


class InviteCompleteBody(BaseModel):
    accept: dict[str, Any]


class SendTextBody(BaseModel):
    text: str = Field(min_length=1, max_length=5000)


class SendTaskBody(BaseModel):
    task_text: str = Field(min_length=1, max_length=5000)


def _require_enabled() -> None:
    settings = get_settings()
    if not bool(getattr(settings, "friends_enabled", False)):
        raise HTTPException(
            status_code=404,
            detail={"code": "feature_not_enabled", "feature": "friends"},
        )


def _service(agent: Any) -> FriendService:
    existing = getattr(agent, "_friend_service", None)
    if isinstance(existing, FriendService):
        return existing
    secrets = getattr(agent, "secrets", None)
    if secrets is None:
        secrets = SecretManager(agent.settings.state_dir)
    service = FriendService(
        agent.settings.state_dir,
        secrets=secrets,
        local_endpoint=str(getattr(agent.settings, "friends_endpoint", "") or ""),
        agent=agent,
    )
    agent._friend_service = service
    return service


@router.get("/status")
async def friends_status(
    auth: dict[str, Any] = Depends(require_auth_dep),
    agent: Any = Depends(get_agent),
) -> dict[str, Any]:
    _require_enabled()
    from js.security.posture import detect_posture

    posture = detect_posture()
    return {
        "enabled": True,
        "isolation_posture": str(posture.level),
        "warn_native": str(posture.level) != "container-full",
    }


@router.post("/invites")
async def create_invite(
    auth: dict[str, Any] = Depends(require_user_write),
    agent: Any = Depends(get_agent),
) -> dict[str, Any]:
    _require_enabled()
    return _service(agent).create_invite(runtime_owner(auth))


@router.post("/invites/accept")
async def accept_invite(
    body: InviteAcceptBody,
    auth: dict[str, Any] = Depends(require_user_write),
    agent: Any = Depends(get_agent),
) -> dict[str, Any]:
    _require_enabled()
    try:
        return _service(agent).accept_invite(
            runtime_owner(auth),
            body.invite_card,
            display_name=body.display_name,
            endpoint=body.endpoint,
        )
    except FriendsError as exc:
        raise HTTPException(400, str(exc)) from exc


@router.post("/invites/complete")
async def complete_invite(
    body: InviteCompleteBody,
    auth: dict[str, Any] = Depends(require_user_write),
    agent: Any = Depends(get_agent),
) -> dict[str, Any]:
    _require_enabled()
    try:
        friend = _service(agent).complete_invite(runtime_owner(auth), body.accept)
    except FriendsError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"friend_id": friend.friend_id, "status": friend.status}


@router.get("")
async def list_friends(
    auth: dict[str, Any] = Depends(require_auth_dep),
    agent: Any = Depends(get_agent),
) -> dict[str, Any]:
    _require_enabled()
    return {"friends": _service(agent).list_friends(runtime_owner(auth))}


@router.post("/{friend_id}/block")
async def block_friend(
    friend_id: str,
    auth: dict[str, Any] = Depends(require_user_write),
    agent: Any = Depends(get_agent),
) -> dict[str, Any]:
    _require_enabled()
    ok = _service(agent).block_friend(runtime_owner(auth), friend_id)
    if not ok:
        raise HTTPException(404, "friend not found")
    return {"success": True}


@router.post("/{friend_id}/revoke")
async def revoke_friend(
    friend_id: str,
    auth: dict[str, Any] = Depends(require_user_write),
    agent: Any = Depends(get_agent),
) -> dict[str, Any]:
    _require_enabled()
    ok = _service(agent).revoke_friend(runtime_owner(auth), friend_id)
    if not ok:
        raise HTTPException(404, "friend not found")
    return {"success": True}


@router.get("/{friend_id}/messages")
async def list_messages(
    friend_id: str,
    auth: dict[str, Any] = Depends(require_auth_dep),
    agent: Any = Depends(get_agent),
) -> dict[str, Any]:
    _require_enabled()
    return {
        "messages": _service(agent).store.list_messages(runtime_owner(auth), friend_id),
    }


@router.post("/{friend_id}/messages")
async def send_message(
    friend_id: str,
    body: SendTextBody,
    auth: dict[str, Any] = Depends(require_user_write),
    agent: Any = Depends(get_agent),
) -> dict[str, Any]:
    _require_enabled()
    try:
        return await _service(agent).send_text(runtime_owner(auth), friend_id, body.text)
    except FriendsError as exc:
        raise HTTPException(400, str(exc)) from exc


@router.post("/{friend_id}/tasks")
async def send_task(
    friend_id: str,
    body: SendTaskBody,
    auth: dict[str, Any] = Depends(require_user_write),
    agent: Any = Depends(get_agent),
) -> dict[str, Any]:
    _require_enabled()
    try:
        return await _service(agent).send_task(runtime_owner(auth), friend_id, body.task_text)
    except FriendsError as exc:
        raise HTTPException(400, str(exc)) from exc


@router.post("/inbound")
async def inbound(request: Request, agent: Any = Depends(get_agent)) -> dict[str, Any]:
    _require_enabled()
    settings = get_settings()
    from js.security.posture import require_untrusted_surface

    try:
        require_untrusted_surface(settings, "friends")
    except RuntimeError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    service = _service(agent)
    recipient = request.headers.get(RECIPIENT_HEADER, "")
    owner = service.store.owner_for_local_id(recipient)
    if not owner:
        raise HTTPException(404, "recipient unknown")
    try:
        return await service.receive(
            owner,
            headers={key.lower(): value for key, value in request.headers.items()},
            body=await request.body(),
        )
    except FriendsError as exc:
        raise HTTPException(400, str(exc)) from exc
