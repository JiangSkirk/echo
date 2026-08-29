"""Bots surface REST API. Stays on product_id=js-agent."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from js.bots.exceptions import BotsError, BotsIsolationError, BotsNotFoundError, BotsStateError
from js.bots.models import BOTS_PRODUCT_ID
from js.bots.service import BotService, bot_store_for
from js.web.auth import require_user_write, runtime_owner
from js.web.deps import get_agent, require_auth_dep

router = APIRouter(prefix="/api/bots", tags=["bots"])


class CreateBotBody(BaseModel):
    display_name: str = Field(min_length=1, max_length=64)


class ActivateSoulBody(BaseModel):
    soul_text: str = Field(min_length=1, max_length=8000)


class CreateRoomBody(BaseModel):
    title: str = Field(min_length=1, max_length=128)
    member_bot_ids: list[str] = Field(default_factory=list)


class PostMessageBody(BaseModel):
    content: str = Field(min_length=1, max_length=16000)
    confirm_suggested: list[str] = Field(default_factory=list)


class ConfirmGoalBody(BaseModel):
    answers: list[str] = Field(default_factory=list)


class ExecuteGoalBody(BaseModel):
    evidence: str = ""


class AddMembersBody(BaseModel):
    member_bot_ids: list[str] = Field(default_factory=list)


def _owner(auth: dict[str, Any]) -> str:
    return runtime_owner(auth)


def _service(agent: Any) -> BotService:
    store = getattr(agent, "_bot_store", None)
    if store is None:
        store = bot_store_for(agent.settings.state_dir)
        agent._bot_store = store
    return BotService(store, agent=agent)


def _room_hit_payload(service: BotService, agent: Any, room: Any) -> dict[str, Any]:
    from js.bots.persona import compute_prefix_id
    from js.web.deps import get_stats_store

    store = get_stats_store()
    empty: dict[str, Any] = {"hit_rate": None, "below_target": False, "per_bot": []}
    if store is None:
        return empty
    tools = None
    getter = getattr(agent, "_get_tools_schema", None)
    if callable(getter):
        try:
            tools = getter(None)
        except Exception:
            tools = None
    slices: list[tuple[str, str]] = []
    for bot_id in room.member_bot_ids:
        try:
            bot = service.store.require_bot(bot_id, owner_key_hash=room.owner_key_hash)
        except Exception:
            continue
        slices.append((bot.id, compute_prefix_id(bot.id, bot.soul_text, tools)))
    if not slices:
        return empty
    return store.room_prefix_hit_summary(slices)


def _raise(exc: Exception) -> None:
    if isinstance(exc, BotsIsolationError):
        raise HTTPException(403, str(exc)) from exc
    if isinstance(exc, BotsNotFoundError):
        raise HTTPException(404, str(exc)) from exc
    if isinstance(exc, BotsStateError | BotsError):
        raise HTTPException(400, str(exc)) from exc
    raise exc


@router.get("")
async def list_bots(
    auth: dict[str, Any] = Depends(require_auth_dep),
    agent: Any = Depends(get_agent),
) -> dict[str, Any]:
    service = _service(agent)
    bots = service.store.list_bots(owner_key_hash=_owner(auth), product_id=BOTS_PRODUCT_ID)
    return {"bots": [bot.to_public_dict() for bot in bots]}


@router.post("")
async def create_bot(
    body: CreateBotBody,
    auth: dict[str, Any] = Depends(require_user_write),
    agent: Any = Depends(get_agent),
) -> dict[str, Any]:
    service = _service(agent)
    try:
        bot = service.create_draft(body.display_name, owner_key_hash=_owner(auth))
        bot = await service.awaken(bot.id, owner_key_hash=_owner(auth))
    except Exception as exc:
        _raise(exc)
        raise
    return {"bot": bot.to_public_dict()}


@router.post("/{bot_id}/activate")
async def activate_bot(
    bot_id: str,
    body: ActivateSoulBody,
    auth: dict[str, Any] = Depends(require_user_write),
    agent: Any = Depends(get_agent),
) -> dict[str, Any]:
    service = _service(agent)
    try:
        bot, room = service.activate(bot_id, body.soul_text, owner_key_hash=_owner(auth))
    except Exception as exc:
        _raise(exc)
        raise
    return {"bot": bot.to_public_dict(), "room": room.to_public_dict()}


@router.get("/rooms")
async def list_rooms(
    auth: dict[str, Any] = Depends(require_auth_dep),
    agent: Any = Depends(get_agent),
) -> dict[str, Any]:
    service = _service(agent)
    rooms = service.store.list_rooms(owner_key_hash=_owner(auth), product_id=BOTS_PRODUCT_ID)
    return {"rooms": [room.to_public_dict() for room in rooms]}


@router.post("/rooms")
async def create_room(
    body: CreateRoomBody,
    auth: dict[str, Any] = Depends(require_user_write),
    agent: Any = Depends(get_agent),
) -> dict[str, Any]:
    service = _service(agent)
    try:
        room = service.store.create_room(
            title=body.title,
            member_bot_ids=body.member_bot_ids,
            owner_key_hash=_owner(auth),
        )
    except Exception as exc:
        _raise(exc)
        raise
    return {"room": room.to_public_dict()}


@router.get("/rooms/{room_id}")
async def get_room(
    room_id: str,
    auth: dict[str, Any] = Depends(require_auth_dep),
    agent: Any = Depends(get_agent),
) -> dict[str, Any]:
    service = _service(agent)
    try:
        room = service.store.require_room(room_id, owner_key_hash=_owner(auth))
        messages = service.store.list_messages(room_id, owner_key_hash=_owner(auth))
        goal = (
            service.store.get_goal_run(room.goal_run_id, owner_key_hash=_owner(auth))
            if room.goal_run_id
            else None
        )
    except Exception as exc:
        _raise(exc)
        raise
    return {
        "room": room.to_public_dict(),
        "messages": [item.to_public_dict() for item in messages],
        "goal": goal.to_public_dict() if goal is not None else None,
        "suggested_roster": [
            bot.to_public_dict()
            for bot in service.suggest_roster(room.id, owner_key_hash=_owner(auth))
        ],
        "hit_rate": _room_hit_payload(service, agent, room),
    }


@router.post("/rooms/{room_id}/messages")
async def post_message(
    room_id: str,
    body: PostMessageBody,
    auth: dict[str, Any] = Depends(require_user_write),
    agent: Any = Depends(get_agent),
) -> dict[str, Any]:
    service = _service(agent)
    try:
        return await service.post_user_message(
            room_id,
            body.content,
            owner_key_hash=_owner(auth),
            confirm_suggested=body.confirm_suggested or None,
        )
    except Exception as exc:
        _raise(exc)
        raise


@router.post("/goals/{goal_id}/confirm")
async def confirm_goal(
    goal_id: str,
    body: ConfirmGoalBody,
    auth: dict[str, Any] = Depends(require_user_write),
    agent: Any = Depends(get_agent),
) -> dict[str, Any]:
    service = _service(agent)
    try:
        goal = await service.confirm_contract(
            goal_id, owner_key_hash=_owner(auth), answers=body.answers
        )
    except Exception as exc:
        _raise(exc)
        raise
    return {"goal": goal.to_public_dict()}


@router.post("/goals/{goal_id}/execute")
async def execute_goal(
    goal_id: str,
    body: ExecuteGoalBody,
    auth: dict[str, Any] = Depends(require_user_write),
    agent: Any = Depends(get_agent),
) -> dict[str, Any]:
    service = _service(agent)
    try:
        goal = await service.execute_goal(
            goal_id, owner_key_hash=_owner(auth), evidence=body.evidence
        )
    except Exception as exc:
        _raise(exc)
        raise
    return {"goal": goal.to_public_dict()}


@router.post("/goals/{goal_id}/cancel")
async def cancel_goal(
    goal_id: str,
    auth: dict[str, Any] = Depends(require_user_write),
    agent: Any = Depends(get_agent),
) -> dict[str, Any]:
    service = _service(agent)
    try:
        goal = service.cancel_goal(goal_id, owner_key_hash=_owner(auth))
    except Exception as exc:
        _raise(exc)
        raise
    return {"goal": goal.to_public_dict()}


@router.post("/rooms/{room_id}/members")
async def add_room_members(
    room_id: str,
    body: AddMembersBody,
    auth: dict[str, Any] = Depends(require_user_write),
    agent: Any = Depends(get_agent),
) -> dict[str, Any]:
    service = _service(agent)
    try:
        room = service.store.add_room_members(
            room_id,
            body.member_bot_ids,
            owner_key_hash=_owner(auth),
        )
    except Exception as exc:
        _raise(exc)
        raise
    return {"room": room.to_public_dict()}
