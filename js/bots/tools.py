"""Bots tools registered on the agent. Production calls still go through Echo leases."""

from __future__ import annotations

from typing import Any

from js.bots.exceptions import BotsError
from js.bots.models import BOTS_PRODUCT_ID
from js.bots.persona import current_bot_binding
from js.bots.service import BotService, bot_store_for
from js.echo.turn_context import current_runtime_context
from js.tools.registry import ToolParam, ToolResult, ToolSpec


def _service(agent: Any) -> BotService:
    store = getattr(agent, "_bot_store", None)
    if store is None:
        store = bot_store_for(agent.settings.state_dir)
        agent._bot_store = store
    return BotService(store, agent=agent)


def _owner_product() -> tuple[str, str]:
    context = current_runtime_context()
    if context is None or not context.owner_key_hash:
        raise PermissionError("bots tools require an Echo runtime context")
    return context.owner_key_hash, context.product_id or BOTS_PRODUCT_ID


def register_bots_tools(registry: Any, agent: Any) -> None:
    service = _service(agent)

    async def _ask_user(question: str) -> ToolResult:
        return ToolResult(success=True, output=f"ask_user: {question}")

    async def _rooms_create(title: str, member_bot_ids: list[str] | None = None) -> ToolResult:
        owner, product = _owner_product()
        room = service.store.create_room(
            title=title,
            member_bot_ids=list(member_bot_ids or []),
            owner_key_hash=owner,
            product_id=product,
        )
        return ToolResult(success=True, output=f"room:{room.id}")

    async def _bots_ask(bot_id: str, brief: str, room_id: str = "") -> ToolResult:
        owner, product = _owner_product()
        binding = current_bot_binding()
        target_room = room_id or (binding.room_id if binding is not None else "")
        if not target_room:
            raise BotsError("bots_ask requires a room")
        message = await service.ask_bot(
            bot_id,
            brief,
            room_id=target_room,
            owner_key_hash=owner,
            product_id=product,
        )
        return ToolResult(success=True, output=message.content)

    registry.register(
        ToolSpec(
            name="ask_user",
            description="向用户提出一个澄清问题。澄清阶段只允许这个工具产生副作用。",
            parameters=[ToolParam("question", "string", "要问用户的具体问题")],
        ),
        _ask_user,
    )
    registry.register(
        ToolSpec(
            name="rooms_create",
            description="创建一个群聊房间并邀请已 active 的机器人。",
            parameters=[
                ToolParam("title", "string", "房间标题"),
                ToolParam("member_bot_ids", "array", "成员 bot id 列表", required=False),
            ],
        ),
        _rooms_create,
    )
    registry.register(
        ToolSpec(
            name="bots_ask",
            description="向房间里的另一个 bot 提问。回复会出现在群聊气泡中。深度上限 1。",
            parameters=[
                ToolParam("bot_id", "string", "目标 bot id"),
                ToolParam("brief", "string", "受权 brief"),
                ToolParam("room_id", "string", "房间 id", required=False),
            ],
        ),
        _bots_ask,
    )
