"""bots_ask is an Echo turn that reuses the room transcript session."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from js.bots.authority import refuse_ask_depth
from js.bots.exceptions import BotsStateError
from js.bots.service import BotService
from js.bots.store import BotStore


@pytest.mark.asyncio
async def test_bots_ask_uses_echo_runner_and_room_session(tmp_path: Path) -> None:
    store = BotStore(tmp_path / "state")
    owner = "owner-a"
    left = store.create_bot(
        display_name="调查bot", owner_key_hash=owner, status="active", soul_text="我是调查bot"
    )
    right = store.create_bot(
        display_name="研究员", owner_key_hash=owner, status="active", soul_text="我是研究员"
    )
    room = store.create_room(
        title="组",
        member_bot_ids=[left.id, right.id],
        owner_key_hash=owner,
    )
    calls: list[dict[str, Any]] = []

    async def runner(agent: Any, message: str, **kwargs: Any) -> Any:
        calls.append({"message": message, **kwargs})
        return SimpleNamespace(messages=[SimpleNamespace(role="assistant", content="可见回复")])

    service = BotService(store, agent=object())
    message = await service.ask_bot(
        right.id,
        "交叉验证这一条",
        room_id=room.id,
        owner_key_hash=owner,
        turn_runner=runner,
    )
    assert message.content == "可见回复"
    assert message.speaker_id == right.id
    assert calls
    assert calls[0]["surface"] == "bots"
    assert calls[0]["session_id"] == room.transcript_session
    assert calls[0]["channel"] == "bots"
    stored = store.list_messages(room.id, owner_key_hash=owner)
    assert any(item.content == "可见回复" for item in stored)


def test_bots_ask_depth_two_is_refused() -> None:
    with pytest.raises(BotsStateError, match="depth exceeds 1"):
        refuse_ask_depth(2)
