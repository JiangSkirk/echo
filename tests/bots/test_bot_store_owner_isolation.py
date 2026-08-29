"""Bots store stays inside one product/owner boundary."""

from __future__ import annotations

from pathlib import Path

import pytest

from js.bots.exceptions import BotsIsolationError, BotsNotFoundError, BotsStateError
from js.bots.models import BOT_STATUS_ACTIVE
from js.bots.store import BotStore, private_memory_session, room_transcript_session


def _store(tmp_path: Path) -> BotStore:
    return BotStore(tmp_path / "state")


def test_missing_owner_fails_closed(tmp_path: Path) -> None:
    store = _store(tmp_path)
    with pytest.raises(BotsIsolationError, match="owner context is required"):
        store.create_bot(display_name="调查bot", owner_key_hash="")


def test_missing_product_fails_closed(tmp_path: Path) -> None:
    store = _store(tmp_path)
    with pytest.raises(BotsIsolationError, match="product context is required"):
        store.create_bot(display_name="调查bot", owner_key_hash="owner-a", product_id="")


def test_owner_cannot_read_another_owners_bot(tmp_path: Path) -> None:
    store = _store(tmp_path)
    bot = store.create_bot(display_name="调查bot", owner_key_hash="owner-a")
    assert store.get_bot(bot.id, owner_key_hash="owner-b") is None
    with pytest.raises(BotsNotFoundError):
        store.require_bot(bot.id, owner_key_hash="owner-b")
    assert store.list_bots(owner_key_hash="owner-b") == []


def test_same_owner_different_product_is_isolated(tmp_path: Path) -> None:
    store = _store(tmp_path)
    bot = store.create_bot(
        display_name="调查bot",
        owner_key_hash="owner-a",
        product_id="js-agent",
    )
    assert store.get_bot(bot.id, owner_key_hash="owner-a", product_id="js-work") is None
    assert store.list_bots(owner_key_hash="owner-a", product_id="js-work") == []


def test_private_memory_sessions_do_not_collide(tmp_path: Path) -> None:
    store = _store(tmp_path)
    first = store.create_bot(display_name="调查bot", owner_key_hash="owner-a")
    second = store.create_bot(display_name="研究员", owner_key_hash="owner-a")
    assert first.memory_session == private_memory_session(first.id)
    assert second.memory_session == private_memory_session(second.id)
    assert first.memory_session != second.memory_session
    assert first.memory_session.startswith("bot:")
    assert first.memory_session.endswith(":private")


def test_draft_bot_cannot_join_a_room(tmp_path: Path) -> None:
    store = _store(tmp_path)
    draft = store.create_bot(display_name="调查bot", owner_key_hash="owner-a")
    assert draft.status == "draft"
    with pytest.raises(BotsStateError, match="draft bots cannot join rooms"):
        store.create_room(
            title="调查组",
            member_bot_ids=[draft.id],
            owner_key_hash="owner-a",
        )


def test_cannot_add_foreign_bot_to_room(tmp_path: Path) -> None:
    store = _store(tmp_path)
    local = store.create_bot(
        display_name="调查bot",
        owner_key_hash="owner-a",
        status=BOT_STATUS_ACTIVE,
        soul_text="我是调查bot，所以我先搜再下结论。",
    )
    foreign = store.create_bot(
        display_name="研究员",
        owner_key_hash="owner-b",
        status=BOT_STATUS_ACTIVE,
        soul_text="我是研究员，所以我引用可靠来源。",
    )
    room = store.create_room(
        title="本方房间",
        member_bot_ids=[local.id],
        owner_key_hash="owner-a",
    )
    with pytest.raises(BotsNotFoundError):
        store.add_room_members(
            room.id,
            [foreign.id],
            owner_key_hash="owner-a",
        )
    assert store.get_room(room.id, owner_key_hash="owner-b") is None


def test_room_transcript_is_scoped_and_append_only(tmp_path: Path) -> None:
    store = _store(tmp_path)
    bot = store.create_bot(
        display_name="调查bot",
        owner_key_hash="owner-a",
        status=BOT_STATUS_ACTIVE,
        soul_text="我是调查bot，所以我先列证据缺口。",
    )
    room = store.create_room(
        title="调查组",
        member_bot_ids=[bot.id],
        owner_key_hash="owner-a",
    )
    assert room.transcript_session == room_transcript_session(room.id)
    first = store.append_message(
        room.id,
        speaker_kind="user",
        speaker_id="owner-a",
        content="查一下这段声明",
        taint=1,
        owner_key_hash="owner-a",
    )
    store.append_message(
        room.id,
        speaker_kind="bot",
        speaker_id=bot.id,
        content="先核来源。",
        taint=0,
        owner_key_hash="owner-a",
    )
    assert [item.content for item in store.list_messages(room.id, owner_key_hash="owner-a")] == [
        "查一下这段声明",
        "先核来源。",
    ]
    with pytest.raises(BotsNotFoundError):
        store.list_messages(room.id, owner_key_hash="owner-b")
    assert first.content == "查一下这段声明"


def test_list_messages_keeps_the_newest_window(tmp_path: Path) -> None:
    store = _store(tmp_path)
    bot = store.create_bot(
        display_name="调查bot",
        owner_key_hash="owner-a",
        status=BOT_STATUS_ACTIVE,
        soul_text="我是调查bot，所以我先列证据缺口。",
    )
    room = store.create_room(
        title="调查组",
        member_bot_ids=[bot.id],
        owner_key_hash="owner-a",
    )
    for index in range(6):
        store.append_message(
            room.id,
            speaker_kind="user",
            speaker_id="owner-a",
            content=f"msg-{index}",
            taint=1,
            owner_key_hash="owner-a",
        )
    contents = [
        item.content for item in store.list_messages(room.id, owner_key_hash="owner-a", limit=3)
    ]
    assert contents == ["msg-3", "msg-4", "msg-5"]


def test_goal_run_cannot_be_read_across_owners(tmp_path: Path) -> None:
    store = _store(tmp_path)
    bot = store.create_bot(
        display_name="调查bot",
        owner_key_hash="owner-a",
        status=BOT_STATUS_ACTIVE,
        soul_text="我是调查bot，所以我交叉验证。",
    )
    room = store.create_room(
        title="调查组",
        member_bot_ids=[bot.id],
        owner_key_hash="owner-a",
    )
    goal = store.create_goal_run(room.id, owner_key_hash="owner-a")
    assert store.get_goal_run(goal.id, owner_key_hash="owner-b") is None
    bound = store.require_room(room.id, owner_key_hash="owner-a")
    assert bound.goal_run_id == goal.id
