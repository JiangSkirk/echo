"""BotStore CRUD, session naming, and owner-bound negative cases."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from js.bots.exceptions import BotsIsolationError, BotsNotFoundError, BotsStateError
from js.bots.models import (
    BOT_STATUS_ACTIVE,
    GoalBudget,
    GoalContract,
    GoalTodo,
)
from js.bots.store import (
    BotStore,
    room_transcript_session,
)

OWNER_A = "owner-a"
OWNER_B = "owner-b"


def _store(tmp_path: Path) -> BotStore:
    return BotStore(tmp_path / "state")


def _active(store: BotStore, name: str, *, owner: str = OWNER_A) -> object:
    return store.create_bot(
        display_name=name,
        owner_key_hash=owner,
        status=BOT_STATUS_ACTIVE,
        soul_text=f"我是{name}",
    )


def test_display_name_must_be_one_to_sixty_four(tmp_path: Path) -> None:
    store = _store(tmp_path)
    with pytest.raises(BotsStateError, match="display_name"):
        store.create_bot(display_name="", owner_key_hash=OWNER_A)
    with pytest.raises(BotsStateError, match="display_name"):
        store.create_bot(display_name="x" * 65, owner_key_hash=OWNER_A)
    ok = store.create_bot(display_name="  调查bot  ", owner_key_hash=OWNER_A)
    assert ok.display_name == "调查bot"


def test_invalid_status_is_refused(tmp_path: Path) -> None:
    store = _store(tmp_path)
    with pytest.raises(BotsStateError, match="invalid bot status"):
        store.create_bot(display_name="调查bot", owner_key_hash=OWNER_A, status="retired")


def test_scope_identity_length_is_capped(tmp_path: Path) -> None:
    store = _store(tmp_path)
    with pytest.raises(BotsIsolationError, match="exceeds limit"):
        store.create_bot(display_name="调查bot", owner_key_hash="o" * 129)
    with pytest.raises(BotsIsolationError, match="exceeds limit"):
        store.create_bot(
            display_name="调查bot",
            owner_key_hash=OWNER_A,
            product_id="p" * 129,
        )


def test_slug_collision_allocates_numeric_suffix(tmp_path: Path) -> None:
    store = _store(tmp_path)
    first = store.create_bot(display_name="Researcher", owner_key_hash=OWNER_A)
    second = store.create_bot(display_name="Researcher", owner_key_hash=OWNER_A)
    third = store.create_bot(display_name="Researcher", owner_key_hash=OWNER_A)
    assert first.slug == "researcher"
    assert second.slug == "researcher-2"
    assert third.slug == "researcher-3"
    other = store.create_bot(display_name="Researcher", owner_key_hash=OWNER_B)
    assert other.slug == "researcher"


def test_get_bot_by_name_or_slug(tmp_path: Path) -> None:
    store = _store(tmp_path)
    draft = store.create_bot(display_name="调查bot", owner_key_hash=OWNER_A)
    active = _active(store, "研究员")
    assert store.get_bot_by_name_or_slug("", owner_key_hash=OWNER_A) is None
    assert store.get_bot_by_name_or_slug("调查bot", owner_key_hash=OWNER_A).id == draft.id
    assert store.get_bot_by_name_or_slug(active.slug, owner_key_hash=OWNER_A).id == active.id
    assert (
        store.get_bot_by_name_or_slug("调查bot", owner_key_hash=OWNER_A, active_only=True) is None
    )
    assert (
        store.get_bot_by_name_or_slug("研究员", owner_key_hash=OWNER_A, active_only=True).id
        == active.id
    )
    assert store.get_bot_by_name_or_slug("调查bot", owner_key_hash=OWNER_B) is None


def test_list_bots_filters_status_and_scope(tmp_path: Path) -> None:
    store = _store(tmp_path)
    draft = store.create_bot(display_name="调查bot", owner_key_hash=OWNER_A)
    active = _active(store, "研究员")
    store.create_bot(display_name="外人", owner_key_hash=OWNER_B)
    names = [bot.display_name for bot in store.list_bots(owner_key_hash=OWNER_A)]
    assert names == ["调查bot", "研究员"]
    drafts = store.list_bots(owner_key_hash=OWNER_A, status="draft")
    assert [bot.id for bot in drafts] == [draft.id]
    actives = store.list_bots(owner_key_hash=OWNER_A, status="active")
    assert [bot.id for bot in actives] == [active.id]


def test_update_soul_validates_length_and_scope(tmp_path: Path) -> None:
    store = _store(tmp_path)
    bot = store.create_bot(display_name="调查bot", owner_key_hash=OWNER_A)
    with pytest.raises(BotsStateError, match="soul_text"):
        store.update_soul(bot.id, soul_text="", owner_key_hash=OWNER_A)
    with pytest.raises(BotsStateError, match="soul_text"):
        store.update_soul(bot.id, soul_text="x" * 8001, owner_key_hash=OWNER_A)
    with pytest.raises(BotsNotFoundError):
        store.update_soul(bot.id, soul_text="我是调查bot", owner_key_hash=OWNER_B)
    updated = store.update_soul(
        bot.id,
        soul_text="  我是调查bot  ",
        owner_key_hash=OWNER_A,
        activate=True,
        persona_appendix="附录",
    )
    assert updated.status == "active"
    assert updated.soul_text == "我是调查bot"
    assert updated.persona_appendix == "附录"
    assert updated.updated_at >= bot.updated_at


def test_create_room_validates_title_and_members(tmp_path: Path) -> None:
    store = _store(tmp_path)
    bot = _active(store, "调查bot")
    with pytest.raises(BotsStateError, match="room title"):
        store.create_room(title="", member_bot_ids=[bot.id], owner_key_hash=OWNER_A)
    with pytest.raises(BotsStateError, match="room title"):
        store.create_room(title="t" * 129, member_bot_ids=[bot.id], owner_key_hash=OWNER_A)
    with pytest.raises(BotsStateError, match="at least one bot"):
        store.create_room(title="空", member_bot_ids=[], owner_key_hash=OWNER_A)
    room = store.create_room(
        title="  调查组  ",
        member_bot_ids=[bot.id, bot.id],
        owner_key_hash=OWNER_A,
    )
    assert room.title == "调查组"
    assert room.member_bot_ids == (bot.id,)
    assert room.transcript_session == room_transcript_session(room.id)


def test_ensure_dm_room_rejects_draft_and_reuses_existing(tmp_path: Path) -> None:
    store = _store(tmp_path)
    draft = store.create_bot(display_name="调查bot", owner_key_hash=OWNER_A)
    with pytest.raises(BotsStateError, match="draft bots cannot join rooms"):
        store.ensure_dm_room(draft.id, owner_key_hash=OWNER_A)
    bot = store.update_soul(
        draft.id, soul_text="我是调查bot", owner_key_hash=OWNER_A, activate=True
    )
    first = store.ensure_dm_room(bot.id, owner_key_hash=OWNER_A)
    second = store.ensure_dm_room(bot.id, owner_key_hash=OWNER_A)
    assert first.id == second.id
    assert first.kind == "dm"


def test_list_rooms_is_owner_scoped_and_newest_first(tmp_path: Path) -> None:
    store = _store(tmp_path)
    left = _active(store, "调查bot")
    right = _active(store, "研究员")
    older = store.ensure_dm_room(left.id, owner_key_hash=OWNER_A)
    newer = store.create_room(
        title="组", member_bot_ids=[left.id, right.id], owner_key_hash=OWNER_A
    )
    foreign = _active(store, "外人", owner=OWNER_B)
    store.ensure_dm_room(foreign.id, owner_key_hash=OWNER_B)
    rooms = store.list_rooms(owner_key_hash=OWNER_A)
    assert [room.id for room in rooms] == [newer.id, older.id]
    assert store.list_rooms(owner_key_hash=OWNER_B)[0].member_bot_ids == (foreign.id,)


def test_add_room_members_rejects_draft_and_foreign(tmp_path: Path) -> None:
    store = _store(tmp_path)
    host = _active(store, "调查bot")
    draft = store.create_bot(display_name="草稿", owner_key_hash=OWNER_A)
    peer = _active(store, "研究员")
    room = store.ensure_dm_room(host.id, owner_key_hash=OWNER_A)
    with pytest.raises(BotsStateError, match="draft bots cannot join rooms"):
        store.add_room_members(room.id, [draft.id], owner_key_hash=OWNER_A)
    with pytest.raises(BotsNotFoundError):
        store.add_room_members(room.id, [peer.id], owner_key_hash=OWNER_B)
    updated = store.add_room_members(room.id, [peer.id], owner_key_hash=OWNER_A)
    assert updated.kind == "group"
    assert set(updated.member_bot_ids) == {host.id, peer.id}
    again = store.add_room_members(room.id, [peer.id], owner_key_hash=OWNER_A)
    assert set(again.member_bot_ids) == {host.id, peer.id}


def test_bind_goal_run_and_unbind(tmp_path: Path) -> None:
    store = _store(tmp_path)
    bot = _active(store, "调查bot")
    room = store.ensure_dm_room(bot.id, owner_key_hash=OWNER_A)
    goal = store.create_goal_run(room.id, owner_key_hash=OWNER_A)
    assert store.require_room(room.id, owner_key_hash=OWNER_A).goal_run_id == goal.id
    unbound = store.bind_goal_run(room.id, None, owner_key_hash=OWNER_A)
    assert unbound.goal_run_id is None
    rebound = store.bind_goal_run(room.id, goal.id, owner_key_hash=OWNER_A)
    assert rebound.goal_run_id == goal.id
    with pytest.raises(BotsNotFoundError):
        store.bind_goal_run(room.id, goal.id, owner_key_hash=OWNER_B)


def test_append_message_validates_content(tmp_path: Path) -> None:
    store = _store(tmp_path)
    bot = _active(store, "调查bot")
    room = store.ensure_dm_room(bot.id, owner_key_hash=OWNER_A)
    with pytest.raises(BotsStateError, match="message content"):
        store.append_message(
            room.id,
            speaker_kind="user",
            speaker_id="user",
            content="   ",
            taint=0,
            owner_key_hash=OWNER_A,
        )
    with pytest.raises(BotsStateError, match="message content"):
        store.append_message(
            room.id,
            speaker_kind="user",
            speaker_id="user",
            content="x" * 16001,
            taint=0,
            owner_key_hash=OWNER_A,
        )
    message = store.append_message(
        room.id,
        speaker_kind="user",
        speaker_id="user",
        content="  查来源  ",
        taint=3,
        owner_key_hash=OWNER_A,
    )
    assert message.content == "查来源"
    assert message.taint == 3
    with pytest.raises(BotsNotFoundError):
        store.append_message(
            room.id,
            speaker_kind="user",
            speaker_id="user",
            content="x",
            taint=0,
            owner_key_hash=OWNER_B,
        )


def test_list_messages_clamps_limit(tmp_path: Path) -> None:
    store = _store(tmp_path)
    bot = _active(store, "调查bot")
    room = store.ensure_dm_room(bot.id, owner_key_hash=OWNER_A)
    for index in range(8):
        store.append_message(
            room.id,
            speaker_kind="user",
            speaker_id="user",
            content=f"msg-{index}",
            taint=0,
            owner_key_hash=OWNER_A,
        )
    assert [item.content for item in store.list_messages(room.id, owner_key_hash=OWNER_A, limit=0)][
        -1
    ] == "msg-7"
    window = store.list_messages(room.id, owner_key_hash=OWNER_A, limit=2)
    assert [item.content for item in window] == ["msg-6", "msg-7"]
    assert len(store.list_messages(room.id, owner_key_hash=OWNER_A, limit=600)) == 8


def test_goal_run_crud_and_list_limit(tmp_path: Path) -> None:
    store = _store(tmp_path)
    bot = _active(store, "调查bot")
    room = store.ensure_dm_room(bot.id, owner_key_hash=OWNER_A)
    contract = GoalContract(
        objective="查风险",
        success_criteria=("有出处",),
        constraints=("不改仓库",),
        out_of_scope=("股价预测",),
    )
    budget = GoalBudget(max_echo_turns=6, max_tool_calls=10)
    first = store.create_goal_run(
        room.id,
        owner_key_hash=OWNER_A,
        questions=["目标是什么？"],
        contract=contract,
        budget=budget,
    )
    assert first.phase == "clarify"
    assert first.contract.objective == "查风险"
    assert first.budget.max_echo_turns == 6
    from dataclasses import replace

    saved = store.save_goal_run(
        replace(
            first,
            phase="confirmed",
            answers=("查风险",),
            todos=(GoalTodo(id="t1", title="列缺口"),),
        )
    )
    assert saved.phase == "confirmed"
    assert saved.todos[0].title == "列缺口"
    second = store.create_goal_run(room.id, owner_key_hash=OWNER_A)
    listed = store.list_goal_runs(owner_key_hash=OWNER_A, limit=1)
    assert [item.id for item in listed] == [second.id]
    assert store.list_goal_runs(owner_key_hash=OWNER_B) == []
    with pytest.raises(BotsNotFoundError):
        store.require_goal_run(first.id, owner_key_hash=OWNER_B)
    with pytest.raises(BotsIsolationError, match="goal write refused"):
        store.save_goal_run(replace(first, owner_key_hash=OWNER_B))


def test_corrupt_goal_json_falls_back_to_defaults(tmp_path: Path) -> None:
    store = _store(tmp_path)
    bot = _active(store, "调查bot")
    room = store.ensure_dm_room(bot.id, owner_key_hash=OWNER_A)
    goal = store.create_goal_run(room.id, owner_key_hash=OWNER_A)
    with sqlite3.connect(store.db_path) as conn:
        conn.execute(
            "UPDATE goal_runs SET contract = ?, todos = ?, budget = ?, questions = ? WHERE id = ?",
            ("not-json", "not-json", "not-json", "not-json", goal.id),
        )
        conn.commit()
    loaded = store.require_goal_run(goal.id, owner_key_hash=OWNER_A)
    assert loaded.contract.objective == ""
    assert loaded.todos == ()
    assert loaded.budget.max_echo_turns == 24
    assert loaded.questions == ()


def test_public_dicts_hide_owner_hashes(tmp_path: Path) -> None:
    store = _store(tmp_path)
    bot = _active(store, "调查bot")
    room = store.ensure_dm_room(bot.id, owner_key_hash=OWNER_A)
    message = store.append_message(
        room.id,
        speaker_kind="user",
        speaker_id="user",
        content="hi",
        taint=1,
        owner_key_hash=OWNER_A,
    )
    goal = store.create_goal_run(room.id, owner_key_hash=OWNER_A)
    for payload in (
        bot.to_public_dict(),
        room.to_public_dict(),
        message.to_public_dict(),
        goal.to_public_dict(),
    ):
        assert "owner_key_hash" not in payload
        assert "owner" not in payload
    assert json.dumps(goal.to_public_dict())


def test_require_unknown_ids_fail_closed(tmp_path: Path) -> None:
    store = _store(tmp_path)
    with pytest.raises(BotsNotFoundError, match="bot is not visible"):
        store.require_bot("missing", owner_key_hash=OWNER_A)
    with pytest.raises(BotsNotFoundError, match="room is not visible"):
        store.require_room("missing", owner_key_hash=OWNER_A)
    with pytest.raises(BotsNotFoundError, match="goal run is not visible"):
        store.require_goal_run("missing", owner_key_hash=OWNER_A)
