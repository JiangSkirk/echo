"""BotService public lifecycle and fail-closed refusals."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from js.bots.exceptions import BotsIsolationError, BotsNotFoundError, BotsStateError
from js.bots.models import BOTS_PRODUCT_ID, GoalBudget, RoomRecord
from js.bots.persona import BotTurnBinding, bind_bot_turn, current_bot_binding
from js.bots.service import (
    BotService,
    _default_turn_runner,
    _record_bots_usage,
    bot_store_for,
)
from js.bots.store import BotStore, private_memory_session

OWNER_A = "owner-a"
OWNER_B = "owner-b"


def _store(tmp_path: Path) -> BotStore:
    return BotStore(tmp_path / "state")


def _service(tmp_path: Path, *, agent: Any | None = None) -> BotService:
    return BotService(_store(tmp_path), agent=agent)


def _reply(text: str) -> Any:
    return SimpleNamespace(messages=[SimpleNamespace(role="assistant", content=text)])


async def _echo_runner(agent: Any, message: str, **kwargs: Any) -> Any:
    del agent
    return _reply(f"echo:{message[:40]}")


def _active(
    store: BotStore,
    name: str,
    *,
    owner: str = OWNER_A,
    product_id: str = BOTS_PRODUCT_ID,
) -> Any:
    return store.create_bot(
        display_name=name,
        owner_key_hash=owner,
        product_id=product_id,
        status="active",
        soul_text=f"我是{name}",
    )


def test_bot_store_for_points_at_state_dir(tmp_path: Path) -> None:
    store = bot_store_for(tmp_path / "state")
    assert store.db_path == tmp_path / "state" / "bots.db"
    assert store.db_path.parent.is_dir()


def test_create_draft_requires_owner(tmp_path: Path) -> None:
    service = _service(tmp_path)
    with pytest.raises(BotsIsolationError, match="owner context is required"):
        service.create_draft("调查bot", owner_key_hash="")


def test_create_draft_requires_product(tmp_path: Path) -> None:
    service = _service(tmp_path)
    with pytest.raises(BotsIsolationError, match="product context is required"):
        service.create_draft("调查bot", owner_key_hash=OWNER_A, product_id="")


def test_create_draft_stays_inactive_with_empty_soul(tmp_path: Path) -> None:
    service = _service(tmp_path)
    draft = service.create_draft("调查bot", owner_key_hash=OWNER_A)
    assert draft.status == "draft"
    assert draft.soul_text == ""
    assert draft.memory_session == private_memory_session(draft.id)
    assert draft.persona_appendix
    assert "交叉验证" in draft.persona_appendix or "证据" in draft.persona_appendix
    assert service.store.get_bot(draft.id, owner_key_hash=OWNER_B) is None


@pytest.mark.asyncio
async def test_awaken_without_runner_writes_soul_seed(tmp_path: Path) -> None:
    service = _service(tmp_path)
    draft = service.create_draft("调查bot", owner_key_hash=OWNER_A)
    awakened = await service.awaken(draft.id, owner_key_hash=OWNER_A)
    assert awakened.status == "draft"
    assert "调查bot" in awakened.soul_text
    assert awakened.persona_appendix


@pytest.mark.asyncio
async def test_awaken_uses_turn_runner_text(tmp_path: Path) -> None:
    service = _service(tmp_path, agent=object())
    draft = service.create_draft("研究员", owner_key_hash=OWNER_A)

    async def runner(agent: Any, message: str, **kwargs: Any) -> Any:
        assert agent is service.agent
        assert kwargs["channel"] == "bots"
        assert kwargs["surface"] == "bots"
        assert kwargs["disable_tools"] is True
        assert kwargs["session_id"] == draft.memory_session
        assert "研究员" in message
        return _reply("我是研究员，所以我先收集来源。")

    awakened = await service.awaken(draft.id, owner_key_hash=OWNER_A, turn_runner=runner)
    assert awakened.soul_text == "我是研究员，所以我先收集来源。"
    assert awakened.status == "draft"


@pytest.mark.asyncio
async def test_awaken_runner_failure_falls_back_to_soul_seed(tmp_path: Path) -> None:
    service = _service(tmp_path, agent=object())
    draft = service.create_draft("安全专家", owner_key_hash=OWNER_A)

    async def boom(agent: Any, message: str, **kwargs: Any) -> Any:
        raise RuntimeError("provider down")

    awakened = await service.awaken(draft.id, owner_key_hash=OWNER_A, turn_runner=boom)
    assert awakened.status == "draft"
    assert "安全专家" in awakened.soul_text


@pytest.mark.asyncio
async def test_awaken_empty_assistant_falls_back_to_seed(tmp_path: Path) -> None:
    service = _service(tmp_path, agent=object())
    draft = service.create_draft("程序员", owner_key_hash=OWNER_A)

    async def blank(agent: Any, message: str, **kwargs: Any) -> Any:
        return _reply("")

    awakened = await service.awaken(draft.id, owner_key_hash=OWNER_A, turn_runner=blank)
    assert "程序员" in awakened.soul_text


@pytest.mark.asyncio
async def test_awaken_refuses_foreign_owner(tmp_path: Path) -> None:
    service = _service(tmp_path)
    draft = service.create_draft("调查bot", owner_key_hash=OWNER_A)
    with pytest.raises(BotsNotFoundError):
        await service.awaken(draft.id, owner_key_hash=OWNER_B)


def test_activate_creates_dm_and_is_idempotent(tmp_path: Path) -> None:
    service = _service(tmp_path)
    draft = service.create_draft("调查bot", owner_key_hash=OWNER_A)
    bot, room = service.activate(
        draft.id, "我是调查bot，所以我先搜再下结论。", owner_key_hash=OWNER_A
    )
    assert bot.status == "active"
    assert bot.soul_text.startswith("我是调查bot")
    assert room.kind == "dm"
    assert room.member_bot_ids == (bot.id,)
    again, same = service.activate(bot.id, bot.soul_text, owner_key_hash=OWNER_A)
    assert again.id == bot.id
    assert same.id == room.id


def test_activate_refuses_empty_soul(tmp_path: Path) -> None:
    service = _service(tmp_path)
    draft = service.create_draft("调查bot", owner_key_hash=OWNER_A)
    with pytest.raises(BotsStateError, match="soul_text"):
        service.activate(draft.id, "   ", owner_key_hash=OWNER_A)


def test_activate_refuses_foreign_owner(tmp_path: Path) -> None:
    service = _service(tmp_path)
    draft = service.create_draft("调查bot", owner_key_hash=OWNER_A)
    with pytest.raises(BotsNotFoundError):
        service.activate(draft.id, "我是调查bot", owner_key_hash=OWNER_B)


def test_suggest_roster_omits_room_members(tmp_path: Path) -> None:
    service = _service(tmp_path)
    left = _active(service.store, "调查bot")
    right = _active(service.store, "研究员")
    room = service.store.ensure_dm_room(left.id, owner_key_hash=OWNER_A)
    suggested = service.suggest_roster(room.id, owner_key_hash=OWNER_A)
    assert [bot.id for bot in suggested] == [right.id]
    with pytest.raises(BotsNotFoundError):
        service.suggest_roster(room.id, owner_key_hash=OWNER_B)


def test_pull_mentioned_adds_named_active_bot(tmp_path: Path) -> None:
    service = _service(tmp_path)
    left = _active(service.store, "调查bot")
    right = _active(service.store, "研究员")
    room = service.store.ensure_dm_room(left.id, owner_key_hash=OWNER_A)
    unchanged = service.pull_mentioned(room.id, "随便聊聊", owner_key_hash=OWNER_A)
    assert unchanged.member_bot_ids == (left.id,)
    pulled = service.pull_mentioned(room.id, "请 @研究员 交叉验证", owner_key_hash=OWNER_A)
    assert set(pulled.member_bot_ids) == {left.id, right.id}
    assert pulled.kind == "group"


@pytest.mark.asyncio
async def test_post_chitchat_does_not_open_a_goal(tmp_path: Path) -> None:
    service = _service(tmp_path)
    bot = _active(service.store, "调查bot")
    room = service.store.ensure_dm_room(bot.id, owner_key_hash=OWNER_A)
    payload = await service.post_user_message(
        room.id,
        "你好",
        owner_key_hash=OWNER_A,
        turn_runner=_echo_runner,
    )
    assert payload["goal"] is None
    assert payload["suggested_roster"] == []
    assert payload["message"]["speaker_kind"] == "user"
    assert payload["message"]["content"] == "你好"
    speakers = {item["speaker_kind"] for item in payload["messages"]}
    assert speakers == {"user", "bot"}


@pytest.mark.asyncio
async def test_post_task_opens_clarify_and_suggests_roster(tmp_path: Path) -> None:
    service = _service(tmp_path)
    left = _active(service.store, "调查bot")
    right = _active(service.store, "研究员")
    room = service.store.ensure_dm_room(left.id, owner_key_hash=OWNER_A)
    payload = await service.post_user_message(
        room.id,
        "调查宇树的招股书风险，先列证据缺口",
        owner_key_hash=OWNER_A,
        turn_runner=_echo_runner,
    )
    assert payload["goal"] is not None
    assert payload["goal"]["phase"] == "clarify"
    assert payload["goal"]["questions"]
    assert payload["suggested_roster"][0]["id"] == right.id
    contents = [item["content"] for item in payload["messages"]]
    assert any("调查宇树" in text for text in contents)
    assert any(item["speaker_kind"] == "bot" for item in payload["messages"])


@pytest.mark.asyncio
async def test_post_task_confirm_suggested_adds_member(tmp_path: Path) -> None:
    service = _service(tmp_path)
    left = _active(service.store, "调查bot")
    right = _active(service.store, "研究员")
    room = service.store.ensure_dm_room(left.id, owner_key_hash=OWNER_A)
    payload = await service.post_user_message(
        room.id,
        "调查这段声明的来源",
        owner_key_hash=OWNER_A,
        confirm_suggested=[right.id],
        turn_runner=_echo_runner,
    )
    assert right.id in payload["room"]["member_bot_ids"]
    assert payload["room"]["kind"] == "group"


@pytest.mark.asyncio
async def test_clarify_answers_confirm_on_second_reply(tmp_path: Path) -> None:
    service = _service(tmp_path)
    bot = _active(service.store, "调查bot")
    room = service.store.ensure_dm_room(bot.id, owner_key_hash=OWNER_A)
    first = await service.post_user_message(
        room.id,
        "整理一份可核对的风险清单",
        owner_key_hash=OWNER_A,
        turn_runner=_echo_runner,
    )
    goal_id = first["goal"]["id"]
    assert first["goal"]["phase"] == "clarify"
    await service.post_user_message(
        room.id,
        "覆盖招股书和诉讼记录",
        owner_key_hash=OWNER_A,
        turn_runner=_echo_runner,
    )
    still = service.store.require_goal_run(goal_id, owner_key_hash=OWNER_A)
    assert still.phase == "clarify"
    assert still.answers == ("覆盖招股书和诉讼记录",)
    second = await service.post_user_message(
        room.id,
        "成功标准是每条有来源",
        owner_key_hash=OWNER_A,
        turn_runner=_echo_runner,
    )
    assert second["goal"]["phase"] == "confirmed"
    assert second["goal"]["contract"]["objective"]
    assert any(item["speaker_kind"] == "system" for item in second["messages"])


@pytest.mark.asyncio
async def test_post_user_message_skips_no_reply(tmp_path: Path) -> None:
    service = _service(tmp_path)
    bot = _active(service.store, "调查bot")
    room = service.store.ensure_dm_room(bot.id, owner_key_hash=OWNER_A)

    async def silent(agent: Any, message: str, **kwargs: Any) -> Any:
        return _reply("NO_REPLY")

    payload = await service.post_user_message(
        room.id,
        "你好",
        owner_key_hash=OWNER_A,
        turn_runner=silent,
    )
    assert [item["speaker_kind"] for item in payload["messages"]] == ["user"]


@pytest.mark.asyncio
async def test_post_user_message_refuses_foreign_owner(tmp_path: Path) -> None:
    service = _service(tmp_path)
    bot = _active(service.store, "调查bot")
    room = service.store.ensure_dm_room(bot.id, owner_key_hash=OWNER_A)
    with pytest.raises(BotsNotFoundError):
        await service.post_user_message(room.id, "你好", owner_key_hash=OWNER_B)


@pytest.mark.asyncio
async def test_confirm_contract_merges_answers(tmp_path: Path) -> None:
    service = _service(tmp_path)
    bot = _active(service.store, "调查bot")
    room = service.store.ensure_dm_room(bot.id, owner_key_hash=OWNER_A)
    goal = service.store.create_goal_run(
        room.id,
        owner_key_hash=OWNER_A,
        questions=["目标是什么？", "成功标准？"],
    )
    confirmed = await service.confirm_contract(
        goal.id,
        owner_key_hash=OWNER_A,
        answers=["查招股书风险", "每条有出处"],
    )
    assert confirmed.phase == "confirmed"
    assert confirmed.answers == ("查招股书风险", "每条有出处")
    assert confirmed.contract.objective == "查招股书风险"
    assert confirmed.contract.success_criteria == ("每条有出处",)
    with pytest.raises(BotsNotFoundError):
        await service.confirm_contract(goal.id, owner_key_hash=OWNER_B)


@pytest.mark.asyncio
async def test_execute_goal_blocks_when_budget_is_exhausted(tmp_path: Path) -> None:
    service = _service(tmp_path)
    bot = _active(service.store, "调查bot")
    room = service.store.ensure_dm_room(bot.id, owner_key_hash=OWNER_A)
    goal = service.store.create_goal_run(
        room.id,
        owner_key_hash=OWNER_A,
        budget=GoalBudget(max_echo_turns=1, echo_turns_used=0),
    )
    blocked = await service.execute_goal(goal.id, owner_key_hash=OWNER_A, evidence="x")
    assert blocked.phase == "blocked"
    assert blocked.pause_reason == "budget"
    stored = service.store.require_goal_run(goal.id, owner_key_hash=OWNER_A)
    assert stored.phase == "blocked"


@pytest.mark.asyncio
async def test_execute_goal_verification_requires_evidence(tmp_path: Path) -> None:
    service = _service(tmp_path)
    bot = _active(service.store, "调查bot")
    room = service.store.ensure_dm_room(bot.id, owner_key_hash=OWNER_A)
    missing = service.store.create_goal_run(
        room.id,
        owner_key_hash=OWNER_A,
        budget=GoalBudget(max_echo_turns=8),
    )
    blocked = await service.execute_goal(
        missing.id, owner_key_hash=OWNER_A, evidence="", turn_runner=_echo_runner
    )
    assert blocked.phase == "blocked"
    assert "verification_stop" in blocked.pause_reason
    fresh = service.store.create_goal_run(
        room.id,
        owner_key_hash=OWNER_A,
        budget=GoalBudget(max_echo_turns=8),
    )
    finished = await service.execute_goal(
        fresh.id,
        owner_key_hash=OWNER_A,
        evidence="来源 A 与 B 交叉一致",
        turn_runner=_echo_runner,
    )
    assert finished.phase == "done"
    assert finished.todos
    assert finished.todos[0].evidence.startswith("来源")


@pytest.mark.asyncio
async def test_execute_goal_refuses_foreign_owner(tmp_path: Path) -> None:
    service = _service(tmp_path)
    bot = _active(service.store, "调查bot")
    room = service.store.ensure_dm_room(bot.id, owner_key_hash=OWNER_A)
    goal = service.store.create_goal_run(room.id, owner_key_hash=OWNER_A)
    with pytest.raises(BotsNotFoundError):
        await service.execute_goal(goal.id, owner_key_hash=OWNER_B, evidence="x")


@pytest.mark.asyncio
async def test_ask_bot_refuses_draft_and_non_member(tmp_path: Path) -> None:
    service = _service(tmp_path)
    draft = service.create_draft("调查bot", owner_key_hash=OWNER_A)
    member = _active(service.store, "研究员")
    outsider = _active(service.store, "安全专家")
    room = service.store.ensure_dm_room(member.id, owner_key_hash=OWNER_A)
    with pytest.raises(BotsStateError, match="draft bots cannot join rooms"):
        await service.ask_bot(draft.id, "交叉验证", room_id=room.id, owner_key_hash=OWNER_A)
    with pytest.raises(BotsStateError, match="not a room member"):
        await service.ask_bot(outsider.id, "交叉验证", room_id=room.id, owner_key_hash=OWNER_A)


@pytest.mark.asyncio
async def test_ask_bot_depth_two_is_refused(tmp_path: Path) -> None:
    service = _service(tmp_path)
    left = _active(service.store, "调查bot")
    right = _active(service.store, "研究员")
    room = service.store.create_room(
        title="组", member_bot_ids=[left.id, right.id], owner_key_hash=OWNER_A
    )
    binding = BotTurnBinding(
        bot_id=left.id,
        soul_text=left.soul_text,
        persona_appendix=left.persona_appendix,
        room_id=room.id,
        memory_session=left.memory_session,
        prefix_id=left.id,
        ask_depth=1,
    )
    with bind_bot_turn(binding), pytest.raises(BotsStateError, match="depth exceeds 1"):
        await service.ask_bot(right.id, "再问一层", room_id=room.id, owner_key_hash=OWNER_A)


@pytest.mark.asyncio
async def test_ask_bot_without_agent_echoes_locally(tmp_path: Path) -> None:
    service = _service(tmp_path)
    left = _active(service.store, "调查bot")
    right = _active(service.store, "研究员")
    room = service.store.create_room(
        title="组", member_bot_ids=[left.id, right.id], owner_key_hash=OWNER_A
    )
    message = await service.ask_bot(
        right.id, "交叉验证这一条", room_id=room.id, owner_key_hash=OWNER_A
    )
    assert message.speaker_id == right.id
    assert "交叉验证这一条" in message.content
    stored = service.store.list_messages(room.id, owner_key_hash=OWNER_A)
    assert stored[-1].id == message.id


def test_cancel_goal_is_idempotent_on_terminal_phases(tmp_path: Path) -> None:
    from dataclasses import replace

    service = _service(tmp_path)
    bot = _active(service.store, "调查bot")
    room = service.store.ensure_dm_room(bot.id, owner_key_hash=OWNER_A)
    goal = service.store.create_goal_run(room.id, owner_key_hash=OWNER_A)
    cancelled = service.cancel_goal(goal.id, owner_key_hash=OWNER_A)
    assert cancelled.phase == "blocked"
    assert cancelled.pause_reason == "cancelled"
    again = service.cancel_goal(goal.id, owner_key_hash=OWNER_A)
    assert again.phase == "blocked"
    assert again.pause_reason == "cancelled"
    finished = service.store.save_goal_run(replace(goal, phase="done", pause_reason=""))
    kept = service.cancel_goal(finished.id, owner_key_hash=OWNER_A)
    assert kept.phase == "done"


def test_cancel_goal_refuses_foreign_owner(tmp_path: Path) -> None:
    service = _service(tmp_path)
    bot = _active(service.store, "调查bot")
    room = service.store.ensure_dm_room(bot.id, owner_key_hash=OWNER_A)
    goal = service.store.create_goal_run(room.id, owner_key_hash=OWNER_A)
    with pytest.raises(BotsNotFoundError):
        service.cancel_goal(goal.id, owner_key_hash=OWNER_B)


def test_primary_bot_requires_members(tmp_path: Path) -> None:
    service = _service(tmp_path)
    empty = RoomRecord(
        id="r-empty",
        owner_key_hash=OWNER_A,
        product_id=BOTS_PRODUCT_ID,
        kind="group",
        title="空房间",
        member_bot_ids=(),
        transcript_session="room:r-empty",
        goal_run_id=None,
        created_at=1.0,
        updated_at=1.0,
    )
    with pytest.raises(BotsStateError, match="room has no members"):
        service._primary_bot(empty, owner_key_hash=OWNER_A, product_id=BOTS_PRODUCT_ID)


@pytest.mark.asyncio
async def test_bot_echo_binds_full_frozen_schema_and_forwards_ask_user_lease(
    tmp_path: Path,
) -> None:
    from js.models.usage import sorted_tools_schema

    schema = [
        {"function": {"name": "shell", "parameters": {"type": "object"}}},
        {"function": {"name": "ask_user", "parameters": {"type": "object"}}},
    ]

    class _Agent:
        def _get_tools_schema(self, _tools: Any) -> list[dict[str, Any]]:
            return list(schema)

    service = BotService(_store(tmp_path), agent=_Agent())
    bot = _active(service.store, "调查bot")
    room = service.store.ensure_dm_room(bot.id, owner_key_hash=OWNER_A)
    seen: dict[str, Any] = {}

    async def runner(agent: Any, message: str, **kwargs: Any) -> Any:
        binding = current_bot_binding()
        assert binding is not None
        seen["frozen"] = binding.frozen_tools
        seen["kwargs"] = kwargs
        seen["message"] = message
        return _reply("可见回复")

    text = await service._bot_echo(
        bot,
        room,
        "当前请求",
        owner_key_hash=OWNER_A,
        product_id=BOTS_PRODUCT_ID,
        turn_runner=runner,
        lease_tool_allowlist=("ask_user",),
    )
    assert text == "可见回复"
    assert seen["kwargs"]["lease_tool_allowlist"] == ("ask_user",)
    assert seen["kwargs"]["session_id"] == room.transcript_session
    frozen_names = {item["function"]["name"] for item in seen["frozen"]}
    # Prefix schema stays the full agent surface; lease, not the schema, is the gate.
    assert frozen_names == {"ask_user", "shell"}
    assert seen["frozen"] == tuple(sorted_tools_schema(schema))


@pytest.mark.asyncio
async def test_default_turn_runner_requires_echo_agent() -> None:
    with pytest.raises(BotsStateError, match="Echo agent is required"):
        await _default_turn_runner(None, "hi")


def test_record_bots_usage_is_noop_without_state() -> None:
    _record_bots_usage(None, bot_id="b1", prefix_id="p1")
    _record_bots_usage(SimpleNamespace(), bot_id="b1", prefix_id="p1")


def test_same_owner_different_product_is_invisible(tmp_path: Path) -> None:
    service = _service(tmp_path)
    draft = service.create_draft("调查bot", owner_key_hash=OWNER_A, product_id="js-agent")
    with pytest.raises(BotsNotFoundError):
        service.store.require_bot(draft.id, owner_key_hash=OWNER_A, product_id="js-work")


@pytest.mark.asyncio
async def test_room_replies_only_addressed_bots_speak(tmp_path: Path) -> None:
    from dataclasses import replace

    service = _service(tmp_path)
    left = _active(service.store, "调查bot")
    right = _active(service.store, "研究员")
    room = service.store.create_room(
        title="组", member_bot_ids=[left.id, right.id], owner_key_hash=OWNER_A
    )
    goal = service.store.create_goal_run(room.id, owner_key_hash=OWNER_A)
    service.store.save_goal_run(replace(goal, phase="executing"))
    payload = await service.post_user_message(
        room.id,
        "请研究员补充来源",
        owner_key_hash=OWNER_A,
        turn_runner=_echo_runner,
    )
    bot_speakers = {
        item["speaker_id"] for item in payload["messages"] if item["speaker_kind"] == "bot"
    }
    assert bot_speakers == {right.id}
