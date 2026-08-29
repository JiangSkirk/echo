"""GoalRun stops on budget. No evidence cannot be done."""

from __future__ import annotations

from pathlib import Path

import pytest

from js.bots.exceptions import BotsBudgetError
from js.bots.harness import consume_budget, looks_like_task, verification_stop
from js.bots.models import GoalBudget, GoalContract, GoalRun
from js.bots.service import BotService
from js.bots.store import BotStore


def _goal(*, turns: int = 0, max_turns: int = 2) -> GoalRun:
    return GoalRun(
        id="g1",
        owner_key_hash="owner-a",
        product_id="js-agent",
        room_id="r1",
        phase="executing",
        questions=(),
        answers=(),
        contract=GoalContract(objective="查X"),
        todos=(),
        budget=GoalBudget(max_echo_turns=max_turns, echo_turns_used=turns),
        pause_reason="",
        created_at=1.0,
        updated_at=1.0,
    )


def test_budget_stop_raises() -> None:
    goal = _goal(turns=0, max_turns=2)
    goal = consume_budget(goal, echo_turns=1)
    assert goal.budget.echo_turns_used == 1
    with pytest.raises(BotsBudgetError):
        consume_budget(goal, echo_turns=1)


def test_verification_requires_evidence() -> None:
    blocked = verification_stop(_goal(), evidence="")
    assert blocked.phase == "blocked"
    done = verification_stop(_goal(), evidence="来源 A 与 B 交叉一致")
    assert done.phase == "done"


def test_chitchat_is_not_a_new_task() -> None:
    assert looks_like_task("你好", room_phase=None) is False
    assert looks_like_task("谢谢", room_phase=None) is False
    assert looks_like_task("调查宇树的招股书风险", room_phase=None) is True
    assert looks_like_task("范围是港股", room_phase="clarify") is False


def test_cancel_goal_blocks_without_background_continue(tmp_path: Path) -> None:
    store = BotStore(tmp_path / "state")
    owner = "owner-a"
    bot = store.create_bot(
        display_name="调查bot", owner_key_hash=owner, status="active", soul_text="soul"
    )
    room = store.create_room(title="组", member_bot_ids=[bot.id], owner_key_hash=owner)
    goal = store.create_goal_run(room.id, owner_key_hash=owner, questions=["目标是什么？"])
    service = BotService(store)
    cancelled = service.cancel_goal(goal.id, owner_key_hash=owner)
    assert cancelled.phase == "blocked"
    assert cancelled.pause_reason == "cancelled"
