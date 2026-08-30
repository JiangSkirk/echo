"""Table-driven coverage for identity, models, tools, harness, and rooms."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from js.bots.exceptions import BotsBudgetError, BotsError, BotsStateError
from js.bots.harness import (
    DEFAULT_CLARIFY_QUESTIONS,
    clarify_questions,
    consume_budget,
    contract_from_answers,
    looks_like_task,
    require_clarify_lease,
    verification_stop,
)
from js.bots.identity import (
    awakening_prompt,
    compile_bot_identity,
    fleet_persona_block,
    infer_specialty_key,
    slugify_bot_name,
    soul_digest,
)
from js.bots.models import (
    BOT_STATUS_ACTIVE,
    BOT_STATUS_DRAFT,
    BOTS_PRODUCT_ID,
    GOAL_PHASES,
    ROOM_KIND_DM,
    BotRecord,
    BotStatus,
    CompiledIdentity,
    GoalBudget,
    GoalContract,
    GoalPhase,
    GoalRun,
    GoalTodo,
    RoomKind,
    RoomMessage,
    RoomRecord,
    SpeakerKind,
)
from js.bots.rooms import (
    mentioned_bots,
    mentioned_tokens,
    room_message_taint,
    should_speak,
    wrap_room_transcript,
)
from js.bots.store import BotStore
from js.bots.tools import register_bots_tools
from js.echo.turn_context import RuntimeContext, reset_runtime_context, set_runtime_context
from js.orin import taint as orin_taint
from js.tools.registry import ToolSpec


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("Researcher", "researcher"),
        ("调查bot", "bot"),
        ("调查", "investigator"),
        ("123abc", "bot-123abc"),
        ("!!!", "bot"),
        ("A" * 80, "a" * 48),
        ("  Hello World  ", "hello-world"),
        ("安全-专家", "security"),
    ],
)
def test_slugify_bot_name_table(name: str, expected: str) -> None:
    assert slugify_bot_name(name) == expected


@pytest.mark.parametrize(
    ("name", "specialty"),
    [
        ("worker", "worker"),
        ("reviewer", "reviewer"),
        ("销售顾问", "sales"),
        ("sale desk", "sales"),
        ("客服", "sales"),
        ("研究员", "researcher"),
        ("research intern", "researcher"),
        ("调查bot", "investigator"),
        ("侦探", "investigator"),
        ("取证", "investigator"),
        ("开发工程师", "coder"),
        ("engineer", "coder"),
        ("UI 设计", "designer"),
        ("qa", "tester"),
        ("质检", "tester"),
        ("系统架构", "architect"),
        ("风控", "security"),
        ("perf", "performance"),
        ("技术文档", "doc_writer"),
        ("数据分析", "analyst"),
        ("审查员", "reviewer"),
        ("项目经理", "manager"),
        ("干活的", "worker"),
        ("无名氏", "general"),
    ],
)
def test_infer_specialty_key_table(name: str, specialty: str) -> None:
    assert infer_specialty_key(name) == specialty


def test_compile_identity_uses_exact_persona_and_specialty_appendix() -> None:
    compiled = compile_bot_identity("investigator")
    assert compiled.specialty_key == "investigator"
    assert compiled.slug == "investigator"
    assert "调查" in compiled.soul_seed or "搜" in compiled.soul_seed
    assert compiled.fleet_persona_block.startswith("\n\n【你的身份】")
    assert "交叉验证" in compiled.persona_appendix
    general = compile_bot_identity("园丁")
    assert general.specialty_key == "general"
    assert "不编造" in general.soul_seed
    assert "本职做到最大" in general.persona_appendix
    assert fleet_persona_block("coder") == compile_bot_identity("coder").fleet_persona_block


def test_awakening_prompt_and_soul_digest_are_stable() -> None:
    compiled = compile_bot_identity("调查bot")
    prompt = awakening_prompt("调查bot", compiled)
    assert "调查bot" in prompt
    assert compiled.specialty_key in prompt
    assert "不要调用工具" in prompt
    assert "第一人称" in prompt
    assert soul_digest("abc") == soul_digest("abc")
    assert soul_digest("abc") != soul_digest("abd")
    assert len(soul_digest("abc")) == 64


def test_goal_budget_defaults_exhausted_and_from_dict_fallbacks() -> None:
    budget = GoalBudget()
    assert budget.max_echo_turns == 24
    assert budget.max_tool_calls == 80
    assert budget.max_elapsed_ms == 15 * 60 * 1000
    assert budget.exhausted() is False
    assert GoalBudget(echo_turns_used=24).exhausted() is True
    assert GoalBudget(tool_calls_used=80).exhausted() is True
    assert GoalBudget(elapsed_ms_used=15 * 60 * 1000).exhausted() is True
    parsed = GoalBudget.from_dict(
        {
            "max_echo_turns": "3",
            "max_tool_calls": None,
            "max_elapsed_ms": True,
            "echo_turns_used": 1.5,
            "tool_calls_used": [],
            "elapsed_ms_used": "",
        }
    )
    assert parsed.max_echo_turns == 3
    assert parsed.max_tool_calls == 80
    assert parsed.max_elapsed_ms == 15 * 60 * 1000
    assert parsed.echo_turns_used == 1
    assert parsed.tool_calls_used == 0
    assert parsed.elapsed_ms_used == 0
    empty = GoalBudget.from_dict(None)
    assert empty.to_dict() == GoalBudget().to_dict()
    assert empty.remaining().to_dict() == empty.to_dict()


def test_goal_contract_todo_and_enums_round_trip() -> None:
    contract = GoalContract.from_dict(None)
    assert contract.objective == ""
    filled = GoalContract.from_dict(
        {
            "objective": "查X",
            "success_criteria": ["有出处"],
            "constraints": ["不改仓库"],
            "out_of_scope": ["股价"],
        }
    )
    assert filled.to_dict()["success_criteria"] == ["有出处"]
    todo = GoalTodo.from_dict({"id": 1, "title": None, "done": 1, "evidence": None})
    assert todo.id == "1"
    assert todo.title == ""
    assert todo.done is True
    assert todo.evidence == ""
    assert set(GOAL_PHASES) == {phase.value for phase in GoalPhase}
    assert BotStatus.DRAFT == BOT_STATUS_DRAFT
    assert BotStatus.ACTIVE == BOT_STATUS_ACTIVE
    assert RoomKind.DM == ROOM_KIND_DM
    assert SpeakerKind.USER == "user"


def test_record_public_dicts_omit_owner() -> None:
    bot = BotRecord(
        id="b1",
        owner_key_hash="owner-a",
        product_id=BOTS_PRODUCT_ID,
        display_name="调查bot",
        slug="bot",
        status=BOT_STATUS_ACTIVE,
        soul_text="soul",
        persona_appendix="app",
        memory_session="bot:b1:private",
        created_at=1.0,
        updated_at=2.0,
    )
    assert bot.is_active() is True
    assert "owner" not in bot.to_public_dict()
    room = RoomRecord(
        id="r1",
        owner_key_hash="owner-a",
        product_id=BOTS_PRODUCT_ID,
        kind="dm",
        title="调查bot",
        member_bot_ids=("b1",),
        transcript_session="room:r1",
        goal_run_id=None,
        created_at=1.0,
        updated_at=1.0,
    )
    assert room.to_public_dict()["member_bot_ids"] == ["b1"]
    message = RoomMessage(
        id="m1",
        owner_key_hash="owner-a",
        product_id=BOTS_PRODUCT_ID,
        room_id="r1",
        speaker_kind="bot",
        speaker_id="b1",
        content="hi",
        taint=0,
        created_at=1.0,
    )
    assert "taint" not in message.to_public_dict()
    goal = GoalRun(
        id="g1",
        owner_key_hash="owner-a",
        product_id=BOTS_PRODUCT_ID,
        room_id="r1",
        phase="clarify",
        questions=("q",),
        answers=(),
        contract=GoalContract(objective="x"),
        todos=(GoalTodo(id="t1", title="a"),),
        budget=GoalBudget(),
        pause_reason="",
        created_at=1.0,
        updated_at=1.0,
    )
    public = goal.to_public_dict()
    assert public["contract"]["objective"] == "x"
    assert public["todos"][0]["id"] == "t1"
    assert isinstance(compile_bot_identity("x"), CompiledIdentity)


@pytest.mark.parametrize(
    ("text", "phase", "expected"),
    [
        ("", None, False),
        ("   ", None, False),
        ("你好", None, False),
        ("hello", None, False),
        ("谢谢", None, False),
        ("thank you", None, False),
        ("ok", None, False),
        ("好的", None, False),
        ("调查宇树的招股书风险", None, True),
        ("hi there friend", None, True),
        ("范围是港股", "clarify", False),
        ("继续执行", "executing", False),
        ("核验证据", "verifying", False),
        ("已确认后补充", "confirmed", False),
        ("新任务请调查", "blocked", True),
        ("新任务请调查", "done", True),
    ],
)
def test_looks_like_task_table(text: str, phase: str | None, expected: bool) -> None:
    assert looks_like_task(text, room_phase=phase) is expected


def test_contract_from_answers_and_clarify_questions() -> None:
    assert clarify_questions("anything") == DEFAULT_CLARIFY_QUESTIONS[:4]
    empty = contract_from_answers("", ())
    assert empty.objective == ""
    assert empty.success_criteria == ("对照目标给出可核对的证据",)
    filled = contract_from_answers(
        "  查风险  ",
        ("目标A", "标准B", "约束C", "不做D", "多余"),
    )
    assert filled.objective == "查风险"
    assert filled.success_criteria == ("标准B",)
    assert filled.constraints == ("约束C",)
    assert filled.out_of_scope == ("不做D",)
    fallback = contract_from_answers("", ("只用答案",))
    assert fallback.objective == "只用答案"


def test_consume_budget_and_verification_stop() -> None:
    goal = GoalRun(
        id="g1",
        owner_key_hash="owner-a",
        product_id=BOTS_PRODUCT_ID,
        room_id="r1",
        phase="executing",
        questions=(),
        answers=(),
        contract=GoalContract(objective="查X"),
        todos=(GoalTodo(id="t1", title="列缺口"), GoalTodo(id="t2", title="核来源", done=True)),
        budget=GoalBudget(max_echo_turns=2, max_tool_calls=2),
        pause_reason="",
        created_at=1.0,
        updated_at=1.0,
    )
    used = consume_budget(goal, echo_turns=1, tool_calls=1)
    assert used.budget.echo_turns_used == 1
    assert used.budget.tool_calls_used == 1
    with pytest.raises(BotsBudgetError, match="budget exhausted"):
        consume_budget(used, echo_turns=1)
    blocked = verification_stop(goal, evidence="   ")
    assert blocked.phase == "blocked"
    done = verification_stop(goal, evidence="来源交叉一致")
    assert done.phase == "done"
    assert done.todos[0].done is True
    assert done.todos[0].evidence == "来源交叉一致"
    assert done.todos[1].done is True
    bare = verification_stop(
        GoalRun(
            id="g2",
            owner_key_hash="owner-a",
            product_id=BOTS_PRODUCT_ID,
            room_id="r1",
            phase="verifying",
            questions=(),
            answers=(),
            contract=GoalContract(objective="查X"),
            todos=(),
            budget=GoalBudget(),
            pause_reason="x",
            created_at=1.0,
            updated_at=1.0,
        ),
        evidence="ok",
    )
    assert bare.todos[0].id == "t1"
    assert bare.pause_reason == ""


def test_require_clarify_lease_is_ask_user_only() -> None:
    require_clarify_lease(("ask_user",))
    with pytest.raises(BotsStateError, match="ask_user only"):
        require_clarify_lease(("ask_user", "shell"))
    with pytest.raises(BotsStateError):
        require_clarify_lease(())
    with pytest.raises(BotsStateError):
        require_clarify_lease(None)


def _bot(bot_id: str, name: str, *, slug: str, status: str = BOT_STATUS_ACTIVE) -> BotRecord:
    return BotRecord(
        id=bot_id,
        owner_key_hash="owner-a",
        product_id=BOTS_PRODUCT_ID,
        display_name=name,
        slug=slug,
        status=status,
        soul_text="soul",
        persona_appendix="",
        memory_session=f"bot:{bot_id}:private",
        created_at=1.0,
        updated_at=1.0,
    )


def test_mentioned_bots_and_tokens() -> None:
    left = _bot("b1", "调查bot", slug="investigator")
    right = _bot("b2", "研究员", slug="researcher")
    draft = _bot("b3", "草稿", slug="draft", status=BOT_STATUS_DRAFT)
    assert mentioned_tokens("请 @研究员 和 @investigator 看") == ("研究员", "investigator")
    assert mentioned_bots("", (left, right)) == ()
    named = mentioned_bots("请研究员补充", (left, right, draft))
    assert [bot.id for bot in named] == ["b2"]
    at_named = mentioned_bots("请 @investigator 先搜", (left, right))
    assert [bot.id for bot in at_named] == ["b1"]
    both = mentioned_bots("调查bot 和 研究员一起", (left, right, left))
    assert [bot.id for bot in both] == ["b1", "b2"]
    assert mentioned_bots("请 @草稿 加入", (draft,)) == ()


def test_should_speak_and_transcript_taint() -> None:
    assert should_speak(addressed=True) is True
    assert should_speak(addressed=False) is False
    assert should_speak(addressed=False, can_add_evidence=True) is True
    assert should_speak(addressed=False, can_correct=True) is True
    assert wrap_room_transcript([]) == ""
    message = RoomMessage(
        id="m1",
        owner_key_hash="owner-a",
        product_id=BOTS_PRODUCT_ID,
        room_id="r1",
        speaker_kind="user",
        speaker_id="owner-a",
        content="查X",
        taint=0,
        created_at=1.0,
    )
    wrapped = wrap_room_transcript([message])
    assert "查X" in wrapped
    peer = room_message_taint(peer=True)
    user = room_message_taint(peer=False)
    assert user & orin_taint.ROOM_SHARED
    assert user & orin_taint.USER_TURN
    assert peer & orin_taint.BOT_PEER
    assert not (user & orin_taint.BOT_PEER)


class _FakeRegistry:
    def __init__(self) -> None:
        self.specs: dict[str, ToolSpec] = {}
        self.handlers: dict[str, Any] = {}

    def register(self, spec: ToolSpec, handler: Any) -> None:
        self.specs[spec.name] = spec
        self.handlers[spec.name] = handler


class _Agent:
    def __init__(self, tmp_path: Path) -> None:
        self.settings = SimpleNamespace(state_dir=tmp_path / "state")
        self._bot_store: BotStore | None = None


def _runtime(tmp_path: Path, *, owner: str = "owner-a") -> RuntimeContext:
    workspace = tmp_path / "workspace"
    state = tmp_path / "state"
    workspace.mkdir(parents=True, exist_ok=True)
    state.mkdir(parents=True, exist_ok=True)
    return RuntimeContext(
        product_id=BOTS_PRODUCT_ID,
        channel="bots",
        owner_key_hash=owner,
        session_id="session-a",
        run_id="run-a",
        role="local-user",
        profile="default",
        capabilities=(),
        workspace=workspace,
        state_dir=state,
        fs_roots=(workspace,),
        surface="bots",
    )


def test_register_bots_tools_exposes_three_names(tmp_path: Path) -> None:
    registry = _FakeRegistry()
    agent = _Agent(tmp_path)
    register_bots_tools(registry, agent)
    assert set(registry.specs) == {"ask_user", "rooms_create", "bots_ask"}
    assert agent._bot_store is not None
    assert agent._bot_store.db_path == tmp_path / "state" / "bots.db"
    register_bots_tools(_FakeRegistry(), agent)
    assert agent._bot_store is not None


@pytest.mark.asyncio
async def test_ask_user_does_not_need_runtime_context(tmp_path: Path) -> None:
    registry = _FakeRegistry()
    register_bots_tools(registry, _Agent(tmp_path))
    result = await registry.handlers["ask_user"]("范围是什么？")
    assert result.success is True
    assert result.output == "ask_user: 范围是什么？"


@pytest.mark.asyncio
async def test_rooms_create_and_bots_ask_require_echo_context(tmp_path: Path) -> None:
    registry = _FakeRegistry()
    agent = _Agent(tmp_path)
    register_bots_tools(registry, agent)
    with pytest.raises(PermissionError, match="Echo runtime context"):
        await registry.handlers["rooms_create"]("组", [])
    with pytest.raises(PermissionError, match="Echo runtime context"):
        await registry.handlers["bots_ask"]("b1", "brief")


@pytest.mark.asyncio
async def test_rooms_create_and_bots_ask_bind_owner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    registry = _FakeRegistry()
    agent = _Agent(tmp_path)
    register_bots_tools(registry, agent)
    store = agent._bot_store
    assert store is not None
    left = store.create_bot(
        display_name="调查bot",
        owner_key_hash="owner-a",
        status="active",
        soul_text="soul-a",
    )
    right = store.create_bot(
        display_name="研究员",
        owner_key_hash="owner-a",
        status="active",
        soul_text="soul-b",
    )

    async def _local_runner(agent: Any, message: str, **kwargs: Any) -> Any:
        del agent, kwargs
        return SimpleNamespace(
            messages=[SimpleNamespace(role="assistant", content=f"peer:{message[-8:]}")]
        )

    monkeypatch.setattr("js.bots.service._default_turn_runner", _local_runner)
    token = set_runtime_context(_runtime(tmp_path))
    try:
        created = await registry.handlers["rooms_create"]("调查组", [left.id, right.id])
        assert created.success is True
        room_id = created.output.removeprefix("room:")
        asked = await registry.handlers["bots_ask"](right.id, "交叉验证", room_id)
        assert asked.success is True
        assert asked.output
        with pytest.raises(BotsError, match="requires a room"):
            await registry.handlers["bots_ask"](right.id, "交叉验证", "")
    finally:
        reset_runtime_context(token)
