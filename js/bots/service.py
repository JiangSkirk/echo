"""Bots orchestration. Every model/tool path enters Echo."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import replace
from pathlib import Path
from typing import Any

from js.bots.authority import refuse_ask_depth
from js.bots.exceptions import BotsBudgetError, BotsIsolationError, BotsStateError
from js.bots.harness import (
    clarify_questions,
    consume_budget,
    contract_from_answers,
    looks_like_task,
    require_clarify_lease,
    verification_stop,
)
from js.bots.identity import awakening_prompt, compile_bot_identity
from js.bots.models import (
    BOTS_PRODUCT_ID,
    BotRecord,
    GoalRun,
    RoomMessage,
    RoomRecord,
)
from js.bots.persona import (
    BotTurnBinding,
    bind_bot_turn,
    compute_prefix_id,
    current_ask_depth,
    last_assistant_text,
)
from js.bots.rooms import mentioned_bots, room_message_taint, should_speak, wrap_room_transcript
from js.bots.store import BotStore
from js.orin import taint as orin_taint

TurnRunner = Callable[..., Awaitable[Any]]


def bot_store_for(state_dir: Path) -> BotStore:
    return BotStore(Path(state_dir))


class BotService:
    """Owner-scoped bots/rooms/goals. Not a second runtime."""

    def __init__(self, store: BotStore, *, agent: Any | None = None) -> None:
        self.store = store
        self.agent = agent

    def _scope(self, owner_key_hash: str, product_id: str) -> tuple[str, str]:
        if not owner_key_hash or not product_id:
            raise BotsIsolationError("owner context is required")
        return owner_key_hash, product_id

    def create_draft(
        self,
        display_name: str,
        *,
        owner_key_hash: str,
        product_id: str = BOTS_PRODUCT_ID,
    ) -> BotRecord:
        compiled = compile_bot_identity(display_name)
        return self.store.create_bot(
            display_name=display_name,
            owner_key_hash=owner_key_hash,
            product_id=product_id,
            soul_text="",
            persona_appendix=compiled.persona_appendix,
        )

    async def awaken(
        self,
        bot_id: str,
        *,
        owner_key_hash: str,
        product_id: str = BOTS_PRODUCT_ID,
        turn_runner: TurnRunner | None = None,
    ) -> BotRecord:
        bot = self.store.require_bot(bot_id, owner_key_hash=owner_key_hash, product_id=product_id)
        compiled = compile_bot_identity(bot.display_name)
        prompt = awakening_prompt(bot.display_name, compiled)
        text = compiled.soul_seed
        runner = turn_runner or _default_turn_runner
        if self.agent is not None or turn_runner is not None:
            binding = BotTurnBinding(
                bot_id=bot.id,
                soul_text=compiled.soul_seed,
                persona_appendix=compiled.persona_appendix,
                memory_session=bot.memory_session,
                prefix_id=compute_prefix_id(bot.id, compiled.soul_seed, None),
            )
            try:
                with bind_bot_turn(binding):
                    state = await runner(
                        self.agent,
                        prompt,
                        channel="bots",
                        owner_key_hash=owner_key_hash,
                        session_id=bot.memory_session,
                        disable_tools=True,
                        surface="bots",
                    )
                text = last_assistant_text(state) or compiled.soul_seed
                _record_bots_usage(state, bot_id=bot.id, prefix_id=binding.prefix_id)
            except Exception:
                text = compiled.soul_seed
        return self.store.update_soul(
            bot.id,
            soul_text=text,
            owner_key_hash=owner_key_hash,
            product_id=product_id,
            activate=False,
            persona_appendix=compiled.persona_appendix,
        )

    def activate(
        self,
        bot_id: str,
        soul_text: str,
        *,
        owner_key_hash: str,
        product_id: str = BOTS_PRODUCT_ID,
    ) -> tuple[BotRecord, RoomRecord]:
        bot = self.store.update_soul(
            bot_id,
            soul_text=soul_text,
            owner_key_hash=owner_key_hash,
            product_id=product_id,
            activate=True,
        )
        room = self.store.ensure_dm_room(
            bot.id, owner_key_hash=owner_key_hash, product_id=product_id
        )
        return bot, room

    def suggest_roster(
        self,
        room_id: str,
        *,
        owner_key_hash: str,
        product_id: str = BOTS_PRODUCT_ID,
    ) -> list[BotRecord]:
        room = self.store.require_room(
            room_id, owner_key_hash=owner_key_hash, product_id=product_id
        )
        active = self.store.list_bots(
            owner_key_hash=owner_key_hash, product_id=product_id, status="active"
        )
        return [bot for bot in active if bot.id not in room.member_bot_ids]

    def pull_mentioned(
        self,
        room_id: str,
        text: str,
        *,
        owner_key_hash: str,
        product_id: str = BOTS_PRODUCT_ID,
    ) -> RoomRecord:
        room = self.store.require_room(
            room_id, owner_key_hash=owner_key_hash, product_id=product_id
        )
        active = self.store.list_bots(
            owner_key_hash=owner_key_hash, product_id=product_id, status="active"
        )
        named = mentioned_bots(text, active)
        extra = [bot.id for bot in named if bot.id not in room.member_bot_ids]
        if not extra:
            return room
        return self.store.add_room_members(
            room.id, extra, owner_key_hash=owner_key_hash, product_id=product_id
        )

    async def post_user_message(
        self,
        room_id: str,
        text: str,
        *,
        owner_key_hash: str,
        product_id: str = BOTS_PRODUCT_ID,
        confirm_suggested: list[str] | None = None,
        turn_runner: TurnRunner | None = None,
    ) -> dict[str, Any]:
        room = self.pull_mentioned(
            room_id, text, owner_key_hash=owner_key_hash, product_id=product_id
        )
        if confirm_suggested:
            room = self.store.add_room_members(
                room.id,
                confirm_suggested,
                owner_key_hash=owner_key_hash,
                product_id=product_id,
            )
        message = self.store.append_message(
            room.id,
            speaker_kind="user",
            speaker_id="user",
            content=text,
            taint=room_message_taint(peer=False),
            owner_key_hash=owner_key_hash,
            product_id=product_id,
        )
        phase = None
        goal: GoalRun | None = None
        if room.goal_run_id:
            goal = self.store.get_goal_run(
                room.goal_run_id, owner_key_hash=owner_key_hash, product_id=product_id
            )
            phase = goal.phase if goal is not None else None
        opened: GoalRun | None = None
        suggested: list[BotRecord] = []
        if looks_like_task(text, room_phase=phase):
            opened = self.store.create_goal_run(
                room.id,
                owner_key_hash=owner_key_hash,
                product_id=product_id,
                questions=list(clarify_questions(text)),
            )
            room = self.store.require_room(
                room.id, owner_key_hash=owner_key_hash, product_id=product_id
            )
            if len(room.member_bot_ids) == 1:
                suggested = self.suggest_roster(
                    room.id, owner_key_hash=owner_key_hash, product_id=product_id
                )
            await self._clarify_turn(
                room,
                opened,
                text,
                owner_key_hash=owner_key_hash,
                product_id=product_id,
                turn_runner=turn_runner,
            )
        elif goal is not None and goal.phase == "clarify":
            await self._record_clarify_answer(
                room,
                goal,
                text,
                owner_key_hash=owner_key_hash,
                product_id=product_id,
                turn_runner=turn_runner,
            )
        else:
            await self._room_replies(
                room,
                text,
                owner_key_hash=owner_key_hash,
                product_id=product_id,
                turn_runner=turn_runner,
            )
        room = self.store.require_room(
            room.id, owner_key_hash=owner_key_hash, product_id=product_id
        )
        goal = (
            self.store.get_goal_run(
                room.goal_run_id, owner_key_hash=owner_key_hash, product_id=product_id
            )
            if room.goal_run_id
            else None
        )
        return {
            "room": room.to_public_dict(),
            "message": message.to_public_dict(),
            "goal": goal.to_public_dict() if goal is not None else None,
            "suggested_roster": [bot.to_public_dict() for bot in suggested],
            "messages": [
                item.to_public_dict()
                for item in self.store.list_messages(
                    room.id, owner_key_hash=owner_key_hash, product_id=product_id
                )
            ],
        }

    async def confirm_contract(
        self,
        goal_id: str,
        *,
        owner_key_hash: str,
        product_id: str = BOTS_PRODUCT_ID,
        answers: list[str] | None = None,
        turn_runner: TurnRunner | None = None,
    ) -> GoalRun:
        goal = self.store.require_goal_run(
            goal_id, owner_key_hash=owner_key_hash, product_id=product_id
        )
        merged_answers = tuple(answers) if answers is not None else goal.answers
        contract = contract_from_answers(
            goal.contract.objective or (merged_answers[0] if merged_answers else ""),
            merged_answers,
        )
        goal = replace(goal, answers=merged_answers, contract=contract, phase="confirmed")
        return self.store.save_goal_run(goal)

    async def execute_goal(
        self,
        goal_id: str,
        *,
        owner_key_hash: str,
        product_id: str = BOTS_PRODUCT_ID,
        evidence: str = "",
        turn_runner: TurnRunner | None = None,
    ) -> GoalRun:
        goal = self.store.require_goal_run(
            goal_id, owner_key_hash=owner_key_hash, product_id=product_id
        )
        room = self.store.require_room(
            goal.room_id, owner_key_hash=owner_key_hash, product_id=product_id
        )
        goal = replace(goal, phase="executing")
        goal = self.store.save_goal_run(goal)
        try:
            goal = consume_budget(goal, echo_turns=1)
        except BotsBudgetError:
            blocked = replace(goal, phase="blocked", pause_reason="budget")
            return self.store.save_goal_run(blocked)
        await self._room_replies(
            room,
            f"执行目标：{goal.contract.objective}",
            owner_key_hash=owner_key_hash,
            product_id=product_id,
            turn_runner=turn_runner,
            force=True,
        )
        goal = replace(goal, phase="verifying")
        goal = verification_stop(goal, evidence=evidence)
        return self.store.save_goal_run(goal)

    async def ask_bot(
        self,
        target_bot_id: str,
        brief: str,
        *,
        room_id: str,
        owner_key_hash: str,
        product_id: str = BOTS_PRODUCT_ID,
        turn_runner: TurnRunner | None = None,
    ) -> RoomMessage:
        depth = current_ask_depth() + 1
        refuse_ask_depth(depth)
        target = self.store.require_bot(
            target_bot_id, owner_key_hash=owner_key_hash, product_id=product_id
        )
        if not target.is_active():
            raise BotsStateError("draft bots cannot join rooms")
        room = self.store.require_room(
            room_id, owner_key_hash=owner_key_hash, product_id=product_id
        )
        if target.id not in room.member_bot_ids:
            raise BotsStateError("bots_ask target is not a room member")
        reply = await self._bot_echo(
            target,
            room,
            brief,
            owner_key_hash=owner_key_hash,
            product_id=product_id,
            turn_runner=turn_runner,
            ask_depth=depth,
        )
        return self.store.append_message(
            room.id,
            speaker_kind="bot",
            speaker_id=target.id,
            content=reply,
            taint=room_message_taint(peer=True) | orin_taint.BOT_PEER,
            owner_key_hash=owner_key_hash,
            product_id=product_id,
        )

    async def _clarify_turn(
        self,
        room: RoomRecord,
        goal: GoalRun,
        text: str,
        *,
        owner_key_hash: str,
        product_id: str,
        turn_runner: TurnRunner | None,
    ) -> None:
        allowlist = ("ask_user",)
        require_clarify_lease(allowlist)
        speaker = self._primary_bot(room, owner_key_hash=owner_key_hash, product_id=product_id)
        questions = "\n".join(f"{index + 1}. {item}" for index, item in enumerate(goal.questions))
        prompt = f"用户任务：{text}\n请先用 ask_user 澄清，不要调用其它工具。\n{questions}"
        reply = await self._bot_echo(
            speaker,
            room,
            prompt,
            owner_key_hash=owner_key_hash,
            product_id=product_id,
            turn_runner=turn_runner,
            lease_tool_allowlist=allowlist,
        )
        self.store.append_message(
            room.id,
            speaker_kind="bot",
            speaker_id=speaker.id,
            content=reply,
            taint=room_message_taint(peer=True),
            owner_key_hash=owner_key_hash,
            product_id=product_id,
        )

    async def _record_clarify_answer(
        self,
        room: RoomRecord,
        goal: GoalRun,
        text: str,
        *,
        owner_key_hash: str,
        product_id: str,
        turn_runner: TurnRunner | None,
    ) -> None:
        answers = goal.answers + (text,)
        phase = "clarify" if len(answers) < 2 else "confirmed"
        contract = goal.contract
        if phase == "confirmed":
            contract = contract_from_answers(goal.contract.objective or text, answers)
        updated = replace(goal, answers=answers, phase=phase, contract=contract)
        self.store.save_goal_run(updated)
        if phase == "confirmed":
            self.store.append_message(
                room.id,
                speaker_kind="system",
                speaker_id="harness",
                content=f"GoalContract 已确认：{contract.objective}",
                taint=orin_taint.ROOM_SHARED,
                owner_key_hash=owner_key_hash,
                product_id=product_id,
            )

    async def _room_replies(
        self,
        room: RoomRecord,
        text: str,
        *,
        owner_key_hash: str,
        product_id: str,
        turn_runner: TurnRunner | None,
        force: bool = False,
    ) -> None:
        members = [
            self.store.require_bot(bot_id, owner_key_hash=owner_key_hash, product_id=product_id)
            for bot_id in room.member_bot_ids
        ]
        named = {bot.id for bot in mentioned_bots(text, members)}
        for bot in members:
            addressed = bot.id in named or len(members) == 1
            if not force and not should_speak(addressed=addressed):
                continue
            reply = await self._bot_echo(
                bot,
                room,
                text,
                owner_key_hash=owner_key_hash,
                product_id=product_id,
                turn_runner=turn_runner,
            )
            if reply.strip() == "NO_REPLY":
                continue
            self.store.append_message(
                room.id,
                speaker_kind="bot",
                speaker_id=bot.id,
                content=reply,
                taint=room_message_taint(peer=True),
                owner_key_hash=owner_key_hash,
                product_id=product_id,
            )

    def _primary_bot(
        self,
        room: RoomRecord,
        *,
        owner_key_hash: str,
        product_id: str,
    ) -> BotRecord:
        if not room.member_bot_ids:
            raise BotsStateError("room has no members")
        return self.store.require_bot(
            room.member_bot_ids[0], owner_key_hash=owner_key_hash, product_id=product_id
        )

    async def _bot_echo(
        self,
        bot: BotRecord,
        room: RoomRecord,
        user_text: str,
        *,
        owner_key_hash: str,
        product_id: str,
        turn_runner: TurnRunner | None,
        lease_tool_allowlist: tuple[str, ...] | None = None,
        ask_depth: int = 0,
    ) -> str:
        transcript = wrap_room_transcript(
            self.store.list_messages(room.id, owner_key_hash=owner_key_hash, product_id=product_id)
        )
        prompt = user_text
        if transcript:
            prompt = f"{transcript}\n\n当前请求：{user_text}"
        tools = None
        if self.agent is not None:
            getter = getattr(self.agent, "_get_tools_schema", None)
            if callable(getter):
                tools = getter(None)
        prefix_id = compute_prefix_id(bot.id, bot.soul_text, tools)
        frozen = None
        if tools:
            from js.models.usage import sorted_tools_schema

            frozen = tuple(sorted_tools_schema(list(tools)))
        binding = BotTurnBinding(
            bot_id=bot.id,
            soul_text=bot.soul_text,
            persona_appendix=bot.persona_appendix,
            room_id=room.id,
            memory_session=bot.memory_session,
            prefix_id=prefix_id,
            frozen_tools=frozen,
            ask_depth=ask_depth,
        )
        runner = turn_runner or _default_turn_runner
        if self.agent is None and turn_runner is None:
            return f"{bot.display_name}: {user_text}"
        with bind_bot_turn(binding):
            state = await runner(
                self.agent,
                prompt,
                channel="bots",
                owner_key_hash=owner_key_hash,
                session_id=room.transcript_session,
                surface="bots",
                lease_tool_allowlist=lease_tool_allowlist,
            )
        _record_bots_usage(state, bot_id=bot.id, prefix_id=prefix_id)
        return last_assistant_text(state) or "NO_REPLY"

    def cancel_goal(
        self,
        goal_id: str,
        *,
        owner_key_hash: str,
        product_id: str = BOTS_PRODUCT_ID,
    ) -> GoalRun:
        goal = self.store.require_goal_run(
            goal_id, owner_key_hash=owner_key_hash, product_id=product_id
        )
        if goal.phase in {"done", "blocked"}:
            return goal
        return self.store.save_goal_run(replace(goal, phase="blocked", pause_reason="cancelled"))


def _record_bots_usage(state: Any, *, bot_id: str, prefix_id: str) -> None:
    if state is None:
        return
    try:
        from js.bots.prefix import note_hit_rate, warmup_excluded_hit_rate_or_none
        from js.web.deps import get_stats_store
        from js.web.stats_store import buckets_for_state
    except Exception:
        return
    store = get_stats_store()
    if store is None:
        return
    buckets = buckets_for_state(state)
    exclude = buckets.cache_write > 0 and buckets.cache_read == 0
    usage_source = str(getattr(state, "usage_source", buckets.usage_source) or buckets.usage_source)
    try:
        store.record(
            str(getattr(state, "model", None) or "unknown"),
            "",
            buckets.input_total,
            buckets.output,
            cost=float(getattr(state, "cost_estimate", 0.0) or 0.0),
            cached_tokens=buckets.cache_read,
            session_id=str(getattr(state, "session_id", "") or ""),
            run_id=str(getattr(state, "run_id", "") or ""),
            uncached_input=buckets.uncached_input,
            cache_read=buckets.cache_read,
            cache_write=buckets.cache_write,
            output=buckets.output,
            reasoning=buckets.reasoning,
            input_total=buckets.input_total,
            usage_source=usage_source,
            prefix_id=prefix_id or buckets.prefix_id,
            bot_id=bot_id,
            exclude_from_hit_rate=exclude,
        )
        note_hit_rate(
            warmup_excluded_hit_rate_or_none(
                store.bots_hit_rows(bot_id=bot_id, prefix_id=prefix_id or buckets.prefix_id)
            ),
            bot_id=bot_id,
            prefix_id=prefix_id or buckets.prefix_id,
        )
    except Exception:
        return


async def _default_turn_runner(agent: Any, message: str, **kwargs: Any) -> Any:
    from js.echo.turn_runtime import run_echo_turn

    if agent is None:
        raise BotsStateError("Echo agent is required")
    return await run_echo_turn(agent, message, **kwargs)
