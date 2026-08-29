"""Clarify → Contract → Execute → Verify. Outer loop; Echo stays the turn runtime."""

from __future__ import annotations

import re
from dataclasses import replace

from js.bots.exceptions import BotsBudgetError, BotsStateError
from js.bots.models import GoalBudget, GoalContract, GoalRun, GoalTodo

_CHITCHAT_RE = re.compile(
    r"^(你好|您好|嗨|哈喽|hi|hello|hey|谢谢|thank(?:s| you)?|ok|okay|好的|嗯+|哦+|[😀-🙏]+)$",
    re.IGNORECASE,
)

DEFAULT_CLARIFY_QUESTIONS: tuple[str, ...] = (
    "目标是什么，做成什么样算完成？",
    "范围和成功标准分别是什么？",
    "有哪些约束、时限或已知材料？",
    "明确不要做什么？",
)


def looks_like_task(text: str, *, room_phase: str | None) -> bool:
    """Fail-closed toward task. Follow-ups during clarify/executing are not new contracts."""

    if room_phase in {"clarify", "executing", "verifying", "confirmed"}:
        return False
    stripped = text.strip()
    if not stripped:
        return False
    return not (len(stripped) <= 12 and _CHITCHAT_RE.fullmatch(stripped))


def clarify_questions(user_text: str) -> tuple[str, ...]:
    del user_text
    return DEFAULT_CLARIFY_QUESTIONS[:4]


def contract_from_answers(objective: str, answers: tuple[str, ...]) -> GoalContract:
    criteria = tuple(item for item in answers[1:2] if item.strip()) or ("对照目标给出可核对的证据",)
    constraints = tuple(item for item in answers[2:3] if item.strip())
    out_of_scope = tuple(item for item in answers[3:4] if item.strip())
    return GoalContract(
        objective=objective.strip() or (answers[0] if answers else ""),
        success_criteria=criteria,
        constraints=constraints,
        out_of_scope=out_of_scope,
    )


def consume_budget(goal: GoalRun, *, echo_turns: int = 0, tool_calls: int = 0) -> GoalRun:
    budget = goal.budget
    next_budget = GoalBudget(
        max_echo_turns=budget.max_echo_turns,
        max_tool_calls=budget.max_tool_calls,
        max_elapsed_ms=budget.max_elapsed_ms,
        echo_turns_used=budget.echo_turns_used + echo_turns,
        tool_calls_used=budget.tool_calls_used + tool_calls,
        elapsed_ms_used=budget.elapsed_ms_used,
    )
    updated = replace(goal, budget=next_budget)
    if next_budget.exhausted():
        raise BotsBudgetError("GoalRun budget exhausted")
    return updated


def verification_stop(goal: GoalRun, *, evidence: str) -> GoalRun:
    """Hermes-style: no evidence means not done."""

    if not evidence.strip():
        return replace(goal, phase="blocked", pause_reason="verification_stop: no evidence")
    todos = tuple(
        GoalTodo(id=item.id, title=item.title, done=True, evidence=evidence)
        if not item.done
        else item
        for item in goal.todos
    )
    if not todos:
        todos = (
            GoalTodo(
                id="t1", title=goal.contract.objective or "goal", done=True, evidence=evidence
            ),
        )
    return replace(goal, phase="done", todos=todos, pause_reason="")


def require_clarify_lease(allowlist: tuple[str, ...] | None) -> None:
    if allowlist is None or set(allowlist) != {"ask_user"}:
        raise BotsStateError("clarify lease must be ask_user only")
