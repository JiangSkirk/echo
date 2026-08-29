"""Persistent Bots surface models. Orchestration only — not a second runtime."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

BOTS_PRODUCT_ID: str = "js-agent"
BOT_STATUS_DRAFT: str = "draft"
BOT_STATUS_ACTIVE: str = "active"
ROOM_KIND_DM: str = "dm"
ROOM_KIND_GROUP: str = "group"

GOAL_PHASES: tuple[str, ...] = (
    "clarify",
    "confirmed",
    "executing",
    "verifying",
    "done",
    "blocked",
)


def _int_field(value: object, default: int) -> int:
    if value is None or value == "":
        return default
    if isinstance(value, bool) or not isinstance(value, int | float | str):
        return default
    return int(value)


class BotStatus(StrEnum):
    DRAFT = BOT_STATUS_DRAFT
    ACTIVE = BOT_STATUS_ACTIVE


class RoomKind(StrEnum):
    DM = ROOM_KIND_DM
    GROUP = ROOM_KIND_GROUP


class GoalPhase(StrEnum):
    CLARIFY = "clarify"
    CONFIRMED = "confirmed"
    EXECUTING = "executing"
    VERIFYING = "verifying"
    DONE = "done"
    BLOCKED = "blocked"


class SpeakerKind(StrEnum):
    USER = "user"
    BOT = "bot"
    SYSTEM = "system"


@dataclass(frozen=True, slots=True)
class GoalContract:
    objective: str
    success_criteria: tuple[str, ...] = ()
    constraints: tuple[str, ...] = ()
    out_of_scope: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "objective": self.objective,
            "success_criteria": list(self.success_criteria),
            "constraints": list(self.constraints),
            "out_of_scope": list(self.out_of_scope),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> GoalContract:
        payload = data or {}
        return cls(
            objective=str(payload.get("objective") or ""),
            success_criteria=tuple(str(item) for item in payload.get("success_criteria") or ()),
            constraints=tuple(str(item) for item in payload.get("constraints") or ()),
            out_of_scope=tuple(str(item) for item in payload.get("out_of_scope") or ()),
        )


@dataclass(frozen=True, slots=True)
class GoalBudget:
    max_echo_turns: int = 24
    max_tool_calls: int = 80
    max_elapsed_ms: int = 15 * 60 * 1000
    echo_turns_used: int = 0
    tool_calls_used: int = 0
    elapsed_ms_used: int = 0

    def to_dict(self) -> dict[str, int]:
        return {
            "max_echo_turns": self.max_echo_turns,
            "max_tool_calls": self.max_tool_calls,
            "max_elapsed_ms": self.max_elapsed_ms,
            "echo_turns_used": self.echo_turns_used,
            "tool_calls_used": self.tool_calls_used,
            "elapsed_ms_used": self.elapsed_ms_used,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> GoalBudget:
        payload = data or {}
        return cls(
            max_echo_turns=_int_field(payload.get("max_echo_turns"), 24),
            max_tool_calls=_int_field(payload.get("max_tool_calls"), 80),
            max_elapsed_ms=_int_field(payload.get("max_elapsed_ms"), 15 * 60 * 1000),
            echo_turns_used=_int_field(payload.get("echo_turns_used"), 0),
            tool_calls_used=_int_field(payload.get("tool_calls_used"), 0),
            elapsed_ms_used=_int_field(payload.get("elapsed_ms_used"), 0),
        )

    def remaining(self) -> GoalBudget:
        return GoalBudget(
            max_echo_turns=self.max_echo_turns,
            max_tool_calls=self.max_tool_calls,
            max_elapsed_ms=self.max_elapsed_ms,
            echo_turns_used=self.echo_turns_used,
            tool_calls_used=self.tool_calls_used,
            elapsed_ms_used=self.elapsed_ms_used,
        )

    def exhausted(self) -> bool:
        return (
            self.echo_turns_used >= self.max_echo_turns
            or self.tool_calls_used >= self.max_tool_calls
            or self.elapsed_ms_used >= self.max_elapsed_ms
        )


@dataclass(frozen=True, slots=True)
class GoalTodo:
    id: str
    title: str
    done: bool = False
    evidence: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "done": self.done,
            "evidence": self.evidence,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> GoalTodo:
        return cls(
            id=str(data.get("id") or ""),
            title=str(data.get("title") or ""),
            done=bool(data.get("done")),
            evidence=str(data.get("evidence") or ""),
        )


@dataclass(frozen=True, slots=True)
class BotRecord:
    id: str
    owner_key_hash: str
    product_id: str
    display_name: str
    slug: str
    status: str
    soul_text: str
    persona_appendix: str
    memory_session: str
    created_at: float
    updated_at: float

    def is_active(self) -> bool:
        return self.status == BOT_STATUS_ACTIVE

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "display_name": self.display_name,
            "slug": self.slug,
            "status": self.status,
            "soul_text": self.soul_text,
            "persona_appendix": self.persona_appendix,
            "memory_session": self.memory_session,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


@dataclass(frozen=True, slots=True)
class RoomRecord:
    id: str
    owner_key_hash: str
    product_id: str
    kind: str
    title: str
    member_bot_ids: tuple[str, ...]
    transcript_session: str
    goal_run_id: str | None
    created_at: float
    updated_at: float

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "title": self.title,
            "member_bot_ids": list(self.member_bot_ids),
            "transcript_session": self.transcript_session,
            "goal_run_id": self.goal_run_id,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


@dataclass(frozen=True, slots=True)
class RoomMessage:
    id: str
    owner_key_hash: str
    product_id: str
    room_id: str
    speaker_kind: str
    speaker_id: str
    content: str
    taint: int
    created_at: float

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "room_id": self.room_id,
            "speaker_kind": self.speaker_kind,
            "speaker_id": self.speaker_id,
            "content": self.content,
            "created_at": self.created_at,
        }


@dataclass(frozen=True, slots=True)
class GoalRun:
    id: str
    owner_key_hash: str
    product_id: str
    room_id: str
    phase: str
    questions: tuple[str, ...]
    answers: tuple[str, ...]
    contract: GoalContract
    todos: tuple[GoalTodo, ...]
    budget: GoalBudget
    pause_reason: str
    created_at: float
    updated_at: float

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "room_id": self.room_id,
            "phase": self.phase,
            "questions": list(self.questions),
            "answers": list(self.answers),
            "contract": self.contract.to_dict(),
            "todos": [item.to_dict() for item in self.todos],
            "budget": self.budget.to_dict(),
            "pause_reason": self.pause_reason,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


@dataclass(frozen=True, slots=True)
class CompiledIdentity:
    display_name: str
    slug: str
    specialty_key: str
    soul_seed: str
    persona_appendix: str
    fleet_persona_block: str = field(default="")
