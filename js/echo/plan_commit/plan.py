"""Plan JSON schema, parse, and fail-closed rejection (R1)."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Final, Literal

FillSource = Literal["literal", "projection", "extract"]
TaintPolicy = Literal["trusted", "untrusted", "any"]
SourceLabel = Literal["user", "prior_tool", "extract", "unknown"]

_MAX_STEPS: Final[int] = 32
_MAX_TOOL_NAME: Final[int] = 128
_SLOT_REF_RE: Final[re.Pattern[str]] = re.compile(r"^\{[A-Za-z_][A-Za-z0-9_]*(:[^}]*)?\}$")
_FENCE_RE: Final[re.Pattern[str]] = re.compile(
    r"```(?:json)?\s*(\{.*\})\s*```",
    re.DOTALL,
)


class PlanError(ValueError):
    """Illegal plan: fail closed, execute nothing."""


@dataclass(frozen=True, slots=True)
class SlotBinding:
    """One BIND slot: name, taint policy, fill source, and source label."""

    name: str
    taint_policy: TaintPolicy
    fill_source: FillSource
    source_label: SourceLabel = "user"


@dataclass(frozen=True, slots=True)
class PlanStep:
    tool: str
    arguments: dict[str, Any]
    slots: tuple[SlotBinding, ...] = ()

    def needs_untrusted_fill(self) -> bool:
        if any(slot.fill_source != "literal" for slot in self.slots):
            return True
        return any(is_slot_placeholder(value) for value in self.arguments.values())


@dataclass(frozen=True, slots=True)
class Plan:
    steps: tuple[PlanStep, ...]

    def tool_names(self) -> tuple[str, ...]:
        return tuple(step.tool for step in self.steps)


PLAN_INSTRUCTIONS: Final[str] = (
    "Output a JSON object only, no tools, no prose. Schema: "
    '{"steps":[{"tool":"<name>","arguments":{...},"slots":'
    '[{"name":"<arg>","taint_policy":"trusted|untrusted|any",'
    '"fill_source":"literal|projection|extract",'
    '"source_label":"user|prior_tool|extract"}]}]}. '
    "Use literal arguments for values taken only from the user instruction. "
    "Omit steps you cannot bind from trusted text."
)

REMAINING_PLAN_INSTRUCTIONS: Final[str] = (
    "Executed steps already ran and must not be repeated. "
    "Output remaining steps only. Do not bind write, shell, or network tools. " + PLAN_INSTRUCTIONS
)


def parse_plan(text: str) -> Plan:
    """Parse a PLAN model response. Illegal JSON or shape raises PlanError."""

    if not isinstance(text, str) or not text.strip():
        raise PlanError("plan is empty")
    payload = _extract_json_object(text)
    if not isinstance(payload, dict):
        raise PlanError("plan must be a JSON object")
    extra = set(payload) - {"steps"}
    if extra:
        raise PlanError(f"plan has unknown keys: {sorted(extra)}")
    raw_steps = payload.get("steps")
    if not isinstance(raw_steps, list):
        raise PlanError("plan.steps must be a list")
    if len(raw_steps) > _MAX_STEPS:
        raise PlanError("plan exceeds step limit")
    steps: list[PlanStep] = []
    for index, raw in enumerate(raw_steps):
        steps.append(_parse_step(raw, index=index))
    return Plan(steps=tuple(steps))


def _extract_json_object(text: str) -> Any:
    stripped = text.strip()
    fenced = _FENCE_RE.search(stripped)
    candidate = fenced.group(1) if fenced is not None else stripped
    try:
        return json.loads(candidate)
    except json.JSONDecodeError as exc:
        start = stripped.find("{")
        end = stripped.rfind("}")
        if start >= 0 and end > start:
            try:
                return json.loads(stripped[start : end + 1])
            except json.JSONDecodeError:
                pass
        raise PlanError(f"plan is not valid JSON: {exc}") from exc


def _parse_step(raw: object, *, index: int) -> PlanStep:
    if not isinstance(raw, dict):
        raise PlanError(f"step {index} must be an object")
    extra = set(raw) - {"tool", "arguments", "slots"}
    if extra:
        raise PlanError(f"step {index} has unknown keys: {sorted(extra)}")
    tool = raw.get("tool")
    if not isinstance(tool, str) or not tool.strip() or len(tool) > _MAX_TOOL_NAME:
        raise PlanError(f"step {index} has an invalid tool name")
    if not tool.isidentifier() and not all(ch.isalnum() or ch in "._-" for ch in tool):
        raise PlanError(f"step {index} has an invalid tool name")
    arguments = raw.get("arguments", {})
    if arguments is None:
        arguments = {}
    if not isinstance(arguments, dict) or any(not isinstance(key, str) for key in arguments):
        raise PlanError(f"step {index} arguments must be an object")
    if not _json_safe(arguments):
        raise PlanError(f"step {index} arguments are not JSON-safe")
    slots = _parse_slots(raw.get("slots"), index=index)
    return PlanStep(tool=tool.strip(), arguments=dict(arguments), slots=slots)


def _parse_slots(raw: object, *, index: int) -> tuple[SlotBinding, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise PlanError(f"step {index} slots must be a list")
    slots: list[SlotBinding] = []
    seen: set[str] = set()
    for slot_index, item in enumerate(raw):
        if not isinstance(item, dict):
            raise PlanError(f"step {index} slot {slot_index} must be an object")
        extra = set(item) - {"name", "taint_policy", "fill_source", "source_label"}
        if extra:
            raise PlanError(f"step {index} slot {slot_index} has unknown keys")
        name = item.get("name")
        if not isinstance(name, str) or not name.strip():
            raise PlanError(f"step {index} slot {slot_index} has an invalid name")
        if name in seen:
            raise PlanError(f"step {index} has duplicate slot {name}")
        seen.add(name)
        taint_policy = item.get("taint_policy", "trusted")
        fill_source = item.get("fill_source", "literal")
        if taint_policy not in ("trusted", "untrusted", "any"):
            raise PlanError(f"step {index} slot {name} has an invalid taint_policy")
        if fill_source not in ("literal", "projection", "extract"):
            raise PlanError(f"step {index} slot {name} has an invalid fill_source")
        source_label = item.get("source_label")
        if source_label is None:
            source_label = {
                "literal": "user",
                "projection": "prior_tool",
                "extract": "extract",
            }[str(fill_source)]
        if source_label not in ("user", "prior_tool", "extract", "unknown"):
            raise PlanError(f"step {index} slot {name} has an invalid source_label")
        slots.append(
            SlotBinding(
                name=name,
                taint_policy=taint_policy,  # type: ignore[arg-type]
                fill_source=fill_source,  # type: ignore[arg-type]
                source_label=source_label,  # type: ignore[arg-type]
            )
        )
    return tuple(slots)


def is_slot_placeholder(value: object) -> bool:
    """True for `{slot}` / `{slot:hint}` refs and fill-descriptor objects."""

    if isinstance(value, str) and _SLOT_REF_RE.fullmatch(value.strip()):
        return True
    return isinstance(value, dict) and (
        "fill_source" in value or "slot" in value or "fill" in value
    )


def _json_safe(value: object, *, depth: int = 0) -> bool:
    if depth > 8:
        return False
    if value is None or isinstance(value, (bool, int, float, str)):
        return True
    if isinstance(value, list):
        return all(_json_safe(item, depth=depth + 1) for item in value)
    if isinstance(value, dict):
        return all(
            isinstance(key, str) and _json_safe(item, depth=depth + 1)
            for key, item in value.items()
        )
    return False
