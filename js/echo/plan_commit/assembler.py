"""Deterministic plan-commit argument assembly. Model arguments are not authority."""

from __future__ import annotations

import json
import re
from collections.abc import Awaitable, Callable
from contextvars import ContextVar, Token
from dataclasses import dataclass
from typing import Any, Final

from js.echo.plan_commit.labels import source_label_for_fill
from js.echo.plan_commit.plan import (
    PlanStep,
    SlotBinding,
    SourceLabel,
    is_slot_placeholder,
)
from js.echo.primitives import stable_payload_hash

PROJECTION_KEYS: Final[tuple[str, ...]] = ("path", "id", "url", "status")
_PATH_RE: Final[re.Pattern[str]] = re.compile(
    r"(?:[A-Za-z]:)?(?:/[\w.\-]+)+/?",
)
_URL_RE: Final[re.Pattern[str]] = re.compile(r"https?://[^\s\"'<>]+", re.I)

ExtractFn = Callable[[SlotBinding, str], Awaitable[Any]]

_assembled: ContextVar[dict[str, Any] | None] = ContextVar(
    "echo_plan_commit_assembled_arguments",
    default=None,
)
_assembled_tool: ContextVar[str | None] = ContextVar(
    "echo_plan_commit_assembled_tool",
    default=None,
)


class AssemblyError(ValueError):
    """A slot could not be filled without untrusted model tool-calls."""


@dataclass(frozen=True, slots=True)
class AssembledCall:
    tool: str
    arguments: dict[str, Any]
    filled: tuple[str, ...]
    slot_labels: tuple[SlotBinding, ...] = ()


def current_assembled_arguments() -> dict[str, Any] | None:
    bound = _assembled.get()
    return dict(bound) if bound is not None else None


def current_assembled_tool() -> str | None:
    return _assembled_tool.get()


def set_assembled_call(*, tool: str, arguments: dict[str, Any]) -> tuple[Token[Any], Token[Any]]:
    return _assembled.set(dict(arguments)), _assembled_tool.set(tool)


def reset_assembled_call(tokens: tuple[Token[Any], Token[Any]]) -> None:
    _assembled.reset(tokens[0])
    _assembled_tool.reset(tokens[1])


def arguments_match_assembled(
    presented: dict[str, Any],
    assembled: dict[str, Any],
) -> bool:
    """Model may not add keys or change already-filled slots."""

    extra = set(presented) - set(assembled)
    if extra:
        return False
    for key, value in assembled.items():
        if key in presented and presented[key] != value:
            return False
    return True


def tool_name_matches_assembled(presented: str, assembled_tool: str | None) -> bool:
    if assembled_tool is None:
        return True
    return presented == assembled_tool


def plan_commit_argument_error(tool_name: str, arguments: dict[str, Any]) -> str | None:
    """Deny model-supplied arguments that diverge from the assembled step."""

    assembled_tool = current_assembled_tool()
    assembled_args = current_assembled_arguments()
    if assembled_tool is None and assembled_args is None:
        return None
    if not tool_name_matches_assembled(tool_name, assembled_tool):
        return "plan-commit assembled tool name mismatch"
    if assembled_args is not None and not arguments_match_assembled(arguments, assembled_args):
        return "plan-commit assembled arguments mismatch"
    return None


def apply_assembled_arguments(
    tool_name: str, arguments: dict[str, Any]
) -> tuple[str | None, dict[str, Any]]:
    """Validate model suggestions, then use the assembled dict as authority."""

    error = plan_commit_argument_error(tool_name, arguments)
    if error is not None:
        return error, arguments
    assembled = current_assembled_arguments()
    if assembled is not None:
        return None, dict(assembled)
    return None, arguments


def assembled_args_schema(arguments: dict[str, Any]) -> str:
    return stable_payload_hash(arguments)


async def assemble_step(
    step: PlanStep,
    *,
    prior_outputs: tuple[str, ...],
    extract: ExtractFn,
) -> AssembledCall:
    """Fill one EXECUTE step. Projection first; extract is disable_tools only."""

    arguments = dict(step.arguments)
    filled: list[str] = []
    labeled: list[SlotBinding] = []
    slots = step.slots or _inferred_slots(step)
    for slot in slots:
        if slot.name in arguments and not _needs_fill(arguments[slot.name]):
            filled.append(slot.name)
            labeled.append(
                SlotBinding(
                    name=slot.name,
                    taint_policy=slot.taint_policy,
                    fill_source=slot.fill_source,
                    source_label="user",
                )
            )
            continue
        value, label = await _fill_slot(slot, prior_outputs=prior_outputs, extract=extract)
        arguments[slot.name] = value
        filled.append(slot.name)
        labeled.append(
            SlotBinding(
                name=slot.name,
                taint_policy=slot.taint_policy,
                fill_source=slot.fill_source,
                source_label=label,
            )
        )
    if step.needs_untrusted_fill() and any(
        slot.name not in arguments or _needs_fill(arguments[slot.name]) for slot in slots
    ):
        raise AssemblyError(f"step {step.tool} has unbound slots")
    if not _json_safe(arguments):
        raise AssemblyError("assembled arguments are not JSON-safe")
    leftover = [key for key, value in arguments.items() if is_slot_placeholder(value)]
    if leftover:
        raise AssemblyError(f"step {step.tool} has unbound slots: {sorted(leftover)}")
    return AssembledCall(
        tool=step.tool,
        arguments=arguments,
        filled=tuple(filled),
        slot_labels=tuple(labeled),
    )


async def _fill_slot(
    slot: SlotBinding,
    *,
    prior_outputs: tuple[str, ...],
    extract: ExtractFn,
) -> tuple[Any, SourceLabel]:
    if slot.fill_source == "literal":
        raise AssemblyError(f"slot {slot.name} is literal but missing")
    for source_text in reversed(prior_outputs):
        projected = project_value(source_text, slot.name)
        if projected is not None:
            return projected, "prior_tool"
    if slot.fill_source == "projection":
        raise AssemblyError(f"slot {slot.name} has no projection")
    extracted = await extract(slot, "\n".join(prior_outputs))
    if extracted is None:
        raise AssemblyError(f"slot {slot.name} extract returned null")
    return extracted, source_label_for_fill("extract")


def project_value(source_text: str, slot_name: str) -> Any | None:
    """Deterministic path/id/url/status projection. No model."""

    if not source_text.strip():
        return None
    parsed = _maybe_json(source_text)
    if isinstance(parsed, dict):
        if slot_name in parsed:
            return parsed[slot_name]
        for key in PROJECTION_KEYS:
            if slot_name == key and key in parsed:
                return parsed[key]
    if slot_name == "url":
        match = _URL_RE.search(source_text)
        if match is not None:
            return match.group(0)
    if slot_name == "path":
        match = _PATH_RE.search(source_text)
        if match is not None:
            return match.group(0)
    if slot_name == "status":
        status = _maybe_json(source_text)
        if isinstance(status, dict) and "status" in status:
            return status["status"]
        if source_text.strip().isdigit():
            return int(source_text.strip())
    if slot_name == "id":
        ident = _maybe_json(source_text)
        if isinstance(ident, dict) and "id" in ident:
            return ident["id"]
    return None


def _inferred_slots(step: PlanStep) -> tuple[SlotBinding, ...]:
    slots: list[SlotBinding] = []
    for key, value in step.arguments.items():
        if is_slot_placeholder(value):
            slots.append(
                SlotBinding(
                    name=key,
                    taint_policy="untrusted",
                    fill_source="projection",
                    source_label="prior_tool",
                )
            )
    return tuple(slots)


def _needs_fill(value: object) -> bool:
    return value is None or is_slot_placeholder(value)


def _maybe_json(text: str) -> Any:
    stripped = text.strip()
    start = stripped.find("{")
    end = stripped.rfind("}")
    if start >= 0 and end > start:
        try:
            return json.loads(stripped[start : end + 1])
        except json.JSONDecodeError:
            return None
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        return None


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
