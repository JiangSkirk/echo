"""Slot source labels and bind-time policy (T4).

Policy runs when a plan step is bound, not only when a tool is later
called. A later dirty bit may only refuse remaining write/egress steps.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Final, Literal

from js.echo.plan_commit.narrowing import DIRTY_MIDTURN, is_write_or_egress_tool
from js.echo.plan_commit.plan import PlanStep

SourceLabel = Literal["user", "prior_tool", "extract", "unknown"]

_FILL_TO_LABEL: Final[dict[str, SourceLabel]] = {
    "literal": "user",
    "projection": "prior_tool",
    "extract": "extract",
}


def source_label_for_fill(fill_source: str) -> SourceLabel:
    return _FILL_TO_LABEL.get(fill_source, "unknown")


def bind_context_taint(messages: Sequence[Any]) -> int:
    """OR of tool-result taint. User/entry bits are not mid-turn dirty."""

    bits = 0
    for message in messages:
        if getattr(message, "role", "") != "tool":
            continue
        bits |= int(getattr(message, "taint", 0) or 0)
    return bits


def remaining_step_allowed(step: PlanStep, *, context_taint: int) -> bool:
    """True when this not-yet-executed step may still run.

    Read-only steps stay. Remaining write/egress is refused once messages
    carry a mid-turn injection dirty bit (tighten only).
    """

    if not is_write_or_egress_tool(step.tool):
        return True
    return not bool(context_taint & DIRTY_MIDTURN)
