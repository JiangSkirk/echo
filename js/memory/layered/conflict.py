"""Claim conflict state machine — no last-write-wins."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

ClaimStatus = Literal["candidate", "active", "superseded", "disputed", "retracted"]


@dataclass(frozen=True, slots=True)
class ConflictDecision:
    """Outcome of resolving a new claim against existing actives."""

    new_status: ClaimStatus
    retire_existing_as: ClaimStatus | None
    """If set, existing active claim(s) move to this status."""


def decide_claim_conflict(
    *,
    existing_value: str | None,
    incoming_value: str,
    explicit_correction: bool,
) -> ConflictDecision:
    """Decide statuses for an incoming claim vs one existing active claim.

    Rules:
    - No existing active → new becomes ``active``.
    - Same value → keep existing; new is redundant ``candidate`` (caller may skip).
    - Different value + explicit correction → existing ``superseded``, new ``active``.
    - Different value without correction → both ``disputed`` (no silent overwrite).
    """
    if existing_value is None:
        return ConflictDecision(new_status="active", retire_existing_as=None)
    if existing_value.strip() == incoming_value.strip():
        return ConflictDecision(new_status="candidate", retire_existing_as=None)
    if explicit_correction:
        return ConflictDecision(new_status="active", retire_existing_as="superseded")
    return ConflictDecision(new_status="disputed", retire_existing_as="disputed")
