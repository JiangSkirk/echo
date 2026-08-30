"""Lattice compare for Orin policy / config changes (P1-3).

``compat`` is a strictly larger action space than ``conservative`` (non-allow
verdicts become allow+log). Widening requires an explicit operator setting or
human approval. Unknown comparisons fail closed toward approval (R5).

This module must not import ``js.orind``: the C1 worker omits the daemon.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Final, Literal

PROFILE_COMPAT: Final[str] = "compat"
PROFILE_CONSERVATIVE: Final[str] = "conservative"

# Higher rank = smaller action space.
_PROFILE_RANK: Final[dict[str, int]] = {
    PROFILE_COMPAT: 0,
    PROFILE_CONSERVATIVE: 1,
}

ChangeKind = Literal["narrow", "widen", "equal", "unknown"]

_POLICY_MUTATION_KEYS: Final[frozenset[str]] = frozenset(
    {
        "policy_profile",
        "orin.policy_profile",
        "policy.change",
        "orin",
        "tool_sinks",
        "_TOOL_SINKS",
        "TOOL_SINKS",
    }
)


class PolicyChangeError(PermissionError):
    """A widening or unknown policy mutation was not approved."""


@dataclass(frozen=True, slots=True)
class PolicyChangeDecision:
    allowed: bool
    kind: ChangeKind
    reason: str
    requires_approval: bool = False


def profile_name(value: Any) -> str:
    if value is None:
        return ""
    return str(getattr(value, "value", value) or "")


def compare_profiles(before: str, after: str) -> ChangeKind:
    """Compare two policy-profile names on the action-space lattice."""

    left = _PROFILE_RANK.get(profile_name(before))
    right = _PROFILE_RANK.get(profile_name(after))
    if left is None or right is None:
        return "unknown"
    if right > left:
        return "narrow"
    if right < left:
        return "widen"
    return "equal"


def evaluate_profile_change(
    *,
    before: str,
    after: str,
    explicit: bool = False,
    approved: bool = False,
) -> PolicyChangeDecision:
    """Decide whether a profile switch may proceed.

    Widening (``conservative`` → ``compat``) needs ``explicit`` operator
    configuration or ``approved`` human approval. Narrowing auto-passes.
    """

    kind = compare_profiles(before, after)
    if kind == "equal":
        return PolicyChangeDecision(True, kind, "policy profile unchanged")
    if kind == "narrow":
        return PolicyChangeDecision(True, kind, "policy profile narrowed")
    if kind == "widen":
        if approved:
            return PolicyChangeDecision(
                True, kind, "policy profile widened with approval", requires_approval=True
            )
        if explicit:
            return PolicyChangeDecision(
                True, kind, "policy profile widened by explicit operator setting"
            )
        return PolicyChangeDecision(
            False,
            kind,
            "widening policy_profile requires explicit config or approval",
            requires_approval=True,
        )
    return PolicyChangeDecision(
        False,
        "unknown",
        "unrecognized policy profile; fail closed toward approval",
        requires_approval=True,
    )


def policy_profile_explicitly_set(orin: Any) -> bool:
    """True when the operator set ``orin.policy_profile`` (not the field default)."""

    if orin is None:
        return False
    fields_set: set[str] = set(getattr(orin, "model_fields_set", set()))
    return "policy_profile" in fields_set


def compare_orin_config(before: dict[str, Any], after: dict[str, Any]) -> ChangeKind:
    """Lattice-compare two ``orin.*`` snapshots.

    ``shadow_mode=true`` is a widening (non-allow becomes allow). Unknown extra
    keys that change fail closed as ``unknown``.
    """

    kinds: set[ChangeKind] = set()
    before_profile = profile_name(before.get("policy_profile", PROFILE_CONSERVATIVE))
    after_profile = profile_name(after.get("policy_profile", PROFILE_CONSERVATIVE))
    kinds.add(compare_profiles(before_profile, after_profile))
    if bool(after.get("shadow_mode")) and not bool(before.get("shadow_mode")):
        kinds.add("widen")
    elif bool(before.get("shadow_mode")) and not bool(after.get("shadow_mode")):
        kinds.add("narrow")
    extra_keys = (set(before) | set(after)) - {
        "policy_profile",
        "shadow_mode",
        "enabled",
    }
    for key in extra_keys:
        if before.get(key) != after.get(key):
            kinds.add("unknown")
    if "widen" in kinds:
        return "widen"
    if "unknown" in kinds:
        return "unknown"
    if "narrow" in kinds:
        return "narrow"
    return "equal"


def evaluate_orin_config_change(
    *,
    before: dict[str, Any],
    after: dict[str, Any],
    explicit: bool = False,
    approved: bool = False,
) -> PolicyChangeDecision:
    kind = compare_orin_config(before, after)
    if kind == "equal":
        return PolicyChangeDecision(True, kind, "orin config unchanged")
    if kind == "narrow":
        return PolicyChangeDecision(True, kind, "orin config narrowed")
    if kind == "widen" and (approved or explicit):
        return PolicyChangeDecision(
            True,
            kind,
            "orin config widened with explicit setting or approval",
            requires_approval=approved,
        )
    return PolicyChangeDecision(
        False,
        kind,
        "orin config widening requires explicit setting or approval",
        requires_approval=True,
    )


def payload_mutates_orin_policy(payload: dict[str, Any] | None) -> bool:
    """True when an evolution (or similar) payload tries to touch Orin policy."""

    if not isinstance(payload, dict):
        return False
    stack: list[Any] = [payload]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            for key, value in item.items():
                lowered = str(key).strip()
                if lowered in _POLICY_MUTATION_KEYS or lowered.startswith("orin."):
                    return True
                if lowered == "policy_profile":
                    return True
                stack.append(value)
        elif isinstance(item, list):
            stack.extend(item)
    return False


def reject_evolution_policy_mutation(payload: dict[str, Any] | None) -> None:
    """Evolution is proposal-only and must never apply Orin policy edits."""

    if payload_mutates_orin_policy(payload):
        raise PolicyChangeError("evolution must not mutate Orin policy")


def evaluate_policy_change_intent(
    arguments: dict[str, Any] | None,
    *,
    current_profile: str,
    approved: bool = False,
) -> PolicyChangeDecision:
    """Lattice gate for a ``policy.change`` intent's arguments."""

    args = arguments or {}
    after = profile_name(args.get("policy_profile") or args.get("profile") or current_profile)
    return evaluate_profile_change(
        before=current_profile,
        after=after or current_profile,
        explicit=False,
        approved=approved,
    )
