"""orind policy table: dual profiles, default row, fixed priority.

The table is a verbatim transcription of D §6.2 (frozen), with the merged
review's fixed conflict priority:

    deny > export_gate > approval > allow

Stage A scope note: the export gate (SECRET egress) only lays down the
SECRET/clearance data path — a verdict of ``approval_required`` is
returned with an explicit ``needs_export_gate`` marker for the approval
card; two-phase export-gate execution itself is Stage B (per the Stage A
spec §7).

Iron law: taint is a detection signal, never an authorization. A clean
taint skips nothing — lease checks, path sandboxing, and origin
validation all stay; this table may only *add* ``approval_required`` /
``deny`` on top of them.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from js.orin import taint as t
from js.orin.sinks import (
    SINK_CONNECTOR,
    SINK_FS_OUTSIDE,
    SINK_FS_READ,
    SINK_FS_WRITE,
    SINK_MEMORY_WRITE,
    SINK_NETWORK_EGRESS,
    SINK_POLICY_CHANGE,
    SINK_SPAWN,
    sinks_for_tool,
)

# ---------------------------------------------------------------------------
# Verdicts (fixed vocabulary; strongest first)
# ---------------------------------------------------------------------------
VERDICT_DENY: Final[str] = "deny"
VERDICT_EXPORT_GATE: Final[str] = "export_gate"
VERDICT_APPROVAL: Final[str] = "approval_required"
VERDICT_ALLOW: Final[str] = "allow"

_PRIORITY: Final[dict[str, int]] = {
    VERDICT_ALLOW: 0,
    VERDICT_APPROVAL: 1,
    VERDICT_EXPORT_GATE: 2,
    VERDICT_DENY: 3,
}

PROFILE_CONSERVATIVE: Final[str] = "conservative"
PROFILE_COMPAT: Final[str] = "compat"
PROFILES: Final[frozenset[str]] = frozenset({PROFILE_CONSERVATIVE, PROFILE_COMPAT})

# Action sink bits and sinks_for_tool live in js.orin.sinks so Echo can
# classify tools without importing the orind daemon package.


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    """One policy-table evaluation outcome."""

    verdict: str
    reason: str
    needs_export_gate: bool = False
    matched_row: str = ""


def _strongest(*candidates: PolicyDecision) -> PolicyDecision:
    best = candidates[0]
    for candidate in candidates[1:]:
        if _PRIORITY[candidate.verdict] > _PRIORITY[best.verdict]:
            best = candidate
    return best


# ---------------------------------------------------------------------------
# Row evaluation (D §6.2 verbatim; conflict priority fixed)
# ---------------------------------------------------------------------------
def _row_fs_read(sinks: int) -> PolicyDecision | None:
    if sinks & SINK_FS_READ and not sinks & (SINK_FS_WRITE | SINK_NETWORK_EGRESS | SINK_SPAWN):
        return PolicyDecision(VERDICT_ALLOW, "read-workspace-file", matched_row="fs_read")
    return None


def _row_fs_write(
    sinks: int,
    context_taint: int,
    arg_taint_bits: int,
    profile: str,
) -> PolicyDecision | None:
    if sinks & SINK_FS_WRITE and not sinks & (SINK_NETWORK_EGRESS | SINK_SPAWN):
        if arg_taint_bits & t.DIRTY_FOR_WRITE:
            return PolicyDecision(
                VERDICT_APPROVAL, "write driven by untrusted content", matched_row="fs_write"
            )
        return PolicyDecision(VERDICT_ALLOW, "write-workspace-file", matched_row="fs_write")
    del context_taint, profile
    return None


def _row_shell(
    sinks: int,
    context_taint: int,
    args_overlap_dirty: bool,
) -> PolicyDecision | None:
    if sinks & SINK_SPAWN:
        if context_taint & t.WEB_CONTENT and args_overlap_dirty:
            return PolicyDecision(
                VERDICT_DENY,
                "shell arguments overlap untrusted web content",
                matched_row="shell",
            )
        if context_taint & t.USER_TURN:
            return PolicyDecision(VERDICT_ALLOW, "shell driven by user turn", matched_row="shell")
        return PolicyDecision(
            VERDICT_APPROVAL, "shell without user-turn drive", matched_row="shell"
        )
    return None


def _row_egress(
    sinks: int,
    context_taint: int,
    arg_taint_bits: int,
) -> PolicyDecision | None:
    if sinks & SINK_NETWORK_EGRESS:
        candidates: list[PolicyDecision] = []
        if context_taint & t.SECRET:
            # Stage A: data path only — the export gate itself is Stage B.
            candidates.append(
                PolicyDecision(
                    VERDICT_EXPORT_GATE,
                    "egress from a SECRET context needs the export gate",
                    needs_export_gate=True,
                    matched_row="egress_secret",
                )
            )
        if arg_taint_bits & t.EGRESS_SENSITIVE or arg_taint_bits & t.DIRTY_FOR_WRITE:
            candidates.append(
                PolicyDecision(
                    VERDICT_APPROVAL,
                    "egress arguments draw on memory or untrusted content",
                    matched_row="egress_dirty",
                )
            )
        if not candidates:
            candidates.append(
                PolicyDecision(VERDICT_ALLOW, "egress with clean arguments", matched_row="egress")
            )
        return _strongest(*candidates)
    return None


def _row_memory_write(sinks: int) -> PolicyDecision | None:
    if sinks & SINK_MEMORY_WRITE and not sinks & (SINK_NETWORK_EGRESS | SINK_SPAWN):
        return PolicyDecision(
            VERDICT_ALLOW, "memory-write (async review)", matched_row="memory_write"
        )
    return None


def _row_policy_change(
    sinks: int,
    context_taint: int,
) -> PolicyDecision | None:
    if sinks & SINK_POLICY_CHANGE:
        if context_taint & t.USER_TURN and context_taint == t.USER_TURN:
            return PolicyDecision(
                VERDICT_ALLOW,
                "policy change driven directly by the user",
                matched_row="policy_change",
            )
        return PolicyDecision(
            VERDICT_DENY,
            "policy/lease permission changes require direct user drive",
            matched_row="policy_change",
        )
    return None


def _row_host_control(tool_name: str) -> PolicyDecision | None:
    """Host admin control-plane tools already require HTTP admin + Echo lease.

    They are hidden from the model schema. Conservative must not stall
    first-run Host on the unmatched default row (that used to be hidden
    by a silent compat widen, which P1-3 forbids).
    """

    if tool_name.startswith("control_"):
        return PolicyDecision(
            VERDICT_ALLOW,
            "host control-plane (admin Echo lease)",
            matched_row="host_control",
        )
    return None


def _default_row(profile: str) -> PolicyDecision:
    if profile == PROFILE_COMPAT:
        return PolicyDecision(VERDICT_ALLOW, "compat default: allow + log", matched_row="default")
    return PolicyDecision(
        VERDICT_APPROVAL, "no policy row matched; conservative default", matched_row="default"
    )


def evaluate(
    *,
    tool_name: str,
    context_taint: int = 0,
    arg_taint_bits: int = 0,
    args_overlap_dirty: bool = False,
    clearance: int = 1,
    profile: str,
) -> PolicyDecision:
    """Evaluate the policy table; strongest matching verdict wins.

    Profile semantics per the Stage A spec (施工权威, overriding the D
    §6.2 dual-column reading): ``conservative`` enforces every row;
    ``compat`` evaluates the same table but degrades every non-allow
    verdict to allow-with-log — it is the pure rollback profile
    ("旧行为 + 记录").
    """

    if profile not in PROFILES:
        profile = PROFILE_CONSERVATIVE
    sinks = sinks_for_tool(tool_name)
    candidates = [
        _row_host_control(tool_name),
        _row_fs_read(sinks),
        _row_fs_write(sinks, context_taint, arg_taint_bits, profile),
        _row_shell(sinks, context_taint, args_overlap_dirty),
        _row_egress(sinks, context_taint, arg_taint_bits),
        _row_memory_write(sinks),
        _row_policy_change(sinks, context_taint),
    ]
    matched = [row for row in candidates if row is not None]
    if not matched:
        return _default_row(profile)
    decision = _strongest(*matched)
    if profile == PROFILE_COMPAT and decision.verdict != VERDICT_ALLOW:
        return PolicyDecision(
            verdict=VERDICT_ALLOW,
            reason=f"compat: {decision.verdict} ({decision.reason})",
            matched_row=decision.matched_row,
        )
    # Clearance may only escalate, never relax (monotonic re-check).
    if (
        clearance >= t.CLEARANCE_SECRET
        and sinks & SINK_NETWORK_EGRESS
        and _PRIORITY[decision.verdict] < _PRIORITY[VERDICT_EXPORT_GATE]
    ):
        decision = PolicyDecision(
            VERDICT_EXPORT_GATE,
            "SECRET clearance egress needs the export gate",
            needs_export_gate=True,
            matched_row=decision.matched_row or "clearance_secret",
        )
    if profile == PROFILE_COMPAT and decision.verdict != VERDICT_ALLOW:
        return PolicyDecision(
            verdict=VERDICT_ALLOW,
            reason=f"compat: {decision.verdict} ({decision.reason})",
            matched_row=decision.matched_row,
        )
    return decision


__all__ = [
    "PROFILE_COMPAT",
    "PROFILE_CONSERVATIVE",
    "PROFILES",
    "PolicyDecision",
    "SINK_CONNECTOR",
    "SINK_FS_OUTSIDE",
    "SINK_FS_READ",
    "SINK_FS_WRITE",
    "SINK_MEMORY_WRITE",
    "SINK_NETWORK_EGRESS",
    "SINK_POLICY_CHANGE",
    "SINK_SPAWN",
    "VERDICT_ALLOW",
    "VERDICT_APPROVAL",
    "VERDICT_DENY",
    "VERDICT_EXPORT_GATE",
    "evaluate",
    "sinks_for_tool",
]
