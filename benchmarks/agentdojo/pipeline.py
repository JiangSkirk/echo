"""Deterministic AgentDojo pipeline over the Orin policy table."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from js.echo.agentdojo.cases import AdapterCase
from js.echo.agentdojo.gate import asr_from_counts
from js.echo.agentdojo.mapping import MappingError, map_agentdojo_tool
from js.orin import taint as taint_mod
from js.orind.policy import PROFILE_CONSERVATIVE, VERDICT_ALLOW, evaluate


@dataclass(frozen=True, slots=True)
class CaseOutcome:
    case_id: str
    split: str
    js_tool: str
    verdict: str
    attack: bool
    attack_success: bool
    reason: str


@dataclass(frozen=True, slots=True)
class PipelineReport:
    asr: float
    attacks: int
    successes: int
    benign: int
    benign_allowed: int
    outcomes: tuple[CaseOutcome, ...]
    mapping_errors: tuple[str, ...]
    runtime: str
    suite: str
    model: str
    seeds: tuple[int, ...]
    budget_usd: float
    spent_usd: float
    budget_exceeded: bool


def evaluate_case(case: AdapterCase, *, profile: str = PROFILE_CONSERVATIVE) -> CaseOutcome:
    js_tool = map_agentdojo_tool(case.agentdojo_tool)
    decision = evaluate(
        tool_name=js_tool,
        context_taint=case.context_taint,
        arg_taint_bits=case.arg_taint,
        args_overlap_dirty=case.args_overlap_dirty,
        clearance=taint_mod.CLEARANCE_SECRET if case.context_taint & taint_mod.SECRET else 1,
        profile=profile,
    )
    attack_success = bool(case.attack and decision.verdict == VERDICT_ALLOW)
    return CaseOutcome(
        case_id=case.id,
        split=case.split,
        js_tool=js_tool,
        verdict=decision.verdict,
        attack=case.attack,
        attack_success=attack_success,
        reason=decision.reason,
    )


def run_pipeline(
    cases: tuple[AdapterCase, ...],
    *,
    suite: str,
    model: str,
    seeds: tuple[int, ...],
    budget_usd: float,
    cost_per_case_usd: float = 0.0,
    runtime: str = "offline_policy",
) -> PipelineReport:
    outcomes: list[CaseOutcome] = []
    mapping_errors: list[str] = []
    spent = 0.0
    budget_exceeded = False
    for case in cases:
        if budget_usd >= 0 and spent + cost_per_case_usd > budget_usd and cost_per_case_usd > 0:
            budget_exceeded = True
            break
        try:
            outcomes.append(evaluate_case(case))
        except MappingError as exc:
            mapping_errors.append(f"{case.id}: {exc}")
        spent += cost_per_case_usd
    attacks = sum(1 for item in outcomes if item.attack)
    successes = sum(1 for item in outcomes if item.attack_success)
    benign = sum(1 for item in outcomes if not item.attack)
    benign_allowed = sum(
        1 for item in outcomes if not item.attack and item.verdict == VERDICT_ALLOW
    )
    return PipelineReport(
        asr=asr_from_counts(attacks=attacks, successes=successes),
        attacks=attacks,
        successes=successes,
        benign=benign,
        benign_allowed=benign_allowed,
        outcomes=tuple(outcomes),
        mapping_errors=tuple(mapping_errors),
        runtime=runtime,
        suite=suite,
        model=model,
        seeds=seeds,
        budget_usd=budget_usd,
        spent_usd=round(spent, 6),
        budget_exceeded=budget_exceeded,
    )


def report_to_dict(report: PipelineReport) -> dict[str, Any]:
    return {
        "asr": report.asr,
        "attacks": report.attacks,
        "successes": report.successes,
        "benign": report.benign,
        "benign_allowed": report.benign_allowed,
        "mapping_errors": list(report.mapping_errors),
        "runtime": report.runtime,
        "suite": report.suite,
        "model": report.model,
        "seeds": list(report.seeds),
        "budget_usd": report.budget_usd,
        "spent_usd": report.spent_usd,
        "budget_exceeded": report.budget_exceeded,
        "outcomes": [
            {
                "id": item.case_id,
                "split": item.split,
                "js_tool": item.js_tool,
                "verdict": item.verdict,
                "attack": item.attack,
                "attack_success": item.attack_success,
                "reason": item.reason,
            }
            for item in report.outcomes
        ],
    }
