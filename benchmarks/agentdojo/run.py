"""AgentDojo CI runner: nightly subset / weekly full, report always on.

Baseline period (no benchmarks/agentdojo/BASELINE.json): never blocks.
``--no-block`` can disable blocking after a baseline exists; reporting
cannot be turned off.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

from benchmarks.agentdojo.pipeline import report_to_dict, run_pipeline
from js.echo.agentdojo.cases import load_cases
from js.echo.agentdojo.gate import BASELINE_NAME, evaluate_gate, load_baseline

REPO_ROOT = Path(__file__).resolve().parents[2]
SUITE_PATH = Path(__file__).resolve().parent / "offline_suite.jsonl"
BASELINE_PATH = Path(__file__).resolve().parent / BASELINE_NAME
DEFAULT_OUTPUT = Path(__file__).resolve().parent / "last_report.json"


def live_runtime_status() -> str:
    if "agentdojo" in sys.modules:
        return "agentdojo_imported"
    try:
        __import__("agentdojo")
    except ImportError:
        return "offline_policy_subset"
    return "agentdojo_installed_not_wired"


def _parse_seeds(raw: str) -> tuple[int, ...]:
    parts = [item.strip() for item in raw.split(",") if item.strip()]
    if not parts:
        return (1,)
    return tuple(int(item) for item in parts)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="AgentDojo adapter report runner")
    parser.add_argument("--suite", choices=("subset", "full"), default="subset")
    parser.add_argument("--model", default=os.environ.get("AGENTDOJO_MODEL", "offline-policy"))
    parser.add_argument("--seeds", default=os.environ.get("AGENTDOJO_SEEDS", "1,2,3"))
    parser.add_argument(
        "--budget-usd",
        type=float,
        default=float(os.environ.get("AGENTDOJO_BUDGET_USD", "8")),
    )
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--no-block",
        action="store_true",
        help="Keep report-only even if a baseline file exists",
    )
    args = parser.parse_args(argv)

    all_cases = load_cases(SUITE_PATH)
    if args.suite == "subset":
        selected = tuple(case for case in all_cases if case.split == "ci")
    else:
        selected = all_cases
    runtime = live_runtime_status()
    cost = 0.0 if runtime == "offline_policy_subset" else 0.15
    report = run_pipeline(
        selected,
        suite=args.suite,
        model=str(args.model),
        seeds=_parse_seeds(str(args.seeds)),
        budget_usd=float(args.budget_usd),
        cost_per_case_usd=cost,
        runtime=runtime,
    )
    baseline = load_baseline(BASELINE_PATH)
    gate = evaluate_gate(
        asr=report.asr,
        baseline=baseline,
        allow_block=not args.no_block,
    )
    payload = {
        "generated_at": datetime.now(UTC).isoformat(),
        "gate": {
            "block": gate.block,
            "reason": gate.reason,
            "baseline_present": gate.baseline_present,
            "baseline_asr": gate.baseline_asr,
        },
        "report": report_to_dict(report),
        "held_out_excluded_from_gate": args.suite == "subset",
        "note": (
            "Held-out cases are reported on --suite full but never used to "
            "tune the policy table (R3). Missing BASELINE.json is report-only."
        ),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(payload["gate"] | {"asr": report.asr, "output": str(args.output)}))
    if report.mapping_errors:
        print("mapping_errors:", *report.mapping_errors, sep="\n  ")
        return 1
    if report.budget_exceeded:
        print("budget exceeded; run stopped and reported")
    if gate.block:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
