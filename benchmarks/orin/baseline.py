"""Orin Stage A WP0 baseline measurements.

Records real numbers only. Does not modify lease MAC pre-images or issue /
consume semantics.

Usage:
    uv run python -m benchmarks.orin.baseline
    uv run python -m benchmarks.orin.baseline --skip-pytest
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import statistics
import subprocess
import sys
import tempfile
import time
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import psutil

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from benchmarks.runner import load_tasks, run_task  # noqa: E402
from js.echo.capability import LeaseAuthority  # noqa: E402

LEASE_ITERS = 10_000
LEASE_KEY = b"wp0-orin-baseline-mac-key!!"
LEASE_NOW_MS = 1_000_000
TASK_REPEATS = 3
COLD_START_RUNS = 10
LEDGER_ITERS = 1_000


def _percentile(samples: Sequence[float], p: float) -> float:
    if not samples:
        return 0.0
    ordered = sorted(samples)
    if len(ordered) == 1:
        return float(ordered[0])
    rank = (len(ordered) - 1) * p
    low = int(rank)
    high = min(low + 1, len(ordered) - 1)
    frac = rank - low
    return float(ordered[low] + (ordered[high] - ordered[low]) * frac)


def _summary_ms(samples: Sequence[float]) -> dict[str, Any]:
    values = [float(item) for item in samples]
    return {
        "n": len(values),
        "p50": round(_percentile(values, 0.50), 3),
        "p99": round(_percentile(values, 0.99), 3),
        "min": round(min(values), 3) if values else 0.0,
        "max": round(max(values), 3) if values else 0.0,
        "mean": round(statistics.fmean(values), 3) if values else 0.0,
        "samples": [round(item, 3) for item in values],
    }


def _git_meta() -> dict[str, Any]:
    def _run(args: list[str]) -> str:
        return subprocess.check_output(args, cwd=REPO_ROOT, text=True).strip()

    try:
        dirty = bool(
            subprocess.check_output(
                ["git", "status", "--porcelain"],
                cwd=REPO_ROOT,
                text=True,
            ).strip()
        )
        return {
            "branch": _run(["git", "branch", "--show-current"]),
            "head": _run(["git", "rev-parse", "HEAD"]),
            "dirty": dirty,
        }
    except (OSError, subprocess.CalledProcessError) as exc:
        return {"error": str(exc)}


def _measure_lease_batch(
    *,
    iterations: int,
    ledger_path: Path | None,
) -> dict[str, Any]:
    authority = LeaseAuthority(
        mac_key=LEASE_KEY,
        now_fn=lambda: LEASE_NOW_MS,
        ledger_path=ledger_path,
    )
    issue_s: list[float] = []
    consume_s: list[float] = []
    leases = []
    issue_t0 = time.perf_counter()
    for index in range(iterations):
        started = time.perf_counter()
        lease = authority.issue(
            owner_key_hash="wp0-owner",
            run_id=f"wp0-run-{index}",
            tool_name="echo",
            args_schema="schema-v1",
            resource_scope="scope-a",
            max_bytes=1024,
            max_duration_ms=1_000,
            ttl_ms=60_000,
            product_id="js-agent",
            session_id="wp0-session",
        )
        issue_s.append(time.perf_counter() - started)
        leases.append(lease)
    issue_total = time.perf_counter() - issue_t0

    consume_t0 = time.perf_counter()
    for lease in leases:
        started = time.perf_counter()
        authority.consume(lease, now=LEASE_NOW_MS)
        consume_s.append(time.perf_counter() - started)
    consume_total = time.perf_counter() - consume_t0

    def _ops(samples: list[float], total_s: float) -> dict[str, Any]:
        micros = [item * 1_000_000 for item in samples]
        return {
            "n": len(samples),
            "p50_us": round(_percentile(micros, 0.50), 3),
            "p99_us": round(_percentile(micros, 0.99), 3),
            "total_s": round(total_s, 6),
            "ops_per_s": round(len(samples) / total_s, 1) if total_s > 0 else 0.0,
        }

    return {
        "ledger_path": None if ledger_path is None else str(ledger_path),
        "issue": _ops(issue_s, issue_total),
        "consume": _ops(consume_s, consume_total),
    }


async def _measure_tasks() -> dict[str, Any]:
    tasks = load_tasks(REPO_ROOT / "benchmarks" / "tasks")
    per_task: dict[str, list[float]] = {task.id: [] for task in tasks}
    walls_ms: list[float] = []
    scores: dict[str, list[float]] = {task.id: [] for task in tasks}
    failures: list[dict[str, Any]] = []

    for _repeat in range(TASK_REPEATS):
        for task in tasks:
            with tempfile.TemporaryDirectory(prefix="orin-wp0-task-") as tmp:
                started = time.perf_counter()
                result = await run_task(task, Path(tmp), mock=True)
                wall_ms = (time.perf_counter() - started) * 1000
            walls_ms.append(wall_ms)
            per_task[task.id].append(wall_ms)
            scores[task.id].append(result.score)
            if not result.success:
                failures.append(
                    {
                        "task_id": task.id,
                        "score": result.score,
                        "details": result.details,
                    }
                )

    return {
        "task_count": len(tasks),
        "repeats": TASK_REPEATS,
        "note": (
            "End-to-end mock-provider task wall time, not isolated tool-handler "
            "latency. Scoring duration from runner.score_task is ignored."
        ),
        "overall_ms": _summary_ms(walls_ms),
        "per_task_ms": {task_id: _summary_ms(samples) for task_id, samples in per_task.items()},
        "scores": {
            task_id: {
                "mean": round(statistics.fmean(values), 3) if values else 0.0,
                "samples": values,
            }
            for task_id, values in scores.items()
        },
        "failures": failures,
    }


async def _run_cold_start_child(workspace: Path, state_dir: Path) -> int:
    from js.agent import JSAgent
    from js.config import JSSettings

    proc = psutil.Process()
    started = time.perf_counter()
    settings = JSSettings(workspace=workspace, state_dir=state_dir)
    agent = JSAgent(settings)
    elapsed_ms = (time.perf_counter() - started) * 1000
    rss_bytes = int(proc.memory_info().rss)
    await agent.close()
    print(json.dumps({"elapsed_ms": elapsed_ms, "rss_bytes": rss_bytes}), flush=True)
    return 0


def _measure_cold_start() -> dict[str, Any]:
    elapsed: list[float] = []
    rss: list[float] = []
    errors: list[str] = []
    for index in range(COLD_START_RUNS):
        with tempfile.TemporaryDirectory(prefix=f"orin-wp0-cold-{index}-") as tmp:
            tmp_path = Path(tmp)
            workspace = tmp_path / "workspace"
            state_dir = tmp_path / "state"
            workspace.mkdir()
            state_dir.mkdir()
            env = os.environ.copy()
            env["JS_WORKSPACE"] = str(workspace)
            env["JS_STATE_DIR"] = str(state_dir)
            env["PYTHONPATH"] = str(REPO_ROOT)
            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "benchmarks.orin.baseline",
                    "--cold-start-child",
                    "--workspace",
                    str(workspace),
                    "--state-dir",
                    str(state_dir),
                ],
                cwd=REPO_ROOT,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
        if completed.returncode != 0:
            errors.append(completed.stderr.strip() or completed.stdout.strip())
            continue
        payload = json.loads(completed.stdout.strip().splitlines()[-1])
        elapsed.append(float(payload["elapsed_ms"]))
        rss.append(float(payload["rss_bytes"]))
    return {
        "n_requested": COLD_START_RUNS,
        "elapsed_ms": _summary_ms(elapsed),
        "rss_bytes": _summary_ms(rss),
        "rss_mib": _summary_ms([item / (1024 * 1024) for item in rss]),
        "errors": errors,
    }


def _measure_pytest(*, skip: bool) -> dict[str, Any]:
    if skip:
        return {"skipped": True}
    started = time.perf_counter()
    completed = subprocess.run(
        ["uv", "run", "pytest", "tests/", "-q"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    elapsed_s = time.perf_counter() - started
    tail = "\n".join((completed.stdout + completed.stderr).splitlines()[-20:])
    return {
        "skipped": False,
        "returncode": completed.returncode,
        "elapsed_s": round(elapsed_s, 3),
        "summary_tail": tail,
    }


def _write_outputs(report: dict[str, Any]) -> tuple[Path, Path]:
    out_dir = REPO_ROOT / "benchmarks" / "orin"
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "WP0_BASELINE.json"
    md_path = out_dir / "WP0_BASELINE.md"
    json_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    tasks = report["tasks"]
    lease = report["lease_in_memory"]
    ledger = report["lease_jsonl_separate"]
    cold = report["cold_start"]
    pytest_rep = report["pytest"]
    lines = [
        "# Orin Stage A WP0 baseline",
        "",
        f"- generated_at: `{report['generated_at']}`",
        f"- git: `{report['git'].get('branch', '?')}` @ `{report['git'].get('head', '?')}`",
        f"- dirty: `{report['git'].get('dirty')}`",
        "",
        "These are measured numbers, not targets. Do not treat them as acceptance.",
        "",
        "## Mock task wall time (11 YAML tasks × 3 repeats)",
        "",
        f"- n = {tasks['overall_ms']['n']}",
        f"- p50 = **{tasks['overall_ms']['p50']} ms**",
        f"- p99 = **{tasks['overall_ms']['p99']} ms**",
        f"- mean = {tasks['overall_ms']['mean']} ms",
        f"- failures = {len(tasks['failures'])}",
        "",
        "## LeaseAuthority issue/consume (in-memory, primary)",
        "",
        f"- issue n={lease['issue']['n']}: p50 **{lease['issue']['p50_us']} µs**, "
        f"p99 {lease['issue']['p99_us']} µs, {lease['issue']['ops_per_s']} ops/s",
        f"- consume n={lease['consume']['n']}: p50 **{lease['consume']['p50_us']} µs**, "
        f"p99 {lease['consume']['p99_us']} µs, {lease['consume']['ops_per_s']} ops/s",
        "",
        "## LeaseAuthority JSONL path (separate, not the primary number)",
        "",
        f"- issue n={ledger['issue']['n']}: p50 {ledger['issue']['p50_us']} µs, "
        f"p99 {ledger['issue']['p99_us']} µs, {ledger['issue']['ops_per_s']} ops/s",
        f"- consume n={ledger['consume']['n']}: p50 {ledger['consume']['p50_us']} µs, "
        f"p99 {ledger['consume']['p99_us']} µs, {ledger['consume']['ops_per_s']} ops/s",
        "",
        "## Cold start ×10 (new process, JSAgent construct)",
        "",
        f"- elapsed p50 **{cold['elapsed_ms']['p50']} ms**, p99 {cold['elapsed_ms']['p99']} ms",
        f"- RSS p50 **{cold['rss_mib']['p50']} MiB**, p99 {cold['rss_mib']['p99']} MiB",
        "",
        "## pytest tests/ wall time",
        "",
    ]
    if pytest_rep.get("skipped"):
        lines.append("- skipped")
    else:
        lines.append(
            f"- elapsed **{pytest_rep['elapsed_s']} s**, returncode {pytest_rep['returncode']}"
        )
        lines.append("")
        lines.append("```")
        lines.append(str(pytest_rep.get("summary_tail", "")).rstrip())
        lines.append("```")
    lines.append("")
    lines.append("## Notes")
    lines.append("")
    lines.append(
        "- `is_lease_authority_handle` was already on the tree; WP0 did not edit "
        "`_canonical_lease_payload` or issue/consume semantics."
    )
    lines.append(
        "- JSONL microbench is smaller (1k) and reported separately because the "
        "existing ledger replay cost is O(n²) TECH_DEBT."
    )
    lines.append("")
    md_path.write_text("\n".join(lines), encoding="utf-8")
    return json_path, md_path


async def _main(args: argparse.Namespace) -> int:
    if args.cold_start_child:
        return await _run_cold_start_child(Path(args.workspace), Path(args.state_dir))

    with tempfile.TemporaryDirectory(prefix="orin-wp0-ledger-") as tmp:
        ledger_path = Path(tmp) / "echo_tool_lease.jsonl"
        report: dict[str, Any] = {
            "generated_at": datetime.now(UTC).isoformat(),
            "git": _git_meta(),
            "tasks": await _measure_tasks(),
            "lease_in_memory": _measure_lease_batch(
                iterations=LEASE_ITERS,
                ledger_path=None,
            ),
            "lease_jsonl_separate": _measure_lease_batch(
                iterations=LEDGER_ITERS,
                ledger_path=ledger_path,
            ),
            "cold_start": _measure_cold_start(),
            "pytest": _measure_pytest(skip=args.skip_pytest),
        }
    json_path, md_path = _write_outputs(report)
    print(f"wrote {json_path}")
    print(f"wrote {md_path}")
    pytest_rep = report["pytest"]
    if not pytest_rep.get("skipped") and pytest_rep.get("returncode") not in {0, None}:
        return int(pytest_rep["returncode"])
    if report["cold_start"]["errors"]:
        return 1
    return 0


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Orin Stage A WP0 baseline")
    parser.add_argument("--skip-pytest", action="store_true")
    parser.add_argument("--cold-start-child", action="store_true")
    parser.add_argument("--workspace", type=Path, default=None)
    parser.add_argument("--state-dir", type=Path, default=None)
    args = parser.parse_args()
    if args.cold_start_child and (args.workspace is None or args.state_dir is None):
        parser.error("--cold-start-child requires --workspace and --state-dir")
    return args


if __name__ == "__main__":
    sys.exit(asyncio.run(_main(_parse_args())))
