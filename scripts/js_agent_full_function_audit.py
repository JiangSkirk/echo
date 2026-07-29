"""JS Agent full-function audit runner.

Produces machine-readable JSON plus a Markdown summary. The script is honest
about local-only evidence: external FTO, clean-room review, external security
audit, and real red-team signoff remain pending until independently completed.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_JSON_OUT = ROOT / "docs" / "security" / "JS_AGENT_FULL_FUNCTION_AUDIT.json"
DEFAULT_MD_OUT = ROOT / "docs" / "echo" / "JS_AGENT_FULL_FUNCTION_AUDIT.md"


@dataclass(frozen=True)
class AuditCheck:
    group: str
    name: str
    command: tuple[str, ...]
    risk: str = "P1"
    timeout_seconds: int = 120


def _py(*args: str) -> tuple[str, ...]:
    return (str(ROOT / ".venv" / "bin" / "python"), *args)


def build_audit_plan(rounds: int = 7, *, scratch_dir: Path | None = None) -> list[AuditCheck]:
    scratch = scratch_dir or ROOT / ".tmp" / "full-function-audit"
    benchmark_output = scratch / "ECHO_SLO_BENCHMARK.json"
    baseline_evidence = ROOT / "docs" / "security" / "ECHO_BASELINE_65CC545.json"
    return [
        AuditCheck("web_api", "HTTP chat/status/router regression", _py("-m", "pytest", "tests/web", "tests/echo/test_web_echo_on_e2e.py", "-q")),
        AuditCheck("websocket", "WebSocket message and stream regression", _py("-m", "pytest", "tests/echo/ledger/test_websocket_primary.py", "-q")),
        AuditCheck("stream_thinking", "Stream events and thinking frames", _py("-m", "pytest", "tests/test_stream_events_dispatch.py", "-q")),
        AuditCheck("tools", "Tool lease and registry boundary", _py("-m", "pytest", "tests/echo/test_tool_capability_context.py", "tests/test_progress_callback_redacts.py", "-q")),
        AuditCheck("attachments_vision", "Attachments and vision safety", _py("-m", "pytest", "tests/web/test_chat_router.py", "tests/echo/ledger/test_agent_model_gate.py", "-q")),
        AuditCheck("memory_skills", "Memory, capsule, and skills", _py("-m", "pytest", "tests/test_memory.py", "tests/test_session_capsule.py", "tests/test_skills.py", "-q")),
        AuditCheck("fleet_cron_setup", "Fleet, cron, setup, and static frontend", _py("-m", "pytest", "tests/test_orchestration.py", "tests/test_cron_nlp.py", "tests/test_setup_wizard.py", "tests/test_frontend_sanity.py", "-q")),
        AuditCheck(
            "work",
            "JS Agent Work Echo product smoke",
            _py(
                "scripts/js_work_echo_smoke.py",
                "--turns",
                "3",
                "--state-dir",
                str(scratch / "js-work"),
            ),
            timeout_seconds=180,
        ),
        AuditCheck("security", "Security and red-team regression", _py("-m", "pytest", "tests/test_sandbox.py", "tests/test_security.py", "tests/test_security_expanded.py", "tests/test_redteam.py", "-q"), risk="P0"),
        AuditCheck(
            "performance",
            "Echo benchmark SLO",
            _py(
                "scripts/echo_architecture_benchmark.py",
                "--iterations",
                "50",
                "--warmup",
                "10",
                "--enforce-slo",
                "--baseline",
                str(baseline_evidence),
                "--output",
                str(benchmark_output),
            ),
            timeout_seconds=240,
        ),
        AuditCheck(
            "release",
            "Echo ledger smoke",
            _py(
                "scripts/echo_ledger_smoke.py",
                "--turns",
                "5",
                "--state-dir",
                str(scratch / "echo-ledger-smoke"),
            ),
            timeout_seconds=180,
        ),
        AuditCheck("release", "Release smoke all", _py("scripts/release_smoke.py", "--all"), timeout_seconds=240),
        AuditCheck(
            "quality",
            "Ruff quality gate",
            _py("-m", "ruff", "check", "js", "js_work", "tests", "scripts"),
            timeout_seconds=180,
        ),
        AuditCheck(
            "quality",
            "Mypy quality gate",
            _py("-m", "mypy", "js", "js_work", "--no-error-summary"),
            timeout_seconds=240,
        ),
        *[
            AuditCheck(
                "code_audit",
                f"Round {idx} repository audit",
                _py(
                    "scripts/echo_full_audit.py",
                    "--rounds",
                    str(idx),
                    "--output",
                    str(scratch / f"audit-round-{idx}.md"),
                    "--final-report-output",
                    str(scratch / f"final-round-{idx}.md"),
                    "--fix-verification",
                ),
                timeout_seconds=180,
            )
            for idx in range(1, rounds + 1)
        ],
    ]


def _run_check(check: AuditCheck, *, dry_run: bool) -> dict[str, Any]:
    started = time.perf_counter()
    if dry_run:
        return {
            **asdict(check),
            "command": list(check.command),
            "status": "planned",
            "duration_seconds": 0.0,
            "returncode": None,
            "stdout_tail": "",
            "stderr_tail": "",
        }
    try:
        proc = subprocess.run(
            check.command,
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=check.timeout_seconds,
            check=False,
        )
        status = "passed" if proc.returncode == 0 else "failed"
        return {
            **asdict(check),
            "command": list(check.command),
            "status": status,
            "duration_seconds": round(time.perf_counter() - started, 3),
            "returncode": proc.returncode,
            "stdout_tail": proc.stdout[-4000:],
            "stderr_tail": proc.stderr[-4000:],
        }
    except subprocess.TimeoutExpired as exc:
        return {
            **asdict(check),
            "command": list(check.command),
            "status": "timeout",
            "duration_seconds": round(time.perf_counter() - started, 3),
            "returncode": None,
            "stdout_tail": (exc.stdout or "")[-4000:] if isinstance(exc.stdout, str) else "",
            "stderr_tail": (exc.stderr or "")[-4000:] if isinstance(exc.stderr, str) else "",
        }


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _write_markdown(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# JS Agent Full Function Audit",
        "",
        f"- Status: `{payload['status']}`",
        f"- Rounds: `{payload['rounds']}`",
        f"- Generated at: `{payload['generated_at']}`",
        "- GitHub stable external approvals remain pending: FTO, clean-room reviewer, external security audit, real red-team.",
        "",
        "## Checks",
        "",
        "| Group | Check | Risk | Status |",
        "|---|---|---|---|",
    ]
    for check in payload["checks"]:
        lines.append(
            f"| {check['group']} | {check['name']} | {check['risk']} | {check['status']} |"
        )
    lines.extend(["", "## 7-Round Code Audit Tracking", ""])
    for idx in range(1, int(payload["rounds"]) + 1):
        lines.append(f"- Round {idx}: recorded in `code_audit` checks when executed.")
    lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rounds", type=int, default=7)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--json-out", type=Path, default=DEFAULT_JSON_OUT)
    parser.add_argument("--md-out", type=Path, default=DEFAULT_MD_OUT)
    args = parser.parse_args(argv)

    with tempfile.TemporaryDirectory(prefix="js-agent-full-function-audit-") as temp_dir:
        checks = [
            _run_check(check, dry_run=args.dry_run)
            for check in build_audit_plan(args.rounds, scratch_dir=Path(temp_dir))
        ]
    failed = [check for check in checks if check["status"] not in {"passed", "planned"}]
    status = "dry_run" if args.dry_run else ("passed" if not failed else "failed")
    payload = {
        "status": status,
        "rounds": args.rounds,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "checks": checks,
        "external_stable_blockers": [
            "legal_fto_review_pending",
            "clean_room_reviewer_pending",
            "external_security_audit_pending",
            "real_redteam_report_pending",
        ],
    }
    if not args.dry_run:
        _write_json(args.json_out, payload)
        _write_markdown(args.md_out, payload)
    return 0 if status in {"passed", "dry_run"} else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
