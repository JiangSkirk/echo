from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from scripts.echo_full_audit import _benchmark_findings, collect_round_findings


def test_echo_full_audit_script_writes_ten_round_report(tmp_path: Path) -> None:
    output = tmp_path / "audit.md"
    final_output = tmp_path / "final.md"
    repository_report = (
        Path(__file__).resolve().parents[2] / "docs" / "echo" / "ECHO_FINAL_REPLACEMENT_REPORT.md"
    )
    original_repository_report = repository_report.read_bytes()

    proc = subprocess.run(
        [
            sys.executable,
            "scripts/echo_full_audit.py",
            "--rounds",
            "10",
            "--root",
            ".",
            "--output",
            str(output),
            "--final-report-output",
            str(final_output),
        ],
        cwd=Path(__file__).resolve().parents[2],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )

    assert proc.returncode == 0, proc.stdout
    text = output.read_text(encoding="utf-8")
    assert "# Echo 10 Round Audit" in text
    assert "Round 1" in text
    assert "Round 10" in text
    assert "Echo-only default" in text
    assert "Security matrix" in text
    assert "Stable release blockers" in text
    assert final_output.is_file()
    final_text = final_output.read_text(encoding="utf-8")
    assert "deterministic local fake provider" in final_text
    assert "does not include network or provider latency variance" in final_text
    assert "not DeepSeek or provider billing data" in final_text
    assert "Five-run API p95 median" in final_text
    assert "excel_precise_edit" in final_text
    assert "never overwrites the source or an existing output" in final_text
    assert repository_report.read_bytes() == original_repository_report


def test_benchmark_findings_expose_missing_concurrency_as_open(tmp_path: Path) -> None:
    artifact = tmp_path / "docs" / "security" / "ECHO_SLO_BENCHMARK.json"
    artifact.parent.mkdir(parents=True)
    artifact.write_text(
        json.dumps(
            {
                "modes": {
                    "echo": {
                        name: {"latency": {"n": 1, "p95_ms": 1.0}}
                        for name in (
                            "api_full_agent",
                            "api_wrapper_only",
                            "ws_message_wrapper",
                            "ws_stream_wrapper",
                        )
                    }
                },
                "token_comparison": {
                    "api_full_agent_prompt_p95_echo": 1.0,
                    "api_full_agent_prompt_p95_limit": 9_000.0,
                    "api_full_agent_prompt_within_limit": True,
                    "token_source": "estimated",
                },
                "recovery_probes": {
                    "journal_replay_10k_record_count": 10_000,
                    "journal_replay_10k_records_s": 0.1,
                    "bad_tail_recovery_ok": True,
                    "compaction_ok": True,
                    "compaction_latency_ms": 1.0,
                },
                "security_matrix": {"ok": True, "passed": 25, "total": 25},
            }
        ),
        encoding="utf-8",
    )

    findings = _benchmark_findings(tmp_path)

    assert any(
        finding.status == "open" and "concurrency" in finding.title.lower() for finding in findings
    )


def test_model_boundary_round_recognizes_effect_interpreter_stream_gate() -> None:
    root = Path(__file__).resolve().parents[2]

    model_boundary = collect_round_findings(root)[1][0]

    assert model_boundary.status == "fixed"
