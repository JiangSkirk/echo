from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from js.echo.ledger.evidence_export import verify_export_receipt_log_closure
from js.echo.ledger.release_gates import format_release_result_line, parse_gate_stdout

DIGEST = "a" * 64


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _write_gate(
    export: Path,
    gate: str,
    *,
    stdout: str,
    parser: str = "ruff",
    parse_result: dict[str, object] | None = None,
) -> None:
    (export / "final").mkdir(parents=True, exist_ok=True)
    (export / "gates").mkdir(parents=True, exist_ok=True)
    stdout_path = export / "gates" / f"{gate}.stdout.txt"
    stderr_path = export / "gates" / f"{gate}.stderr.txt"
    stdout_path.write_text(stdout, encoding="utf-8")
    stderr_path.write_text("", encoding="utf-8")
    if parse_result is None:
        parse_result = parse_gate_stdout(
            parser,
            stdout,
            exit_code=0,
            require_exit_code_zero=True,
            expected_gate=gate,
        )
    receipt = {
        "gate_name": gate,
        "stdout_path": f"<EVIDENCE_ROOT>/gates/{gate}.stdout.txt",
        "stderr_path": f"<EVIDENCE_ROOT>/gates/{gate}.stderr.txt",
        "stdout_sha256": _sha(stdout),
        "stderr_sha256": _sha(""),
        "source_digest_before": DIGEST,
        "source_digest_after": DIGEST,
        "exit_code": 0,
        "output_parse": {
            "parser": parser,
            "require_exit_code_zero": True,
            "stderr_must_be_empty": False,
        },
        "parse_result": parse_result,
        "passed": True,
    }
    (export / "final" / f"{gate}.receipt.json").write_text(
        json.dumps(receipt, indent=2) + "\n", encoding="utf-8"
    )


def test_exact_gate_set_closure(tmp_path: Path) -> None:
    export = tmp_path / "sanitized-export"
    _write_gate(export, "ruff", stdout="All checks passed!\n")
    _write_gate(export, "mypy", stdout="Success: no issues found in 1 source file\n", parser="mypy")
    verify_export_receipt_log_closure(
        export_dir=export,
        expected_source_digest=DIGEST,
        required_gates=("ruff", "mypy"),
    )


def test_missing_required_gate_with_unknown_filler_fails(tmp_path: Path) -> None:
    export = tmp_path / "sanitized-export"
    _write_gate(export, "ruff", stdout="All checks passed!\n")
    _write_gate(export, "totally_wrong", stdout="All checks passed!\n")
    with pytest.raises(RuntimeError, match="gates/ set mismatch"):
        verify_export_receipt_log_closure(
            export_dir=export,
            expected_source_digest=DIGEST,
            required_gates=("ruff", "mypy"),
        )


def test_basename_alias_and_swapped_logs_fail(tmp_path: Path) -> None:
    export = tmp_path / "sanitized-export"
    _write_gate(export, "ruff", stdout="All checks passed!\n")
    _write_gate(export, "mypy", stdout="Success: no issues found in 1 source file\n", parser="mypy")
    # Basename-only alias in receipt path must fail exact path check.
    receipt = json.loads((export / "final" / "ruff.receipt.json").read_text(encoding="utf-8"))
    receipt["stdout_path"] = "ruff.stdout.txt"
    (export / "final" / "ruff.receipt.json").write_text(
        json.dumps(receipt, indent=2) + "\n", encoding="utf-8"
    )
    with pytest.raises(RuntimeError, match="exactly gates/"):
        verify_export_receipt_log_closure(
            export_dir=export,
            expected_source_digest=DIGEST,
            required_gates=("ruff", "mypy"),
        )

    # Restore and swap stdout contents between gates.
    _write_gate(export, "ruff", stdout="All checks passed!\n")
    _write_gate(export, "mypy", stdout="Success: no issues found in 1 source file\n", parser="mypy")
    ruff_out = (export / "gates" / "ruff.stdout.txt").read_text(encoding="utf-8")
    mypy_out = (export / "gates" / "mypy.stdout.txt").read_text(encoding="utf-8")
    (export / "gates" / "ruff.stdout.txt").write_text(mypy_out, encoding="utf-8")
    (export / "gates" / "mypy.stdout.txt").write_text(ruff_out, encoding="utf-8")
    with pytest.raises(RuntimeError, match="sha mismatch|parse_result"):
        verify_export_receipt_log_closure(
            export_dir=export,
            expected_source_digest=DIGEST,
            required_gates=("ruff", "mypy"),
        )


def test_extra_log_symlink_hardlink_fail(tmp_path: Path) -> None:
    export = tmp_path / "sanitized-export"
    _write_gate(export, "ruff", stdout="All checks passed!\n")
    (export / "gates" / "extra.stdout.txt").write_text("x\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="gates/ set mismatch"):
        verify_export_receipt_log_closure(
            export_dir=export,
            expected_source_digest=DIGEST,
            required_gates=("ruff",),
        )
    (export / "gates" / "extra.stdout.txt").unlink()
    os.link(export / "gates" / "ruff.stdout.txt", export / "gates" / "ruff.stdout.copy.txt")
    with pytest.raises(RuntimeError, match="gates/ set mismatch|hardlink|nlink"):
        verify_export_receipt_log_closure(
            export_dir=export,
            expected_source_digest=DIGEST,
            required_gates=("ruff",),
        )


def test_release_marker_gate_identity_in_closure(tmp_path: Path) -> None:
    export = tmp_path / "sanitized-export"
    line = format_release_result_line(gate="release_smoke")
    stdout = f"[OK] release_smoke\n{line}\n"
    _write_gate(
        export,
        "release_smoke",
        stdout=stdout,
        parser="release_markers",
    )
    verify_export_receipt_log_closure(
        export_dir=export,
        expected_source_digest=DIGEST,
        required_gates=("release_smoke",),
    )
    # Wrong gate identity in forged parse_result must fail reparse equality.
    receipt = json.loads(
        (export / "final" / "release_smoke.receipt.json").read_text(encoding="utf-8")
    )
    receipt["parse_result"] = {
        "parser": "release_markers",
        "ok": True,
        "ok_markers": 1,
        "json_ok": True,
        "payload": {
            "schema_version": "js-agent-release-result-v1",
            "ok": True,
            "gate": "echo_full_audit",
        },
        "expected_gate": "release_smoke",
    }
    (export / "final" / "release_smoke.receipt.json").write_text(
        json.dumps(receipt, indent=2) + "\n", encoding="utf-8"
    )
    with pytest.raises(RuntimeError, match="parse_result"):
        verify_export_receipt_log_closure(
            export_dir=export,
            expected_source_digest=DIGEST,
            required_gates=("release_smoke",),
        )
