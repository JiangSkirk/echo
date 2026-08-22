"""Phase E.1 attack tests for gate receipt v4 contract closure.

These tests enforce the strict receipt schema required by Phase E.1:
- Missing required fields must fail.
- ``ok=true`` without ``passed`` must fail.
- Unknown fields must fail (closed-set key validation).
- stdout/stderr tampering must fail.
- Receipt end_utc after envelope generated_utc must fail.
- Duration / timestamp inconsistency must fail.
- Soak duration below threshold must fail.
- Source digest before/after mismatch must fail.
- Old-digest artifacts must fail.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from js.echo.ledger.release_gates import (
    REQUIRED_FINAL_LOCAL_GATES,
    _valid_local_gate_receipt,
    get_local_gate_spec,
    release_source_digest,
    validate_final_local_gate_evidence,
    write_toolchain_lock,
)
from tests.test_local_gate_receipt_round85 import (
    _ensure_repo_toolchain,
    _stdout_for_parser,
    _valid_receipt_payload,
    _write_capture,
)

_REPEATED_NEW_DIGEST = "f" * 64
_OLD_DIGEST = "0" * 64


def _make_valid_receipt(
    *,
    root: Path,
    evidence_dir: Path,
    gate_name: str = "ruff",
    stdout_text: str | None = None,
    stderr_text: str = "",
) -> dict[str, Any]:
    """Build a complete v4 receipt that passes validation."""
    _ensure_repo_toolchain(root)
    write_toolchain_lock(evidence_dir, root)
    digest = release_source_digest(root)
    spec = get_local_gate_spec(gate_name, evidence_dir=evidence_dir)
    assert spec is not None
    stdout_path = evidence_dir / "gates" / f"{gate_name}.stdout.txt"
    stderr_path = evidence_dir / "gates" / f"{gate_name}.stderr.txt"
    text = stdout_text if stdout_text is not None else _stdout_for_parser(
        spec.output_parse.parser, gate_name, source_digest=digest,
    )
    stdout_sha = _write_capture(stdout_path, text)
    stderr_sha = _write_capture(stderr_path, stderr_text)
    receipt = _valid_receipt_payload(
        root=root,
        evidence_dir=evidence_dir,
        gate_name=gate_name,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
        stdout_sha256=stdout_sha,
        stderr_sha256=stderr_sha,
    )
    return receipt


# ---------------------------------------------------------------------------
# 1. Missing required fields must fail
# ---------------------------------------------------------------------------

_REQUIRED_FIELDS = [
    "schema_version",
    "gate_spec_version",
    "gate_name",
    "argv",
    "normalized_argv",
    "coverage_scope",
    "output_parse",
    "toolchain",
    "toolchain_lock_sha256",
    "toolchain_before",
    "toolchain_after",
    "parse_result",
    "cwd",
    "start_utc",
    "end_utc",
    "duration_seconds",
    "source_digest_before",
    "source_digest_after",
    "exit_code",
    "stdout_path",
    "stderr_path",
    "stdout_sha256",
    "stderr_sha256",
    "passed",
]


@pytest.mark.parametrize("missing_field", _REQUIRED_FIELDS)
def test_missing_required_field_fails(
    missing_field: str, tmp_path: Path,
) -> None:
    root = tmp_path / "repo"
    evidence = tmp_path / "evidence"
    root.mkdir()
    evidence.mkdir()
    _ensure_repo_toolchain(root)
    receipt = _make_valid_receipt(root=root, evidence_dir=evidence)
    del receipt[missing_field]
    assert not _valid_local_gate_receipt(
        receipt,
        root=root,
        expected_source_digest=release_source_digest(root),
        evidence_dir=evidence,
    )


# ---------------------------------------------------------------------------
# 2. ok=true without passed must fail
# ---------------------------------------------------------------------------

def test_ok_true_without_passed_fails(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    evidence = tmp_path / "evidence"
    root.mkdir()
    evidence.mkdir()
    _ensure_repo_toolchain(root)
    receipt = _make_valid_receipt(root=root, evidence_dir=evidence)
    receipt["ok"] = True
    receipt["passed"] = False
    assert not _valid_local_gate_receipt(
        receipt,
        root=root,
        expected_source_digest=release_source_digest(root),
        evidence_dir=evidence,
    )


# ---------------------------------------------------------------------------
# 3. Unknown fields must fail
# ---------------------------------------------------------------------------

def test_unknown_field_fails(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    evidence = tmp_path / "evidence"
    root.mkdir()
    evidence.mkdir()
    _ensure_repo_toolchain(root)
    receipt = _make_valid_receipt(root=root, evidence_dir=evidence)
    receipt["unexpected_extra_field"] = "malicious"
    assert not _valid_local_gate_receipt(
        receipt,
        root=root,
        expected_source_digest=release_source_digest(root),
        evidence_dir=evidence,
    )


# ---------------------------------------------------------------------------
# 4. stdout/stderr tampering must fail
# ---------------------------------------------------------------------------

def test_stdout_tampering_fails(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    evidence = tmp_path / "evidence"
    root.mkdir()
    evidence.mkdir()
    _ensure_repo_toolchain(root)
    receipt = _make_valid_receipt(root=root, evidence_dir=evidence)
    stdout_path = evidence / "gates" / "ruff.stdout.txt"
    stdout_path.write_text("TAMPERED\n")
    assert not _valid_local_gate_receipt(
        receipt,
        root=root,
        expected_source_digest=release_source_digest(root),
        evidence_dir=evidence,
    )


def test_stderr_tampering_fails(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    evidence = tmp_path / "evidence"
    root.mkdir()
    evidence.mkdir()
    _ensure_repo_toolchain(root)
    receipt = _make_valid_receipt(root=root, evidence_dir=evidence)
    stderr_path = evidence / "gates" / "ruff.stderr.txt"
    stderr_path.write_text("UNEXPECTED STDERR\n")
    assert not _valid_local_gate_receipt(
        receipt,
        root=root,
        expected_source_digest=release_source_digest(root),
        evidence_dir=evidence,
    )


# ---------------------------------------------------------------------------
# 5. Receipt end_utc after envelope generated_utc must fail
# ---------------------------------------------------------------------------

def test_receipt_after_envelope_fails(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    evidence = tmp_path / "evidence"
    final_dir = evidence / "final"
    root.mkdir()
    final_dir.mkdir(parents=True)

    _ensure_repo_toolchain(root)
    write_toolchain_lock(evidence, root)
    digest = release_source_digest(root)

    for gate_name in REQUIRED_FINAL_LOCAL_GATES:
        spec = get_local_gate_spec(gate_name, evidence_dir=evidence)
        assert spec is not None
        stdout = evidence / "gates" / f"{gate_name}.stdout.txt"
        stderr = evidence / "gates" / f"{gate_name}.stderr.txt"
        stdout_text = _stdout_for_parser(
            spec.output_parse.parser, gate_name, source_digest=digest,
        )
        stdout_sha = _write_capture(stdout, stdout_text)
        stderr_sha = _write_capture(stderr, "")
        receipt = _valid_receipt_payload(
            root=root,
            evidence_dir=evidence,
            gate_name=gate_name,
            stdout_path=stdout,
            stderr_path=stderr,
            stdout_sha256=stdout_sha,
            stderr_sha256=stderr_sha,
        )
        # Set receipt end_utc to AFTER the envelope time
        receipt["end_utc"] = "2026-08-05T12:00:00Z"
        receipt["start_utc"] = "2026-08-05T11:00:00Z"
        receipt["duration_seconds"] = 3600.0
        (final_dir / f"{gate_name}.receipt.json").write_text(
            json.dumps(receipt, indent=2) + "\n",
        )

    # Write envelope with earlier timestamp
    envelope = {
        "schema_version": "js-agent-evidence-envelope-v1",
        "source_digest": digest,
        "manifest_sha256": "a" * 64,
        "manifest_relative": "sanitized-export/MANIFEST.sha256",
        "entry_count": 1,
        "generated_utc": "2026-08-05T10:00:00Z",
        "not_a_third_party_signature": True,
    }
    (evidence / "MANIFEST.envelope.json").write_text(
        json.dumps(envelope, indent=2) + "\n",
    )

    report = validate_final_local_gate_evidence(
        root,
        final_dir=final_dir,
        evidence_dir=evidence,
        expected_source_digest=digest,
    )
    assert not report.all_local_gates_passed
    assert any("envelope" in b for b in report.blockers)


# ---------------------------------------------------------------------------
# 6. Duration / timestamp inconsistency must fail
# ---------------------------------------------------------------------------

def test_duration_inconsistency_fails(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    evidence = tmp_path / "evidence"
    root.mkdir()
    evidence.mkdir()
    _ensure_repo_toolchain(root)
    receipt = _make_valid_receipt(root=root, evidence_dir=evidence)
    receipt["start_utc"] = "2026-08-05T10:00:00Z"
    receipt["end_utc"] = "2026-08-05T10:01:00Z"
    receipt["duration_seconds"] = 999.0
    assert not _valid_local_gate_receipt(
        receipt,
        root=root,
        expected_source_digest=release_source_digest(root),
        evidence_dir=evidence,
    )


def test_reversed_timestamps_fail(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    evidence = tmp_path / "evidence"
    root.mkdir()
    evidence.mkdir()
    _ensure_repo_toolchain(root)
    receipt = _make_valid_receipt(root=root, evidence_dir=evidence)
    receipt["start_utc"] = "2026-08-05T10:01:00Z"
    receipt["end_utc"] = "2026-08-05T10:00:00Z"
    receipt["duration_seconds"] = 1.0
    assert not _valid_local_gate_receipt(
        receipt,
        root=root,
        expected_source_digest=release_source_digest(root),
        evidence_dir=evidence,
    )


# ---------------------------------------------------------------------------
# 7. Soak duration below threshold must fail
# ---------------------------------------------------------------------------

def test_soak_duration_below_threshold_fails(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    evidence = tmp_path / "evidence"
    root.mkdir()
    evidence.mkdir()
    _ensure_repo_toolchain(root)
    receipt = _make_valid_receipt(
        root=root, evidence_dir=evidence, gate_name="soak_3600",
    )
    receipt["duration_seconds"] = 100.0
    receipt["end_utc"] = "2026-08-05T10:01:40Z"
    receipt["start_utc"] = "2026-08-05T10:00:00Z"
    assert not _valid_local_gate_receipt(
        receipt,
        root=root,
        expected_source_digest=release_source_digest(root),
        evidence_dir=evidence,
    )


# ---------------------------------------------------------------------------
# 8. Source digest before/after mismatch must fail
# ---------------------------------------------------------------------------

def test_source_digest_mismatch_fails(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    evidence = tmp_path / "evidence"
    root.mkdir()
    evidence.mkdir()
    _ensure_repo_toolchain(root)
    receipt = _make_valid_receipt(root=root, evidence_dir=evidence)
    receipt["source_digest_after"] = _OLD_DIGEST
    assert not _valid_local_gate_receipt(
        receipt,
        root=root,
        expected_source_digest=release_source_digest(root),
        evidence_dir=evidence,
    )


def test_source_drift_flag_fails(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    evidence = tmp_path / "evidence"
    root.mkdir()
    evidence.mkdir()
    _ensure_repo_toolchain(root)
    receipt = _make_valid_receipt(root=root, evidence_dir=evidence)
    receipt["source_drift"] = True
    assert not _valid_local_gate_receipt(
        receipt,
        root=root,
        expected_source_digest=release_source_digest(root),
        evidence_dir=evidence,
    )


# ---------------------------------------------------------------------------
# 9. Old-digest artifacts must fail
# ---------------------------------------------------------------------------

def test_old_digest_artifact_fails(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    evidence = tmp_path / "evidence"
    root.mkdir()
    evidence.mkdir()
    _ensure_repo_toolchain(root)
    receipt = _make_valid_receipt(root=root, evidence_dir=evidence)
    receipt["source_digest_before"] = _OLD_DIGEST
    receipt["source_digest_after"] = _OLD_DIGEST
    assert not _valid_local_gate_receipt(
        receipt,
        root=root,
        expected_source_digest=release_source_digest(root),
        evidence_dir=evidence,
    )
