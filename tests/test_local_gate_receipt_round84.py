from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from js.echo.ledger.release_gates import (
    LOCAL_GATE_RECEIPT_SCHEMA_VERSION,
    LOCAL_GATE_SPEC_VERSION,
    REQUIRED_FINAL_LOCAL_GATES,
    FinalLocalGateEvidenceReport,
    _valid_local_gate_receipt,
    build_frozen_toolchain_lock,
    build_receipt_toolchain_for_argv,
    expected_gate_argv,
    get_local_gate_spec,
    normalize_gate_argv,
    parse_gate_stdout,
    release_source_digest,
    validate_final_local_gate_evidence,
    write_toolchain_lock,
)
from scripts.run_local_gate_receipt import run_local_gate_receipt


def _write_capture(path: Path, text: str = "") -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text.encode("utf-8"))
    import hashlib

    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _stdout_for_parser(parser: str, gate_name: str, *, source_digest: str | None = None) -> str:
    if parser == "pytest":
        return "5 passed in 0.01s\n"
    if parser == "ruff":
        return ""
    if parser == "git_diff":
        return ""
    if parser == "mypy":
        return "Success: no issues found in 1 source file\n"
    if parser == "release_markers":
        from js.echo.ledger.release_gates import format_release_result_line

        bindings = None
        if gate_name == "desktop_build":
            bindings = {
                "desktop_manifest_sha256": "1" * 64,
                "app_tree_sha256": "2" * 64,
                "app_sha256": "3" * 64,
            }
        elif gate_name == "tauri_webview_lifecycle":
            bindings = {
                "desktop_manifest_sha256": "1" * 64,
                "app_tree_sha256": "2" * 64,
                "app_sha256": "3" * 64,
                "result_sha256": "4" * 64,
                "harness_sha256": "5" * 64,
            }
        return (
            f"[OK] {gate_name}\n"
            f"{format_release_result_line(gate=gate_name, ok=True, bindings=bindings)}\n"
        )
    if parser == "readiness_json":
        from js.echo.ledger.release_gates import (
            READINESS_RESULT_SCHEMA_VERSION,
            READINESS_RESULT_SENTINEL,
        )

        digest = source_digest or ("a" * 64)
        return (
            READINESS_RESULT_SENTINEL
            + json.dumps(
                {
                    "schema_version": READINESS_RESULT_SCHEMA_VERSION,
                    "source_digest": digest,
                    "internal_ready": True,
                    "internal_blockers": [],
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        )
    return f"ok:{gate_name}\n"


def _ensure_repo_toolchain(root: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    for name in ("python", "ruff", "mypy"):
        source = repo_root / ".venv" / "bin" / name
        if not source.is_file():
            continue
        target = root / ".venv" / "bin" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(source, target)
        target.chmod(0o755)


def _valid_receipt_payload(
    *,
    root: Path,
    evidence_dir: Path,
    gate_name: str,
    stdout_path: Path,
    stderr_path: Path,
    stdout_sha256: str,
    stderr_sha256: str,
) -> dict[str, object]:
    digest = release_source_digest(root)
    spec = get_local_gate_spec(gate_name, evidence_dir=evidence_dir)
    assert spec is not None

    resolved_argv = list(
        expected_gate_argv(
            spec,
            root=root,
            evidence_dir=evidence_dir,
            source_digest=digest,
        )
    )
    normalized = normalize_gate_argv(
        resolved_argv,
        root=root,
        evidence_dir=evidence_dir,
        source_digest=digest,
    )
    toolchain = build_receipt_toolchain_for_argv(root, resolved_argv)
    frozen = build_frozen_toolchain_lock(root)
    lock_path = evidence_dir / "TOOLCHAIN.lock.json"
    if not lock_path.is_file():
        write_toolchain_lock(evidence_dir, root)
    from js.echo.ledger.evidence_export import redact_text

    def _redact_structure(value: object) -> object:
        if isinstance(value, str):
            return redact_text(value, repo_root=root, evidence_root=evidence_dir)
        if isinstance(value, dict):
            return {str(key): _redact_structure(item) for key, item in value.items()}
        if isinstance(value, list):
            return [_redact_structure(item) for item in value]
        return value

    redacted_frozen = _redact_structure(frozen)
    payload: dict[str, object] = {
        "schema_version": LOCAL_GATE_RECEIPT_SCHEMA_VERSION,
        "gate_spec_version": LOCAL_GATE_SPEC_VERSION,
        "gate_name": gate_name,
        "argv": resolved_argv,
        "normalized_argv": list(normalized),
        "coverage_scope": list(spec.coverage_scope),
        "output_parse": {
            "parser": spec.output_parse.parser,
            "require_exit_code_zero": spec.output_parse.require_exit_code_zero,
            "stderr_must_be_empty": spec.output_parse.stderr_must_be_empty,
        },
        "toolchain": _redact_structure(toolchain),
        "toolchain_lock_sha256": __import__("hashlib").sha256(lock_path.read_bytes()).hexdigest(),
        "toolchain_before": redacted_frozen,
        "toolchain_after": redacted_frozen,
        "parse_result": parse_gate_stdout(
            spec.output_parse.parser,
            stdout_path.read_text(encoding="utf-8"),
            exit_code=0,
            require_exit_code_zero=spec.output_parse.require_exit_code_zero,
            expected_gate=gate_name,
        ),
        "cwd": str(root.resolve()),
        "evidence_dir": str(evidence_dir.resolve()),
        "start_utc": "2026-07-23T06:00:00Z",
        "end_utc": "2026-07-23T07:00:05Z" if gate_name == "soak_3600" else "2026-07-23T06:00:01Z",
        "duration_seconds": 3605.0 if gate_name == "soak_3600" else 1.0,
        "source_digest_before": digest,
        "source_digest_after": digest,
        "exit_code": 0,
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
        "stdout_sha256": stdout_sha256,
        "stderr_sha256": stderr_sha256,
        "passed": True,
    }
    if (
        spec.output_parse.parser in {"slo_json", "soak_json", "e2e_json"}
        or gate_name == "echo_full_audit"
    ):
        from js.echo.ledger.release_gates import _artifact_path_from_argv

        artifact_path = _artifact_path_from_argv(
            resolved_argv,
            spec,
            root=root,
            evidence_dir=evidence_dir,
            source_digest=digest,
        )
        if artifact_path is not None:
            artifact_path.parent.mkdir(parents=True, exist_ok=True)
            body = b"{}" if gate_name != "echo_full_audit" else b"# Echo 10 Round Audit\n"
            artifact_path.write_bytes(body)
            import hashlib

            payload["artifact_sha256"] = hashlib.sha256(body).hexdigest()
    return payload


def _seed_final_receipts(final_dir: Path, evidence_dir: Path, root: Path) -> None:
    _ensure_repo_toolchain(root)
    write_toolchain_lock(evidence_dir, root)
    digest = release_source_digest(root)
    for gate_name in REQUIRED_FINAL_LOCAL_GATES:
        spec = get_local_gate_spec(gate_name, evidence_dir=evidence_dir)
        assert spec is not None
        stdout = evidence_dir / "gates" / f"{gate_name}.stdout.txt"
        stderr = evidence_dir / "gates" / f"{gate_name}.stderr.txt"
        stdout_text = _stdout_for_parser(spec.output_parse.parser, gate_name, source_digest=digest)
        stdout_sha = _write_capture(stdout, stdout_text)
        stderr_sha = _write_capture(stderr, "")
        receipt = _valid_receipt_payload(
            root=root,
            evidence_dir=evidence_dir,
            gate_name=gate_name,
            stdout_path=stdout,
            stderr_path=stderr,
            stdout_sha256=stdout_sha,
            stderr_sha256=stderr_sha,
        )
        (final_dir / f"{gate_name}.receipt.json").write_text(
            json.dumps(receipt, indent=2) + "\n",
            encoding="utf-8",
        )


def test_run_local_gate_receipt_success(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "evidence"
    with pytest.raises(ValueError, match="unknown gate_name"):
        run_local_gate_receipt(
            gate_name="echo",
            argv=["/bin/echo", "gate-ok"],
            receipt_path=evidence_dir / "final" / "echo.receipt.json",
            repo_root=tmp_path,
            evidence_dir=evidence_dir,
        )


def test_run_local_gate_receipt_marks_source_drift(tmp_path: Path) -> None:
    _ensure_repo_toolchain(tmp_path)
    digest = "a" * 64
    other = "b" * 64
    with (
        patch(
            "scripts.run_local_gate_receipt.release_source_digest",
            side_effect=[digest, other],
        ),
        patch("scripts.run_local_gate_receipt.validate_release_source_integrity"),
    ):
        receipt = run_local_gate_receipt(
            gate_name="git_diff_check",
            argv=["git", "diff", "--check"],
            receipt_path=tmp_path / "evidence" / "final" / "git_diff_check.receipt.json",
            repo_root=tmp_path,
            evidence_dir=tmp_path / "evidence",
        )
    assert receipt["source_drift"] is True
    assert receipt["passed"] is False
    assert receipt["source_digest_before"] == digest
    assert receipt["source_digest_after"] == other


def test_run_local_gate_receipt_failed_command(tmp_path: Path) -> None:
    with (
        patch("scripts.run_local_gate_receipt.validate_release_source_integrity"),
        pytest.raises(ValueError, match="argv does not match gate spec"),
    ):
        run_local_gate_receipt(
            gate_name="git_diff_check",
            argv=["/usr/bin/false"],
            receipt_path=tmp_path / "evidence" / "final" / "git_diff_check.receipt.json",
            repo_root=tmp_path,
            evidence_dir=tmp_path / "evidence",
        )


def test_valid_local_gate_receipt_rejects_source_drift_flag(tmp_path: Path) -> None:
    _ensure_repo_toolchain(tmp_path)
    evidence_dir = tmp_path / "evidence"
    digest = release_source_digest(tmp_path)
    stdout = evidence_dir / "gates" / "ruff.stdout.txt"
    stderr = evidence_dir / "gates" / "ruff.stderr.txt"
    stdout_sha = _write_capture(stdout, "")
    stderr_sha = _write_capture(stderr, "")
    payload = _valid_receipt_payload(
        root=tmp_path,
        evidence_dir=evidence_dir,
        gate_name="ruff",
        stdout_path=stdout,
        stderr_path=stderr,
        stdout_sha256=stdout_sha,
        stderr_sha256=stderr_sha,
    )
    payload["source_drift"] = True
    payload["passed"] = False
    assert (
        _valid_local_gate_receipt(
            payload,
            root=tmp_path,
            expected_source_digest=digest,
            evidence_dir=evidence_dir,
        )
        is False
    )


def test_validate_final_local_gate_evidence_accepts_complete_set(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    evidence_dir = tmp_path / "evidence"
    final_dir = evidence_dir / "final"
    final_dir.mkdir(parents=True)
    _seed_final_receipts(final_dir, evidence_dir, tmp_path)
    monkeypatch.setattr(
        "js.echo.ledger.release_gates.verify_release_readiness",
        lambda *args, **kwargs: type(
            "Report",
            (),
            {
                "internal_ready": True,
                "stable_ready": False,
                "passed": ("security_matrix_25",),
                "internal_blockers": (),
                "external_blockers": ("legal_fto_review_pending",),
            },
        )(),
    )
    monkeypatch.setattr(
        "js.echo.ledger.release_gates._valid_isolated_venv_e2e",
        lambda *args, **kwargs: True,
    )
    monkeypatch.setattr(
        "js.echo.ledger.release_gates._valid_echo_slo_benchmark",
        lambda *args, **kwargs: True,
    )
    monkeypatch.setattr(
        "js.echo.ledger.release_gates._valid_echo_live_acceptance",
        lambda *args, **kwargs: True,
    )
    # This test exercises the required-receipt set, not supervised-soak internals.
    # The shared legacy fixture writes `{}` for JSON artifacts, so explicitly
    # isolate the new mandatory combined-artifact validator in this success path.
    monkeypatch.setattr(
        "js.echo.ledger.release_gates._valid_supervised_soak_artifact",
        lambda *args, **kwargs: True,
    )
    monkeypatch.setattr(
        "js.echo.ledger.release_gates._valid_desktop_release_bindings",
        lambda *args, **kwargs: True,
    )
    report = validate_final_local_gate_evidence(
        tmp_path,
        final_dir=final_dir,
        evidence_dir=evidence_dir,
    )
    assert isinstance(report, FinalLocalGateEvidenceReport)
    assert report.all_local_gates_passed is True
    assert set(report.passed_gates) == set(REQUIRED_FINAL_LOCAL_GATES)
    assert report.blockers == ()


def test_validate_final_local_gate_evidence_rejects_missing_receipts(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "evidence"
    final_dir = evidence_dir / "final"
    final_dir.mkdir(parents=True)
    report = validate_final_local_gate_evidence(
        tmp_path,
        final_dir=final_dir,
        evidence_dir=evidence_dir,
    )
    assert report.all_local_gates_passed is False
    assert "final_gate_receipts_missing" in report.blockers


def test_validate_final_local_gate_evidence_rejects_internal_ready_substitute(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    _ensure_repo_toolchain(tmp_path)
    evidence_dir = tmp_path / "evidence"
    final_dir = evidence_dir / "final"
    final_dir.mkdir(parents=True)
    stdout = evidence_dir / "gates" / "git_diff_check.stdout.txt"
    stderr = evidence_dir / "gates" / "git_diff_check.stderr.txt"
    stdout_sha = _write_capture(stdout, "")
    stderr_sha = _write_capture(stderr, "")
    receipt = _valid_receipt_payload(
        root=tmp_path,
        evidence_dir=evidence_dir,
        gate_name="git_diff_check",
        stdout_path=stdout,
        stderr_path=stderr,
        stdout_sha256=stdout_sha,
        stderr_sha256=stderr_sha,
    )
    (final_dir / "git_diff_check.receipt.json").write_text(
        json.dumps(receipt, indent=2) + "\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "js.echo.ledger.release_gates.verify_release_readiness",
        lambda *args, **kwargs: type(
            "Report",
            (),
            {
                "internal_ready": True,
                "stable_ready": False,
                "passed": ("security_matrix_25",),
                "internal_blockers": (),
                "external_blockers": ("legal_fto_review_pending",),
            },
        )(),
    )
    report = validate_final_local_gate_evidence(
        tmp_path,
        final_dir=final_dir,
        evidence_dir=evidence_dir,
    )
    assert report.all_local_gates_passed is False
    assert "verify_release_readiness_not_substitute_for_local_gates" in report.blockers
    assert "ruff:receipt_missing" in report.blockers


def test_validate_final_local_gate_evidence_rejects_failed_final_receipt(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "evidence"
    final_dir = evidence_dir / "final"
    final_dir.mkdir(parents=True)
    _seed_final_receipts(final_dir, evidence_dir, tmp_path)
    ruff_receipt_path = final_dir / "ruff.receipt.json"
    payload = json.loads(ruff_receipt_path.read_text(encoding="utf-8"))
    payload["passed"] = False
    payload["exit_code"] = 1
    ruff_receipt_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    report = validate_final_local_gate_evidence(
        tmp_path,
        final_dir=final_dir,
        evidence_dir=evidence_dir,
    )
    assert report.all_local_gates_passed is False
    assert "ruff:not_passed" in report.blockers
