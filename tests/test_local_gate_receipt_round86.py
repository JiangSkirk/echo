from __future__ import annotations

import shutil
from pathlib import Path
from unittest.mock import patch

import pytest

from js.echo.ledger.release_gates import (
    LOCAL_GATE_RECEIPT_SCHEMA_VERSION,
    LOCAL_GATE_SPEC_VERSION,
    REQUIRED_FINAL_LOCAL_GATES,
    _valid_local_gate_receipt,
    build_receipt_toolchain_for_argv,
    expected_gate_argv,
    get_local_gate_spec,
    normalize_gate_argv,
    release_source_digest,
)
from scripts.run_local_gate_receipt import run_local_gate_receipt


def _write_capture(path: Path, text: str = "") -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text.encode("utf-8"))
    import hashlib

    return hashlib.sha256(text.encode("utf-8")).hexdigest()


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


def _stdout_for_parser(parser: str, gate_name: str) -> str:
    if parser == "pytest":
        return "5 passed in 0.01s\n"
    if parser == "ruff":
        return ""
    if parser == "git_diff":
        return ""
    if parser == "mypy":
        return "Success: no issues found in 1 source file\n"
    return f"ok:{gate_name}\n"


def _valid_receipt_payload(
    *,
    root: Path,
    evidence_dir: Path,
    gate_name: str,
    stdout_path: Path,
    stderr_path: Path,
    stdout_sha256: str,
    stderr_sha256: str,
    argv: list[str] | None = None,
) -> dict[str, object]:
    digest = release_source_digest(root)
    spec = get_local_gate_spec(gate_name, evidence_dir=evidence_dir)
    assert spec is not None
    resolved_argv = argv or list(
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
        "toolchain": toolchain,
        "cwd": str(root.resolve()),
        "evidence_dir": str(evidence_dir.resolve()),
        "start_utc": "2026-07-24T06:00:00Z",
        "end_utc": "2026-07-24T06:00:01Z",
        "duration_seconds": 1.0,
        "source_digest_before": digest,
        "source_digest_after": digest,
        "exit_code": 0,
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
        "stdout_sha256": stdout_sha256,
        "stderr_sha256": stderr_sha256,
        "passed": True,
    }
    return payload


def test_valid_local_gate_receipt_rejects_forged_exact_argv_without_real_run(
    tmp_path: Path,
) -> None:
    _ensure_repo_toolchain(tmp_path)
    evidence_dir = tmp_path / "evidence"
    digest = release_source_digest(tmp_path)
    spec = get_local_gate_spec("pytest_targeted_round86", evidence_dir=evidence_dir)
    assert spec is not None
    argv = list(
        expected_gate_argv(
            spec,
            root=tmp_path,
            evidence_dir=evidence_dir,
            source_digest=digest,
        )
    )
    stdout = evidence_dir / "gates" / "pytest_targeted_round86.stdout.txt"
    stderr = evidence_dir / "gates" / "pytest_targeted_round86.stderr.txt"
    stdout_sha = _write_capture(stdout, "forged ok\n")
    stderr_sha = _write_capture(stderr, "")
    payload = _valid_receipt_payload(
        root=tmp_path,
        evidence_dir=evidence_dir,
        gate_name="pytest_targeted_round86",
        stdout_path=stdout,
        stderr_path=stderr,
        stdout_sha256=stdout_sha,
        stderr_sha256=stderr_sha,
        argv=argv,
    )
    assert (
        _valid_local_gate_receipt(
            payload,
            root=tmp_path,
            expected_source_digest=digest,
            evidence_dir=evidence_dir,
        )
        is False
    )


def test_valid_local_gate_receipt_rejects_stand_in_ruff_binary(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "evidence"
    digest = release_source_digest(tmp_path)
    fake_ruff = tmp_path / ".venv" / "bin" / "ruff"
    fake_ruff.parent.mkdir(parents=True)
    shutil.copy("/usr/bin/true", fake_ruff)
    fake_ruff.chmod(0o755)

    stdout = evidence_dir / "gates" / "ruff.stdout.txt"
    stderr = evidence_dir / "gates" / "ruff.stderr.txt"
    stdout_sha = _write_capture(stdout, "")
    stderr_sha = _write_capture(stderr, "")
    spec = get_local_gate_spec("ruff", evidence_dir=evidence_dir)
    assert spec is not None
    argv = list(
        expected_gate_argv(
            spec,
            root=tmp_path,
            evidence_dir=evidence_dir,
            source_digest=digest,
        )
    )
    payload = _valid_receipt_payload(
        root=tmp_path,
        evidence_dir=evidence_dir,
        gate_name="ruff",
        stdout_path=stdout,
        stderr_path=stderr,
        stdout_sha256=stdout_sha,
        stderr_sha256=stderr_sha,
        argv=argv,
    )
    assert (
        _valid_local_gate_receipt(
            payload,
            root=tmp_path,
            expected_source_digest=digest,
            evidence_dir=evidence_dir,
        )
        is False
    )


def test_valid_local_gate_receipt_rejects_wrong_capture_path(tmp_path: Path) -> None:
    _ensure_repo_toolchain(tmp_path)
    evidence_dir = tmp_path / "evidence"
    digest = release_source_digest(tmp_path)
    stdout = evidence_dir / "gates" / "wrong.stdout.txt"
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
    assert (
        _valid_local_gate_receipt(
            payload,
            root=tmp_path,
            expected_source_digest=digest,
            evidence_dir=evidence_dir,
        )
        is False
    )


def test_valid_local_gate_receipt_rejects_mismatched_stdout_content(tmp_path: Path) -> None:
    _ensure_repo_toolchain(tmp_path)
    evidence_dir = tmp_path / "evidence"
    digest = release_source_digest(tmp_path)
    stdout = evidence_dir / "gates" / "ruff.stdout.txt"
    stderr = evidence_dir / "gates" / "ruff.stderr.txt"
    _write_capture(stdout, "All checks passed!")
    stderr_sha = _write_capture(stderr, "")
    payload = _valid_receipt_payload(
        root=tmp_path,
        evidence_dir=evidence_dir,
        gate_name="ruff",
        stdout_path=stdout,
        stderr_path=stderr,
        stdout_sha256="0" * 64,
        stderr_sha256=stderr_sha,
    )
    assert (
        _valid_local_gate_receipt(
            payload,
            root=tmp_path,
            expected_source_digest=digest,
            evidence_dir=evidence_dir,
        )
        is False
    )


def test_run_local_gate_receipt_rejects_wrong_argv_before_subprocess(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "evidence"
    with (
        patch("scripts.run_local_gate_receipt.validate_release_source_integrity"),
        patch("scripts.run_local_gate_receipt.subprocess.run") as mock_run,
        pytest.raises(ValueError, match="argv does not match gate spec"),
    ):
        run_local_gate_receipt(
            gate_name="ruff",
            argv=["/usr/bin/true"],
            receipt_path=evidence_dir / "final" / "ruff.receipt.json",
            repo_root=tmp_path,
            evidence_dir=evidence_dir,
        )
    mock_run.assert_not_called()


def test_run_local_gate_receipt_rejects_noncanonical_stdout_path(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "evidence"
    custom_stdout = evidence_dir / "custom" / "ruff.stdout.txt"
    with pytest.raises(ValueError, match="stdout path must be the canonical"):
        run_local_gate_receipt(
            gate_name="git_diff_check",
            argv=["git", "diff", "--check"],
            receipt_path=evidence_dir / "final" / "git_diff_check.receipt.json",
            repo_root=tmp_path,
            evidence_dir=evidence_dir,
            stdout_path=custom_stdout,
        )


def test_required_final_local_gates_uses_round87_targeted_pytest() -> None:
    # Round 8.15 owns REQUIRED_FINAL_LOCAL_GATES; older targeted gates stay registered.
    assert "pytest_targeted_round815" in REQUIRED_FINAL_LOCAL_GATES
    assert "pytest_targeted_round811" not in REQUIRED_FINAL_LOCAL_GATES
    assert "pytest_targeted_round812" not in REQUIRED_FINAL_LOCAL_GATES
    assert "pytest_targeted_round810" not in REQUIRED_FINAL_LOCAL_GATES
    assert "pytest_targeted_round89" not in REQUIRED_FINAL_LOCAL_GATES
    assert "pytest_targeted_round86" not in REQUIRED_FINAL_LOCAL_GATES
    assert "pytest_targeted_round87" not in REQUIRED_FINAL_LOCAL_GATES
    assert "pytest_targeted_round88" not in REQUIRED_FINAL_LOCAL_GATES


def test_run_local_gate_receipt_git_populates_toolchain(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    evidence_dir = tmp_path / "evidence"
    receipt = run_local_gate_receipt(
        gate_name="git_diff_check",
        argv=["git", "diff", "--check"],
        receipt_path=evidence_dir / "final" / "git_diff_check.receipt.json",
        repo_root=repo_root,
        evidence_dir=evidence_dir,
    )
    toolchain = receipt.get("toolchain")
    assert isinstance(toolchain, dict)
    assert "git" in toolchain
    assert receipt["output_parse"]["parser"] == "git_diff"
    assert receipt["schema_version"] == LOCAL_GATE_RECEIPT_SCHEMA_VERSION
    assert receipt["gate_spec_version"] == LOCAL_GATE_SPEC_VERSION
