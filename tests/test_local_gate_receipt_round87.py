from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

import pytest

from js.echo.ledger.release_gates import (
    LOCAL_GATE_RECEIPT_SCHEMA_VERSION,
    LOCAL_GATE_SPEC_VERSION,
    REQUIRED_FINAL_LOCAL_GATES,
    TOOLCHAIN_LOCK_SCHEMA_VERSION,
    _valid_local_gate_receipt,
    build_frozen_toolchain_lock,
    get_local_gate_spec,
    parse_gate_stdout,
    release_source_digest,
    snapshot_final_gate_inputs,
    write_final_validator_receipt,
    write_toolchain_lock,
)
from scripts.run_local_gate_receipt import run_local_gate_receipt
from tests.test_local_gate_receipt_round85 import (
    _ensure_repo_toolchain,
    _valid_receipt_payload,
    _write_capture,
)


def test_round87_gate_versions_and_required_target() -> None:
    assert LOCAL_GATE_RECEIPT_SCHEMA_VERSION == "js-agent-local-gate-receipt-v4"
    assert LOCAL_GATE_SPEC_VERSION == "js-agent-local-gate-spec-v3"
    # Round 8.15 owns REQUIRED_FINAL_LOCAL_GATES; round87 gate specs remain registered.
    assert "pytest_targeted_round815" in REQUIRED_FINAL_LOCAL_GATES
    assert "pytest_targeted_round811" not in REQUIRED_FINAL_LOCAL_GATES
    assert "pytest_targeted_round812" not in REQUIRED_FINAL_LOCAL_GATES
    assert "pytest_targeted_round810" not in REQUIRED_FINAL_LOCAL_GATES
    assert "pytest_targeted_round89" not in REQUIRED_FINAL_LOCAL_GATES
    assert "pytest_targeted_round87" not in REQUIRED_FINAL_LOCAL_GATES
    assert "pytest_targeted_round88" not in REQUIRED_FINAL_LOCAL_GATES
    assert get_local_gate_spec("pytest_targeted_round87", evidence_dir=Path("/tmp/e")) is not None


def test_frozen_toolchain_has_complete_provenance() -> None:
    lock = build_frozen_toolchain_lock(Path(__file__).resolve().parents[1])
    assert lock["schema_version"] == TOOLCHAIN_LOCK_SCHEMA_VERSION
    assert set(lock["tools"]) == {"python", "ruff", "mypy", "git"}
    assert all(entry["provenance"] for entry in lock["tools"].values())


def test_structured_parsers_fail_closed() -> None:
    assert parse_gate_stdout(
        "pytest", "2 passed, 1 skipped in 0.1s\n", exit_code=0, require_exit_code_zero=True
    )["ok"]
    assert not parse_gate_stdout(
        "pytest", "# 2 passed\n", exit_code=0, require_exit_code_zero=True
    )["ok"]
    assert not parse_gate_stdout(
        "mypy", "internal error\n", exit_code=0, require_exit_code_zero=True
    )["ok"]
    spec = get_local_gate_spec("strict_readiness", evidence_dir=Path("/tmp/evidence"))
    assert spec is not None and spec.output_parse.parser == "readiness_json"
    from js.echo.ledger.release_gates import (
        READINESS_RESULT_SCHEMA_VERSION,
        READINESS_RESULT_SENTINEL,
    )

    digest = "a" * 64
    sentinel = READINESS_RESULT_SENTINEL + json.dumps(
        {
            "schema_version": READINESS_RESULT_SCHEMA_VERSION,
            "source_digest": digest,
            "internal_ready": True,
            "internal_blockers": [],
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    noisy = (
        "2026-07-24 17:21:21 [info     ] RLIMIT_AS is not enforced on macOS; "
        "sandbox memory cap relies on the psutil polling monitor\n"
        f"{sentinel}\n"
    )
    assert parse_gate_stdout("readiness_json", noisy, exit_code=0, require_exit_code_zero=True)[
        "ok"
    ]
    assert not parse_gate_stdout(
        "readiness_json",
        noisy + "ERROR boom\n",
        exit_code=0,
        require_exit_code_zero=True,
    )["ok"]
    assert not parse_gate_stdout(
        "readiness_json",
        "not json\n",
        exit_code=0,
        require_exit_code_zero=True,
    )["ok"]
    assert not parse_gate_stdout(
        "readiness_json",
        '{"internal_ready": true, "internal_blockers": []}\n',
        exit_code=0,
        require_exit_code_zero=True,
    )["ok"]


def test_runner_rejects_wrong_argv_before_subprocess(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    with (
        patch("scripts.run_local_gate_receipt.validate_release_source_integrity"),
        patch("scripts.run_local_gate_receipt.subprocess.run") as run,
        pytest.raises(ValueError, match="argv does not match gate spec"),
    ):
        run_local_gate_receipt(
            gate_name="ruff",
            argv=["/usr/bin/true"],
            receipt_path=evidence / "final" / "ruff.receipt.json",
            repo_root=tmp_path,
            evidence_dir=evidence,
        )
    run.assert_not_called()


def test_true_standing_in_for_ruff_fails_runner_and_validator(tmp_path: Path) -> None:
    fake_ruff = tmp_path / ".venv" / "bin" / "ruff"
    fake_ruff.parent.mkdir(parents=True)
    shutil.copy("/usr/bin/true", fake_ruff)
    fake_ruff.chmod(0o755)
    with (
        patch("scripts.run_local_gate_receipt.validate_release_source_integrity"),
        pytest.raises(ValueError, match="toolchain"),
    ):
        run_local_gate_receipt(
            gate_name="ruff",
            argv=[".venv/bin/ruff", "check", "js/", "js_work/", "tests/"],
            receipt_path=tmp_path / "evidence/final/ruff.receipt.json",
            repo_root=tmp_path,
            evidence_dir=tmp_path / "evidence",
        )


@pytest.mark.parametrize("fault", ["lock_sha", "before", "after"])
def test_receipt_rejects_toolchain_lock_binding_fault(tmp_path: Path, fault: str) -> None:
    _ensure_repo_toolchain(tmp_path)
    evidence = tmp_path / "evidence"
    write_toolchain_lock(evidence, tmp_path)
    stdout = evidence / "gates/ruff.stdout.txt"
    stderr = evidence / "gates/ruff.stderr.txt"
    payload = _valid_receipt_payload(
        root=tmp_path,
        evidence_dir=evidence,
        gate_name="ruff",
        stdout_path=stdout,
        stderr_path=stderr,
        stdout_sha256=_write_capture(stdout),
        stderr_sha256=_write_capture(stderr),
    )
    if fault == "lock_sha":
        payload["toolchain_lock_sha256"] = "0" * 64
    else:
        altered = json.loads(json.dumps(payload[f"toolchain_{fault}"]))
        altered["tools"]["ruff"]["sha256"] = "0" * 64
        payload[f"toolchain_{fault}"] = altered
    assert not _valid_local_gate_receipt(
        payload,
        root=tmp_path,
        expected_source_digest=release_source_digest(tmp_path),
        evidence_dir=evidence,
    )


@pytest.mark.parametrize("stdout", ["# 5 passed\n", "5 passed, 5 failed in 0.1s\n"])
def test_forged_pytest_stdout_fails_parser_and_receipt(tmp_path: Path, stdout: str) -> None:
    parsed = parse_gate_stdout("pytest", stdout, exit_code=0, require_exit_code_zero=True)
    assert parsed["ok"] is False
    _ensure_repo_toolchain(tmp_path)
    evidence = tmp_path / "evidence"
    write_toolchain_lock(evidence, tmp_path)
    stdout_path = evidence / "gates/pytest_targeted_round87.stdout.txt"
    stderr_path = evidence / "gates/pytest_targeted_round87.stderr.txt"
    payload = _valid_receipt_payload(
        root=tmp_path,
        evidence_dir=evidence,
        gate_name="pytest_targeted_round87",
        stdout_path=stdout_path,
        stderr_path=stderr_path,
        stdout_sha256=_write_capture(stdout_path, stdout),
        stderr_sha256=_write_capture(stderr_path),
    )
    assert payload["parse_result"] == parsed
    assert not _valid_local_gate_receipt(
        payload,
        root=tmp_path,
        expected_source_digest=release_source_digest(tmp_path),
        evidence_dir=evidence,
    )


def test_runner_marks_toolchain_mutation_during_exec_failed(tmp_path: Path) -> None:
    _ensure_repo_toolchain(tmp_path)
    evidence = tmp_path / "evidence"
    ruff = tmp_path / ".venv/bin/ruff"

    original_run = subprocess.run

    def mutate_toolchain(*args: object, **kwargs: object) -> CompletedProcess[bytes]:
        command = args[0] if args else kwargs.get("args")
        if command == ["git", "diff", "--check"]:
            ruff.write_bytes(ruff.read_bytes() + b"\n")
            return CompletedProcess([], 0, stdout=b"", stderr=b"")
        return original_run(*args, **kwargs)

    with (
        patch("scripts.run_local_gate_receipt.subprocess.run", side_effect=mutate_toolchain),
        patch("scripts.run_local_gate_receipt.validate_release_source_integrity"),
    ):
        receipt = run_local_gate_receipt(
            gate_name="git_diff_check",
            argv=["git", "diff", "--check"],
            receipt_path=evidence / "final/git_diff_check.receipt.json",
            repo_root=tmp_path,
            evidence_dir=evidence,
        )
    assert receipt["toolchain_drift"] is True
    assert receipt["passed"] is False


def test_final_validator_helpers_archive_and_bind_inputs(tmp_path: Path) -> None:
    (tmp_path / "benchmarks").mkdir()
    (tmp_path / "scripts").mkdir()
    (tmp_path / "benchmarks/old_architecture_baseline.py").write_text("BASELINE = 1\n")
    (tmp_path / "scripts/echo_architecture_benchmark.py").write_text("BENCHMARK = 1\n")
    evidence = tmp_path / "evidence"
    inputs = snapshot_final_gate_inputs(tmp_path, evidence)
    artifacts = inputs["artifacts"]
    assert artifacts["baseline_script"]["present"] is True
    assert artifacts["benchmark_script"]["present"] is True
    assert artifacts["tokenizer_digest"]["present"] is True

    summary = {"schema_version": "summary", "validator_inputs": inputs}
    receipt = {"schema_version": "receipt", "ok": True}
    write_final_validator_receipt(
        evidence,
        summary_payload=summary,
        validator_payload=receipt,
    )
    assert json.loads((evidence / "gate_run_summary.json").read_text()) == summary
    assert json.loads((evidence / "final_validator.receipt.json").read_text()) == receipt
