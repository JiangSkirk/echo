from __future__ import annotations

import hashlib
import inspect
import time
from pathlib import Path

import js.echo.ledger.release_gates as rg
from js.echo.ledger.release_gates import (
    generate_final_local_gate_summary,
    validate_final_local_gate_evidence,
)


def _tree_fingerprint(root: Path) -> dict[str, tuple[int, str, int]]:
    """Map relative posix path -> (size, sha256, mtime_ns)."""
    out: dict[str, tuple[int, str, int]] = {}
    if not root.exists():
        return out
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        data = path.read_bytes()
        st = path.stat()
        out[rel] = (len(data), hashlib.sha256(data).hexdigest(), st.st_mtime_ns)
    return out


def test_validate_final_is_read_only_on_success_and_failure(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    final = evidence / "final"
    final.mkdir(parents=True)
    before = _tree_fingerprint(evidence)
    time.sleep(0.02)
    report = validate_final_local_gate_evidence(
        tmp_path,
        final_dir=final,
        evidence_dir=evidence,
        expected_source_digest="a" * 64,
    )
    after = _tree_fingerprint(evidence)
    assert report.all_local_gates_passed is False
    assert before == after
    assert not (evidence / "gate_run_summary.json").exists()
    assert not (evidence / "final_validator.receipt.json").exists()
    assert not (evidence / "validator_inputs").exists()


def test_generate_writes_only_under_explicit_evidence_root(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence-out"
    final = evidence / "final"
    final.mkdir(parents=True)
    before = _tree_fingerprint(tmp_path)
    report, summary, validator = generate_final_local_gate_summary(
        tmp_path,
        final_dir=final,
        evidence_dir=evidence,
        expected_source_digest="b" * 64,
    )
    assert isinstance(report.all_local_gates_passed, bool)
    assert summary["schema_version"] == "js-agent-gate-run-summary-v2"
    assert validator["writer"] == "generate_final_local_gate_summary"
    assert (evidence / "gate_run_summary.json").is_file()
    assert (evidence / "final_validator.receipt.json").is_file()
    after = _tree_fingerprint(tmp_path)
    for rel, meta in before.items():
        if rel.startswith("evidence-out/"):
            continue
        assert after.get(rel) == meta
    assert isinstance(summary.get("validator_inputs"), dict)


def test_validate_docstring_promises_readonly() -> None:
    doc = rg.validate_final_local_gate_evidence.__doc__ or ""
    assert "Read-only" in doc or "read-only" in doc
    assert "generate_final_local_gate_summary" in doc
    src = inspect.getsource(rg.validate_final_local_gate_evidence)
    assert "write_final_validator_receipt" not in src
    assert "snapshot_final_gate_inputs" not in src
    assert "mkdir" not in src
