from __future__ import annotations

import hashlib
import io
import json
import tarfile
import zipfile
from pathlib import Path

import pytest

from js.echo.ledger.evidence_export import (
    ARCHIVE_SCAN_RECEIPT_NAME,
    build_sanitized_export,
    verify_archive_scan_receipt,
    write_archive_scan_receipt,
)

DIGEST = "d" * 64


@pytest.fixture(autouse=True)
def _formal_validator_for_export_mechanics(monkeypatch: pytest.MonkeyPatch) -> None:
    import js.echo.ledger.release_gates as release_gates

    report = release_gates.FinalLocalGateEvidenceReport(
        all_local_gates_passed=False,
        passed_gates=("ruff",),
        blockers=("remaining_required_gates_not_seeded",),
        product_internal_ready=False,
    )
    monkeypatch.setattr(release_gates, "release_source_digest", lambda _root: DIGEST)
    monkeypatch.setattr(
        release_gates, "validate_final_local_gate_evidence", lambda *_a, **_k: report
    )


def _seed(evidence: Path) -> None:
    (evidence / "final").mkdir(parents=True)
    (evidence / "gates").mkdir(parents=True)
    body = "All checks passed!\n"
    (evidence / "gates" / "ruff.stdout.txt").write_text(body, encoding="utf-8")
    (evidence / "gates" / "ruff.stderr.txt").write_text("", encoding="utf-8")
    receipt = {
        "gate_name": "ruff",
        "stdout_path": "<EVIDENCE_ROOT>/gates/ruff.stdout.txt",
        "stderr_path": "<EVIDENCE_ROOT>/gates/ruff.stderr.txt",
        "stdout_sha256": hashlib.sha256(body.encode()).hexdigest(),
        "stderr_sha256": hashlib.sha256(b"").hexdigest(),
        "source_digest_before": DIGEST,
        "source_digest_after": DIGEST,
        "exit_code": 0,
        "output_parse": {
            "parser": "ruff",
            "require_exit_code_zero": True,
            "stderr_must_be_empty": False,
        },
        "parse_result": {"parser": "ruff", "ok": True},
        "passed": True,
    }
    (evidence / "final" / "ruff.receipt.json").write_text(
        json.dumps(receipt, indent=2) + "\n", encoding="utf-8"
    )
    (evidence / "TOOLCHAIN.lock.json").write_text("{}\n", encoding="utf-8")
    (evidence / "e2e" / "artifacts").mkdir(parents=True)
    whl = evidence / "e2e" / "artifacts" / "demo-0.0.1-py3-none-any.whl"
    with zipfile.ZipFile(whl, "w") as archive:
        archive.writestr("demo/__init__.py", "x=1\n")
    sdist = evidence / "e2e" / "artifacts" / "demo-0.0.1.tar.gz"
    sdist_content = b"x=1\n"
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as archive:
        info = tarfile.TarInfo("demo/__init__.py")
        info.size = len(sdist_content)
        archive.addfile(info, io.BytesIO(sdist_content))
    sdist.write_bytes(stream.getvalue())
    wheel_payload = whl.read_bytes()
    sdist_payload = sdist.read_bytes()
    (evidence / "e2e" / "ECHO_ISOLATED_VENV_E2E.json").write_text(
        json.dumps(
            {
                "ok": True,
                "artifacts": {
                    "wheel": {
                        "path": "e2e/artifacts/demo-0.0.1-py3-none-any.whl",
                        "sha256": hashlib.sha256(wheel_payload).hexdigest(),
                        "bytes": len(wheel_payload),
                    },
                    "sdist": {
                        "path": "e2e/artifacts/demo-0.0.1.tar.gz",
                        "sha256": hashlib.sha256(sdist_payload).hexdigest(),
                        "bytes": len(sdist_payload),
                    },
                },
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def test_archive_scan_includes_e2e_artifacts_and_binds_digest(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    evidence = tmp_path / "evidence"
    repo.mkdir()
    _seed(evidence)
    result = build_sanitized_export(
        evidence_root=evidence,
        repo_root=repo,
        source_digest=DIGEST,
        out_root=evidence,
        required_gates=("ruff",),
    )
    assert (result.export_dir / ARCHIVE_SCAN_RECEIPT_NAME).is_file()
    assert result.manifest_file_sha256
    assert result.envelope_file_sha256
    assert result.envelope_manifest_sha256 == result.manifest_file_sha256
    envelope = json.loads(result.envelope_path.read_text(encoding="utf-8"))
    assert envelope["manifest_sha256"] == result.envelope_manifest_sha256
    assert envelope["manifest_sha256"] != result.envelope_file_sha256

    verify_archive_scan_receipt(
        result.export_dir,
        source_digest=DIGEST,
        e2e_artifact_json=evidence / "e2e" / "ECHO_ISOLATED_VENV_E2E.json",
    )


def test_archive_scan_rejects_digest_or_artifact_drift(tmp_path: Path) -> None:
    export = tmp_path / "sanitized-export"
    (export / "e2e" / "artifacts").mkdir(parents=True)
    whl = export / "e2e" / "artifacts" / "demo-0.0.1-py3-none-any.whl"
    with zipfile.ZipFile(whl, "w") as archive:
        archive.writestr("demo/__init__.py", "x=1\n")
    write_archive_scan_receipt(export, source_digest=DIGEST, hits=())
    verify_archive_scan_receipt(export, source_digest=DIGEST)

    with pytest.raises(RuntimeError, match="source_digest"):
        verify_archive_scan_receipt(export, source_digest="e" * 64)

    whl.write_bytes(whl.read_bytes() + b"\x00")
    with pytest.raises(RuntimeError, match="identity drift|archive"):
        verify_archive_scan_receipt(export, source_digest=DIGEST)
