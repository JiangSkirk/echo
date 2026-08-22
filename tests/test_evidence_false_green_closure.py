from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

import js.echo.ledger.evidence_export as evidence_export
import js.echo.ledger.final_evidence as final_evidence
import js.echo.ledger.release_gates as release_gates
from scripts import build_final_evidence_summary, build_sanitized_evidence_export

_DIGEST = "d" * 64


def _write_minimal_gate(evidence: Path, gate: str = "ruff") -> None:
    final = evidence / "final"
    gates = evidence / "gates"
    final.mkdir(parents=True)
    gates.mkdir(parents=True)
    stdout = b"All checks passed!\n"
    (gates / f"{gate}.stdout.txt").write_bytes(stdout)
    (gates / f"{gate}.stderr.txt").write_bytes(b"")
    (final / f"{gate}.receipt.json").write_text(
        json.dumps(
            {
                "schema_version": "js-agent-local-gate-receipt-v4",
                "gate_name": gate,
                "stdout_path": f"<EVIDENCE_ROOT>/gates/{gate}.stdout.txt",
                "stderr_path": f"<EVIDENCE_ROOT>/gates/{gate}.stderr.txt",
                "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
                "stderr_sha256": hashlib.sha256(b"").hexdigest(),
                "source_digest_before": _DIGEST,
                "source_digest_after": _DIGEST,
                "exit_code": 0,
                "output_parse": {
                    "parser": "ruff",
                    "require_exit_code_zero": True,
                    "stderr_must_be_empty": False,
                },
                "parse_result": {"parser": "ruff", "ok": True},
                "passed": True,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    (evidence / "TOOLCHAIN.lock.json").write_text("{}\n", encoding="utf-8")


def test_synthetic_minimal_receipt_cannot_drive_export(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    evidence = tmp_path / "evidence"
    repo.mkdir()
    _write_minimal_gate(evidence)
    monkeypatch.setattr(release_gates, "release_source_digest", lambda _root: _DIGEST)

    result = evidence_export.build_sanitized_export(
        evidence_root=evidence,
        repo_root=repo,
        source_digest=_DIGEST,
        out_root=evidence,
    )

    assert result.validation_ok is False
    assert result.passed_gates == ()
    assert not (result.export_dir / "final/ruff.receipt.json").exists()


def test_requested_gate_subset_cannot_override_formal_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    evidence = tmp_path / "evidence"
    repo.mkdir()
    _write_minimal_gate(evidence)
    report = release_gates.FinalLocalGateEvidenceReport(
        all_local_gates_passed=False,
        passed_gates=("ruff",),
        blockers=("mypy:receipt_missing",),
        product_internal_ready=False,
    )
    monkeypatch.setattr(release_gates, "release_source_digest", lambda _root: _DIGEST)
    monkeypatch.setattr(release_gates, "validate_final_local_gate_evidence", lambda *_a, **_k: report)

    with pytest.raises(RuntimeError, match="formal validator"):
        evidence_export.build_sanitized_export(
            evidence_root=evidence,
            repo_root=repo,
            source_digest=_DIGEST,
            out_root=evidence,
            required_gates=("mypy",),
        )


def test_exported_validator_summary_is_hash_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    evidence = tmp_path / "evidence"
    repo.mkdir()
    _write_minimal_gate(evidence)
    report = release_gates.FinalLocalGateEvidenceReport(
        all_local_gates_passed=False,
        passed_gates=("ruff",),
        blockers=("mypy:receipt_missing",),
        product_internal_ready=False,
    )
    monkeypatch.setattr(release_gates, "release_source_digest", lambda _root: _DIGEST)
    monkeypatch.setattr(release_gates, "validate_final_local_gate_evidence", lambda *_a, **_k: report)

    result = evidence_export.build_sanitized_export(
        evidence_root=evidence,
        repo_root=repo,
        source_digest=_DIGEST,
        out_root=evidence,
    )
    evidence_export.verify_export_validator_binding(
        result.export_dir,
        expected_source_digest=_DIGEST,
        report=report,
    )
    summary_path = result.export_dir / "gate_run_summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    summary["passed_gates"] = []
    summary_path.write_text(json.dumps(summary) + "\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="summary hash|passed_gates"):
        evidence_export.verify_export_validator_binding(
            result.export_dir,
            expected_source_digest=_DIGEST,
            report=report,
        )


def test_non_utf8_allowlisted_file_fails_closed(tmp_path: Path) -> None:
    root = tmp_path / "export"
    target = root / "validator_inputs" / "opaque.bin"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"\xff\xfe\x00private")

    hits = evidence_export.privacy_scan(root)

    assert any(hit.rule_id == "non_utf8_forbidden" for hit in hits)


def test_unknown_binary_extension_fails_closed_even_when_ascii(tmp_path: Path) -> None:
    root = tmp_path / "export"
    target = root / "validator_inputs" / "opaque.bin"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"apparently harmless ascii\n")

    hits = evidence_export.privacy_scan(root)

    assert any(hit.rule_id == "unknown_file_type" for hit in hits)


def test_passed_false_receipt_is_only_partial_diagnostic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    evidence = tmp_path / "evidence"
    repo.mkdir()
    _write_minimal_gate(evidence)
    receipt_path = evidence / "final/ruff.receipt.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["passed"] = False
    receipt_path.write_text(json.dumps(receipt) + "\n", encoding="utf-8")
    monkeypatch.setattr(release_gates, "release_source_digest", lambda _root: _DIGEST)

    result = evidence_export.build_sanitized_export(
        evidence_root=evidence,
        repo_root=repo,
        source_digest=_DIGEST,
        out_root=evidence,
    )

    assert result.validation_ok is False
    assert result.passed_gates == ()
    assert not list((result.export_dir / "final").glob("*.receipt.json"))
    validator = json.loads(
        (result.export_dir / "final_validator.receipt.json").read_text(encoding="utf-8")
    )
    assert validator["ok"] is False


@pytest.mark.parametrize("suffix", [".zip", ".xlsx", ".docx", ".pptx"])
def test_zip_family_member_privacy_is_scanned(tmp_path: Path, suffix: str) -> None:
    archive_path = tmp_path / f"artifact{suffix}"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("xl/sharedStrings.xml", "/Users/private-user/secret\n")

    hits = evidence_export.scan_archive_members(archive_path, current_home="/Users/private-user")

    assert any(hit.rule_id == "archive_current_home" for hit in hits)


def test_nested_zip_member_is_recursively_scanned(tmp_path: Path) -> None:
    inner = tmp_path / "inner.zip"
    with zipfile.ZipFile(inner, "w") as archive:
        archive.writestr("secret.txt", "-----BEGIN PRIVATE KEY-----\n")
    outer = tmp_path / "outer.zip"
    with zipfile.ZipFile(outer, "w") as archive:
        archive.writestr("nested/inner.zip", inner.read_bytes())

    hits = evidence_export.scan_archive_members(outer, current_home="/Users/nobody")

    assert any(hit.rule_id == "archive_pem_private" for hit in hits)


def test_zip_path_escape_and_encryption_fail_closed(tmp_path: Path) -> None:
    archive_path = tmp_path / "hostile.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("../escape.txt", "clean\n")
        archive.writestr("encrypted.txt", "clean\n")
    payload = bytearray(archive_path.read_bytes())
    for signature, offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        position = payload.rfind(signature)
        assert position >= 0
        flags = int.from_bytes(payload[position + offset : position + offset + 2], "little")
        payload[position + offset : position + offset + 2] = (flags | 1).to_bytes(2, "little")
    archive_path.write_bytes(payload)

    hits = evidence_export.scan_archive_members(archive_path, current_home="/Users/nobody")

    assert any(hit.rule_id == "archive_path_escape" for hit in hits)
    assert any(hit.rule_id == "archive_encrypted_member" for hit in hits)


def _seed_final_summary_inputs(root: Path, evidence: Path) -> Path:
    (evidence / "final").mkdir(parents=True)
    (evidence / "desktop-build").mkdir(parents=True)
    (evidence / "soak").mkdir(parents=True)
    (evidence / "e2e").mkdir(parents=True)
    (evidence / "FROZEN_DIGEST.txt").write_text(_DIGEST + "\n", encoding="utf-8")
    soak = evidence / "soak/ECHO_LIVE_ACCEPTANCE.json"
    soak.write_text(json.dumps({"ok": True, "source_digest": _DIGEST, "soak": {}}) + "\n")
    e2e = evidence / "e2e/ECHO_ISOLATED_VENV_E2E.json"
    e2e.write_text(json.dumps({"ok": True}) + "\n", encoding="utf-8")
    for gate in release_gates.REQUIRED_FINAL_LOCAL_GATES:
        artifact_sha256 = None
        if gate == "soak_3600":
            artifact_sha256 = hashlib.sha256(soak.read_bytes()).hexdigest()
        elif gate == "isolated_venv_e2e":
            artifact_sha256 = hashlib.sha256(e2e.read_bytes()).hexdigest()
        (evidence / "final" / f"{gate}.receipt.json").write_text(
            json.dumps(
                {"gate_name": gate, "passed": True, "artifact_sha256": artifact_sha256}
            )
            + "\n",
            encoding="utf-8",
        )
    manifest = evidence / "desktop-build" / "manifest.json"
    manifest.write_text(json.dumps({"source_digest": _DIGEST}) + "\n", encoding="utf-8")
    (root / "docs/security").mkdir(parents=True)
    (root / "docs/security/ECHO_ISOLATED_VENV_E2E.json").write_text(
        json.dumps({"ok": True}) + "\n", encoding="utf-8"
    )
    (root / "docs/security/ECHO_SLO_BENCHMARK.json").write_text(
        json.dumps({"source_digest": _DIGEST}) + "\n", encoding="utf-8"
    )
    return soak


def _patch_green_formal_sources(monkeypatch: pytest.MonkeyPatch) -> None:
    report = release_gates.FinalLocalGateEvidenceReport(
        all_local_gates_passed=True,
        passed_gates=release_gates.REQUIRED_FINAL_LOCAL_GATES,
        blockers=(),
        product_internal_ready=True,
    )
    monkeypatch.setattr(release_gates, "release_source_digest", lambda _root: _DIGEST)
    monkeypatch.setattr(release_gates, "validate_final_local_gate_evidence", lambda *_a, **_k: report)
    monkeypatch.setattr(
        release_gates,
        "verify_release_readiness",
        lambda *_a, **_k: SimpleNamespace(internal_ready=True),
    )
    monkeypatch.setattr(final_evidence, "slo_artifact_ok", lambda *_a, **_k: True)


def test_final_summary_derives_readiness_and_binds_desktop_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "repo"
    evidence = tmp_path / "evidence"
    root.mkdir()
    soak_path = _seed_final_summary_inputs(root, evidence)
    _patch_green_formal_sources(monkeypatch)
    monkeypatch.setattr("desktop.build_driver.verify_manifest", lambda *_a, **_k: [])
    manifest = evidence / "desktop-build/manifest.json"

    payload = final_evidence.build_final_evidence_payload(
        root=root,
        evidence_dir=evidence,
        branch="feature/echo-runtime",
        head="a" * 40,
        evidence_root_relative="evidence",
        generated_utc="2026-08-09T00:00:00Z",
        soak_path=soak_path,
        slo_path=root / "docs/security/ECHO_SLO_BENCHMARK.json",
        e2e_path=evidence / "e2e/ECHO_ISOLATED_VENV_E2E.json",
    )

    assert payload["frozen_source_digest"] == _DIGEST
    assert payload["validation_ok"] is True
    assert payload["internal_ready"] is True
    assert payload["product_internal_ready"] is True
    assert payload["desktop_manifest_digest"] == hashlib.sha256(manifest.read_bytes()).hexdigest()
    assert "required_local_gates" in payload["classification"]["passed"]


def test_final_validator_rejects_manifest_and_classification_tamper(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "repo"
    evidence = tmp_path / "evidence"
    root.mkdir()
    soak_path = _seed_final_summary_inputs(root, evidence)
    _patch_green_formal_sources(monkeypatch)
    monkeypatch.setattr("desktop.build_driver.verify_manifest", lambda *_a, **_k: [])
    slo_path = root / "docs/security/ECHO_SLO_BENCHMARK.json"
    e2e_path = evidence / "e2e/ECHO_ISOLATED_VENV_E2E.json"
    payload = final_evidence.build_final_evidence_payload(
        root=root,
        evidence_dir=evidence,
        branch="feature/echo-runtime",
        head="a" * 40,
        evidence_root_relative="evidence",
        soak_path=soak_path,
        slo_path=slo_path,
        e2e_path=e2e_path,
    )
    payload["desktop_manifest_digest"] = "0" * 64
    payload["classification"]["passed"].remove("required_local_gates")

    errors = final_evidence.validate_final_evidence_document(
        payload,
        soak_path=soak_path,
        slo_path=slo_path,
        root=root,
        evidence_dir=evidence,
    )

    assert any("desktop_manifest_digest" in error for error in errors)
    assert any("classification" in error for error in errors)


def test_final_payload_rejects_caller_readiness_booleans(tmp_path: Path) -> None:
    with pytest.raises(TypeError):
        final_evidence.build_final_evidence_payload(  # type: ignore[call-arg]
            root=tmp_path,
            evidence_dir=tmp_path / "evidence",
            branch="main",
            head="a" * 40,
            evidence_root_relative="evidence",
            internal_ready=True,
            validation_ok=True,
        )


def test_partial_formal_report_cannot_promote_unbound_artifact_ok(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "repo"
    evidence = tmp_path / "evidence"
    root.mkdir()
    (root / "docs/security").mkdir(parents=True)
    soak = root / "docs/security/ECHO_LIVE_ACCEPTANCE.json"
    soak.write_text(
        json.dumps({"ok": True, "source_digest": _DIGEST, "soak": {}}) + "\n",
        encoding="utf-8",
    )
    e2e = root / "docs/security/ECHO_ISOLATED_VENV_E2E.json"
    e2e.write_text(json.dumps({"ok": True}) + "\n", encoding="utf-8")
    monkeypatch.setattr(
        final_evidence,
        "_derive_formal_state",
        lambda **_kwargs: {
            "source_digest": _DIGEST,
            "passed_gates": ("ruff",),
            "blockers": ("isolated_venv_e2e:receipt_missing",),
            "validation_ok": False,
            "internal_ready": False,
            "product_internal_ready": False,
            "desktop_manifest_digest": None,
            "gate_receipts": {"ruff": {"passed": True}},
        },
    )

    payload = final_evidence.build_final_evidence_payload(
        root=root,
        evidence_dir=evidence,
        branch="main",
        head="a" * 40,
        evidence_root_relative="evidence",
        soak_path=soak,
        slo_path=root / "docs/security/ECHO_SLO_BENCHMARK.json",
        e2e_path=e2e,
    )

    assert payload["e2e_ok"] is False
    assert payload["soak"]["validated_by_gate"] is False
    assert "isolated_venv_e2e" not in payload["classification"]["passed"]
    assert "real_3600_soak" not in payload["classification"]["passed"]


def test_final_summary_cli_rejects_readiness_boolean_flags(tmp_path: Path) -> None:
    with pytest.raises(SystemExit) as caught:
        build_final_evidence_summary.main(
            [
                "--evidence-dir",
                str(tmp_path / "evidence"),
                "--output",
                str(tmp_path / "out.json"),
                "--internal-ready",
            ]
        )

    assert caught.value.code == 2


def test_sanitized_cli_reports_partial_instead_of_ok(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo = tmp_path / "repo"
    evidence = tmp_path / "evidence"
    repo.mkdir()
    _write_minimal_gate(evidence)
    monkeypatch.setattr(build_sanitized_evidence_export, "release_source_digest", lambda _r: _DIGEST)
    monkeypatch.setattr(release_gates, "release_source_digest", lambda _r: _DIGEST)

    code = build_sanitized_evidence_export.main(
        [
            "--evidence-root",
            str(evidence),
            "--repo-root",
            str(repo),
            "--source-digest",
            _DIGEST,
        ]
    )

    lines = [line for line in capsys.readouterr().out.splitlines() if line.startswith("{")]
    output = json.loads(lines[-1])
    assert code == 2
    assert output["ok"] is False
    assert output["passed_gates"] == []
