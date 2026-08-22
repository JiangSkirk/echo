from __future__ import annotations

import hashlib
import io
import json
import os
import tarfile
import zipfile
from pathlib import Path

import pytest

from js.echo.ledger.evidence_export import (
    ENVELOPE_NAME,
    MANIFEST_NAME,
    assert_docs_byte_identical,
    assert_no_self_hash_fields,
    build_sanitized_export,
    privacy_scan,
    redact_text,
    verify_manifest_v2,
)

DIGEST = "b" * 64


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


def _seed_evidence(root: Path, *, repo: Path) -> None:
    (root / "final").mkdir(parents=True)
    (root / "gates").mkdir(parents=True)
    stdout = root / "gates" / "ruff.stdout.txt"
    stderr = root / "gates" / "ruff.stderr.txt"
    stdout.write_text("All checks passed!\n", encoding="utf-8")
    stderr.write_text("", encoding="utf-8")
    receipt = {
        "gate_name": "ruff",
        "passed": True,
        "cwd": "<REPO_ROOT>",
        "stdout_path": "<EVIDENCE_ROOT>/gates/ruff.stdout.txt",
        "stderr_path": "<EVIDENCE_ROOT>/gates/ruff.stderr.txt",
        "stdout_sha256": __import__("hashlib").sha256(b"All checks passed!\n").hexdigest(),
        "stderr_sha256": __import__("hashlib").sha256(b"").hexdigest(),
        "source_digest_before": DIGEST,
        "source_digest_after": DIGEST,
        "exit_code": 0,
        "output_parse": {
            "parser": "ruff",
            "require_exit_code_zero": True,
            "stderr_must_be_empty": False,
        },
        "parse_result": {"parser": "ruff", "ok": True},
    }
    (root / "final" / "ruff.receipt.json").write_text(
        json.dumps(receipt, indent=2) + "\n", encoding="utf-8"
    )
    (root / "slo").mkdir()
    for index in range(1, 6):
        (root / "slo" / f"slo_run_{index}.json").write_text(
            json.dumps({"ok": True, "run": index}) + "\n", encoding="utf-8"
        )
    (root / "soak").mkdir()
    (root / "soak" / "ECHO_LIVE_ACCEPTANCE.json").write_text(
        json.dumps({"ok": True, "duration_seconds": 3600}) + "\n", encoding="utf-8"
    )
    (root / "e2e").mkdir()
    (root / "e2e" / "artifacts").mkdir()
    (root / "e2e" / "artifacts" / "note.txt").write_text("artifact\n", encoding="utf-8")
    whl = root / "e2e" / "artifacts" / "demo-0.0.1-py3-none-any.whl"
    with zipfile.ZipFile(whl, "w") as archive:
        archive.writestr("demo/__init__.py", "x=1\n")
    sdist = root / "e2e" / "artifacts" / "demo-0.0.1.tar.gz"
    sdist_content = b"x=1\n"
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as archive:
        info = tarfile.TarInfo("demo/__init__.py")
        info.size = len(sdist_content)
        archive.addfile(info, io.BytesIO(sdist_content))
    sdist.write_bytes(stream.getvalue())
    wheel_payload = whl.read_bytes()
    sdist_payload = sdist.read_bytes()
    (root / "e2e" / "ECHO_ISOLATED_VENV_E2E.json").write_text(
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
    (root / "TOOLCHAIN.lock.json").write_text("{}\n", encoding="utf-8")
    (root / "FROZEN_DIGEST.txt").write_text(DIGEST + "\n", encoding="utf-8")
    # Exclusions that must NOT be copied.
    (root / "e2e" / "runtime").mkdir()
    (root / "e2e" / "runtime" / "server.py").write_text(
        "SECRET=/Users/example-user\n", encoding="utf-8"
    )
    (root / "wheelhouse").mkdir()
    (root / "wheelhouse" / "bulk.whl").write_bytes(b"0" * 100)
    (root / "e2e" / "keys").mkdir()
    (root / "e2e" / "keys" / "ledger.ed25519.private").write_bytes(os.urandom(32))
    (root / "pre_fix").mkdir()
    (root / "pre_fix" / "old.txt").write_text("old\n", encoding="utf-8")


def test_redact_and_privacy_scan_catch_home_path(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    evidence = tmp_path / "evidence"
    repo.mkdir()
    evidence.mkdir()
    home = tmp_path / "example-user"
    home.mkdir()
    raw = f"cwd={repo} evidence={evidence} home={home}/secret"
    cleaned = redact_text(raw, repo_root=repo, evidence_root=evidence, home=home)
    assert str(home) not in cleaned
    assert "<REPO_ROOT>" in cleaned and "<EVIDENCE_ROOT>" in cleaned
    leak = evidence / "leak.txt"
    # Generic home-path rule matches platform home prefixes, not arbitrary tmpdirs.
    leak.write_text("home=/Users/example-user/secret\n", encoding="utf-8")
    hits = privacy_scan(evidence)
    assert any(hit.rule_id == "absolute_home_path" for hit in hits)
    assert all(getattr(hit, "excerpt", None) is None for hit in hits)


def test_sanitized_export_excludes_runtime_keys_and_builds_envelope(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    evidence = tmp_path / "evidence"
    repo.mkdir()
    _seed_evidence(evidence, repo=repo)
    private_manifest = evidence / "desktop-build/manifest.json"
    private_manifest.parent.mkdir()
    private_manifest.write_text(
        json.dumps(
            {
                "schema": "JSAgentDesktopProvenanceV4",
                "build_environment": {
                    "python": {"path": "/Users/private-builder/.venv/bin/python"}
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )
    top = tmp_path / "JS_AGENT_FINAL_EVIDENCE.json"
    payload = {
        "schema_version": "js-agent-final-evidence-v1",
        "source_digest": DIGEST,
        "stable_ready": False,
        "not_a_third_party_signature": True,
    }
    top.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    assert_no_self_hash_fields(payload)

    result = build_sanitized_export(
        evidence_root=evidence,
        repo_root=repo,
        source_digest=DIGEST,
        out_root=evidence,
        top_level_docs=(top,),
        required_gates=("ruff",),
    )
    export = result.export_dir
    assert (export / "final" / "ruff.receipt.json").is_file()
    assert not (export / "e2e" / "runtime").exists()
    assert not (export / "wheelhouse").exists()
    assert not (export / "e2e" / "keys" / "ledger.ed25519.private").exists()
    assert not (export / "pre_fix").exists()
    assert not (export / "desktop-build/manifest.json").exists()
    assert not (export / "desktop-build/sanitized-descriptor.json").exists()
    assert (export / MANIFEST_NAME).is_file()
    assert (evidence / ENVELOPE_NAME).is_file()
    verify_manifest_v2(export)

    envelope = json.loads((evidence / ENVELOPE_NAME).read_text(encoding="utf-8"))
    assert envelope["manifest_sha256"] == result.manifest_sha256
    assert envelope["not_a_third_party_signature"] is True
    assert_no_self_hash_fields(envelope)

    # Receipt paths redacted.
    receipt_text = (export / "final" / "ruff.receipt.json").read_text(encoding="utf-8")
    assert str(repo) not in receipt_text
    assert "<REPO_ROOT>" in receipt_text
    assert "/Users/private-builder" not in b"\n".join(
        path.read_bytes() for path in export.rglob("*") if path.is_file()
    ).decode("utf-8", errors="ignore")

    export_doc = export / "docs" / top.name
    assert_docs_byte_identical(top, export_doc)

    # Manifest entry set == regular files minus MANIFEST itself.
    listed = {
        line.split()[-1]
        for line in (export / MANIFEST_NAME).read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#")
    }
    actual = {
        path.relative_to(export).as_posix()
        for path in export.rglob("*")
        if path.is_file() and path.name != MANIFEST_NAME
    }
    assert listed == actual


def test_self_hash_in_content_json_rejected() -> None:
    with pytest.raises(RuntimeError, match="self-hash"):
        assert_no_self_hash_fields({"self_sha256": "a" * 64})
    with pytest.raises(RuntimeError, match="manifest_sha256"):
        assert_no_self_hash_fields({"manifest_sha256": "a" * 64})


def test_manifest_detects_path_escape_and_tamper(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    evidence = tmp_path / "evidence"
    repo.mkdir()
    _seed_evidence(evidence, repo=repo)
    result = build_sanitized_export(
        evidence_root=evidence,
        repo_root=repo,
        source_digest=DIGEST,
        out_root=evidence,
        required_gates=("ruff",),
    )
    target = result.export_dir / "TOOLCHAIN.lock.json"
    target.write_text("{}\n#tamper\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="mismatch"):
        verify_manifest_v2(result.export_dir)
