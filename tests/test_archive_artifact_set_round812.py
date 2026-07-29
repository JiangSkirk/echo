from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path

import pytest

from js.echo.ledger.evidence_export import (
    ARCHIVE_SCAN_RECEIPT_NAME,
    ARCHIVE_SCAN_RULE_VERSION,
    verify_archive_scan_receipt,
    write_archive_scan_receipt,
)

DIGEST = "d" * 64


def _make_archive(path: Path, content: str = "x=1\n") -> bytes:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.name.endswith(".whl"):
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("demo/__init__.py", content)
    else:
        import io
        import tarfile

        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as archive:
            info = tarfile.TarInfo("demo/__init__.py")
            data = content.encode()
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
        path.write_bytes(buf.getvalue())
    return path.read_bytes()


def _e2e_json(export: Path, artifacts: dict[str, bytes]) -> Path:
    arts = {}
    for rel, payload in artifacts.items():
        arts[rel.split("/")[-1].replace("-py3-none-any.whl", "").replace(".tar.gz", "")] = {
            "path": rel,
            "sha256": hashlib.sha256(payload).hexdigest(),
            "bytes": len(payload),
        }
    # Use stable keys wheel/sdist
    declared = {}
    for rel, payload in artifacts.items():
        key = "wheel" if rel.endswith(".whl") else "sdist"
        declared[key] = {
            "path": rel,
            "sha256": hashlib.sha256(payload).hexdigest(),
            "bytes": len(payload),
        }
    path = export / "e2e" / "ECHO_ISOLATED_VENV_E2E.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({"ok": True, "artifacts": declared}, indent=2) + "\n", encoding="utf-8"
    )
    return path


def _seed_gate(export: Path) -> None:
    (export / "final").mkdir(parents=True, exist_ok=True)
    (export / "gates").mkdir(parents=True, exist_ok=True)
    body = "All checks passed!\n"
    (export / "gates" / "ruff.stdout.txt").write_text(body, encoding="utf-8")
    (export / "gates" / "ruff.stderr.txt").write_text("", encoding="utf-8")
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
    (export / "final" / "ruff.receipt.json").write_text(
        json.dumps(receipt, indent=2) + "\n", encoding="utf-8"
    )
    (export / "TOOLCHAIN.lock.json").write_text("{}\n", encoding="utf-8")


def _two_authoritative(export: Path) -> tuple[dict[str, bytes], Path]:
    whl = export / "e2e" / "artifacts" / "demo-0.0.1-py3-none-any.whl"
    sdist = export / "e2e" / "artifacts" / "demo-0.0.1.tar.gz"
    whl_bytes = _make_archive(whl)
    sdist_bytes = _make_archive(sdist)
    artifacts = {
        "e2e/artifacts/demo-0.0.1-py3-none-any.whl": whl_bytes,
        "e2e/artifacts/demo-0.0.1.tar.gz": sdist_bytes,
    }
    e2e = _e2e_json(export, artifacts)
    return artifacts, e2e


def test_exact_two_authoritative_artifacts_pass(tmp_path: Path) -> None:
    export = tmp_path / "sanitized-export"
    _seed_gate(export)
    artifacts, e2e = _two_authoritative(export)
    write_archive_scan_receipt(export, source_digest=DIGEST, hits=[])
    verify_archive_scan_receipt(export, source_digest=DIGEST, e2e_artifact_json=e2e)


def test_extra_dist_archive_must_fail(tmp_path: Path) -> None:
    export = tmp_path / "sanitized-export"
    _seed_gate(export)
    artifacts, e2e = _two_authoritative(export)
    # Sneak an extra dist/ archive into the export (different content/hash).
    extra = export / "dist" / "demo-0.0.1-py3-none-any.whl"
    _make_archive(extra, content="DIFFERENT\n")
    # Receipt built from full-tree enumeration will see the extra archive and
    # already mismatch E2E; even a forged receipt listing only the two e2e
    # archives must fail when the verifier re-enumerates the whole tree.
    payload = {
        "schema_version": "js-agent-archive-scan-receipt-v1",
        "rule_version": ARCHIVE_SCAN_RULE_VERSION,
        "source_digest": DIGEST,
        "artifacts": [
            {
                "relative_path": rel,
                "filename": Path(rel).name,
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
            for rel, data in sorted(artifacts.items())
        ],
        "hit_count": 0,
        "hits": [],
        "ok": True,
        "generated_utc": "2026-07-26T01:00:00Z",
    }
    (export / ARCHIVE_SCAN_RECEIPT_NAME).write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    with pytest.raises(RuntimeError, match="set mismatch|closure|extra|duplicate"):
        verify_archive_scan_receipt(export, source_digest=DIGEST, e2e_artifact_json=e2e)


def test_e2e_json_missing_one_archive_must_fail(tmp_path: Path) -> None:
    export = tmp_path / "sanitized-export"
    _seed_gate(export)
    # Two archives on disk + in receipt, but E2E JSON declares only one.
    artifacts, _ = _two_authoritative(export)
    e2e_path = export / "e2e" / "ECHO_ISOLATED_VENV_E2E.json"
    partial = {
        "wheel": {
            "path": "e2e/artifacts/demo-0.0.1-py3-none-any.whl",
            "sha256": hashlib.sha256(
                artifacts["e2e/artifacts/demo-0.0.1-py3-none-any.whl"]
            ).hexdigest(),
            "bytes": len(artifacts["e2e/artifacts/demo-0.0.1-py3-none-any.whl"]),
        }
    }
    e2e_path.write_text(
        json.dumps({"ok": True, "artifacts": partial}, indent=2) + "\n", encoding="utf-8"
    )
    write_archive_scan_receipt(export, source_digest=DIGEST, hits=[])
    with pytest.raises(RuntimeError, match="closure mismatch|extra"):
        verify_archive_scan_receipt(export, source_digest=DIGEST, e2e_artifact_json=e2e_path)


def test_receipt_with_extra_archive_must_fail(tmp_path: Path) -> None:
    export = tmp_path / "sanitized-export"
    _seed_gate(export)
    artifacts, e2e = _two_authoritative(export)
    # Add a third undeclared archive on disk and forge a receipt listing all three.
    extra = export / "e2e" / "artifacts" / "extra-0.0.1-py3-none-any.whl"
    extra_bytes = _make_archive(extra, content="EXTRA\n")
    all_artifacts = dict(artifacts)
    all_artifacts["e2e/artifacts/extra-0.0.1-py3-none-any.whl"] = extra_bytes
    payload = {
        "schema_version": "js-agent-archive-scan-receipt-v1",
        "rule_version": ARCHIVE_SCAN_RULE_VERSION,
        "source_digest": DIGEST,
        "artifacts": [
            {
                "relative_path": rel,
                "filename": Path(rel).name,
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
            for rel, data in sorted(all_artifacts.items())
        ],
        "hit_count": 0,
        "hits": [],
        "ok": True,
        "generated_utc": "2026-07-26T01:00:00Z",
    }
    (export / ARCHIVE_SCAN_RECEIPT_NAME).write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    with pytest.raises(RuntimeError, match="closure mismatch|missing|extra"):
        verify_archive_scan_receipt(export, source_digest=DIGEST, e2e_artifact_json=e2e)


def test_same_basename_different_path_or_hash_must_fail(tmp_path: Path) -> None:
    export = tmp_path / "sanitized-export"
    _seed_gate(export)
    artifacts, e2e = _two_authoritative(export)
    # Add a dist/ archive with the SAME basename but different content/hash.
    same_basename = export / "dist" / "demo-0.0.1-py3-none-any.whl"
    different_bytes = _make_archive(same_basename, content="DIFFERENT HASH\n")
    # Forge a receipt that lists BOTH the e2e and dist copies (same basename).
    all_artifacts = dict(artifacts)
    all_artifacts["dist/demo-0.0.1-py3-none-any.whl"] = different_bytes
    payload = {
        "schema_version": "js-agent-archive-scan-receipt-v1",
        "rule_version": ARCHIVE_SCAN_RULE_VERSION,
        "source_digest": DIGEST,
        "artifacts": [
            {
                "relative_path": rel,
                "filename": Path(rel).name,
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
            for rel, data in sorted(all_artifacts.items())
        ],
        "hit_count": 0,
        "hits": [],
        "ok": True,
        "generated_utc": "2026-07-26T01:00:00Z",
    }
    (export / ARCHIVE_SCAN_RECEIPT_NAME).write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    # _collect_export_archives only scans e2e/artifacts/, so the dist/ copy is
    # invisible to the verifier's actual set -> set mismatch (receipt lists dist/
    # but actual doesn't). Either way, verification must fail.
    with pytest.raises(RuntimeError, match="set mismatch|closure|missing|extra|duplicate"):
        verify_archive_scan_receipt(export, source_digest=DIGEST, e2e_artifact_json=e2e)
