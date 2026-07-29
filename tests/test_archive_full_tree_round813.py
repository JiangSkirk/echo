from __future__ import annotations

import hashlib
import json
import os
import zipfile
from pathlib import Path

import pytest

from js.echo.ledger.evidence_export import (
    ARCHIVE_SCAN_RECEIPT_NAME,
    ARCHIVE_SCAN_RULE_VERSION,
    _collect_export_archives,
    verify_archive_scan_receipt,
    write_archive_scan_receipt,
)

DIGEST = "d" * 64


def _make_archive(path: Path, content: str = "x=1\n") -> bytes:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.name.lower().endswith(".whl"):
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


def _seed_gate(export: Path) -> None:
    (export / "final").mkdir(parents=True, exist_ok=True)
    (export / "gates").mkdir(parents=True, exist_ok=True)
    (export / "TOOLCHAIN.lock.json").write_text("{}\n", encoding="utf-8")


def _e2e(export: Path, artifacts: dict[str, bytes]) -> Path:
    declared: dict[str, object] = {}
    for rel, payload in artifacts.items():
        key = "wheel" if rel.lower().endswith(".whl") else "sdist"
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


def _forge_receipt(export: Path, artifacts: dict[str, bytes]) -> None:
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
        "generated_utc": "2026-07-26T03:00:00Z",
    }
    (export / ARCHIVE_SCAN_RECEIPT_NAME).write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def test_extra_dist_archive_direct_verifier_fails(tmp_path: Path) -> None:
    export = tmp_path / "sanitized-export"
    _seed_gate(export)
    whl = export / "e2e" / "artifacts" / "demo.whl"
    whl_bytes = _make_archive(whl, content="GOOD\n")
    _make_archive(export / "dist" / "demo.whl", content="BAD_EXTRA\n")
    e2e = _e2e(export, {"e2e/artifacts/demo.whl": whl_bytes})
    _forge_receipt(export, {"e2e/artifacts/demo.whl": whl_bytes})
    with pytest.raises(RuntimeError, match="set mismatch|closure|extra|duplicate"):
        verify_archive_scan_receipt(export, source_digest=DIGEST, e2e_artifact_json=e2e)


def test_deep_directory_extra_archive_fails(tmp_path: Path) -> None:
    export = tmp_path / "sanitized-export"
    _seed_gate(export)
    whl = export / "e2e" / "artifacts" / "demo.whl"
    whl_bytes = _make_archive(whl)
    deep = export / "nested" / "a" / "b" / "sneaky.whl"
    _make_archive(deep, content="DEEP\n")
    e2e = _e2e(export, {"e2e/artifacts/demo.whl": whl_bytes})
    _forge_receipt(export, {"e2e/artifacts/demo.whl": whl_bytes})
    with pytest.raises(RuntimeError, match="set mismatch|closure|extra|duplicate"):
        verify_archive_scan_receipt(export, source_digest=DIGEST, e2e_artifact_json=e2e)


def test_same_basename_different_path_fails(tmp_path: Path) -> None:
    export = tmp_path / "sanitized-export"
    _seed_gate(export)
    a = _make_archive(export / "e2e" / "artifacts" / "demo.whl", content="A\n")
    _make_archive(export / "other" / "demo.whl", content="A\n")  # same hash, different path
    e2e = _e2e(export, {"e2e/artifacts/demo.whl": a})
    _forge_receipt(export, {"e2e/artifacts/demo.whl": a})
    with pytest.raises(RuntimeError, match="duplicate|set mismatch|closure|extra"):
        verify_archive_scan_receipt(export, source_digest=DIGEST, e2e_artifact_json=e2e)


def test_same_basename_different_hash_fails(tmp_path: Path) -> None:
    export = tmp_path / "sanitized-export"
    _seed_gate(export)
    a = _make_archive(export / "e2e" / "artifacts" / "demo.whl", content="A\n")
    _make_archive(export / "dist" / "demo.whl", content="B_DIFFERENT\n")
    e2e = _e2e(export, {"e2e/artifacts/demo.whl": a})
    _forge_receipt(export, {"e2e/artifacts/demo.whl": a})
    with pytest.raises(RuntimeError, match="duplicate|set mismatch|closure|extra"):
        verify_archive_scan_receipt(export, source_digest=DIGEST, e2e_artifact_json=e2e)


def test_case_extension_boundary_rejected(tmp_path: Path) -> None:
    export = tmp_path / "sanitized-export"
    _seed_gate(export)
    a = _make_archive(export / "e2e" / "artifacts" / "demo.whl", content="A\n")
    # Case-insensitive suspect detection must reject non-canonical casing.
    upper = export / "stash" / "extra.WHL"
    upper.parent.mkdir(parents=True)
    upper.write_bytes(a)
    with pytest.raises(RuntimeError, match="canonical|lowercase"):
        _collect_export_archives(export)
    e2e = _e2e(export, {"e2e/artifacts/demo.whl": a})
    _forge_receipt(export, {"e2e/artifacts/demo.whl": a})
    with pytest.raises(RuntimeError, match="canonical|lowercase"):
        verify_archive_scan_receipt(export, source_digest=DIGEST, e2e_artifact_json=e2e)


def test_archive_symlink_rejected(tmp_path: Path) -> None:
    export = tmp_path / "sanitized-export"
    _seed_gate(export)
    a = _make_archive(export / "e2e" / "artifacts" / "demo.whl", content="A\n")
    link = export / "e2e" / "artifacts" / "alias.whl"
    os.symlink(export / "e2e" / "artifacts" / "demo.whl", link)
    e2e = _e2e(export, {"e2e/artifacts/demo.whl": a})
    with pytest.raises(RuntimeError, match="symlink"):
        _collect_export_archives(export)
    _forge_receipt(export, {"e2e/artifacts/demo.whl": a})
    with pytest.raises(RuntimeError, match="symlink|set mismatch|closure"):
        verify_archive_scan_receipt(export, source_digest=DIGEST, e2e_artifact_json=e2e)


def test_archive_hardlink_rejected(tmp_path: Path) -> None:
    export = tmp_path / "sanitized-export"
    _seed_gate(export)
    target = export / "e2e" / "artifacts" / "demo.whl"
    a = _make_archive(target, content="A\n")
    alias = export / "e2e" / "artifacts" / "hard.whl"
    os.link(target, alias)
    e2e = _e2e(export, {"e2e/artifacts/demo.whl": a})
    with pytest.raises(RuntimeError, match="nlink"):
        _collect_export_archives(export)
    _forge_receipt(export, {"e2e/artifacts/demo.whl": a})
    with pytest.raises(RuntimeError, match="nlink|set mismatch|closure"):
        verify_archive_scan_receipt(export, source_digest=DIGEST, e2e_artifact_json=e2e)


def test_e2e_declares_extra_archive_fails(tmp_path: Path) -> None:
    export = tmp_path / "sanitized-export"
    _seed_gate(export)
    whl = _make_archive(export / "e2e" / "artifacts" / "demo.whl")
    sdist = _make_archive(export / "e2e" / "artifacts" / "demo.tar.gz")
    # Disk has both; receipt lists both; E2E declares only wheel.
    write_archive_scan_receipt(export, source_digest=DIGEST, hits=[])
    e2e = _e2e(export, {"e2e/artifacts/demo.whl": whl})
    with pytest.raises(RuntimeError, match="closure mismatch|extra|missing"):
        verify_archive_scan_receipt(export, source_digest=DIGEST, e2e_artifact_json=e2e)
    del sdist


def test_e2e_declares_missing_archive_fails(tmp_path: Path) -> None:
    export = tmp_path / "sanitized-export"
    _seed_gate(export)
    whl = _make_archive(export / "e2e" / "artifacts" / "demo.whl")
    missing_bytes = b"not-on-disk"
    e2e_path = export / "e2e" / "ECHO_ISOLATED_VENV_E2E.json"
    e2e_path.parent.mkdir(parents=True, exist_ok=True)
    e2e_path.write_text(
        json.dumps(
            {
                "ok": True,
                "artifacts": {
                    "wheel": {
                        "path": "e2e/artifacts/demo.whl",
                        "sha256": hashlib.sha256(whl).hexdigest(),
                        "bytes": len(whl),
                    },
                    "sdist": {
                        "path": "e2e/artifacts/demo.tar.gz",
                        "sha256": hashlib.sha256(missing_bytes).hexdigest(),
                        "bytes": len(missing_bytes),
                    },
                },
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    write_archive_scan_receipt(export, source_digest=DIGEST, hits=[])
    with pytest.raises(RuntimeError, match="closure mismatch|missing"):
        verify_archive_scan_receipt(export, source_digest=DIGEST, e2e_artifact_json=e2e_path)


def test_exact_declared_set_passes(tmp_path: Path) -> None:
    export = tmp_path / "sanitized-export"
    _seed_gate(export)
    whl = _make_archive(export / "e2e" / "artifacts" / "demo.whl")
    sdist = _make_archive(export / "e2e" / "artifacts" / "demo.tar.gz")
    arts = {
        "e2e/artifacts/demo.whl": whl,
        "e2e/artifacts/demo.tar.gz": sdist,
    }
    e2e = _e2e(export, arts)
    write_archive_scan_receipt(export, source_digest=DIGEST, hits=[])
    verify_archive_scan_receipt(export, source_digest=DIGEST, e2e_artifact_json=e2e)
