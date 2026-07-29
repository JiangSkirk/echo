from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path

import pytest

from js.echo.ledger import evidence_export
from js.echo.ledger.evidence_export import (
    ARCHIVE_SCAN_RECEIPT_NAME,
    ARCHIVE_SCAN_RULE_VERSION,
    verify_archive_scan_receipt,
    write_archive_scan_receipt,
)

DIGEST = "d" * 64


def _make_wheel_with_home(path: Path, current_home: str) -> bytes:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("demo/__init__.py", f"HOME = {current_home!r}\n")
        archive.writestr("demo/README.md", "clean\n")
    return path.read_bytes()


def _seed_export(export: Path, current_home: str) -> tuple[Path, bytes]:
    (export / "e2e" / "artifacts").mkdir(parents=True)
    whl = export / "e2e" / "artifacts" / "demo-0.0.1-py3-none-any.whl"
    payload = _make_wheel_with_home(whl, current_home)
    return whl, payload


def _forge_zero_hit_receipt(export: Path, whl: Path) -> None:
    data = whl.read_bytes()
    payload = {
        "schema_version": "js-agent-archive-scan-receipt-v1",
        "rule_version": ARCHIVE_SCAN_RULE_VERSION,
        "source_digest": DIGEST,
        "artifacts": [
            {
                "relative_path": whl.relative_to(export).as_posix(),
                "filename": whl.name,
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        ],
        "hit_count": 0,
        "hits": [],
        "ok": True,
        "generated_utc": "2026-07-26T01:00:00Z",
    }
    (export / ARCHIVE_SCAN_RECEIPT_NAME).write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def test_archive_verifier_rejects_forged_zero_hits(tmp_path: Path, monkeypatch) -> None:
    export = tmp_path / "sanitized-export"
    current_home = "/Users/testuser-home-marker"
    monkeypatch.setattr(evidence_export.Path, "home", lambda: Path(current_home))
    whl, _ = _seed_export(export, current_home)
    _forge_zero_hit_receipt(export, whl)

    with pytest.raises(RuntimeError, match="archive scan|hit|forged|rescan"):
        verify_archive_scan_receipt(export, source_digest=DIGEST)


def test_archive_verifier_rejects_hit_count_mismatch(tmp_path: Path, monkeypatch) -> None:
    export = tmp_path / "sanitized-export"
    current_home = "/Users/testuser-home-marker"
    monkeypatch.setattr(evidence_export.Path, "home", lambda: Path(current_home))
    whl, _ = _seed_export(export, current_home)

    # Honest scan would find 1 archive_current_home hit; forge hit_count=2.
    data = whl.read_bytes()
    payload = {
        "schema_version": "js-agent-archive-scan-receipt-v1",
        "rule_version": ARCHIVE_SCAN_RULE_VERSION,
        "source_digest": DIGEST,
        "artifacts": [
            {
                "relative_path": whl.relative_to(export).as_posix(),
                "filename": whl.name,
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        ],
        "hit_count": 2,
        "hits": [
            {"rule_id": "archive_current_home", "relative_path": whl.name, "count": 2},
        ],
        "ok": False,
        "generated_utc": "2026-07-26T01:00:00Z",
    }
    (export / ARCHIVE_SCAN_RECEIPT_NAME).write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    with pytest.raises(RuntimeError, match="hit|rescan|archive scan"):
        verify_archive_scan_receipt(export, source_digest=DIGEST)


def test_archive_verifier_rejects_stale_rule_version(tmp_path: Path) -> None:
    export = tmp_path / "sanitized-export"
    (export / "e2e" / "artifacts").mkdir(parents=True)
    whl = export / "e2e" / "artifacts" / "demo-0.0.1-py3-none-any.whl"
    with zipfile.ZipFile(whl, "w") as archive:
        archive.writestr("demo/__init__.py", "x=1\n")
    write_archive_scan_receipt(export, source_digest=DIGEST, hits=())

    # Rewrite rule_version to a stale value.
    receipt = export / ARCHIVE_SCAN_RECEIPT_NAME
    payload = json.loads(receipt.read_text(encoding="utf-8"))
    payload["rule_version"] = "archive-scan-rules-v1"
    receipt.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="rule_version"):
        verify_archive_scan_receipt(export, source_digest=DIGEST)


def test_archive_verifier_rescans_current_bytes(tmp_path: Path, monkeypatch) -> None:
    export = tmp_path / "sanitized-export"
    current_home = "/Users/testuser-home-marker"
    monkeypatch.setattr(evidence_export.Path, "home", lambda: Path(current_home))
    whl, _ = _seed_export(export, current_home)
    # Write an HONEST receipt via the builder so hits reflect the real scan.
    write_archive_scan_receipt(export, source_digest=DIGEST, hits=[])
    # The builder wrote hits=[] but the archive actually contains HOME; the
    # verifier must rescan and detect the real hit (reject).
    with pytest.raises(RuntimeError, match="hit|rescan|archive scan"):
        verify_archive_scan_receipt(export, source_digest=DIGEST)


def test_archive_verifier_does_not_emit_private_match_text(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    export = tmp_path / "sanitized-export"
    current_home = "/Users/testuser-secret-marker-xyz"
    monkeypatch.setattr(evidence_export.Path, "home", lambda: Path(current_home))
    whl, _ = _seed_export(export, current_home)
    _forge_zero_hit_receipt(export, whl)

    try:
        verify_archive_scan_receipt(export, source_digest=DIGEST)
    except RuntimeError as exc:
        msg = str(exc)
        # The verifier error and the receipt file must never contain the actual
        # HOME string or matched excerpt text.
        assert current_home not in msg
        receipt_text = (export / ARCHIVE_SCAN_RECEIPT_NAME).read_text(encoding="utf-8")
        assert current_home not in receipt_text
        captured = capsys.readouterr()
        assert current_home not in captured.out
        assert current_home not in captured.err
        return
    raise AssertionError("verifier should have rejected the forged receipt")
