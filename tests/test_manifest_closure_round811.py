from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from js.echo.ledger.evidence_export import (
    MANIFEST_NAME,
    build_manifest_v2,
    enumerate_export_regular_files,
    verify_manifest_v2,
)


def _seed_export(export: Path) -> None:
    export.mkdir(parents=True, exist_ok=True)
    (export / "final").mkdir(exist_ok=True)
    (export / "gates").mkdir(exist_ok=True)
    (export / "final" / "ruff.receipt.json").write_text('{"gate_name":"ruff"}\n', encoding="utf-8")
    (export / "gates" / "ruff.stdout.txt").write_text("All checks passed!\n", encoding="utf-8")
    (export / "gates" / "ruff.stderr.txt").write_text("", encoding="utf-8")


def test_manifest_exact_headers_and_set_closure(tmp_path: Path) -> None:
    export = tmp_path / "sanitized-export"
    _seed_export(export)
    build_manifest_v2(export)
    verify_manifest_v2(export)
    members = enumerate_export_regular_files(export)
    assert MANIFEST_NAME not in members
    assert "final/ruff.receipt.json" in members


def test_unknown_duplicate_missing_headers_fail(tmp_path: Path) -> None:
    export = tmp_path / "sanitized-export"
    _seed_export(export)
    manifest, _count, _total = build_manifest_v2(export)
    text = manifest.read_text(encoding="utf-8")

    manifest.write_text(
        text.replace("# entry_count=", "# note=x\n# entry_count="), encoding="utf-8"
    )
    with pytest.raises(RuntimeError, match="header"):
        verify_manifest_v2(export)

    manifest.write_text(
        text.splitlines()[0] + "\n# entry_count=1\n# generated_utc=2026-07-25T00:00:00Z\n",
        encoding="utf-8",
    )
    with pytest.raises(RuntimeError, match="header"):
        verify_manifest_v2(export)

    lines = text.splitlines()
    # Drop generated_utc header
    bad = "\n".join([lines[0], lines[2]] + lines[3:]) + "\n"
    manifest.write_text(bad, encoding="utf-8")
    with pytest.raises(RuntimeError, match="header"):
        verify_manifest_v2(export)


@pytest.mark.parametrize(
    "kind",
    ["symlink", "broken_symlink", "dir_symlink", "fifo", "hardlink"],
)
def test_special_files_fail_closed(tmp_path: Path, kind: str) -> None:
    export = tmp_path / "sanitized-export"
    _seed_export(export)
    build_manifest_v2(export)

    if kind == "symlink":
        target = export / "gates" / "ruff.stdout.txt"
        link = export / "gates" / "alias.stdout.txt"
        link.symlink_to(target.name)
    elif kind == "broken_symlink":
        (export / "broken").symlink_to("missing-target")
    elif kind == "dir_symlink":
        real = tmp_path / "outside"
        real.mkdir()
        (export / "alias_dir").symlink_to(real, target_is_directory=True)
    elif kind == "fifo":
        os.mkfifo(export / "pipe.fifo")
    else:
        src = export / "gates" / "ruff.stdout.txt"
        os.link(src, export / "gates" / "ruff.stdout.hardlink.txt")

    with pytest.raises(RuntimeError):
        verify_manifest_v2(export)


def test_extra_and_missing_and_mode_size_hash_drift(tmp_path: Path) -> None:
    export = tmp_path / "sanitized-export"
    _seed_export(export)
    manifest, _count, _total = build_manifest_v2(export)
    verify_manifest_v2(export)

    extra = export / "extra.txt"
    extra.write_text("x\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="mismatch|extra"):
        verify_manifest_v2(export)
    extra.unlink()

    victim = export / "gates" / "ruff.stderr.txt"
    victim.unlink()
    with pytest.raises(RuntimeError, match="mismatch|missing"):
        verify_manifest_v2(export)
    victim.write_text("", encoding="utf-8")
    build_manifest_v2(export)

    target = export / "gates" / "ruff.stdout.txt"
    os.chmod(target, 0o600)
    with pytest.raises(RuntimeError, match="mode"):
        verify_manifest_v2(export)
    os.chmod(target, stat.S_IMODE(target.stat().st_mode) | 0o644)
    # Rebuild to refresh mode in manifest after chmod restore ambiguity.
    build_manifest_v2(export)
    verify_manifest_v2(export)
    target.write_text(target.read_text(encoding="utf-8") + "x", encoding="utf-8")
    with pytest.raises(RuntimeError, match="sha256|size"):
        verify_manifest_v2(export)
    _ = manifest
