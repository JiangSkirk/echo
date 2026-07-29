#!/usr/bin/env python3
"""Build current and historical SHA-256 evidence manifests."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

_EXCLUDED_CURRENT_DIRS = {"historical", "pre_fix", "failure", "failures", "failed"}
_MANIFEST_NAME = "MANIFEST.sha256"


def _eligible_files(root: Path, *, historical: bool) -> list[Path]:
    files: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file() or path.name == _MANIFEST_NAME:
            continue
        relative = path.relative_to(root)
        lowered_parts = {part.lower() for part in relative.parts}
        if not historical and lowered_parts & _EXCLUDED_CURRENT_DIRS:
            continue
        if not historical and any(
            marker in path.name.lower() for marker in (".old", ".bak", "failure", "failed")
        ):
            continue
        files.append(path)
    return sorted(files, key=lambda item: item.relative_to(root).as_posix())


def build_manifest(root: Path, *, historical: bool = False) -> Path:
    root = root.resolve()
    root.mkdir(parents=True, exist_ok=True)
    manifest = root / _MANIFEST_NAME
    lines = [
        f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(root).as_posix()}"
        for path in _eligible_files(root, historical=historical)
    ]
    manifest.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return manifest


def build_evidence_manifests(evidence_root: Path) -> tuple[Path, Path | None]:
    evidence_root = evidence_root.resolve()
    current = build_manifest(evidence_root)
    historical_root = evidence_root / "historical"
    historical = (
        build_manifest(historical_root, historical=True) if historical_root.is_dir() else None
    )
    return current, historical


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence_root", type=Path)
    args = parser.parse_args()
    current, historical = build_evidence_manifests(args.evidence_root)
    print(current)
    if historical is not None:
        print(historical)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
