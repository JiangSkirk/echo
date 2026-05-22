"""Sync memory chunks to an Obsidian-compatible directory."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from js.pipeline.chunker import Chunk


class ObsidianSync:
    """Write chunks as Markdown files into an Obsidian vault directory.

    Layout:
        vault/
        ├── AutoFetch/
        │   ├── Gmail/
        │   │   ├── 2024-01-15_a1b2c3d4.md
        │   │   └── …
        │   ├── Notion/
        │   └── …
        └── .meta/
            └── manifest.json
    """

    def __init__(self, vault_dir: Path) -> None:
        self.vault_dir = Path(vault_dir)
        self.autofetch_dir = self.vault_dir / "AutoFetch"
        self.meta_dir = self.vault_dir / ".meta"
        self._manifest: dict[str, Any] = {}
        self._load_manifest()

    def _load_manifest(self) -> None:
        manifest_path = self.meta_dir / "manifest.json"
        if manifest_path.exists():
            try:
                self._manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            except Exception:
                self._manifest = {}
        else:
            self._manifest = {"version": 1, "sources": {}}

    def _save_manifest(self) -> None:
        self.meta_dir.mkdir(parents=True, exist_ok=True)
        manifest_path = self.meta_dir / "manifest.json"
        manifest_path.write_text(json.dumps(self._manifest, indent=2, ensure_ascii=False), encoding="utf-8")

    def sync(self, chunks: list[Chunk]) -> list[Path]:
        """Write or update Markdown files for *chunks* and return written paths."""
        written: list[Path] = []
        for chunk in chunks:
            dir_path = self.autofetch_dir / self._sanitize(chunk.source)
            dir_path.mkdir(parents=True, exist_ok=True)
            file_path = dir_path / f"{self._sanitize(chunk.id)}.md"
            content = self._render_chunk(chunk)
            file_path.write_text(content, encoding="utf-8")
            written.append(file_path)

            # Update manifest
            src_meta = self._manifest.setdefault("sources", {}).setdefault(chunk.source, {"files": []})
            if str(file_path.relative_to(self.vault_dir)) not in src_meta["files"]:
                src_meta["files"].append(str(file_path.relative_to(self.vault_dir)))
        if written:
            self._save_manifest()
        return written

    def delete_source(self, source: str) -> int:
        """Remove all files for a given source. Returns deleted count."""
        dir_path = self.autofetch_dir / self._sanitize(source)
        if not dir_path.exists():
            return 0
        count = 0
        for f in dir_path.glob("*.md"):
            f.unlink()
            count += 1
        dir_path.rmdir()
        self._manifest.get("sources", {}).pop(source, None)
        self._save_manifest()
        return count

    @staticmethod
    def _render_chunk(chunk: Chunk) -> str:
        lines = [
            "---",
            f"id: {chunk.id}",
            f"source: {chunk.source}",
            f"title: {chunk.title}",
            f"tokens: {chunk.token_estimate}",
            f"url: {chunk.url}",
            "---",
            "",
            f"# {chunk.title}",
            "",
            chunk.body,
            "",
        ]
        if chunk.metadata:
            lines.extend(["## Metadata", "", "```json", json.dumps(chunk.metadata, indent=2, ensure_ascii=False), "```", ""])
        return "\n".join(lines)

    @staticmethod
    def _sanitize(name: str) -> str:
        """Make a string safe for directory/file names."""
        keep = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
        return "".join(c if c in keep else "_" for c in name)[:64]
