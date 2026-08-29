#!/usr/bin/env python3
"""Ingest factory documentation into JS Agent semantic memory.

Usage:
    python ingest.py

Requires JS Agent to be installed and configured:
    pip install -e ../../
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure js package is importable
PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from js.config import JSSettings  # noqa: E402
from js.memory.store import MemoryStore  # noqa: E402


def load_markdown_files(directory: Path) -> list[dict[str, str]]:
    """Read all .md files and extract YAML frontmatter + body."""
    docs: list[dict[str, str]] = []
    for path in sorted(directory.rglob("*.md")):
        if path.name == "README.md":
            continue
        content = path.read_text(encoding="utf-8")
        # Simple frontmatter extraction
        if content.startswith("---"):
            parts = content.split("---", 2)
            if len(parts) >= 3:
                frontmatter = parts[1].strip()
                body = parts[2].strip()
                docs.append(
                    {
                        "path": str(path.relative_to(directory.parent)),
                        "frontmatter": frontmatter,
                        "body": body,
                    }
                )
            else:
                docs.append(
                    {
                        "path": str(path.relative_to(directory.parent)),
                        "frontmatter": "",
                        "body": content,
                    }
                )
        else:
            docs.append(
                {
                    "path": str(path.relative_to(directory.parent)),
                    "frontmatter": "",
                    "body": content,
                }
            )
    return docs


def chunk_document(doc: dict[str, str], token_limit: int = 3000) -> list[dict[str, str]]:
    """Split document into chunks ≤ token_limit (approximated by characters)."""
    # Rough heuristic: 1 token ≈ 4 chars for English/Chinese mixed
    char_limit = token_limit * 4
    chunks: list[dict[str, str]] = []
    lines = doc["body"].splitlines()
    current: list[str] = []
    current_len = 0

    for line in lines:
        line_len = len(line) + 1
        if current_len + line_len > char_limit and current:
            chunks.append(
                {
                    "path": doc["path"],
                    "frontmatter": doc["frontmatter"],
                    "content": "\n".join(current),
                }
            )
            current = []
            current_len = 0
        current.append(line)
        current_len += line_len

    if current:
        chunks.append(
            {
                "path": doc["path"],
                "frontmatter": doc["frontmatter"],
                "content": "\n".join(current),
            }
        )
    return chunks


def main() -> int:
    settings = JSSettings.from_file()
    memory = MemoryStore(settings.state_dir, settings.memory)

    factory_dir = Path(__file__).parent
    docs = load_markdown_files(factory_dir)

    total_chunks = 0
    for doc in docs:
        chunks = chunk_document(doc)
        for i, chunk in enumerate(chunks):
            # Derive category from frontmatter or path
            category = "factory_doc"
            if "category: product_spec" in chunk["frontmatter"]:
                category = "product_spec"
            elif "category: workflow" in chunk["frontmatter"]:
                category = "workflow"
            elif "category: quality_checklist" in chunk["frontmatter"]:
                category = "quality_checklist"

            key = f"{chunk['path']}#chunk{i + 1}"
            value = f"{chunk['frontmatter']}\n\n{chunk['content']}"
            memory.store_semantic(
                key=key,
                value=value,
                category=category,
                confidence=0.95,
                source=chunk["path"],
            )
            total_chunks += 1
            print(f"  Stored: {key} ({category})")

    print(f"\n✅ Ingested {len(docs)} documents, {total_chunks} chunks into semantic memory.")
    print(f"   Database: {settings.state_dir / 'memory_enhanced.db'}")
    print("\nNext steps:")
    print("  1. Start the local Host: js appshell --no-browser")
    print("  2. Open the JS Agent desktop app")
    print("  3. Ask: 'What is the fabric of HL-2026-TShirt?'")
    print("  4. Check Memory to see sources and edit facts.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
