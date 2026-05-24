#!/usr/bin/env python3
"""Advanced File Search skill — search by name pattern or content."""

from __future__ import annotations

import fnmatch
import json
import os
from pathlib import Path


def _sanitize_file_arg(val: str) -> str:
    """Sanitize inputs to prevent path traversal and injection."""
    if val.startswith("-"):
        raise ValueError(f"Invalid argument (leading dash): {val[:40]}")
    if "\x00" in val:
        raise ValueError("Null bytes not allowed")
    return val


def _search_by_name(root: Path, pattern: str, max_depth: int = 5) -> list[str]:
    """Search for files matching pattern (fnmatch-style) under root."""
    results: list[str] = []
    for dirpath, _dirnames, filenames in os.walk(root):
        # Respect max_depth
        depth = len(Path(dirpath).relative_to(root).parts)
        if depth > max_depth:
            del _dirnames[:]  # Don't descend further
            continue
        for filename in filenames:
            if fnmatch.fnmatch(filename, pattern):
                results.append(str(Path(dirpath) / filename))
    return results


def _search_by_content(root: Path, content: str, max_results: int) -> list[str]:
    """Search for files containing content under root."""
    results: list[str] = []
    for dirpath, _dirnames, filenames in os.walk(root):
        for filename in filenames:
            if len(results) >= max_results:
                break
            filepath = Path(dirpath) / filename
            try:
                # Skip binary files and very large files
                if filepath.stat().st_size > 10 * 1024 * 1024:  # 10MB
                    continue
                with filepath.open("r", encoding="utf-8", errors="ignore") as f:
                    for i, line in enumerate(f, 1):
                        if content in line:
                            results.append(f"{filepath}:{i}:{line.rstrip()}")
                            break
                        if i > 10000:  # Limit lines per file
                            break
            except (OSError, UnicodeDecodeError):
                continue  # Binary or unreadable file
        if len(results) >= max_results:
            break
    return results


def main() -> None:
    args = json.loads(os.environ.get("JS_SKILL_ARGS", "{}"))

    pattern = args.get("pattern", "*")
    search_content = args.get("content", "")
    path = args.get("path", ".")
    max_results = min(int(args.get("max_results", 50)), 200)

    path = _sanitize_file_arg(path)
    pattern = _sanitize_file_arg(pattern)
    if search_content:
        search_content = _sanitize_file_arg(search_content)

    root = Path(path).resolve()
    if not root.exists():
        output = {"results": [f"Path does not exist: {path}"], "count": 0}
        print(json.dumps(output, ensure_ascii=False))
        return

    results: list[str] = []

    if search_content:
        results = _search_by_content(root, search_content, max_results)
        if not results:
            results = [f"No files found containing '{search_content}'"]
    else:
        results = _search_by_name(root, pattern, max_depth=5)
        results = results[:max_results]
        if not results:
            results = [f"No files matching pattern '{pattern}' in '{path}'"]

    output = {"results": results, "count": len(results)}
    print(json.dumps(output, ensure_ascii=False))


if __name__ == "__main__":
    main()
