#!/usr/bin/env python3
"""Advanced File Search skill — search by name pattern or content.

All filesystem access is anchored to ``JS_SKILL_WORKSPACE``.  Any attempt to
escape that directory (absolute paths, ``..``, symlinks, or traversal patterns)
results in an error instead of a search.
"""

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


def _resolve_workspace_path(user_path: str) -> Path:
    """Resolve ``user_path`` strictly inside ``JS_SKILL_WORKSPACE``.

    Rejects absolute paths, parent-directory references, and any result that
    resolves outside the workspace (including via symlinks).
    """
    workspace = Path(os.environ.get("JS_SKILL_WORKSPACE", ".")).resolve()

    if os.path.isabs(user_path):
        raise ValueError(f"Absolute paths are not allowed: {user_path[:80]}")

    # Reject explicit parent traversal before any filesystem operation.
    parts = Path(user_path).parts
    if any(part == ".." for part in parts):
        raise ValueError(f"Parent-directory references are not allowed: {user_path[:80]}")

    candidate = (workspace / user_path).resolve()

    # Defensive: resolve both real paths and ensure the candidate is still
    # under the workspace (mitigates symlink escapes).
    try:
        real_workspace = workspace.resolve()
        real_candidate = candidate.resolve()
    except OSError as exc:
        raise ValueError(f"Invalid path: {user_path[:80]}: {exc}") from exc

    if real_candidate == real_workspace or real_workspace in real_candidate.parents:
        return candidate

    raise ValueError(f"Path escapes workspace: {user_path[:80]}")


def _search_by_name(root: Path, pattern: str, max_depth: int = 5) -> list[str]:
    """Search for files matching pattern (fnmatch-style) under root."""
    results: list[str] = []
    for dirpath, _dirnames, filenames in os.walk(root):
        _dirnames[:] = [d for d in _dirnames if not (Path(dirpath) / d).is_symlink()]
        # Respect max_depth
        depth = len(Path(dirpath).relative_to(root).parts)
        if depth > max_depth:
            del _dirnames[:]  # Don't descend further
            continue
        for filename in filenames:
            filepath = Path(dirpath) / filename
            if filepath.is_symlink():
                continue
            if fnmatch.fnmatch(filename, pattern):
                results.append(str(filepath))
    return results


def _search_by_content(root: Path, content: str, max_results: int) -> list[str]:
    """Search for files containing content under root."""
    results: list[str] = []
    for dirpath, _dirnames, filenames in os.walk(root):
        _dirnames[:] = [d for d in _dirnames if not (Path(dirpath) / d).is_symlink()]
        for filename in filenames:
            if len(results) >= max_results:
                break
            filepath = Path(dirpath) / filename
            try:
                if filepath.is_symlink():
                    continue
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

    try:
        root = _resolve_workspace_path(path)
    except ValueError as exc:
        output = {"results": [f"Access denied: {exc}"], "count": 0}
        print(json.dumps(output, ensure_ascii=False))
        return

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
