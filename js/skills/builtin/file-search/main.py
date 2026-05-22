#!/usr/bin/env python3
"""Advanced File Search skill — search by name pattern or content."""

from __future__ import annotations

import json
import os
import subprocess


def main() -> None:
    args = json.loads(os.environ.get("JS_SKILL_ARGS", "{}"))

    pattern = args.get("pattern", "*")
    search_content = args.get("content", "")
    path = args.get("path", ".")
    max_results = min(int(args.get("max_results", 50)), 200)

    # Sanitize inputs to prevent shell injection via subprocess args
    # Reject leading dashes (flag injection) and null bytes
    def _sanitize_file_arg(val: str) -> str:
        if val.startswith("-"):
            raise ValueError(f"Invalid argument (leading dash): {val[:40]}")
        if "\x00" in val:
            raise ValueError("Null bytes not allowed")
        return val

    path = _sanitize_file_arg(path)
    pattern = _sanitize_file_arg(pattern)
    if search_content:
        search_content = _sanitize_file_arg(search_content)

    results: list[str] = []

    if search_content:
        # Content search: use grep -r -n (line numbers), limit output
        proc = subprocess.run(
            ["grep", "-r", "-n", "--max-count=1", search_content, path],
            capture_output=True,
            text=True,
        )
        raw = proc.stdout or ""
        lines = [line for line in raw.splitlines() if line.strip()]
        results = lines[:max_results]
        if proc.returncode != 0 and not results:
            results = [f"No files found containing '{search_content}'"]
    else:
        # Name pattern search
        proc = subprocess.run(
            ["find", path, "-name", pattern, "-maxdepth", "5"],
            capture_output=True,
            text=True,
        )
        raw = proc.stdout or ""
        lines = [line for line in raw.splitlines() if line.strip()]
        results = lines[:max_results]
        if not results:
            results = [f"No files matching pattern '{pattern}' in '{path}'"]

    output = {"results": results, "count": len(results)}
    print(json.dumps(output, ensure_ascii=False))


if __name__ == "__main__":
    main()
