#!/usr/bin/env python3
"""Report and ratchet test-to-product line density.

M1 (hard): tests/ (.py + .jsonl + .yaml) / (js+js_work .py) >= 1.2
M2/M3 are directional and are not fail-closed here.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SKIP_DIRS = {"__pycache__", ".venv", "node_modules", "vendor", ".git", "dist"}
TEST_SUFFIXES = {".py", ".jsonl", ".yaml", ".yml"}
PRODUCT_SUFFIXES = {".py"}
M1_FLOOR = 1.2


def _count(root: Path, suffixes: set[str]) -> int:
    total = 0
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix not in suffixes:
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        total += sum(1 for _ in path.open(encoding="utf-8", errors="replace"))
    return total


def report(repo: Path = REPO) -> dict[str, float | int]:
    product = _count(repo / "js", PRODUCT_SUFFIXES) + _count(repo / "js_work", PRODUCT_SUFFIXES)
    tests = _count(repo / "tests", TEST_SUFFIXES)
    ratio = (tests / product) if product else 0.0
    return {
        "product_py_lines": product,
        "test_lines": tests,
        "ratio": round(ratio, 4),
        "m1_floor": M1_FLOOR,
        "m1_pass": int(ratio >= M1_FLOOR),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--min", type=float, default=M1_FLOOR)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    data = report()
    if args.json:
        print(json.dumps(data, indent=2))
    else:
        print(
            f"density {data['ratio']}:1 "
            f"(tests={data['test_lines']} / product={data['product_py_lines']}) "
            f"M1>={args.min}"
        )
    if float(data["ratio"]) < args.min:
        print(f"DENSITY_REGRESSION: {data['ratio']} < {args.min}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
