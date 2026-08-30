#!/usr/bin/env python3
"""Report and ratchet test-to-product line density.

M1 (hard): tests/ (.py + .jsonl + .yaml) / (js+js_work .py) >= 1.2
Py-only (hard): tests/ .py / (js+js_work .py) >= 0.94
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
TEST_PY_SUFFIXES = {".py"}
PRODUCT_SUFFIXES = {".py"}
M1_FLOOR = 1.2
PY_FLOOR = 0.94


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
    tests_py = _count(repo / "tests", TEST_PY_SUFFIXES)
    ratio = (tests / product) if product else 0.0
    ratio_py = (tests_py / product) if product else 0.0
    return {
        "product_py_lines": product,
        "test_lines": tests,
        "test_py_lines": tests_py,
        "ratio": round(ratio, 4),
        "ratio_py": round(ratio_py, 4),
        "m1_floor": M1_FLOOR,
        "py_floor": PY_FLOOR,
        "m1_pass": int(ratio >= M1_FLOOR),
        "py_pass": int(ratio_py >= PY_FLOOR),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--min", type=float, default=M1_FLOOR)
    parser.add_argument("--min-py", type=float, default=PY_FLOOR)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    data = report()
    if args.json:
        print(json.dumps(data, indent=2))
    else:
        print(
            f"density {data['ratio']}:1 "
            f"(tests={data['test_lines']} / product={data['product_py_lines']}) "
            f"M1>={args.min}; "
            f"py-only {data['ratio_py']}:1 "
            f"(tests_py={data['test_py_lines']}) "
            f">={args.min_py}"
        )
    failed = False
    if float(data["ratio"]) < args.min:
        print(f"DENSITY_REGRESSION: {data['ratio']} < {args.min}", file=sys.stderr)
        failed = True
    if float(data["ratio_py"]) < args.min_py:
        print(
            f"DENSITY_REGRESSION_PY: {data['ratio_py']} < {args.min_py}",
            file=sys.stderr,
        )
        failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
