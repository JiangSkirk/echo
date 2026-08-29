#!/usr/bin/env python3
"""Fail-closed coverage floors for security, Echo, and the product library.

M1 ratchet floors (fail-closed, do not retreat):
- js/security/ line coverage >= 86%
- js/echo/ line coverage >= 85%
- js/ + js_work/ branch coverage >= 65%

Plan targets 90 / 85 / 75 are M2 directional and are reported, not fail-closed.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

SECURITY_LINE_FLOOR = 86.0
ECHO_LINE_FLOOR = 85.0
LIB_BRANCH_FLOOR = 65.0
PLAN_SECURITY_LINE = 90.0
PLAN_ECHO_LINE = 85.0
PLAN_LIB_BRANCH = 75.0


def _norm(path: str) -> str:
    return path.replace("\\", "/")


def _is_product(path: str) -> bool:
    norm = f"/{_norm(path)}"
    if "/tests/" in norm or "/.venv/" in norm:
        return False
    return "/js/" in norm or "/js_work/" in norm


def _under(path: str, package: str) -> bool:
    norm = f"/{_norm(path)}/"
    return f"/{package}/" in norm


def _summary(files: dict[str, Any], predicate) -> tuple[float, float, int, int, int, int]:
    statements = covered = branches = covered_branches = 0
    for path, data in files.items():
        if not predicate(path):
            continue
        summary = data.get("summary") if isinstance(data, dict) else None
        if not isinstance(summary, dict):
            continue
        statements += int(summary.get("num_statements") or 0)
        covered += int(summary.get("covered_lines") or 0)
        branches += int(summary.get("num_branches") or 0)
        covered_branches += int(summary.get("covered_branches") or 0)
    line_pct = (100.0 * covered / statements) if statements else 0.0
    branch_pct = (100.0 * covered_branches / branches) if branches else 0.0
    return line_pct, branch_pct, covered, statements, covered_branches, branches


def evaluate(
    report: dict[str, Any],
    *,
    security_floor: float = SECURITY_LINE_FLOOR,
    echo_floor: float = ECHO_LINE_FLOOR,
    lib_floor: float = LIB_BRANCH_FLOOR,
) -> tuple[int, dict[str, Any]]:
    files = report.get("files")
    if not isinstance(files, dict) or not files:
        return 1, {"error": "coverage report has no files"}
    security = _summary(files, lambda p: _is_product(p) and _under(p, "js/security"))
    echo = _summary(files, lambda p: _is_product(p) and _under(p, "js/echo"))
    lib = _summary(files, _is_product)
    data = {
        "security_line": round(security[0], 2),
        "echo_line": round(echo[0], 2),
        "lib_branch": round(lib[1], 2),
        "security_floor": security_floor,
        "echo_floor": echo_floor,
        "lib_floor": lib_floor,
        "plan_security_line": PLAN_SECURITY_LINE,
        "plan_echo_line": PLAN_ECHO_LINE,
        "plan_lib_branch": PLAN_LIB_BRANCH,
        "security_lines": f"{security[2]}/{security[3]}",
        "echo_lines": f"{echo[2]}/{echo[3]}",
        "lib_branches": f"{lib[4]}/{lib[5]}",
    }
    failed = (
        security[0] < security_floor
        or echo[0] < echo_floor
        or lib[1] < lib_floor
        or security[3] == 0
        or echo[3] == 0
        or lib[5] == 0
    )
    return (1 if failed else 0), data


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", dest="json_path", type=Path, required=True)
    parser.add_argument("--security", type=float, default=SECURITY_LINE_FLOOR)
    parser.add_argument("--echo", type=float, default=ECHO_LINE_FLOOR)
    parser.add_argument("--lib", type=float, default=LIB_BRANCH_FLOOR)
    args = parser.parse_args()
    report = json.loads(args.json_path.read_text(encoding="utf-8"))
    if not isinstance(report, dict):
        print("COVERAGE_REGRESSION: report root is not an object", file=sys.stderr)
        return 1
    code, data = evaluate(
        report,
        security_floor=args.security,
        echo_floor=args.echo,
        lib_floor=args.lib,
    )
    print(json.dumps(data, indent=2, sort_keys=True))
    if code:
        print("COVERAGE_REGRESSION: floors missed", file=sys.stderr)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
