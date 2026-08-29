#!/usr/bin/env python3
"""Run mutmut on the security-bearing surface. Local only; not a CI gate.

Scope is ``js/security`` + ``js/echo/ledger`` (includes the shell parser).
Writes a JSON summary next to the markdown report when ``--json`` is set.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def _run(argv: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, cwd=REPO, text=True, capture_output=True, check=False)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", dest="json_path", type=Path)
    parser.add_argument(
        "--skip-run",
        action="store_true",
        help="Only collect existing mutmut results",
    )
    args = parser.parse_args()
    if not args.skip_run:
        started = _run(["uv", "run", "mutmut", "run"])
        sys.stdout.write(started.stdout)
        sys.stderr.write(started.stderr)
        if started.returncode != 0:
            print("MUTATION_RUN_FAILED", file=sys.stderr)
            return started.returncode
    results = _run(["uv", "run", "mutmut", "results"])
    sys.stdout.write(results.stdout)
    sys.stderr.write(results.stderr)
    summary = {
        "stdout": results.stdout,
        "returncode": results.returncode,
    }
    if args.json_path:
        args.json_path.parent.mkdir(parents=True, exist_ok=True)
        args.json_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return 0 if results.returncode == 0 else results.returncode


if __name__ == "__main__":
    raise SystemExit(main())
