"""Release smoke test: successful run must not emit long tracebacks."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def test_release_smoke_all_does_not_print_traceback() -> None:
    """A successful release smoke run should be clean, without Python tracebacks.

    Regression guard for the `MemoryOrganizer LLM call failed` path that used
    to print a full Rich traceback because of ``exc_info=True``.

    Excludes ``echo_ledger`` (needs digest-bound SLO/E2E from later gates) and
    ``echo`` (latency SLO is host-noise-sensitive under concurrent pytest load).
    The ``release_smoke`` gate still runs ``--all`` after artifacts are bound.
    """
    from scripts.release_smoke import CHECKS

    checks = [name for name in CHECKS if name not in {"echo_ledger", "echo"}]
    result = subprocess.run(
        [sys.executable, "scripts/release_smoke.py", "--checks", *checks],
        cwd=Path(__file__).resolve().parent.parent,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=300,
    )
    combined = f"{result.stdout}\n{result.stderr}"
    assert result.returncode == 0, (
        f"release_smoke.py checks failed with exit {result.returncode}:\n{combined[-4000:]}"
    )
    assert "Traceback" not in combined, (
        f"release_smoke.py printed a traceback on success:\n{combined[-4000:]}"
    )
    assert "发布烟测通过" in combined, "release_smoke.py success marker missing"
