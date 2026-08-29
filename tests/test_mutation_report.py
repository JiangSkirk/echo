"""Mutation sample report and local-only mutmut wiring stay honest."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "docs" / "quality" / "mutation-2026-08-29.md"


def test_mutation_report_records_sample_not_a_ci_gate() -> None:
    text = REPORT.read_text(encoding="utf-8")
    for marker in (
        "**not** a CI gate",
        "js/security/parser.py",
        "js/security/guard.py",
        "js/echo/ledger/journal.py",
        "2718",
        "tests/security/test_mutation_kills.py",
        "Hardline",
        "Exempt survivors",
        "mutmut run",
    ):
        assert marker in text


def test_mutmut_is_dev_only_and_scoped() -> None:
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "mutmut>=3.3,<4" in text
    assert "js/security/parser.py" in text
    assert "js/echo/ledger/journal.py" in text
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "mutmut run" not in ci
    assert "scripts/run_mutation.py" not in ci
