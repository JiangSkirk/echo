"""CI and release workflows must install from the frozen lockfile."""

from __future__ import annotations

import re
from pathlib import Path

WORKFLOWS = Path(__file__).resolve().parents[1] / ".github" / "workflows"
_ACTION_SHA = re.compile(
    r"^(\s+)(?:- )?uses:\s+([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)@([0-9a-f]{40})\b",
    re.MULTILINE,
)
_ACTION_TAG = re.compile(
    r"^(\s+)(?:- )?uses:\s+([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)@(?![0-9a-f]{40}\b)\S+",
    re.MULTILINE,
)


def _read(name: str) -> str:
    return (WORKFLOWS / name).read_text(encoding="utf-8")


def test_ci_uses_frozen_uv_sync() -> None:
    text = _read("ci.yml")
    assert "pip install -e" not in text
    assert "uv lock --check" in text
    assert "uv sync --frozen --extra dev --extra monitor --extra echo-tokenizer" in text
    assert "scripts/export_constraints.py" in text
    assert "0.11.24" in text


def test_ci_and_audit_actions_are_sha_pinned() -> None:
    for name in ("ci.yml", "deps-audit.yml", "release-smoke.yml"):
        text = _read(name)
        tagged = _ACTION_TAG.findall(text)
        assert tagged == [], f"{name} has unpinned actions: {tagged}"
        pinned = _ACTION_SHA.findall(text)
        assert pinned, f"{name} has no SHA-pinned actions"


def test_deps_audit_workflow_exists() -> None:
    text = _read("deps-audit.yml")
    assert "uv run pip-audit" in text
    assert "uv sync --frozen" in text
    assert "schedule:" in text
