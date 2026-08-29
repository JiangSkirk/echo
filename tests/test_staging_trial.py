"""Staging trial script produces an internal (not external-audit) report."""

from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load() -> object:
    path = ROOT / "scripts" / "staging_trial.py"
    spec = importlib.util.spec_from_file_location("staging_trial", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_minimal_trial_writes_internal_report(tmp_path: Path) -> None:
    module = _load()
    output = tmp_path / "staging-trial.md"
    summary = module.run_trial(output=output, minimal=True)
    text = output.read_text(encoding="utf-8")
    assert summary["ok"] is True
    assert summary["docker_compose_staging_ran"] is False
    assert "not an external audit" in text
    assert "js appshell" in text
    assert "| `" in text
    names = {item["name"] for item in summary["cases"]}
    assert "bob_cannot_search_alice_memory" in names
    assert "anon_status_401" in names
    assert "foreign_api_key_cannot_switch_appshell_identity" in names
    assert "api_key_header_still_accepted_on_host" not in names


def test_audit_pack_points_at_staging_trial() -> None:
    text = (ROOT / "docs" / "security" / "AUDIT_PACK.md").read_text(encoding="utf-8")
    assert "staging-trial-2026-08-29.md" in text
    assert "scripts/staging_trial.py" in text
