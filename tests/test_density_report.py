"""M1 density ratchet: tests/ lines vs js+js_work product lines."""

from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load() -> object:
    path = ROOT / "scripts" / "test_density_report.py"
    spec = importlib.util.spec_from_file_location("density_report_script", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_m1_density_is_at_least_1_2() -> None:
    module = _load()
    data = module.report(ROOT)
    assert data["product_py_lines"] > 0
    assert data["test_lines"] > 0
    assert data["ratio"] >= 1.2
    assert data["m1_pass"] == 1
    assert data["test_py_lines"] > 0
    assert data["ratio_py"] >= 0.94
    assert data["py_pass"] == 1


def test_ci_ratchets_py_only_density() -> None:
    text = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "--min-py" in text
    assert "0.94" in text
