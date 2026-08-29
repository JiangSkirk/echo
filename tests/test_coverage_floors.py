"""Coverage-floor script and CI wiring stay fail-closed."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load() -> object:
    path = ROOT / "scripts" / "check_coverage_floors.py"
    spec = importlib.util.spec_from_file_location("check_coverage_floors", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _file(covered: int, statements: int, covered_branches: int, branches: int) -> dict[str, object]:
    return {
        "summary": {
            "covered_lines": covered,
            "num_statements": statements,
            "covered_branches": covered_branches,
            "num_branches": branches,
        }
    }


def test_floors_pass_on_synthetic_report() -> None:
    module = _load()
    report = {
        "files": {
            "js/security/guard.py": _file(95, 100, 9, 10),
            "js/echo/runtime.py": _file(90, 100, 18, 20),
            "js/bots/store.py": _file(80, 100, 16, 20),
        }
    }
    code, data = module.evaluate(report)
    assert code == 0
    assert data["security_line"] >= 86
    assert data["echo_line"] >= 85
    assert data["lib_branch"] >= 65


def test_floors_fail_when_security_drops() -> None:
    module = _load()
    report = {
        "files": {
            "js/security/guard.py": _file(80, 100, 8, 10),
            "js/echo/runtime.py": _file(90, 100, 18, 20),
        }
    }
    code, data = module.evaluate(report)
    assert code == 1
    assert data["security_line"] < 90


def test_ci_runs_density_and_coverage_floors() -> None:
    text = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "scripts/test_density_report.py" in text
    assert "scripts/check_coverage_floors.py" in text
    assert "--cov-branch" in text
    assert "--cov=js_work" in text
    assert "coverage.json" in text


def test_script_writes_regression_on_empty_report(tmp_path: Path) -> None:
    module = _load()
    path = tmp_path / "coverage.json"
    path.write_text(json.dumps({"files": {}}), encoding="utf-8")
    assert module.evaluate({"files": {}})[0] == 1
