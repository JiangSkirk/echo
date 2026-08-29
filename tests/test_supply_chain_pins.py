"""Runtime dependency ranges must have an upper bound; constraints stay fresh."""

from __future__ import annotations

import importlib.util
import tomllib
from pathlib import Path

from packaging.requirements import Requirement

ROOT = Path(__file__).resolve().parents[1]
_UPPER_OPS = frozenset({"==", "===", "<", "<=", "~="})


def _load_export() -> object:
    path = ROOT / "scripts" / "export_constraints.py"
    spec = importlib.util.spec_from_file_location("export_constraints", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _project_dependencies() -> list[str]:
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    deps = data["project"]["dependencies"]
    assert isinstance(deps, list)
    return [str(item) for item in deps]


def test_runtime_dependencies_have_an_upper_bound() -> None:
    missing: list[str] = []
    for raw in _project_dependencies():
        req = Requirement(raw)
        if not any(spec.operator in _UPPER_OPS for spec in req.specifier):
            missing.append(raw)
    assert missing == [], f"uncapped runtime deps: {missing}"


def test_constraints_file_is_hashed_and_matches_lock() -> None:
    module = _load_export()
    path = ROOT / "constraints.txt"
    expected = module.render_constraints(cwd=ROOT)
    assert path.is_file()
    text = path.read_text(encoding="utf-8")
    assert "--hash=" in text
    pins = [line for line in text.splitlines() if line and not line.startswith("#")]
    assert not any(line.startswith("js-agent") for line in pins)
    assert module.check_constraints(path, expected) == 0


def test_ci_checks_constraints_freshness() -> None:
    text = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "scripts/export_constraints.py" in text
    assert "--check" in text
