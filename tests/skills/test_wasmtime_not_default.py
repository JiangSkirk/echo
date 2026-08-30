"""P3-2 Wasmtime is a prototype report, not the skill production path."""

from __future__ import annotations

import inspect
from pathlib import Path

from js.skills import executor
from js.skills.wasmtime_sandbox import (
    PRODUCTION_ENABLED,
    wasmtime_on_production_path,
    wasmtime_runtime_available,
)


def test_wasmtime_is_not_on_the_production_path() -> None:
    assert PRODUCTION_ENABLED is False
    assert wasmtime_on_production_path() is False
    assert wasmtime_runtime_available() is False
    source = inspect.getsource(executor)
    assert "wasmtime" not in source
    assert "wasmtime_sandbox" not in source


def test_wasmtime_prototype_report_exists() -> None:
    report = Path("docs/prototypes/wasmtime-skill-sandbox.md").read_text(encoding="utf-8")
    assert "prototype report only" in report
    assert "Not on the production path" in report
    assert "js.skills.executor" in report
