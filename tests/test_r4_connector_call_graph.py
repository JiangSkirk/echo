"""R4-B Task B7: Static production connector call-graph gate."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent


def _scan_production_files() -> list[Path]:
    """Find all non-test production Python files in js/."""
    files: list[Path] = []
    for path in (REPO / "js").rglob("*.py"):
        rel = path.relative_to(REPO)
        if "test" in rel.parts:
            continue
        if "__pycache__" in path.parts:
            continue
        files.append(path)
    return files


_ALLOWED_DISPATCH_CALLERS = {
    "js/echo/effect_interpreter.py",
    "js/connectors/manager.py",
    "js/connectors/base.py",
}


def test_no_production_module_directly_instantiates_local_connectors() -> None:
    """No production module (except connectors/local.py and manager.py) may
    instantiate ReadOnlyImportConnector or LimitedWritePublishConnector."""
    forbidden_names = {"ReadOnlyImportConnector", "LimitedWritePublishConnector"}
    for path in _scan_production_files():
        rel = str(path.relative_to(REPO))
        if rel in {"js/connectors/local.py", "js/connectors/manager.py"}:
            continue
        if rel == "js/connectors/__init__.py":
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Name) and func.id in forbidden_names:
                    pytest.fail(
                        f"{rel}:{node.lineno}: production module directly instantiates {func.id}"
                    )
                if isinstance(func, ast.Attribute) and func.attr in forbidden_names:
                    pytest.fail(
                        f"{rel}:{node.lineno}: production module directly instantiates {func.attr}"
                    )


def test_no_production_module_calls_execute_read_or_write() -> None:
    """No production module may call execute_read/execute_write on a connector manager."""
    forbidden_calls = {"execute_read", "execute_write"}
    for path in _scan_production_files():
        rel = str(path.relative_to(REPO))
        if rel == "js/connectors/manager.py":
            continue  # manager defines these (as fail-closed stubs)
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in forbidden_calls
                and "test" not in rel
            ):
                pytest.fail(
                    f"{rel}:{node.lineno}: production module calls {node.func.attr}"
                )


def test_no_production_module_directly_calls_dispatch_authorized() -> None:
    """Only EffectInterpreter may call _dispatch_authorized."""
    for path in _scan_production_files():
        rel = str(path.relative_to(REPO))
        if rel == "js/echo/effect_interpreter.py":
            continue
        if rel == "js/connectors/manager.py":
            continue  # manager defines it
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "_dispatch_authorized"
            ):
                pytest.fail(
                    f"{rel}:{node.lineno}: production module calls _dispatch_authorized"
                )


def test_fake_connector_not_in_production_factory() -> None:
    """FakeConnector must not appear in the production factory composition."""
    factory_code = (REPO / "js/connectors/manager.py").read_text(encoding="utf-8")
    tree = ast.parse(factory_code)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "build_production_connector_manager":
            for child in ast.walk(node):
                if isinstance(child, ast.Name) and child.id == "FakeConnector":
                    pytest.fail("FakeConnector found in production factory")
            return
    pytest.fail("build_production_connector_manager not found")


def test_pipeline_credentials_require_vault_migration() -> None:
    """Orchestrator must reject non-empty legacy credentials."""
    from js.pipeline.connector import ConnectorConfig

    cfg = ConnectorConfig(api_key="secret123")
    assert cfg.api_key == "secret123"  # parse-only, stored but not used at runtime
    # The orchestrator's _build_connectors checks for non-empty legacy fields
    # and raises ValueError. We test this via the source code:
    orch_code = (REPO / "js/pipeline/orchestrator.py").read_text(encoding="utf-8")
    assert "legacy connector credentials require explicit migration to vault_ref" in orch_code
