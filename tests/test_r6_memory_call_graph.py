"""R6 memory static call-graph gate tests - GREEN phase."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent
_JS_DIR = _REPO_ROOT / "js"


def _all_py_files() -> list[Path]:
    return sorted(_JS_DIR.rglob("*.py"))


def _parse_ast(path: Path) -> ast.AST:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


class _CallVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.calls: list[tuple[str, str | None]] = []

    def visit_Call(self, node: ast.Call) -> None:
        if isinstance(node.func, ast.Name):
            self.calls.append((node.func.id, None))
        elif isinstance(node.func, ast.Attribute):
            self.calls.append((node.func.attr, node.func.value.id if isinstance(node.func.value, ast.Name) else None))
        self.generic_visit(node)


class _ImportVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.imports: list[tuple[str, str | None]] = []

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.imports.append((alias.name, alias.asname))
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module:
            for alias in node.names:
                self.imports.append((f"{node.module}.{alias.name}", alias.asname))
        self.generic_visit(node)


class TestR6CallGraph:
    """静态调用图 gate：应 GREEN。"""

    def test_compression_pipeline_constructor_in_store(self) -> None:
        """CompressionPipeline() production constructor 在 js/memory/store.py。"""
        store_file = _JS_DIR / "memory" / "store.py"
        content = store_file.read_text(encoding="utf-8")
        assert "CompressionPipeline" in content, "MemoryStore 应持有 CompressionPipeline"

    def test_web_router_no_direct_sqlite(self) -> None:
        router_dir = _JS_DIR / "web" / "routers"
        if not router_dir.exists():
            pytest.skip("web/routers not found")
        for py_file in sorted(router_dir.glob("*.py")):
            tree = _parse_ast(py_file)
            visitor = _ImportVisitor()
            visitor.visit(tree)
            for mod, _ in visitor.imports:
                assert not mod.startswith("sqlite3"), f"{py_file.name} 不应直接 import sqlite3"

    def test_web_router_no_direct_compression_pipeline(self) -> None:
        router_dir = _JS_DIR / "web" / "routers"
        if not router_dir.exists():
            pytest.skip("web/routers not found")
        for py_file in sorted(router_dir.glob("*.py")):
            tree = _parse_ast(py_file)
            visitor = _ImportVisitor()
            visitor.visit(tree)
            for mod, _ in visitor.imports:
                assert "CompressionPipeline" not in mod, f"{py_file.name} 不应直接 import CompressionPipeline"

    def test_no_insert_or_replace_in_compression(self) -> None:
        """compression 生产代码不应使用 INSERT OR REPLACE 或 REPLACE INTO（代码中，非 docstring）。"""
        compression_files = [
            _JS_DIR / "memory" / "compression.py",
            _JS_DIR / "memory" / "compression_schema.py",
        ]
        for py_file in compression_files:
            if not py_file.exists():
                continue
            tree = _parse_ast(py_file)
            for node in ast.walk(tree):
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    s = node.value.upper()
                    assert "INSERT OR REPLACE" not in s, f"{py_file.name} string literal contains INSERT OR REPLACE"
                    assert "REPLACE INTO" not in s, f"{py_file.name} string literal contains REPLACE INTO"

    def test_memory_store_has_compression_pipeline(self) -> None:
        """MemoryStore 应有 compression_pipeline property。"""
        store_file = _JS_DIR / "memory" / "store.py"
        content = store_file.read_text(encoding="utf-8")
        assert "compression_pipeline" in content, "MemoryStore 应有 compression_pipeline"
        assert "create_compression_proposal" in content
        assert "approve_compression_proposal" in content
