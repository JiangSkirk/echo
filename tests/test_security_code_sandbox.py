"""F-10 regression tests: code.py sandbox escape families.

Each attack string is a CONFIRMED sandbox-bypass vector against
``CodeTool._scan_code``.  After the fix every one must be rejected by the
static scan before any interpreter is spawned (fail-closed).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from js.config import SecurityConfig, ToolLimits
from js.security.guard import BehaviorGuard
from js.tools.code import CodeTool


@pytest.fixture
def code_tool(tmp_path: Path) -> CodeTool:
    limits = ToolLimits()
    guard = BehaviorGuard(SecurityConfig(), tmp_path)
    return CodeTool(tmp_path, limits, guard)


class TestDunderAttributeEscapes:
    @pytest.mark.asyncio
    async def test_builtins_import_rejected(self, code_tool: CodeTool) -> None:
        result = await code_tool.execute('__builtins__.__import__("os")')
        assert not result.success
        assert "Disallowed" in result.error

    @pytest.mark.asyncio
    async def test_class_subclasses_rejected(self, code_tool: CodeTool) -> None:
        result = await code_tool.execute("().__class__.__base__.__subclasses__()")
        assert not result.success
        assert "Disallowed" in result.error

    @pytest.mark.asyncio
    async def test_class_attribute_rejected(self, code_tool: CodeTool) -> None:
        result = await code_tool.execute("print(''.__class__)")
        assert not result.success
        assert "Disallowed" in result.error

    @pytest.mark.asyncio
    async def test_getattribute_rejected(self, code_tool: CodeTool) -> None:
        result = await code_tool.execute("x.__getattribute__('__class__')")
        assert not result.success
        assert "Disallowed" in result.error

    @pytest.mark.asyncio
    async def test_init_rejected(self, code_tool: CodeTool) -> None:
        result = await code_tool.execute("x.__init__.__globals__")
        assert not result.success
        assert "Disallowed" in result.error

    @pytest.mark.asyncio
    async def test_mro_rejected(self, code_tool: CodeTool) -> None:
        result = await code_tool.execute("int.__mro__")
        assert not result.success
        assert "Disallowed" in result.error


class TestImportEscapes:
    @pytest.mark.asyncio
    async def test_relative_import_rejected(self, code_tool: CodeTool) -> None:
        result = await code_tool.execute("from . import os")
        assert not result.success
        assert "Disallowed" in result.error

    @pytest.mark.asyncio
    async def test_relative_parent_import_rejected(self, code_tool: CodeTool) -> None:
        result = await code_tool.execute("from .. import os")
        assert not result.success
        assert "Disallowed" in result.error

    @pytest.mark.asyncio
    @pytest.mark.parametrize("module", ["io", "posix", "runpy", "shutil", "pty", "pathlib"])
    async def test_newly_disallowed_modules_rejected(
        self, code_tool: CodeTool, module: str
    ) -> None:
        result = await code_tool.execute(f"import {module}")
        assert not result.success
        assert "Disallowed import" in result.error

    @pytest.mark.asyncio
    async def test_from_pathlib_import_rejected(self, code_tool: CodeTool) -> None:
        result = await code_tool.execute("from pathlib import Path")
        assert not result.success
        assert "Disallowed import" in result.error


class TestDynamicTypeConstruction:
    @pytest.mark.asyncio
    async def test_type_three_args_rejected(self, code_tool: CodeTool) -> None:
        result = await code_tool.execute('type("X", (), {})()')
        assert not result.success
        assert "Disallowed" in result.error

    @pytest.mark.asyncio
    async def test_type_single_arg_allowed_by_scan(self, code_tool: CodeTool) -> None:
        assert code_tool._scan_code("print(type(1))") is None


class TestLegitCodeStillScansClean:
    @pytest.mark.asyncio
    async def test_math_code_allowed(self, code_tool: CodeTool) -> None:
        assert code_tool._scan_code("import math\nprint(math.sqrt(16))") is None

    def test_bytecode_disabled_in_child_env(self, code_tool: CodeTool) -> None:
        """F-10: the sandboxed interpreter must not write .pyc files."""
        import inspect

        source = inspect.getsource(CodeTool.execute)
        assert "PYTHONDONTWRITEBYTECODE" in source
