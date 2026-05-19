"""Tests for code execution tool."""

from pathlib import Path

import pytest

from js.config import SecurityConfig, ToolLimits
from js.security.guard import BehaviorGuard
from js.tools.code import CodeTool


class TestCodeTool:
    @pytest.fixture
    def code_tool(self, tmp_path: Path) -> CodeTool:
        limits = ToolLimits()
        guard = BehaviorGuard(SecurityConfig(), tmp_path)
        return CodeTool(tmp_path, limits, guard)

    @pytest.mark.asyncio
    async def test_execute_simple(self, code_tool: CodeTool) -> None:
        result = await code_tool.execute("print(2 + 2)")
        assert result.success
        assert "4" in result.output

    @pytest.mark.asyncio
    async def test_eval_blocked(self, code_tool: CodeTool) -> None:
        result = await code_tool.execute("eval('1+1')")
        assert not result.success
        assert "Disallowed" in result.error

    @pytest.mark.asyncio
    async def test_syntax_error(self, code_tool: CodeTool) -> None:
        result = await code_tool.execute("print(")
        assert not result.success
        assert "Syntax" in result.error
