"""Tests for tool system."""

from pathlib import Path

import pytest

from js.config import SecurityConfig, ToolLimits
from js.security.guard import BehaviorGuard
from js.tools.files import FileTools
from js.tools.registry import ToolRegistry


class TestFileTools:
    @pytest.fixture
    def file_tools(self, tmp_path: Path) -> FileTools:
        limits = ToolLimits()
        guard = BehaviorGuard(SecurityConfig(allow_workspace_delete=True), tmp_path)
        return FileTools(tmp_path, limits, guard)

    @pytest.mark.asyncio
    async def test_read_write(self, file_tools: FileTools, tmp_path: Path) -> None:
        result = await file_tools.write("test.txt", "hello world")
        assert result.success

        result = await file_tools.read("test.txt")
        assert result.success
        assert "hello world" in result.output

    @pytest.mark.asyncio
    async def test_list_dir(self, file_tools: FileTools) -> None:
        await file_tools.write("a.txt", "a")
        await file_tools.write("b.txt", "b")

        result = await file_tools.list_dir(".")
        assert result.success
        assert "a.txt" in result.output
        assert "b.txt" in result.output

    @pytest.mark.asyncio
    async def test_delete(self, file_tools: FileTools) -> None:
        await file_tools.write("delete_me.txt", "content")
        result = await file_tools.delete("delete_me.txt")
        assert result.success

        result = await file_tools.read("delete_me.txt")
        assert not result.success


class TestToolRegistry:
    def test_register_and_list(self, tmp_path: Path) -> None:
        limits = ToolLimits()
        guard = BehaviorGuard(SecurityConfig(), tmp_path)
        registry = ToolRegistry(limits, guard)

        from js.tools.registry import ToolParam, ToolSpec

        async def dummy_handler(x: int) -> None:
            pass

        spec = ToolSpec(
            name="test",
            description="A test tool",
            parameters=[ToolParam("x", "integer", "A number")],
        )
        registry.register(spec, dummy_handler)

        assert registry.get("test") is not None
        assert len(registry.list_tools()) == 1
