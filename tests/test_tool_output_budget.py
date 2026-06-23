"""Tests for tool output budget and large-result reference."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from js.config import ToolLimits
from js.tools.files import FileTools
from js.tools.registry import ToolParam, ToolRegistry, ToolResult, ToolSpec


class _AllowGuard:
    def check_path_operation(self, path: str, op: str) -> Any:
        from js.security.guard import SecurityDecisionType

        return type("Decision", (), {"decision": SecurityDecisionType.ALLOW, "reason": ""})()

    def check_loop(self, run_id: str, tool_name: str, args_key: str) -> Any:
        from js.security.guard import SecurityDecisionType

        return type("Decision", (), {"decision": SecurityDecisionType.ALLOW, "reason": ""})()

    def check_tool_result(self, output: str) -> Any:
        from js.security.guard import SecurityDecisionType

        return type("Decision", (), {"decision": SecurityDecisionType.ALLOW, "reason": ""})()


async def _echo_handler(content: str) -> ToolResult:
    return ToolResult(success=True, output=content)


async def test_tool_registry_truncates_over_budget() -> None:
    registry = ToolRegistry(ToolLimits(tool_output_budget_chars=2000), _AllowGuard())
    registry.register(
        ToolSpec(name="echo", description="echo", parameters=[ToolParam("content", "string", "")]),
        _echo_handler,
    )
    result = await registry.execute("run-1", "echo", {"content": "x" * 5000})
    assert result.success is True
    assert len(result.output) <= 2000 + len(
        "\n... [output truncated: 5000 chars; use file_read with offset/limit to paginate]"
    )
    assert "[output truncated" in result.output
    assert result.metadata.get("truncated") is True
    assert result.metadata.get("original_len") == 5000


async def test_tool_registry_keeps_output_within_budget() -> None:
    registry = ToolRegistry(ToolLimits(tool_output_budget_chars=2000), _AllowGuard())
    registry.register(
        ToolSpec(name="echo", description="echo", parameters=[ToolParam("content", "string", "")]),
        _echo_handler,
    )
    result = await registry.execute("run-1", "echo", {"content": "short"})
    assert result.output == "short"
    assert result.metadata.get("truncated") is not True


async def test_file_read_returns_reference_for_large_file(tmp_path: Path) -> None:
    tools = FileTools(tmp_path, ToolLimits(tool_output_budget_chars=2000), _AllowGuard())
    big = tmp_path / "big.txt"
    big.write_text("a" * 5000)
    result = await tools.read("big.txt")
    assert result.success is True
    assert result.output == ""
    assert result.metadata.get("too_large") is True
    assert result.metadata.get("size") == 5000


async def test_file_read_returns_small_file(tmp_path: Path) -> None:
    tools = FileTools(tmp_path, ToolLimits(tool_output_budget_chars=2000), _AllowGuard())
    small = tmp_path / "small.txt"
    small.write_text("hello")
    result = await tools.read("small.txt")
    assert result.success is True
    assert result.output == "hello"
    assert result.metadata.get("too_large") is not True
