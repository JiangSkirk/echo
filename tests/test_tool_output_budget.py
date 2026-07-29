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


async def test_tool_registry_truncates_over_budget(echo_tool_context: Any) -> None:
    registry = ToolRegistry(ToolLimits(tool_output_budget_chars=2000), _AllowGuard())
    registry.register(
        ToolSpec(name="echo", description="echo", parameters=[ToolParam("content", "string", "")]),
        _echo_handler,
    )
    arguments = {"content": "x" * 5000}
    result = await registry.execute(
        "run-1",
        "echo",
        arguments,
            execution_context=echo_tool_context(
                run_id="run-1",
                tool_name="echo",
                arguments=arguments,
                max_bytes=6_000,
                registry=registry,
            ),
    )
    assert result.success is True
    assert len(result.output) <= 2000 + len(
        "\n... [output truncated: 5000 chars; use file_read with offset/limit to paginate]"
    )
    assert "[output truncated" in result.output
    assert result.metadata.get("truncated") is True
    assert result.metadata.get("original_len") == 5000


async def test_tool_registry_keeps_output_within_budget(echo_tool_context: Any) -> None:
    registry = ToolRegistry(ToolLimits(tool_output_budget_chars=2000), _AllowGuard())
    registry.register(
        ToolSpec(name="echo", description="echo", parameters=[ToolParam("content", "string", "")]),
        _echo_handler,
    )
    arguments = {"content": "short"}
    result = await registry.execute(
        "run-1",
        "echo",
        arguments,
            execution_context=echo_tool_context(
                run_id="run-1",
                tool_name="echo",
                arguments=arguments,
                registry=registry,
            ),
    )
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


async def test_file_read_offset_limit_on_single_line_large_file(tmp_path: Path) -> None:
    """A 5000-char single-line file with offset/limit should still respect budget."""
    tools = FileTools(tmp_path, ToolLimits(tool_output_budget_chars=2000), _AllowGuard())
    big = tmp_path / "single_line.txt"
    big.write_text("a" * 5000)
    result = await tools.read("single_line.txt", offset=0, limit=10)
    # Single line: splitlines gives 1 line, limit 10 keeps it, but result is 5000 chars > budget
    assert result.metadata.get("too_large") is True
    assert result.metadata.get("size") == 5000


async def test_file_read_offset_limit_on_multi_line_large_file(tmp_path: Path) -> None:
    """Multi-line large file with offset/limit should return requested lines within budget."""
    tools = FileTools(tmp_path, ToolLimits(tool_output_budget_chars=2000), _AllowGuard())
    big = tmp_path / "multi_line.txt"
    lines = [f"line {i}" for i in range(500)]
    big.write_text("\n".join(lines))
    result = await tools.read("multi_line.txt", offset=10, limit=20)
    assert result.metadata.get("too_large") is not True
    assert result.metadata.get("lines") == 20
    assert result.metadata.get("total_lines") == 500
    assert "line 10" in result.output
    assert "line 29" in result.output
    assert "line 30" not in result.output
