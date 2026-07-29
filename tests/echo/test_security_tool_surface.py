"""F-14 regression tests: Echo tool-schema exposure reduction.

Empty user input must not receive the full tool surface (only the core
subset), and the core subset must not include execution tools (shell /
python) unless explicitly enabled by configuration.
"""

from __future__ import annotations

from js.config import SecurityConfig
from js.echo.turn_loop import _echo_tool_schema_subset


def _schema(name: str) -> dict[str, object]:
    return {"type": "function", "function": {"name": name, "description": name}}


def _names(schemas: list[dict[str, object]]) -> list[str]:
    return [str(item["function"]["name"]) for item in schemas]  # type: ignore[index]


_ALL = [
    _schema("file_read"),
    _schema("shell"),
    _schema("python"),
    _schema("web_search"),
    _schema("web_click"),
    _schema("excel_read"),
]


class TestEmptyInputToolSurface:
    def test_empty_query_returns_core_subset_not_full(self) -> None:
        names = _names(_echo_tool_schema_subset("", _ALL))
        assert names != _names(_ALL)
        assert "web_click" not in names
        assert "excel_read" not in names

    def test_whitespace_query_returns_core_subset_not_full(self) -> None:
        names = _names(_echo_tool_schema_subset("   ", _ALL))
        assert names != _names(_ALL)
        assert "web_click" not in names

    def test_empty_query_keeps_read_only_core(self) -> None:
        names = _names(_echo_tool_schema_subset("", _ALL))
        assert "file_read" in names
        assert "web_search" in names


class TestExecToolsRemovedFromCore:
    def test_core_excludes_shell_and_python_by_default(self) -> None:
        names = _names(_echo_tool_schema_subset("explain this simply", _ALL))
        assert "shell" not in names
        assert "python" not in names
        assert "file_read" in names

    def test_exec_tools_included_when_explicitly_enabled(self) -> None:
        names = _names(
            _echo_tool_schema_subset("explain this simply", _ALL, allow_exec_tools=True)
        )
        assert "shell" in names
        assert "python" in names

    def test_exec_tools_excluded_on_empty_query_by_default(self) -> None:
        names = _names(_echo_tool_schema_subset("", _ALL))
        assert "shell" not in names
        assert "python" not in names


class TestConfigGate:
    def test_security_config_exec_tools_default_off(self) -> None:
        assert SecurityConfig().echo_exec_tools is False

    def test_security_config_exec_tools_opt_in(self) -> None:
        assert SecurityConfig(echo_exec_tools=True).echo_exec_tools is True
