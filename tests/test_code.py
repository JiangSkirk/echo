"""Tests for code execution tool."""

import sys
from pathlib import Path

import pytest

from js.config import SecurityConfig, ToolLimits
from js.security.guard import BehaviorGuard
from js.security.sandbox import SandboxExecutor
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
        if not result.success and "unshare failed" in result.error:
            pytest.skip("Linux unshare is unavailable in this runner")
        if not result.success and "sandbox-exec" in result.error:
            pytest.skip("macOS sandbox-exec is unavailable in this runner")
        if not result.success and result.metadata.get("returncode") == -6:
            pytest.skip("macOS sandbox-exec aborts under filesystem restrictions")
        assert result.success
        assert "4" in result.output

    @pytest.mark.asyncio
    async def test_eval_blocked(self, code_tool: CodeTool) -> None:
        result = await code_tool.execute("eval('1+1')")
        assert not result.success
        assert "Disallowed" in result.error

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "code",
        [
            # operator.attrgetter("__traceback__") chain must be rejected.
            "import operator",
            "import operator as op",
            "from operator import attrgetter",
            "import operator\noperator.attrgetter('__traceback__')",
            # Frame / traceback / generator / coroutine introspection attrs.
            "x.__traceback__",
            "x.tb_frame",
            "x.f_globals",
            "x.f_locals",
            "x.f_builtins",
            "x.gi_frame",
            "x.gi_code",
            "x.cr_frame",
            "x.cr_await",
            "x.__closure__",
            "x.__func__",
            "x.__self__",
            # Dangerous builtins in attribute-call form.
            "x.open('f')",
            "x.eval('1+1')",
            "x.exec('1+1')",
            "x.compile('1', 'f', 'exec')",
            "x.input()",
            "x.__import__('os')",
        ],
    )
    async def test_blacklist_bypass_payloads_blocked(
        self, code_tool: CodeTool, code: str
    ) -> None:
        result = await code_tool.execute(code)
        assert not result.success
        assert "Disallowed" in result.error

    def test_scan_allows_benign_code(self, code_tool: CodeTool) -> None:
        assert code_tool._scan_code("print('a b'.upper())\nprint(len([1, 2]))") is None

    @pytest.mark.asyncio
    async def test_syntax_error(self, code_tool: CodeTool) -> None:
        result = await code_tool.execute("print(")
        assert not result.success
        assert "Syntax" in result.error

    @pytest.mark.asyncio
    async def test_execute_does_not_follow_predictable_temp_symlink(
        self, code_tool: CodeTool, tmp_path: Path
    ) -> None:
        code = "print('safe')"
        victim = tmp_path.parent / "code-tool-victim.txt"
        victim.write_text("preserve-me", encoding="utf-8")
        legacy_path = tmp_path / (
            f".js_temp_script_{id(code)}_{hash(code) & 0xFFFFFFFF}.py"
        )
        legacy_path.symlink_to(victim)

        await code_tool.execute(code)

        assert victim.read_text(encoding="utf-8") == "preserve-me"

    @pytest.mark.asyncio
    async def test_execute_rejects_symlinked_private_temp_directory(
        self, code_tool: CodeTool, tmp_path: Path
    ) -> None:
        outside = tmp_path.parent / "code-tool-outside"
        outside.mkdir()
        (tmp_path / ".js-code").symlink_to(outside, target_is_directory=True)

        result = await code_tool.execute("print('safe')")

        assert not result.success
        assert "temporary directory" in result.error.lower()
        assert list(outside.iterdir()) == []

    @pytest.mark.asyncio
    async def test_workspace_venv_python_cannot_run_external_script(
        self, tmp_path: Path
    ) -> None:
        """The workspace interpreter is trusted, not an external-file bypass."""
        interpreter = tmp_path / ".venv" / "bin" / "python"
        interpreter.parent.mkdir(parents=True)
        interpreter.symlink_to(sys.executable)
        external_script = tmp_path.parent / "external.py"
        external_script.write_text("print('secret')", encoding="utf-8")

        sandbox = SandboxExecutor(workspace=tmp_path, strict_isolation=True)
        result = await sandbox.execute(
            [str(interpreter), str(external_script)],
            fs_restricted=True,
        )

        assert result.returncode == -1
        assert result.stderr == (
            "Filesystem restricted command denied path outside workspace: "
            f"{external_script}"
        )
