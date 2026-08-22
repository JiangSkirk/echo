"""Runtime TCB write deny: file tools, shell allowlist, and matcher."""

from __future__ import annotations

from pathlib import Path

import pytest

from js.config import SecurityConfig, ToolLimits
from js.security.guard import BehaviorGuard
from js.security.runtime_tcb import (
    is_runtime_tcb_write,
    override_runtime_package_root,
    token_is_runtime_tcb_write,
)
from js.tools.files import FileTools
from js.tools.shell import ShellTool


def _fake_js_package(workspace: Path) -> Path:
    js_root = workspace / "js"
    (js_root / "security").mkdir(parents=True)
    (js_root / "echo").mkdir()
    (js_root / "agent").mkdir()
    (js_root / "tools").mkdir()
    (js_root / "web").mkdir()
    (js_root / "skills").mkdir()
    (js_root / "web" / "static").mkdir()
    (js_root / "config.py").write_text("# config\n", encoding="utf-8")
    (js_root / "tools" / "code.py").write_text("# code\n", encoding="utf-8")
    (js_root / "echo" / "capability.py").write_text("# cap\n", encoding="utf-8")
    (js_root / "agent" / "tool_executor.py").write_text("# exec\n", encoding="utf-8")
    (js_root / "web" / "server.py").write_text("# server\n", encoding="utf-8")
    (js_root / "security" / "guard.py").write_text("# guard\n", encoding="utf-8")
    (js_root / "web" / "static" / "app.js").write_text("console.log(1)\n", encoding="utf-8")
    return js_root


class TestRuntimeTcbMatcher:
    def test_entire_package_is_tcb_except_static(self, tmp_path: Path) -> None:
        package = _fake_js_package(tmp_path)
        with override_runtime_package_root(package):
            assert is_runtime_tcb_write(tmp_path / "js" / "tools" / "code.py", workspace=tmp_path)
            assert is_runtime_tcb_write(
                tmp_path / "js" / "echo" / "capability.py", workspace=tmp_path
            )
            assert is_runtime_tcb_write(
                tmp_path / "js" / "agent" / "tool_executor.py", workspace=tmp_path
            )
            assert is_runtime_tcb_write(tmp_path / "js" / "web" / "server.py", workspace=tmp_path)
            assert not is_runtime_tcb_write(tmp_path / "notes.txt", workspace=tmp_path)
            assert not is_runtime_tcb_write(
                tmp_path / "js" / "web" / "static" / "app.js", workspace=tmp_path
            )

    def test_install_tree_outside_workspace_is_not_this_workspace_tcb(self, tmp_path: Path) -> None:
        other = tmp_path / "install" / "js"
        other.mkdir(parents=True)
        (other / "config.py").write_text("x\n", encoding="utf-8")
        workspace = tmp_path / "workspace"
        workspace.mkdir()
        with override_runtime_package_root(other):
            assert not is_runtime_tcb_write(workspace / "js" / "config.py", workspace=workspace)


class TestFileWriteRuntimeTcb:
    @pytest.mark.asyncio
    async def test_file_write_denies_package_allows_static_and_ordinary(
        self, tmp_path: Path
    ) -> None:
        package = _fake_js_package(tmp_path)
        tools = FileTools(
            tmp_path,
            ToolLimits(),
            BehaviorGuard(SecurityConfig(allow_workspace_delete=True), tmp_path),
        )
        with override_runtime_package_root(package):
            for rel in (
                "js/echo/capability.py",
                "js/agent/tool_executor.py",
                "js/web/server.py",
                "js/tools/code.py",
            ):
                denied = await tools.write(rel, "pwned")
                assert not denied.success, rel
                assert "TCB" in denied.error

            allowed = await tools.write("notes.txt", "ok")
            assert allowed.success
            assert (tmp_path / "notes.txt").read_text(encoding="utf-8") == "ok"

            ui = await tools.write("js/web/static/app.js", "console.log(2)\n")
            assert ui.success
            assert (package / "web" / "static" / "app.js").read_text(encoding="utf-8") == (
                "console.log(2)\n"
            )


class TestShellRuntimeTcb:
    def test_write_commands_into_package_denied(self, tmp_path: Path) -> None:
        package = _fake_js_package(tmp_path)
        shell = ShellTool(tmp_path, ToolLimits(), BehaviorGuard(SecurityConfig(), tmp_path))
        with override_runtime_package_root(package):
            for command in (
                "mkdir js/security/evil",
                "touch js/echo/capability.py",
                "touch js/tools/code.py",
                "mv payload.txt js/web/server.py",
                "touch js/$x",
            ):
                assert shell._command_allowlist_error(command, tmp_path) is not None, command
            assert shell._command_allowlist_error("mkdir nested", tmp_path) is None
            assert shell._command_allowlist_error("touch notes.txt", tmp_path) is None
            assert shell._command_allowlist_error("touch js/web/static/app.js", tmp_path) is None
            assert token_is_runtime_tcb_write("js/echo/capability.py", workspace=tmp_path)
            assert not token_is_runtime_tcb_write("notes.txt", workspace=tmp_path)
            assert not token_is_runtime_tcb_write("js/web/static/app.js", workspace=tmp_path)
