"""Sandboxed Python code execution tool."""
# noqa: SIM102 (intentional layered security checks)

from __future__ import annotations

import ast
import os
import secrets
import stat
import sys
from pathlib import Path
from typing import Any

from js.config import ToolLimits
from js.security.guard import BehaviorGuard
from js.security.sandbox import SandboxExecutor
from js.tools.registry import ToolParam, ToolResult, ToolSpec


class CodeTool:
    """Execute Python code in a sandboxed environment."""

    DISALLOWED_BUILTINS = frozenset({
        "open",
        "eval",
        "exec",
        "compile",
        "__import__",
        "input",
        "exit",
        "quit",
        "globals",     # globals()["__builtins__"] bypass
        "locals",      # locals() introspection bypass
        "vars",        # vars() introspection bypass
        "breakpoint",  # breakpoint() debugger bypass
    })

    DISALLOWED_IMPORTS = frozenset({
        "os", "subprocess", "sys", "ctypes", "socket", "urllib",
        "importlib",   # importlib.import_module("os") bypass
        "builtins",    # builtins.open bypass
        "inspect",     # inspect.currentframe() introspection
        "code",        # code.InteractiveConsole bypass
        "types",       # types.FunctionType dynamic code
        "gc",          # gc.get_objects() introspection
        "io",          # io.open raw file access bypass
        "posix",       # posix.system direct syscall module
        "runpy",       # runpy.run_module("os") execution bypass
        "shutil",      # shutil.copy/chown file manipulation
        "pty",         # pty.spawn interactive shell escape
        "pathlib",     # pathlib.Path.write_text file write bypass
    })

    DISALLOWED_ATTRS = frozenset({
        "system", "popen", "spawn", "exec", "eval", "fork", "kill",
        "__subclasses__", "__mro__",
        "__dict__",      # object introspection
        "__bases__",     # class hierarchy traversal
        "__base__",      # ().class .__base__ hierarchy traversal
        "__globals__",   # function global scope access
        "__code__",      # function code object access
        "__builtins__",  # __builtins__.__import__ sandbox escape
        "__class__",     # ().class .__base__.__subclasses__() escape
        "__init__",      # x.__init__.__globals__ escape
        "__getattribute__",  # getattr-equivalent introspection escape
    })

    def __init__(self, workspace: Path, limits: ToolLimits, guard: BehaviorGuard) -> None:
        self.workspace = workspace.resolve()
        self.limits = limits
        self.guard = guard
        self.executor = SandboxExecutor(
            workspace=workspace,
            timeout=limits.shell_timeout,
            max_output_bytes=limits.shell_max_output_bytes,
            strict_isolation=True,
            trusted_executables=[Path(sys.executable)],
        )

    def get_spec(self) -> ToolSpec:
        return ToolSpec(
            name="python",
            description="Execute Python code and return stdout/stderr. Files can be read from workspace.",
            parameters=[
                ToolParam("code", "string", "Python code to execute"),
                ToolParam("timeout", "integer", "Execution timeout in seconds", required=False),
            ],
            dangerous=True,
        )

    async def execute(self, code: str, timeout: int = 0) -> ToolResult:
        if len(code) > self.limits.file_write_max_chars:
            return ToolResult(success=False, error="Code exceeds the execution size limit")

        # Quick AST scan for dangerous patterns
        scan = self._scan_code(code)
        if scan:
            return ToolResult(success=False, error=f"Code security scan failed: {scan}")

        script_path: Path
        temp_dir_fd: int
        script_name: str
        try:
            script_path, temp_dir_fd, script_name = self._create_private_script(code)
        except (OSError, RuntimeError, ValueError):
            return ToolResult(
                success=False,
                error="Secure code temporary directory is unavailable",
            )

        try:
            result = await self.executor.execute(
                [sys.executable, str(script_path)],
                cwd=str(self.workspace),
                # Never let the sandboxed interpreter emit .pyc bytecode into
                # __pycache__ directories (on-host artifact poisoning vector).
                env={"PYTHONDONTWRITEBYTECODE": "1"},
                timeout=timeout or self.limits.shell_timeout,
                network_allowed=False,
                fs_restricted=True,
            )

            return ToolResult(
                success=result.returncode == 0 and not result.killed,
                output=result.stdout,
                error=result.stderr,
                metadata={
                    "returncode": result.returncode,
                    "duration_ms": result.duration_ms,
                },
            )
        finally:
            try:
                os.unlink(script_name, dir_fd=temp_dir_fd)
                os.fsync(temp_dir_fd)
            except FileNotFoundError:
                pass
            finally:
                os.close(temp_dir_fd)

    def _create_private_script(self, code: str) -> tuple[Path, int, str]:
        """Create an execution script without following workspace symlinks."""
        required_dir_fd = (os.open, os.mkdir, os.unlink)
        if (
            not hasattr(os, "O_DIRECTORY")
            or not hasattr(os, "O_NOFOLLOW")
            or not hasattr(os, "O_CLOEXEC")
            or any(function not in os.supports_dir_fd for function in required_dir_fd)
        ):
            raise RuntimeError("Secure temporary-file primitives are unavailable")

        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        workspace_fd = os.open(self.workspace, directory_flags)
        temp_dir_fd = -1
        try:
            try:
                os.mkdir(".js-code", 0o700, dir_fd=workspace_fd)
                os.fsync(workspace_fd)
            except FileExistsError:
                pass
            temp_dir_fd = os.open(".js-code", directory_flags, dir_fd=workspace_fd)
            metadata = os.fstat(temp_dir_fd)
            if not stat.S_ISDIR(metadata.st_mode):
                raise ValueError("Code temporary path is not a directory")
            if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
                raise ValueError("Code temporary directory has an unexpected owner")
            os.fchmod(temp_dir_fd, 0o700)
        except BaseException:
            if temp_dir_fd >= 0:
                os.close(temp_dir_fd)
            raise
        finally:
            os.close(workspace_fd)

        script_name = f"script-{secrets.token_hex(16)}.py"
        script_flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_NOFOLLOW
            | os.O_CLOEXEC
        )
        try:
            script_fd = os.open(script_name, script_flags, 0o600, dir_fd=temp_dir_fd)
            try:
                payload = code.encode("utf-8")
                view = memoryview(payload)
                while view:
                    written = os.write(script_fd, view)
                    if written <= 0:
                        raise OSError("Code script write stalled")
                    view = view[written:]
                os.fsync(script_fd)
            finally:
                os.close(script_fd)
            os.fsync(temp_dir_fd)
        except BaseException:
            try:
                os.unlink(script_name, dir_fd=temp_dir_fd)
            except FileNotFoundError:
                pass
            os.close(temp_dir_fd)
            raise

        return self.workspace / ".js-code" / script_name, temp_dir_fd, script_name

    def _scan_code(self, code: str) -> str | None:
        """Quick static analysis for dangerous patterns."""
        try:
            tree = ast.parse(code)
        except SyntaxError as e:
            return f"Syntax error: {e}"

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split(".")[0]
                    if root in self.DISALLOWED_IMPORTS:
                        return f"Disallowed import: {alias.name}"
            elif isinstance(node, ast.ImportFrom):
                # Relative imports (from . import os) resolve against the
                # caller's package context and escape the module allowlist.
                if node.level and node.level > 0:
                    return "Disallowed relative import — sandbox bypass"
                if node.module:
                    root = node.module.split(".")[0]
                    if root in self.DISALLOWED_IMPORTS:
                        return f"Disallowed import: {node.module}"
            elif isinstance(node, ast.Call):
                # Check for disallowed builtins
                if isinstance(node.func, ast.Name) and node.func.id in self.DISALLOWED_BUILTINS:
                    return f"Disallowed builtin: {node.func.id}"
                # type("X", (), {}) dynamic class construction — bootstrap for
                # metaclass/__subclasses__ escapes.
                if (
                    isinstance(node.func, ast.Name)
                    and node.func.id == "type"
                    and len(node.args) == 3
                ):
                    return "Disallowed type() with 3 arguments — dynamic class construction"
                # Check for subprocess
                if isinstance(node.func, ast.Attribute) and node.func.attr in ("popen", "call", "run"):
                    return f"Disallowed subprocess call: {node.func.attr}"
                # Check for getattr(__builtins__, ...) bypass
                if isinstance(node.func, ast.Name) and node.func.id == "getattr":
                    return "Disallowed getattr() call — potential sandbox bypass"
                # Check for builtins.open / builtins.eval (import builtins; builtins.open(...))
                if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.value.id == "builtins":
                    return f"Disallowed builtins.{node.func.attr} call — sandbox bypass"
                # Check for all reflective class introspection attrs
                if isinstance(node.func, ast.Attribute) and node.func.attr in self.DISALLOWED_ATTRS:
                    return f"Disallowed reflective attribute: {node.func.attr}"
            elif isinstance(node, ast.Attribute) and node.attr in self.DISALLOWED_ATTRS:
                return f"Disallowed reflective attribute access: {node.attr}"
            # Bare __builtins__ name access (e.g. __builtins__.__import__)
            elif isinstance(node, ast.Name) and node.id == "__builtins__":
                return "Disallowed __builtins__ access — sandbox bypass"
            # Check for __builtins__["eval"] / globals()["__builtins__"] subscript bypass
            elif isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name) and node.value.id == "__builtins__":
                return "Disallowed __builtins__ subscript access — sandbox bypass"

        return None

    def register(self, registry: Any) -> None:
        registry.register(self.get_spec(), self.execute)
