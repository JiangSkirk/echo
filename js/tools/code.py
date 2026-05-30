"""Sandboxed Python code execution tool."""

from __future__ import annotations

import ast
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
    })

    DISALLOWED_IMPORTS = frozenset({
        "os", "subprocess", "sys", "ctypes", "socket", "urllib",
    })

    DISALLOWED_ATTRS = frozenset({
        "system", "popen", "spawn", "exec", "eval", "fork", "kill",
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
        # Quick AST scan for dangerous patterns
        scan = self._scan_code(code)
        if scan:
            return ToolResult(success=False, error=f"Code security scan failed: {scan}")

        # Write to a unique temp file to avoid race conditions
        script_path = self.workspace / f".js_temp_script_{id(code)}_{hash(code) & 0xFFFFFFFF}.py"
        try:
            script_path.write_text(code, encoding="utf-8")

            result = await self.executor.execute(
                [sys.executable, str(script_path)],
                cwd=str(self.workspace),
                timeout=timeout or self.limits.shell_timeout,
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
            script_path.unlink(missing_ok=True)

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
                if node.module:
                    root = node.module.split(".")[0]
                    if root in self.DISALLOWED_IMPORTS:
                        return f"Disallowed import: {node.module}"
            elif isinstance(node, ast.Call):
                # Check for disallowed builtins
                if isinstance(node.func, ast.Name) and node.func.id in self.DISALLOWED_BUILTINS:
                    return f"Disallowed builtin: {node.func.id}"
                # Check for subprocess
                if isinstance(node.func, ast.Attribute) and node.func.attr in ("popen", "call", "run"):
                    return f"Disallowed subprocess call: {node.func.attr}"
                # Check for getattr(__builtins__, ...) bypass
                if isinstance(node.func, ast.Name) and node.func.id == "getattr":
                    return "Disallowed getattr() call — potential sandbox bypass"

        return None

    def register(self, registry: Any) -> None:
        registry.register(self.get_spec(), self.execute)
