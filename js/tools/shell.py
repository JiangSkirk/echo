"""Sandboxed shell execution tool."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from js.config import ToolLimits
from js.security.guard import BehaviorGuard, SecurityDecisionType
from js.security.sandbox import SandboxExecutor
from js.tools.registry import ToolParam, ToolResult, ToolSpec


class ShellTool:
    """Secure shell command execution."""

    def __init__(self, workspace: Path, limits: ToolLimits, guard: BehaviorGuard) -> None:
        self.workspace = workspace.resolve()
        self.limits = limits
        self.guard = guard
        self.executor = SandboxExecutor(
            workspace=workspace,
            timeout=limits.shell_timeout,
            max_output_bytes=limits.shell_max_output_bytes,
        )

    def get_spec(self) -> ToolSpec:
        return ToolSpec(
            name="shell",
            description="Execute a shell command. Use with caution. Commands run in workspace.",
            parameters=[
                ToolParam("command", "string", "Shell command to execute"),
                ToolParam("cwd", "string", "Working directory (relative to workspace)", required=False),
                ToolParam("timeout", "integer", "Override timeout in seconds", required=False),
            ],
            dangerous=True,
        )

    async def execute(
        self, command: str, cwd: str = ".", timeout: int = 0
    ) -> ToolResult:
        # Security check
        decision = self.guard.check_command(command, cwd)
        if decision.decision == SecurityDecisionType.BLOCK:
            return ToolResult(success=False, error=f"Security: {decision.reason}")
        elif decision.decision == SecurityDecisionType.WARN:
            # Still allow but mark
            pass

        # Path check for cwd
        path_decision = self.guard.check_path_operation(
            str(self.workspace / cwd), "read"
        )
        if path_decision.decision == SecurityDecisionType.BLOCK:
            return ToolResult(success=False, error=path_decision.reason)

        result = await self.executor.execute(
            command,
            cwd=cwd,
            timeout=timeout or self.limits.shell_timeout,
        )

        output = result.stdout
        if result.stderr:
            output += f"\n[stderr]\n{result.stderr}"

        if result.killed:
            output += "\n[Process was terminated (timeout or resource limit)]"

        return ToolResult(
            success=result.returncode == 0 and not result.killed,
            output=output,
            error=result.stderr if result.returncode != 0 else "",
            metadata={
                "returncode": result.returncode,
                "duration_ms": result.duration_ms,
                "killed": result.killed,
            },
        )

    def register(self, registry: Any) -> None:
        registry.register(self.get_spec(), self.execute)
