"""Sandboxed execution environment for untrusted commands."""

from __future__ import annotations

import asyncio
import os
import signal
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import psutil


@dataclass(frozen=True)
class SandboxResult:
    returncode: int
    stdout: str
    stderr: str
    duration_ms: float
    killed: bool = False
    oom_killed: bool = False


class SandboxExecutor:
    """Execute commands with resource limits and isolation."""

    def __init__(
        self,
        workspace: Path,
        timeout: float = 300.0,
        max_output_bytes: int = 50_000,
        max_memory_mb: int = 1024,
        env_passthrough: list[str] | None = None,
    ) -> None:
        self.workspace = workspace.resolve()
        self.timeout = timeout
        self.max_output_bytes = max_output_bytes
        self.max_memory_mb = max_memory_mb
        self.env_passthrough = env_passthrough or ["PATH", "HOME", "USER", "LANG", "TERM"]

    def _build_env(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        """Build a restricted environment."""
        env: dict[str, str] = {}
        for key in self.env_passthrough:
            if key in os.environ:
                env[key] = os.environ[key]
        if extra:
            env.update(extra)
        # Force working directory
        env["PWD"] = str(self.workspace)
        return env

    async def execute(
        self,
        command: str | list[str],
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        stdin: str | None = None,
        timeout: float | None = None,
    ) -> SandboxResult:
        """Execute a command in sandboxed environment."""
        start_time = asyncio.get_event_loop().time()
        effective_timeout = timeout if timeout is not None else self.timeout

        if isinstance(command, str):
            # Use shell for complex commands, but carefully
            cmd = ["bash", "-c", command]
        else:
            cmd = command

        work_dir = Path(cwd).expanduser().resolve() if cwd else self.workspace
        work_dir.mkdir(parents=True, exist_ok=True)

        built_env = self._build_env(env)

        proc: asyncio.subprocess.Process | None = None
        killed = False
        oom_killed = False
        returncode = 0

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                stdin=asyncio.subprocess.PIPE if stdin else None,
                cwd=str(work_dir),
                env=built_env,
            )

            # Memory monitoring task
            memory_task: asyncio.Task[Any] | None = None
            if self.max_memory_mb > 0:
                memory_task = asyncio.create_task(
                    self._monitor_memory(proc, self.max_memory_mb)
                )

            try:
                stdin_bytes = stdin.encode() if stdin is not None else None
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    proc.communicate(input=stdin_bytes),
                    timeout=effective_timeout,
                )
                returncode = proc.returncode or 0
            except TimeoutError:
                killed = True
                self._kill_process_tree(proc)
                stdout_bytes, stderr_bytes = b"", b"Command timed out"
                returncode = -signal.SIGTERM

            if memory_task and not memory_task.done():
                memory_task.cancel()
                try:
                    oom_killed = await memory_task
                except asyncio.CancelledError:
                    pass

            stdout = stdout_bytes.decode("utf-8", errors="replace")
            stderr = stderr_bytes.decode("utf-8", errors="replace")

            # Truncate if too large
            if len(stdout) > self.max_output_bytes:
                stdout = stdout[: self.max_output_bytes] + "\n... [output truncated]"
            if len(stderr) > self.max_output_bytes:
                stderr = stderr[: self.max_output_bytes] + "\n... [stderr truncated]"

            duration_ms = (asyncio.get_event_loop().time() - start_time) * 1000

            return SandboxResult(
                returncode=returncode,
                stdout=stdout,
                stderr=stderr,
                duration_ms=duration_ms,
                killed=killed,
                oom_killed=oom_killed,
            )

        except Exception as e:
            duration_ms = (asyncio.get_event_loop().time() - start_time) * 1000
            if proc:
                self._kill_process_tree(proc)
            return SandboxResult(
                returncode=-1,
                stdout="",
                stderr=f"Execution error: {e}",
                duration_ms=duration_ms,
                killed=True,
            )

    async def _monitor_memory(self, proc: asyncio.subprocess.Process, max_mb: int) -> bool:
        """Monitor process memory and kill if it exceeds limit."""
        max_bytes = max_mb * 1024 * 1024
        try:
            while proc.returncode is None:
                await asyncio.sleep(0.5)
                try:
                    p = psutil.Process(proc.pid)
                    mem_info = p.memory_info()
                    if mem_info.rss > max_bytes:
                        self._kill_process_tree(proc)
                        return True
                except psutil.NoSuchProcess:
                    break
        except asyncio.CancelledError:
            pass
        return False

    def _kill_process_tree(self, proc: asyncio.subprocess.Process) -> None:
        """Kill a process and all its children."""
        try:
            parent = psutil.Process(proc.pid)
            children = parent.children(recursive=True)
            for child in children:
                child.terminate()
            parent.terminate()
            # Wait briefly, then force kill
            gone, alive = psutil.wait_procs(children + [parent], timeout=2)
            for p in alive:
                p.kill()
        except psutil.NoSuchProcess:
            pass

        try:
            proc.kill()
        except ProcessLookupError:
            pass
