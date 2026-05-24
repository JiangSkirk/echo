"""Sandboxed execution environment for untrusted commands."""

from __future__ import annotations

import asyncio
import os
import platform
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import psutil

from js.utils.log import get_logger

logger = get_logger("js.security.sandbox")


@dataclass(frozen=True)
class SandboxResult:
    returncode: int
    stdout: str
    stderr: str
    duration_ms: float
    killed: bool = False
    oom_killed: bool = False


# macOS sandbox profile that blocks all network access but allows file/process ops.
_MACOS_NETWORK_DENY_PROFILE = """(version 1)
(allow default)
(deny network*)
"""

# macOS sandbox profile that restricts filesystem to workspace + system read-only
_MACOS_FS_RESTRICT_PROFILE = '''(version 1)
(allow default)
(deny network*)
(allow file-read*)
(allow file-write*
    (subpath "{workspace}"))
(deny file-write*
    (subpath "/etc")
    (subpath "/usr")
    (subpath "/bin")
    (subpath "/sbin")
    (subpath "/var")
    (subpath "/System")
    (subpath "~/.ssh")
    (subpath "~/.aws")
    (subpath "~/.kube")
    (subpath "~/.docker"))
'''


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
        self._has_sandbox_exec = shutil.which("sandbox-exec") is not None
        self._has_unshare = shutil.which("unshare") is not None

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

    def _wrap_network_isolation(
        self,
        cmd: list[str],
        network_allowed: bool = True,
    ) -> list[str]:
        """Wrap command with network isolation if requested and tools available."""
        if network_allowed:
            return cmd
        system = platform.system()
        if system == "Darwin" and self._has_sandbox_exec:
            # macOS: use sandbox-exec with a profile denying network
            return [
                "sandbox-exec",
                "-p",
                _MACOS_NETWORK_DENY_PROFILE,
                *cmd,
            ]
        if system == "Linux" and self._has_unshare:
            # Linux: unshare network namespace (no interfaces = no outbound)
            return ["unshare", "-n", *cmd]
        # Fallback: warn but still execute (fail-open to avoid breaking skills)
        import logging
        logging.getLogger("js.security.sandbox").warning(
            "Network isolation requested but no sandbox tool available "
            f"(platform={system}, sandbox-exec={self._has_sandbox_exec}, "
            f"unshare={self._has_unshare})"
        )
        return cmd

    def _wrap_filesystem_isolation(
        self,
        cmd: list[str],
        fs_restricted: bool = False,
    ) -> list[str]:
        """Wrap command with filesystem isolation if requested and tools available."""
        if not fs_restricted:
            return cmd
        system = platform.system()
        if system == "Darwin" and self._has_sandbox_exec:
            profile = _MACOS_FS_RESTRICT_PROFILE.format(workspace=str(self.workspace))
            return [
                "sandbox-exec",
                "-p",
                profile,
                *cmd,
            ]
        if system == "Linux" and self._has_unshare:
            # Linux: unshare mount namespace + bind workspace
            # This is a simplified approach; full chroot requires root
            import shlex
            # Safely quote the workspace path and each command argument
            quoted_ws = shlex.quote(str(self.workspace))
            quoted_cmd = " ".join(shlex.quote(str(arg)) for arg in cmd)
            return [
                "unshare",
                "-m",
                "bash",
                "-c",
                f"cd {quoted_ws} && {quoted_cmd}",
            ]
        logger.warning(
            "Filesystem isolation requested but no sandbox tool available "
            f"(platform={system}, sandbox-exec={self._has_sandbox_exec}, "
            f"unshare={self._has_unshare})"
        )
        return cmd

    async def execute(
        self,
        command: str | list[str],
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        stdin: str | None = None,
        timeout: float | None = None,
        network_allowed: bool = True,
        fs_restricted: bool = False,
    ) -> SandboxResult:
        """Execute a command in sandboxed environment."""
        import time
        start_time = time.monotonic()
        effective_timeout = timeout if timeout is not None else self.timeout

        if isinstance(command, str):
            # Use shell for complex commands, but carefully
            # Cross-platform: use sh on Unix, cmd /c on Windows
            if platform.system() == "Windows":
                cmd = ["cmd", "/c", command]
            else:
                cmd = ["sh", "-c", command]
        else:
            cmd = list(command)

        # Apply isolation wrappers before spawning
        cmd = self._wrap_network_isolation(cmd, network_allowed=network_allowed)
        cmd = self._wrap_filesystem_isolation(cmd, fs_restricted=fs_restricted)

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
                returncode = -9  # Cross-platform: SIGKILL (-9) is recognized on both Unix and Windows

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

            duration_ms = (time.monotonic() - start_time) * 1000

            return SandboxResult(
                returncode=returncode,
                stdout=stdout,
                stderr=stderr,
                duration_ms=duration_ms,
                killed=killed,
                oom_killed=oom_killed,
            )

        except Exception as e:
            duration_ms = (time.monotonic() - start_time) * 1000
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
            # Task was cancelled (normal when the monitored process exits);
            # swallow silently so the caller's await does not re-raise.
            return False
        return False

    def _kill_process_tree(self, proc: asyncio.subprocess.Process) -> None:
        """Kill a process and all its children.

        Tolerates permission errors and cases where child enumeration fails.
        Always falls back to proc.kill() to guarantee termination.
        """
        killed = False
        try:
            parent = psutil.Process(proc.pid)
            try:
                children = parent.children(recursive=True)
            except (psutil.AccessDenied, PermissionError, OSError, psutil.Error):
                children = []
            for child in children:
                try:
                    child.terminate()
                except (psutil.NoSuchProcess, psutil.AccessDenied, PermissionError, OSError, psutil.Error):
                    pass
            try:
                parent.terminate()
            except (psutil.NoSuchProcess, psutil.AccessDenied, PermissionError, OSError, psutil.Error):
                pass
            # Wait briefly, then force kill
            try:
                gone, alive = psutil.wait_procs(children + [parent], timeout=2)
                for p in alive:
                    try:
                        p.kill()
                    except (psutil.NoSuchProcess, psutil.AccessDenied, PermissionError, OSError, psutil.Error):
                        pass
            except (psutil.Error, OSError):
                pass
        except (psutil.NoSuchProcess, psutil.AccessDenied, PermissionError, OSError, psutil.Error):
            pass

        # Ultimate fallback: kill via asyncio subprocess API
        if not killed:
            try:
                proc.kill()
            except (ProcessLookupError, OSError, PermissionError):
                pass
