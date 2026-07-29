from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from js.echo.os_sandbox import SandboxExecutor


@dataclass(frozen=True)
class SandboxBackendProbe:
    backend: str
    real_process_backend: bool
    strict_isolation: bool
    network_isolation_available: bool
    filesystem_isolation_available: bool


@dataclass(frozen=True)
class SandboxBackendResult:
    backend: str
    returncode: int
    stdout: str
    stderr: str
    duration_ms: float
    killed: bool
    oom_killed: bool


class EchoSandboxBackend:
    def __init__(
        self,
        *,
        workspace: Path,
        timeout: float = 5.0,
        max_output_bytes: int = 50_000,
        max_memory_mb: int = 256,
        strict_isolation: bool = True,
    ) -> None:
        self._executor = SandboxExecutor(
            workspace=workspace,
            timeout=timeout,
            max_output_bytes=max_output_bytes,
            max_memory_mb=max_memory_mb,
            strict_isolation=strict_isolation,
        )

    def probe(self) -> SandboxBackendProbe:
        return SandboxBackendProbe(
            backend="js.echo.os_sandbox.SandboxExecutor",
            real_process_backend=True,
            strict_isolation=bool(getattr(self._executor, "strict_isolation", False)),
            network_isolation_available=self._executor.network_isolation_available(),
            filesystem_isolation_available=self._executor.filesystem_isolation_available(),
        )

    async def run(
        self,
        command: str | list[str],
        *,
        stdin: str | None = None,
        timeout: float | None = None,
        network_allowed: bool = True,
        fs_restricted: bool = False,
    ) -> SandboxBackendResult:
        result = await self._executor.execute(
            command,
            stdin=stdin,
            timeout=timeout,
            network_allowed=network_allowed,
            fs_restricted=fs_restricted,
        )
        return SandboxBackendResult(
            backend="js.echo.os_sandbox.SandboxExecutor",
            returncode=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
            duration_ms=result.duration_ms,
            killed=result.killed,
            oom_killed=result.oom_killed,
        )
