"""Optional Echo minimal-OS carrier (not official TCC / notary evidence)."""

from __future__ import annotations

import shutil
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

_WORKER_MODULE = "js.echo.c1_worker"


def echo_minimal_os_carrier_available() -> bool:
    """True only when a deny-default Darwin sandbox-exec backend exists."""

    return sys.platform == "darwin" and shutil.which("sandbox-exec") is not None


def require_echo_minimal_os_carrier() -> None:
    if not echo_minimal_os_carrier_available():
        raise RuntimeError("echo_minimal_os carrier unavailable (Darwin sandbox-exec required)")


def restricted_echo_environment(env: Mapping[str, str] | None = None) -> dict[str, str]:
    """Worker env without owner keys or provider tokens. Not official TCC."""

    from js.orin.process_split import strip_authority_from_env

    source = dict(env) if env is not None else {}
    cleaned = strip_authority_from_env(source)
    cleaned.setdefault("LC_ALL", "C")
    cleaned.setdefault("PYTHONDONTWRITEBYTECODE", "1")
    return cleaned


async def run_restricted_echo_command(
    command: list[str],
    *,
    workspace: Path,
    env: dict[str, str] | None = None,
) -> Any:
    """Run one argv under the existing deny-default sandbox executor.

    This is not a notarized Echo OS identity and must not be treated as
    official TCC evidence.
    """

    require_echo_minimal_os_carrier()
    from js.echo.os_sandbox import SandboxExecutor

    executor = SandboxExecutor(
        workspace,
        strict_isolation=True,
        trusted_executables=[Path(command[0])] if command else None,
    )
    if not executor.network_isolation_available() or not executor.filesystem_isolation_available():
        raise RuntimeError("echo_minimal_os sandbox backend is not available")
    return await executor.execute(
        command,
        cwd=str(workspace),
        env=restricted_echo_environment(env),
        network_allowed=False,
        fs_restricted=True,
    )


def worker_module_name() -> str:
    return _WORKER_MODULE


__all__ = [
    "echo_minimal_os_carrier_available",
    "require_echo_minimal_os_carrier",
    "restricted_echo_environment",
    "run_restricted_echo_command",
    "worker_module_name",
]
