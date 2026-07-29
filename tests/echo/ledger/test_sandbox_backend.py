from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from js.echo.ledger.sandbox_backend import EchoSandboxBackend

if TYPE_CHECKING:
    import pytest


def test_real_sandbox_backend_runs_command_inside_workspace(tmp_path: Path) -> None:
    backend = EchoSandboxBackend(workspace=tmp_path, timeout=2.0)

    result = asyncio.run(
        backend.run([sys.executable, "-c", "import pathlib; print(pathlib.Path.cwd())"])
    )

    assert result.returncode == 0
    assert result.backend == "js.echo.os_sandbox.SandboxExecutor"
    assert result.stdout.strip() == str(tmp_path.resolve())


def test_real_sandbox_backend_enforces_timeout(tmp_path: Path) -> None:
    backend = EchoSandboxBackend(workspace=tmp_path, timeout=0.1)

    result = asyncio.run(
        backend.run([sys.executable, "-c", "import time; time.sleep(5)"])
    )

    assert result.killed
    assert result.returncode == -9


def test_real_sandbox_backend_truncates_output(tmp_path: Path) -> None:
    backend = EchoSandboxBackend(workspace=tmp_path, max_output_bytes=20)

    result = asyncio.run(
        backend.run([sys.executable, "-c", "print('x' * 100)"])
    )

    assert result.returncode == 0
    assert "[output truncated]" in result.stdout


def test_real_sandbox_backend_probe_reports_real_executor(tmp_path: Path) -> None:
    backend = EchoSandboxBackend(workspace=tmp_path)

    probe = backend.probe()

    assert probe.backend == "js.echo.os_sandbox.SandboxExecutor"
    assert probe.real_process_backend


def test_linux_unshare_is_not_reported_as_filesystem_isolation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = EchoSandboxBackend(workspace=tmp_path)
    backend._executor._has_sandbox_exec = False
    backend._executor._has_unshare = True
    backend._executor._has_bwrap = False
    monkeypatch.setattr("js.echo.os_sandbox.platform.system", lambda: "Linux")

    probe = backend.probe()

    assert probe.network_isolation_available
    assert not probe.filesystem_isolation_available
