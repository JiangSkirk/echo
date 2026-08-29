"""Opt-in product AppShell/Echo process split.

Default off (C-I01). Enabling this flag does not open ``orin.enforce`` and
is not evidence that Stage C shipped. The parent keeps owner keys; the
worker environment is stripped of authority material.
"""

from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from js.orin.process_split import (
    mark_appshell_echo_separated,
    reset_process_split_observations,
    strip_authority_from_env,
)

_WORKER_MODULE = "js.echo.c1_worker"


@dataclass(frozen=True, slots=True)
class EchoWorkerHandle:
    pid: int
    process: subprocess.Popen[bytes]


def product_process_split_enabled(settings: Any) -> bool:
    return getattr(settings, "appshell_process_split", False) is True


def worker_environment(env: dict[str, str] | None = None) -> dict[str, str]:
    source = dict(env) if env is not None else dict(os.environ)
    cleaned = strip_authority_from_env(source)
    cleaned["JS_ECHO_WORKER"] = "1"
    cleaned.setdefault("PYTHONDONTWRITEBYTECODE", "1")
    return cleaned


def spawn_echo_worker(*, workspace: Path, env: dict[str, str] | None = None) -> EchoWorkerHandle:
    """Start a restricted Echo worker. Parent retains owner keys."""

    command = [sys.executable, "-m", _WORKER_MODULE]
    process = subprocess.Popen(
        command,
        cwd=str(workspace),
        env=worker_environment(env),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if process.pid is None or process.pid == os.getpid():
        process.kill()
        raise RuntimeError("Echo worker spawn failed to create a new process")
    mark_appshell_echo_separated(True)
    return EchoWorkerHandle(pid=process.pid, process=process)


def maybe_enable_product_process_split(settings: Any) -> EchoWorkerHandle | None:
    """Activate observation only when the product flag is on and a worker starts."""

    if not product_process_split_enabled(settings):
        return None
    workspace = Path(getattr(settings, "workspace", Path.cwd()))
    workspace.mkdir(parents=True, exist_ok=True)
    return spawn_echo_worker(workspace=workspace)


def disable_product_process_split_observation() -> None:
    reset_process_split_observations()


__all__ = [
    "EchoWorkerHandle",
    "disable_product_process_split_observation",
    "maybe_enable_product_process_split",
    "product_process_split_enabled",
    "spawn_echo_worker",
    "worker_environment",
]
