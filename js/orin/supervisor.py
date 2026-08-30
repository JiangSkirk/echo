"""Product-managed orind: JS Agent starts the gatekeeper, not the user.

Stage A leases go through a resident orind process. This does not open
``orin.enforce`` and does not spawn Desktop/Memory Cells.
"""

from __future__ import annotations

import atexit
import os
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Final

from js.utils.log import get_logger

logger = get_logger("js.orin.supervisor")

_MAX_UNIX_PATH: Final[int] = 100
_READY_TIMEOUT_S: Final[float] = 12.0
_POLL_S: Final[float] = 0.02
_OPT_OUT: Final[frozenset[str]] = frozenset({"0", "false", "off", "no"})

_lock = threading.Lock()
_refcount: dict[str, int] = {}
_owned: dict[str, subprocess.Popen[bytes]] = {}


class OrindSupervisorError(RuntimeError):
    """orind could not be started or reached."""


def product_orin_opted_out() -> bool:
    """True when the operator set ``JS_ORIND=0`` (not ``JS_ORIN``, which is settings)."""

    return os.environ.get("JS_ORIND", "1").strip().lower() in _OPT_OUT


def orind_socket_path(settings: Any) -> Path:
    orin = getattr(settings, "orin", None)
    configured = getattr(orin, "socket_path", None) if orin is not None else None
    if configured:
        return Path(configured)
    return Path(settings.state_dir) / "orin" / "orind.sock"


def prepare_product_orin(settings: Any) -> Any:
    """Enable Stage A Orin on product launchers. Never opens enforce."""

    orin = getattr(settings, "orin", None)
    if orin is None or not hasattr(orin, "enabled"):
        return settings
    if product_orin_opted_out():
        orin.enabled = False
        logger.info("JS_ORIND opt-out: product will not start orind")
        return settings
    if getattr(orin, "enforce", False) is True:
        return settings
    orin.enabled = True
    # P1-3: never silently widen conservative → compat. Explicit
    # JS_ORIN__POLICY_PROFILE=compat (or config) is the documented degrade.
    return settings


def _socket_live(path: Path) -> bool:
    if not path.exists():
        return False
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.settimeout(0.2)
        sock.connect(os.fspath(path))
    except OSError:
        return False
    finally:
        sock.close()
    return True


def _argv(settings: Any, socket_path: Path) -> list[str]:
    orin = settings.orin
    argv = [
        sys.executable,
        "-m",
        "js.orind",
        "--dev",
        "--state-dir",
        str(Path(settings.state_dir)),
        "--socket-path",
        str(socket_path),
        "--keybox-tier",
        str(getattr(orin, "keybox_tier", "dev")),
        "--policy-profile",
        str(getattr(orin, "policy_profile", "conservative")),
    ]
    if getattr(orin, "stage_b", False) is True:
        argv.append("--stage-b")
        if getattr(orin, "cell_build", False) is True:
            argv.append("--cell-build")
        if getattr(orin, "cell_secret", False) is True:
            argv.append("--cell-secret")
        if getattr(orin, "cell_net", False) is True:
            argv.append("--cell-net")
        if getattr(orin, "cell_file", False) is True:
            argv.append("--cell-file")
        if getattr(orin, "commit_membrane", False) is True:
            argv.append("--commit-membrane")
        if getattr(orin, "cell_identity_enforce", False) is True:
            argv.append("--cell-identity-enforce")
            if getattr(orin, "cell_desktop", False) is True:
                argv.append("--cell-desktop")
            if getattr(orin, "cell_memory", False) is True:
                argv.append("--cell-memory")
    # Never pass --orin-enforce: Stage C conjunction is still incomplete.
    return argv


def _wait_ready(path: Path, proc: subprocess.Popen[bytes]) -> None:
    deadline = time.monotonic() + _READY_TIMEOUT_S
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise OrindSupervisorError("orind exited before the socket was ready")
        if _socket_live(path):
            return
        time.sleep(_POLL_S)
    raise OrindSupervisorError(f"orind socket not ready within {_READY_TIMEOUT_S:.0f}s: {path}")


def _pin_socket(settings: Any, path: Path) -> Path:
    orin = getattr(settings, "orin", None)
    if orin is not None and hasattr(orin, "socket_path"):
        orin.socket_path = path
    return path


def _socket_key(path: Path) -> str:
    try:
        return os.fspath(path.resolve())
    except OSError:
        return os.fspath(path)


def orind_owned_starting(path: Path) -> bool:
    """True when this process spawned orind and the child is still running."""

    key = _socket_key(path)
    with _lock:
        proc = _owned.get(key)
        return proc is not None and proc.poll() is None


def wait_orind_socket(path: Path, timeout: float = _READY_TIMEOUT_S) -> None:
    """Block until the socket accepts connections, the child dies, or timeout."""

    resolved = Path(path)
    try:
        resolved = resolved.resolve()
    except OSError:
        pass
    key = os.fspath(resolved)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if _socket_live(resolved):
            return
        with _lock:
            proc = _owned.get(key)
        if proc is not None and proc.poll() is not None:
            raise OrindSupervisorError("orind exited before the socket was ready")
        time.sleep(_POLL_S)
    raise OrindSupervisorError(f"orind socket not ready within {timeout:.0f}s: {resolved}")


def ensure_orind(settings: Any, *, wait: bool = True) -> Path:
    """Attach to a live orind or spawn one. Returns the socket path.

    ``wait=False`` records the child and returns immediately so HTTP ready
    does not block on the socket. The first lease path must then call
    ``wait_orind_socket``.
    """

    requested = orind_socket_path(settings)
    if len(os.fspath(requested)) > _MAX_UNIX_PATH:
        requested = Path(tempfile.mkdtemp(prefix="orind-run-")) / "orind.sock"
    requested.parent.mkdir(parents=True, exist_ok=True)
    requested = requested.resolve()
    _pin_socket(settings, requested)
    key = os.fspath(requested)

    with _lock:
        _refcount[key] = _refcount.get(key, 0) + 1
        owned = _owned.get(key)
        if owned is not None and owned.poll() is not None:
            _owned.pop(key, None)
            owned = None
        if owned is not None and owned.poll() is None:
            if wait:
                _wait_ready(requested, owned)
            return requested
        if _socket_live(requested):
            return requested
        if requested.exists():
            requested.unlink()
        proc = subprocess.Popen(  # noqa: S603
            _argv(settings, requested),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        _owned[key] = proc
        if wait:
            try:
                _wait_ready(requested, proc)
            except Exception:
                _refcount[key] = max(0, _refcount.get(key, 1) - 1)
                if _refcount.get(key, 0) == 0:
                    _refcount.pop(key, None)
                _owned.pop(key, None)
                _stop_proc(proc)
                raise
            logger.info("orind listening on %s (pid %s)", requested, proc.pid)
        else:
            logger.info("orind spawning on %s (pid %s)", requested, proc.pid)
        return requested


def release_orind(settings: Any) -> None:
    path = orind_socket_path(settings)
    try:
        key = os.fspath(path.resolve())
    except OSError:
        key = os.fspath(path)
    with _lock:
        remaining = _refcount.get(key, 0) - 1
        if remaining > 0:
            _refcount[key] = remaining
            return
        _refcount.pop(key, None)
        proc = _owned.pop(key, None)
    if proc is not None:
        _stop_proc(proc)


def _stop_proc(proc: subprocess.Popen[bytes]) -> None:
    if proc.poll() is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except (OSError, ProcessLookupError):
        proc.terminate()
    try:
        proc.wait(timeout=5.0)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (OSError, ProcessLookupError):
            proc.kill()
        proc.wait(timeout=2.0)


def _shutdown_owned() -> None:
    with _lock:
        procs = list(_owned.values())
        _owned.clear()
        _refcount.clear()
    for proc in procs:
        try:
            _stop_proc(proc)
        except Exception:
            logger.debug("orind atexit stop failed", exc_info=True)


atexit.register(_shutdown_owned)


__all__ = [
    "OrindSupervisorError",
    "ensure_orind",
    "orind_owned_starting",
    "orind_socket_path",
    "prepare_product_orin",
    "product_orin_opted_out",
    "release_orind",
    "wait_orind_socket",
]
