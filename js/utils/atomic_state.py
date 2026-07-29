"""Cross-process, crash-safe persistence for small UTF-8 state files."""

from __future__ import annotations

import importlib
import os
import stat
import tempfile
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

_LOCKS_GUARD = threading.Lock()
_PROCESS_LOCKS: dict[Path, threading.RLock] = {}


class AtomicStateError(RuntimeError):
    """Raised when a bounded state file cannot be read or published safely."""


def _process_lock(path: Path) -> threading.RLock:
    with _LOCKS_GUARD:
        return _PROCESS_LOCKS.setdefault(path, threading.RLock())


def _acquire_file_lock(lock_fd: int) -> None:
    if os.name == "nt":
        msvcrt: Any = importlib.import_module("msvcrt")
        if os.fstat(lock_fd).st_size == 0:
            os.write(lock_fd, b"\0")
        os.lseek(lock_fd, 0, os.SEEK_SET)
        msvcrt.locking(lock_fd, msvcrt.LK_LOCK, 1)
        return
    fcntl: Any = importlib.import_module("fcntl")
    fcntl.flock(lock_fd, fcntl.LOCK_EX)


def _release_file_lock(lock_fd: int) -> None:
    if os.name == "nt":
        msvcrt: Any = importlib.import_module("msvcrt")
        os.lseek(lock_fd, 0, os.SEEK_SET)
        msvcrt.locking(lock_fd, msvcrt.LK_UNLCK, 1)
        return
    fcntl: Any = importlib.import_module("fcntl")
    fcntl.flock(lock_fd, fcntl.LOCK_UN)


def _resolved_target(target: Path) -> Path:
    unresolved = Path(target).expanduser()
    unresolved.parent.mkdir(parents=True, exist_ok=True)
    parent = unresolved.parent.resolve(strict=True)
    resolved = parent / unresolved.name
    if resolved.is_symlink():
        raise AtomicStateError("Symbolic-link state files are not allowed")
    return resolved


@contextmanager
def _state_lock(target: Path) -> Iterator[None]:
    lock_path = target.parent / f".{target.name}.lock"
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        lock_fd = os.open(lock_path, flags, 0o600)
    except OSError as exc:
        raise AtomicStateError("State lock is unavailable") from exc
    try:
        metadata = os.fstat(lock_fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise AtomicStateError("State lock is unsafe")
        os.fchmod(lock_fd, 0o600)
        with _process_lock(lock_path):
            _acquire_file_lock(lock_fd)
            try:
                yield
            finally:
                _release_file_lock(lock_fd)
    finally:
        os.close(lock_fd)


def _read_unlocked(target: Path, *, max_bytes: int) -> str:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(target, flags)
    except FileNotFoundError:
        return ""
    except OSError as exc:
        raise AtomicStateError("State file is unavailable") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size > max_bytes
        ):
            raise AtomicStateError("State file is unsafe or exceeds its size limit")
        payload = bytearray()
        while len(payload) <= max_bytes:
            chunk = os.read(descriptor, min(64 * 1024, max_bytes + 1 - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    before_fingerprint = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    after_fingerprint = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    if (
        before_fingerprint != after_fingerprint
        or len(payload) != before.st_size
        or len(payload) > max_bytes
    ):
        raise AtomicStateError("State file changed while being read")
    try:
        return bytes(payload).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AtomicStateError("State file is not valid UTF-8") from exc


def read_text_state(target: Path, *, max_bytes: int) -> str:
    """Read one small regular file through a stable no-follow descriptor."""
    if max_bytes <= 0:
        raise ValueError("max_bytes must be positive")
    resolved = _resolved_target(target)
    with _state_lock(resolved):
        return _read_unlocked(resolved, max_bytes=max_bytes)


def _publish_temp(temp_path: Path, target: Path) -> None:
    os.replace(temp_path, target)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_text_state(target: Path, value: str, *, max_bytes: int) -> None:
    """Atomically publish one bounded UTF-8 value with directory durability."""
    if max_bytes <= 0:
        raise ValueError("max_bytes must be positive")
    if not isinstance(value, str):
        raise TypeError("state value must be a string")
    payload = value.encode("utf-8")
    if len(payload) > max_bytes:
        raise AtomicStateError("State value exceeds its size limit")
    resolved = _resolved_target(target)
    temp_path: Path | None = None
    with _state_lock(resolved):
        if resolved.is_symlink():
            raise AtomicStateError("Symbolic-link state files are not allowed")
        try:
            descriptor, raw_temp_path = tempfile.mkstemp(
                prefix=f".{resolved.name}-",
                suffix=".tmp",
                dir=resolved.parent,
            )
            temp_path = Path(raw_temp_path)
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            _publish_temp(temp_path, resolved)
            temp_path = None
            _fsync_directory(resolved.parent)
        except OSError as exc:
            raise AtomicStateError("State file could not be published atomically") from exc
        finally:
            if temp_path is not None:
                try:
                    temp_path.unlink()
                except OSError:
                    pass
