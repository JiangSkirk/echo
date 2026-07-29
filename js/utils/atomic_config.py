"""Cross-process, crash-safe YAML configuration persistence."""

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

import yaml

_MAX_CONFIG_BYTES = 10 * 1024 * 1024
_LOCKS_GUARD = threading.Lock()
_PROCESS_LOCKS: dict[Path, threading.RLock] = {}


class AtomicConfigError(RuntimeError):
    """Raised when a configuration file cannot be read or published safely."""


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


@contextmanager
def _config_lock(target: Path) -> Iterator[None]:
    lock_path = target.parent / f".{target.name}.lock"
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        lock_fd = os.open(lock_path, flags, 0o600)
    except OSError as exc:
        raise AtomicConfigError("Configuration lock is unavailable") from exc
    try:
        metadata = os.fstat(lock_fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise AtomicConfigError("Configuration lock is unsafe")
        os.fchmod(lock_fd, 0o600)
        with _process_lock(lock_path):
            _acquire_file_lock(lock_fd)
            try:
                yield
            finally:
                _release_file_lock(lock_fd)
    finally:
        os.close(lock_fd)


def _read_yaml_mapping(target: Path) -> dict[str, Any]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        file_fd = os.open(target, flags)
    except OSError as exc:
        raise AtomicConfigError("Existing configuration is unavailable") from exc
    try:
        before = os.fstat(file_fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise AtomicConfigError("Existing configuration is unsafe")
        if before.st_size > _MAX_CONFIG_BYTES:
            raise AtomicConfigError("Existing configuration exceeds the size limit")
        chunks: list[bytes] = []
        bytes_read = 0
        while True:
            chunk = os.read(
                file_fd,
                min(1024 * 1024, _MAX_CONFIG_BYTES + 1 - bytes_read),
            )
            if not chunk:
                break
            chunks.append(chunk)
            bytes_read += len(chunk)
            if bytes_read > _MAX_CONFIG_BYTES:
                raise AtomicConfigError("Existing configuration exceeds the size limit")
        after = os.fstat(file_fd)
    finally:
        os.close(file_fd)
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
    if before_fingerprint != after_fingerprint or bytes_read != before.st_size:
        raise AtomicConfigError("Configuration changed while being read")
    try:
        loaded = yaml.safe_load(b"".join(chunks).decode("utf-8")) or {}
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise AtomicConfigError("Existing configuration is invalid") from exc
    if not isinstance(loaded, dict):
        raise AtomicConfigError("Existing configuration must be a mapping")
    return loaded


def _publish_temp(temp_path: Path, target: Path) -> None:
    os.replace(temp_path, target)


def _fsync_directory(path: Path) -> None:
    directory_fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def save_yaml_config(
    target: Path,
    new_data: dict[str, Any],
    *,
    fields: list[str] | None = None,
) -> None:
    """Merge selected fields and atomically publish one private YAML file."""
    unresolved = Path(target).expanduser()
    unresolved.parent.mkdir(parents=True, exist_ok=True)
    parent = unresolved.parent.resolve(strict=True)
    resolved_target = parent / unresolved.name
    if resolved_target.is_symlink():
        raise AtomicConfigError("Symbolic-link configurations are not allowed")

    temp_path: Path | None = None
    with _config_lock(resolved_target):
        output = dict(new_data)
        if fields and resolved_target.exists():
            output = _read_yaml_mapping(resolved_target)
            for key in fields:
                if key in new_data:
                    output[key] = new_data[key]
        try:
            payload = yaml.safe_dump(
                output,
                default_flow_style=False,
                sort_keys=False,
            ).encode("utf-8")
        except yaml.YAMLError as exc:
            raise AtomicConfigError("Configuration could not be serialized") from exc
        if len(payload) > _MAX_CONFIG_BYTES:
            raise AtomicConfigError("Configuration exceeds the size limit")
        try:
            temp_fd, raw_temp_path = tempfile.mkstemp(
                prefix=f".{resolved_target.name}-",
                suffix=".tmp",
                dir=parent,
            )
            temp_path = Path(raw_temp_path)
            os.fchmod(temp_fd, 0o600)
            with os.fdopen(temp_fd, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            _publish_temp(temp_path, resolved_target)
            temp_path = None
            _fsync_directory(parent)
        except OSError as exc:
            raise AtomicConfigError("Configuration could not be published atomically") from exc
        finally:
            if temp_path is not None:
                try:
                    temp_path.unlink()
                except FileNotFoundError:
                    pass
                except OSError:
                    pass
