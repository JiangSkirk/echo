"""Tool-lease MAC key load/create helpers."""

from __future__ import annotations

import fcntl
import os
import secrets
import stat
import threading
from pathlib import Path


def _read_tool_lease_key_strict(path: Path) -> bytes:
    """Read the tool-lease MAC key with the same hardening as the Echo ledger
    journal key (see ``_read_strict_key`` in js/echo/ledger/service.py):
    lstat+fstat identity checks, no symlink following, single hardlink, and a
    mandatory 0600 mode."""
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ValueError(f"invalid tool lease key {path}: expected a 32-byte key file") from exc
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise ValueError(f"invalid tool lease key {path}: expected a 32-byte regular file")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(fd)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino)
        ):
            raise ValueError(f"invalid tool lease key {path}: key file changed while opening")
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "r", encoding="utf-8") as handle:
            fd = -1
            encoded = handle.read().strip()
        current = path.lstat()
        if (
            stat.S_ISLNK(current.st_mode)
            or current.st_nlink != 1
            or (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino)
        ):
            raise ValueError(f"invalid tool lease key {path}: key file changed while reading")
    finally:
        if fd >= 0:
            os.close(fd)
    try:
        key = bytes.fromhex(encoded)
    except ValueError as exc:
        raise ValueError(
            f"invalid tool lease key {path}: expected 32-byte hexadecimal data"
        ) from exc
    if len(encoded) != 64 or len(key) != 32:
        raise ValueError(f"invalid tool lease key {path}: expected 32-byte hexadecimal data")
    if stat.S_IMODE(current.st_mode) != 0o600:
        raise ValueError(f"invalid tool lease key {path}: expected mode 0600")
    return key


def _load_or_create_tool_lease_key(path: Path) -> bytes:
    path.parent.mkdir(parents=True, exist_ok=True)
    # Serialize first-start creation through a lock file so concurrent
    # processes cannot race and end up with different keys or a torn write.
    lock_path = path.with_name(path.name + ".lock")
    lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.fchmod(lock_fd, 0o600)
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        if path.exists() or path.is_symlink():
            return _read_tool_lease_key_strict(path)
        key = secrets.token_bytes(32)
        tmp_path: Path | None = None
        try:
            tmp_path = path.with_name(
                f".{path.name}.{os.getpid()}.{threading.get_ident()}.{secrets.token_hex(8)}.tmp"
            )
            key_fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.fchmod(key_fd, 0o600)
            with os.fdopen(key_fd, "w", encoding="utf-8") as handle:
                handle.write(key.hex())
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_path, path)
            tmp_path = None
            os.chmod(path, 0o600)
            dir_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        finally:
            if tmp_path is not None:
                try:
                    tmp_path.unlink()
                except FileNotFoundError:
                    pass
        return _read_tool_lease_key_strict(path)
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)
