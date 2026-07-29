"""Descriptor-relative, physically partitioned Fleet history storage."""

from __future__ import annotations

import importlib
import json
import os
import re
import stat
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

_SAFE_PARTITION_RE = re.compile(r"^[0-9a-f]{24}$")
_SAFE_SESSION_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
_MAX_HISTORY_BYTES = 10 * 1024 * 1024
_MAX_HISTORY_FILES = 200


class FleetHistoryError(RuntimeError):
    """Raised when Fleet history cannot be stored inside its owned partition."""


def _directory_flags() -> int:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return flags


def _acquire_lock(descriptor: int) -> None:
    if os.name == "nt":
        msvcrt: Any = importlib.import_module("msvcrt")
        if os.fstat(descriptor).st_size == 0:
            os.write(descriptor, b"\0")
        os.lseek(descriptor, 0, os.SEEK_SET)
        msvcrt.locking(descriptor, msvcrt.LK_LOCK, 1)
        return
    fcntl: Any = importlib.import_module("fcntl")
    fcntl.flock(descriptor, fcntl.LOCK_EX)


def _release_lock(descriptor: int) -> None:
    if os.name == "nt":
        msvcrt: Any = importlib.import_module("msvcrt")
        os.lseek(descriptor, 0, os.SEEK_SET)
        msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
        return
    fcntl: Any = importlib.import_module("fcntl")
    fcntl.flock(descriptor, fcntl.LOCK_UN)


class SecureFleetHistoryStore:
    """Store JSON records with no-follow directory handles and atomic publish."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self._initialize_root()

    def _initialize_root(self) -> None:
        self.root.parent.mkdir(parents=True, exist_ok=True)
        parent_fd = os.open(self.root.parent, _directory_flags())
        try:
            try:
                os.mkdir(self.root.name, mode=0o700, dir_fd=parent_fd)
            except FileExistsError:
                pass
            root_fd = os.open(self.root.name, _directory_flags(), dir_fd=parent_fd)
            os.close(root_fd)
        finally:
            os.close(parent_fd)

    @staticmethod
    def _validate_partition(value: str) -> None:
        if not _SAFE_PARTITION_RE.fullmatch(value):
            raise ValueError("invalid Fleet history partition")

    @staticmethod
    def _filename(session_id: str) -> str:
        if not _SAFE_SESSION_RE.fullmatch(session_id):
            raise ValueError("invalid Fleet history session")
        return f"{session_id}.json"

    def _open_scope(self, product_slug: str, owner_slug: str, *, create: bool) -> int:
        self._validate_partition(product_slug)
        self._validate_partition(owner_slug)
        current_fd = os.open(self.root, _directory_flags())
        try:
            for component in (product_slug, owner_slug):
                if create:
                    try:
                        os.mkdir(component, mode=0o700, dir_fd=current_fd)
                    except FileExistsError:
                        pass
                next_fd = os.open(component, _directory_flags(), dir_fd=current_fd)
                os.close(current_fd)
                current_fd = next_fd
            return current_fd
        except Exception:
            os.close(current_fd)
            raise

    @contextmanager
    def _locked_scope(
        self,
        product_slug: str,
        owner_slug: str,
        *,
        create: bool,
    ) -> Iterator[int]:
        scope_fd = self._open_scope(product_slug, owner_slug, create=create)
        lock_flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_CLOEXEC", 0)
        if hasattr(os, "O_NOFOLLOW"):
            lock_flags |= os.O_NOFOLLOW
        lock_fd = os.open(".history.lock", lock_flags, 0o600, dir_fd=scope_fd)
        try:
            metadata = os.fstat(lock_fd)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise FleetHistoryError("Fleet history lock is unsafe")
            os.fchmod(lock_fd, 0o600)
            _acquire_lock(lock_fd)
            try:
                yield scope_fd
            finally:
                _release_lock(lock_fd)
        finally:
            os.close(lock_fd)
            os.close(scope_fd)

    def ensure_scope(self, product_slug: str, owner_slug: str) -> None:
        with self._locked_scope(product_slug, owner_slug, create=True):
            return

    @staticmethod
    def _write_all(descriptor: int, payload: bytes) -> None:
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError("short Fleet history write")
            offset += written

    @staticmethod
    def _read_record_at(scope_fd: int, filename: str) -> tuple[dict[str, Any], int] | None:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(filename, flags, dir_fd=scope_fd)
        except OSError:
            return None
        try:
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or before.st_size > _MAX_HISTORY_BYTES
            ):
                return None
            payload = bytearray()
            while len(payload) <= _MAX_HISTORY_BYTES:
                chunk = os.read(
                    descriptor,
                    min(1024 * 1024, _MAX_HISTORY_BYTES + 1 - len(payload)),
                )
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
            or len(payload) > _MAX_HISTORY_BYTES
        ):
            return None
        try:
            data = json.loads(bytes(payload).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        if not isinstance(data, dict):
            return None
        return data, before.st_mtime_ns

    def write(
        self,
        product_slug: str,
        owner_slug: str,
        session_id: str,
        record: dict[str, Any],
    ) -> None:
        filename = self._filename(session_id)
        payload = json.dumps(record, ensure_ascii=False, indent=2).encode("utf-8")
        if len(payload) > _MAX_HISTORY_BYTES:
            raise FleetHistoryError("Fleet history record exceeds the size limit")
        with self._locked_scope(product_slug, owner_slug, create=True) as scope_fd:
            temp_name = f".{session_id}-{uuid.uuid4().hex}.tmp"
            descriptor = -1
            installed = False
            try:
                flags = (
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_CLOEXEC", 0)
                )
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                descriptor = os.open(temp_name, flags, 0o600, dir_fd=scope_fd)
                os.fchmod(descriptor, 0o600)
                self._write_all(descriptor, payload)
                os.fsync(descriptor)
                os.close(descriptor)
                descriptor = -1
                os.replace(
                    temp_name,
                    filename,
                    src_dir_fd=scope_fd,
                    dst_dir_fd=scope_fd,
                )
                installed = True
                os.fsync(scope_fd)
                self._rotate_locked(scope_fd)
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
                if not installed:
                    try:
                        os.unlink(temp_name, dir_fd=scope_fd)
                    except OSError:
                        pass

    def _rotate_locked(self, scope_fd: int) -> None:
        files: list[tuple[int, str]] = []
        for name in os.listdir(scope_fd):
            if not name.endswith(".json") or not _SAFE_SESSION_RE.fullmatch(name[:-5]):
                continue
            try:
                metadata = os.stat(name, dir_fd=scope_fd, follow_symlinks=False)
            except OSError:
                continue
            if stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1:
                files.append((metadata.st_mtime_ns, name))
        files.sort(reverse=True)
        for _mtime, name in files[_MAX_HISTORY_FILES:]:
            try:
                os.unlink(name, dir_fd=scope_fd)
            except OSError:
                continue
        os.fsync(scope_fd)

    def read(
        self,
        product_slug: str,
        owner_slug: str,
        session_id: str,
    ) -> dict[str, Any] | None:
        filename = self._filename(session_id)
        try:
            with self._locked_scope(product_slug, owner_slug, create=False) as scope_fd:
                item = self._read_record_at(scope_fd, filename)
        except (FileNotFoundError, NotADirectoryError, OSError):
            return None
        return item[0] if item is not None else None

    def list_records(
        self,
        product_slug: str,
        owner_slug: str,
    ) -> list[dict[str, Any]]:
        try:
            with self._locked_scope(product_slug, owner_slug, create=False) as scope_fd:
                records: list[tuple[int, dict[str, Any]]] = []
                for name in os.listdir(scope_fd):
                    if not name.endswith(".json") or not _SAFE_SESSION_RE.fullmatch(name[:-5]):
                        continue
                    item = self._read_record_at(scope_fd, name)
                    if item is not None:
                        records.append((item[1], item[0]))
        except (FileNotFoundError, NotADirectoryError, OSError):
            return []
        records.sort(key=lambda item: item[0], reverse=True)
        return [record for _mtime, record in records]

    def delete(
        self,
        product_slug: str,
        owner_slug: str,
        session_id: str,
        *,
        expected_product_id: str,
        expected_owner: str,
    ) -> bool:
        filename = self._filename(session_id)
        try:
            with self._locked_scope(product_slug, owner_slug, create=False) as scope_fd:
                item = self._read_record_at(scope_fd, filename)
                if item is None:
                    return False
                record = item[0]
                if (
                    record.get("product_id") != expected_product_id
                    or record.get("owner_key_hash") != expected_owner
                    or record.get("session_id") != session_id
                ):
                    return False
                os.unlink(filename, dir_fd=scope_fd)
                os.fsync(scope_fd)
                return True
        except (FileNotFoundError, NotADirectoryError, OSError):
            return False
