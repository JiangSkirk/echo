"""Descriptor-relative atomic JSON storage for owner-scoped Work routines."""

from __future__ import annotations

import importlib
import json
import os
import re
import stat
import threading
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

_SAFE_OWNER_COMPONENT = re.compile(r"^[os]_[0-9a-f]{24}$")
_SAFE_RECORD_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_MAX_RECORD_BYTES = 5 * 1024 * 1024
_MAX_RECORDS = 1000


class RoutineJsonStoreError(RuntimeError):
    """Raised when a routine record cannot be safely persisted."""


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


def _replace_at(temp_name: str, filename: str, directory_fd: int) -> None:
    os.replace(
        temp_name,
        filename,
        src_dir_fd=directory_fd,
        dst_dir_fd=directory_fd,
    )


class RoutineJsonDirectory:
    """One physically separated owner directory with serialized mutations."""

    def __init__(self, root: Path, owner_component: str) -> None:
        if not _SAFE_OWNER_COMPONENT.fullmatch(owner_component):
            raise ValueError("invalid Work routine owner partition")
        self.root = Path(root)
        self.owner_component = owner_component
        self.owner_path = self.root / owner_component
        self._thread_lock = threading.RLock()
        self._initialize_owner()

    @staticmethod
    def _filename(record_id: str) -> str:
        if not _SAFE_RECORD_ID.fullmatch(record_id):
            raise ValueError("invalid Work routine record id")
        return f"{record_id}.json"

    def _initialize_owner(self) -> None:
        self.root.parent.mkdir(parents=True, exist_ok=True)
        parent_fd = os.open(self.root.parent, _directory_flags())
        try:
            try:
                os.mkdir(self.root.name, mode=0o700, dir_fd=parent_fd)
            except FileExistsError:
                pass
            root_fd = os.open(self.root.name, _directory_flags(), dir_fd=parent_fd)
        finally:
            os.close(parent_fd)
        try:
            try:
                os.mkdir(self.owner_component, mode=0o700, dir_fd=root_fd)
            except FileExistsError:
                pass
            owner_fd = os.open(self.owner_component, _directory_flags(), dir_fd=root_fd)
            try:
                flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_CLOEXEC", 0)
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                lock_fd = os.open(".routines.lock", flags, 0o600, dir_fd=owner_fd)
                try:
                    metadata = os.fstat(lock_fd)
                    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                        raise RoutineJsonStoreError("Work routine store lock is unsafe")
                    os.fchmod(lock_fd, 0o600)
                finally:
                    os.close(lock_fd)
            finally:
                os.close(owner_fd)
        finally:
            os.close(root_fd)

    def _open_owner(self) -> int:
        root_fd = os.open(self.root, _directory_flags())
        try:
            return os.open(self.owner_component, _directory_flags(), dir_fd=root_fd)
        finally:
            os.close(root_fd)

    @contextmanager
    def _locked_owner(self) -> Iterator[int]:
        with self._thread_lock:
            owner_fd = self._open_owner()
            flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0)
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            lock_fd = -1
            try:
                lock_fd = os.open(".routines.lock", flags, dir_fd=owner_fd)
                metadata = os.fstat(lock_fd)
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                    raise RoutineJsonStoreError("Work routine store lock is unsafe")
                os.fchmod(lock_fd, 0o600)
                _acquire_lock(lock_fd)
                try:
                    yield owner_fd
                finally:
                    _release_lock(lock_fd)
            finally:
                if lock_fd >= 0:
                    os.close(lock_fd)
                os.close(owner_fd)

    @staticmethod
    def _read_locked(owner_fd: int, filename: str) -> dict[str, Any] | None:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(filename, flags, dir_fd=owner_fd)
        except OSError:
            return None
        try:
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or before.st_size > _MAX_RECORD_BYTES
            ):
                return None
            payload = bytearray()
            while len(payload) <= _MAX_RECORD_BYTES:
                chunk = os.read(
                    descriptor,
                    min(1024 * 1024, _MAX_RECORD_BYTES + 1 - len(payload)),
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
            or len(payload) > _MAX_RECORD_BYTES
        ):
            return None
        try:
            data = json.loads(bytes(payload).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        return data if isinstance(data, dict) else None

    @staticmethod
    def _write_locked(
        owner_fd: int,
        filename: str,
        data: dict[str, Any],
        *,
        create_only: bool,
    ) -> None:
        payload = json.dumps(
            data,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        ).encode("utf-8")
        if len(payload) > _MAX_RECORD_BYTES:
            raise RoutineJsonStoreError("Work routine record exceeds the size limit")
        if create_only:
            try:
                os.stat(filename, dir_fd=owner_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise FileExistsError(filename)
        temp_name = f".{filename}-{uuid.uuid4().hex}.tmp"
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
            descriptor = os.open(temp_name, flags, 0o600, dir_fd=owner_fd)
            os.fchmod(descriptor, 0o600)
            offset = 0
            while offset < len(payload):
                written = os.write(descriptor, payload[offset:])
                if written <= 0:
                    raise OSError("short Work routine write")
                offset += written
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            _replace_at(temp_name, filename, owner_fd)
            installed = True
            os.fsync(owner_fd)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if not installed:
                try:
                    os.unlink(temp_name, dir_fd=owner_fd)
                except OSError:
                    pass

    def write(self, record_id: str, data: dict[str, Any], *, create_only: bool = False) -> None:
        filename = self._filename(record_id)
        with self._locked_owner() as owner_fd:
            self._write_locked(owner_fd, filename, data, create_only=create_only)

    def read(self, record_id: str) -> dict[str, Any] | None:
        filename = self._filename(record_id)
        with self._locked_owner() as owner_fd:
            return self._read_locked(owner_fd, filename)

    def mutate(
        self,
        record_id: str,
        transform: Callable[[dict[str, Any]], dict[str, Any]],
    ) -> dict[str, Any] | None:
        filename = self._filename(record_id)
        with self._locked_owner() as owner_fd:
            current = self._read_locked(owner_fd, filename)
            if current is None:
                return None
            updated = transform(dict(current))
            if not isinstance(updated, dict):
                raise TypeError("routine transform must return an object")
            self._write_locked(owner_fd, filename, updated, create_only=False)
            return updated

    def upsert_mutate(
        self,
        record_id: str,
        transform: Callable[[dict[str, Any]], dict[str, Any]],
    ) -> dict[str, Any]:
        """Atomically create or mutate one JSON object under the owner lock."""
        filename = self._filename(record_id)
        with self._locked_owner() as owner_fd:
            current = self._read_locked(owner_fd, filename)
            if current is None:
                try:
                    os.stat(filename, dir_fd=owner_fd, follow_symlinks=False)
                except FileNotFoundError:
                    current = {}
                else:
                    raise RoutineJsonStoreError(
                        "Work routine record exists but is not safely readable"
                    )
            updated = transform(dict(current))
            if not isinstance(updated, dict):
                raise TypeError("routine transform must return an object")
            self._write_locked(owner_fd, filename, updated, create_only=False)
            return updated

    def list_records(self) -> list[dict[str, Any]]:
        with self._locked_owner() as owner_fd:
            names = sorted(
                name
                for name in os.listdir(owner_fd)
                if name.endswith(".json") and _SAFE_RECORD_ID.fullmatch(name[:-5])
            )
            if len(names) > _MAX_RECORDS:
                names = names[:_MAX_RECORDS]
            records: list[dict[str, Any]] = []
            for name in names:
                record = self._read_locked(owner_fd, name)
                if record is not None:
                    records.append(record)
            return records
