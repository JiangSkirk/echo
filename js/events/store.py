"""Append-only event store for agent observability.

Events are written to bounded, daily JSONL segments for durability and easy
ingestion. Rotation is rename-only; archives are never compressed on the write
path.
"""

from __future__ import annotations

import importlib
import json
import os
import re
import sys
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, date, datetime, time, timedelta
from pathlib import Path
from typing import Any

from js.events.models import AgentEvent
from js.utils.log import get_logger

logger = get_logger("js.events")

DEFAULT_MAX_FILE_BYTES = 256 * 1024
DEFAULT_MAX_ARCHIVES = 4

_APPEND_ATTEMPTS = 2
_EVENT_FILE_PATTERN = re.compile(r"^events_(\d{4}-\d{2}-\d{2})(?:\.(\d+))?\.jsonl$")
_LOCK_BACKEND = "windows" if os.name == "nt" else "posix"
_PROCESS_LOCK = threading.RLock()


def _acquire_file_lock(lock_fd: int) -> None:
    if _LOCK_BACKEND == "windows":
        msvcrt: Any = importlib.import_module("msvcrt")
        if os.fstat(lock_fd).st_size == 0:
            os.lseek(lock_fd, 0, os.SEEK_SET)
            os.write(lock_fd, b"\0")
        os.lseek(lock_fd, 0, os.SEEK_SET)
        msvcrt.locking(lock_fd, msvcrt.LK_LOCK, 1)
        return

    fcntl: Any = importlib.import_module("fcntl")
    fcntl.flock(lock_fd, fcntl.LOCK_EX)


def _release_file_lock(lock_fd: int) -> None:
    if _LOCK_BACKEND == "windows":
        msvcrt: Any = importlib.import_module("msvcrt")
        os.lseek(lock_fd, 0, os.SEEK_SET)
        msvcrt.locking(lock_fd, msvcrt.LK_UNLCK, 1)
        return

    fcntl: Any = importlib.import_module("fcntl")
    fcntl.flock(lock_fd, fcntl.LOCK_UN)


@dataclass(frozen=True)
class _EventFile:
    path: Path
    day: date
    sequence: int | None


class EventStore:
    """Append-only event store with bounded daily segment rotation.

    Events are encrypted at rest using the same Fernet key as SecretManager.
    ``max_archives`` is a global cap for all non-active event files. The defaults
    target about 256 MiB of non-active storage. A record larger than
    ``max_file_bytes`` remains indivisible, occupies one segment by itself, and
    emits a capacity warning.
    """

    def __init__(
        self,
        base_dir: Path | str,
        retention_days: int = 90,
        *,
        max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
        max_archives: int = DEFAULT_MAX_ARCHIVES,
    ) -> None:
        if retention_days < 1:
            raise ValueError("retention_days must be at least 1")
        if max_file_bytes < 1:
            raise ValueError("max_file_bytes must be at least 1")
        if max_archives < 0:
            raise ValueError("max_archives must be non-negative")

        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self._retention_days = retention_days
        self._max_file_bytes = max_file_bytes
        self._max_archives = max_archives
        self._lock_path = self.base_dir / ".events.lock"
        self._secrets_inst: Any | None = None
        self._health_lock = threading.Lock()
        self._write_failures = 0
        self._consecutive_write_failures = 0
        self._last_error = ""
        self._last_failure_at: float | None = None
        self._last_success_at: float | None = None

    @property
    def _secrets(self) -> Any:
        if self._secrets_inst is None:
            from js.security.secrets import SecretManager

            self._secrets_inst = SecretManager(self.base_dir.parent)
        return self._secrets_inst

    def _get_file(self) -> Path:
        today = datetime.now(UTC).strftime("%Y-%m-%d")
        return self.base_dir / f"events_{today}.jsonl"

    @contextmanager
    def _exclusive_lock(self) -> Iterator[None]:
        """Serialize rotation, writes, reads, and pruning across store instances."""
        with _PROCESS_LOCK:
            lock_fd = os.open(self._lock_path, os.O_CREAT | os.O_RDWR, 0o600)
            acquired = False
            try:
                _acquire_file_lock(lock_fd)
                acquired = True
                yield
            finally:
                try:
                    if acquired:
                        _release_file_lock(lock_fd)
                finally:
                    os.close(lock_fd)

    @staticmethod
    def _parse_event_file(path: Path) -> _EventFile | None:
        match = _EVENT_FILE_PATTERN.fullmatch(path.name)
        if match is None:
            return None
        try:
            day = datetime.strptime(match.group(1), "%Y-%m-%d").date()
        except ValueError:
            return None
        sequence_text = match.group(2)
        sequence = int(sequence_text) if sequence_text is not None else None
        return _EventFile(path=path, day=day, sequence=sequence)

    def _event_files(self) -> list[_EventFile]:
        files: list[_EventFile] = []
        for path in self.base_dir.glob("events_*.jsonl"):
            parsed = self._parse_event_file(path)
            if parsed is not None:
                files.append(parsed)
        return files

    @staticmethod
    def _query_sort_key(event_file: _EventFile) -> tuple[int, int]:
        sequence = event_file.sequence
        return (
            -event_file.day.toordinal(),
            sequence if sequence is not None else sys.maxsize,
        )

    @staticmethod
    def _archive_sort_key(event_file: _EventFile) -> tuple[int, int]:
        sequence = event_file.sequence
        return (
            event_file.day.toordinal(),
            sequence if sequence is not None else sys.maxsize,
        )

    def _next_archive_path(self, active: Path) -> Path:
        parsed_active = self._parse_event_file(active)
        if parsed_active is None:
            raise ValueError(f"Invalid active event path: {active}")
        sequences = [
            event_file.sequence
            for event_file in self._event_files()
            if event_file.day == parsed_active.day and event_file.sequence is not None
        ]
        next_sequence = max(sequences, default=0) + 1
        return active.with_name(f"{active.stem}.{next_sequence}{active.suffix}")

    def _sync_directory(self) -> None:
        if _LOCK_BACKEND == "windows":
            return
        directory_fd = os.open(self.base_dir, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        except OSError:
            logger.warning("Failed to sync event directory", exc_info=True)
        finally:
            os.close(directory_fd)

    def _rotate(self, active: Path) -> Path:
        archive = self._next_archive_path(active)
        os.replace(active, archive)
        self._sync_directory()
        return archive

    @staticmethod
    def _has_incomplete_tail(path: Path) -> bool:
        try:
            if path.stat().st_size == 0:
                return False
            with path.open("rb") as handle:
                handle.seek(-1, os.SEEK_END)
                return handle.read(1) != b"\n"
        except FileNotFoundError:
            return False

    def _should_rotate(self, active: Path, incoming_bytes: int) -> bool:
        try:
            current_size = active.stat().st_size
        except FileNotFoundError:
            return False
        return current_size > 0 and current_size + incoming_bytes > self._max_file_bytes

    @staticmethod
    def _write_complete(fd: int, data: bytes) -> None:
        view = memoryview(data)
        written = 0
        while written < len(view):
            count = os.write(fd, view[written:])
            if count <= 0:
                raise OSError("event append made no progress")
            written += count

    def _append_line(self, path: Path, line: bytes) -> None:
        flags = os.O_APPEND | os.O_CREAT | os.O_WRONLY
        for attempt in range(_APPEND_ATTEMPTS):
            fd = os.open(path, flags, 0o600)
            initial_size = os.fstat(fd).st_size
            try:
                self._write_complete(fd, line)
                os.fsync(fd)
                return
            except OSError:
                try:
                    os.ftruncate(fd, initial_size)
                    os.fsync(fd)
                except OSError:
                    logger.warning("Failed to roll back partial event append", exc_info=True)
                    raise
                if attempt + 1 >= _APPEND_ATTEMPTS:
                    raise
            finally:
                os.close(fd)
        raise RuntimeError("unreachable event append state")

    def emit(self, event: AgentEvent) -> bool:
        """Append one encrypted event, rotating before the configured size cap."""
        try:
            raw = json.dumps(event.to_dict(), ensure_ascii=False, default=str)
            with self._exclusive_lock():
                encrypted = self._secrets.encrypt_blob(raw.encode("utf-8"))
                line = encrypted + b"\n"
                if len(line) > self._max_file_bytes:
                    logger.warning(
                        "Event record size %d exceeds max_file_bytes %d; storing intact",
                        len(line),
                        self._max_file_bytes,
                    )
                active = self._get_file()
                if self._has_incomplete_tail(active):
                    archive = self._rotate(active)
                    logger.warning("Preserved incomplete event tail in %s", archive)
                    self._prune_locked(active)
                elif self._should_rotate(active, len(line)):
                    self._rotate(active)
                    self._prune_locked(active)
                self._append_line(active, line)
            with self._health_lock:
                self._consecutive_write_failures = 0
                self._last_error = ""
                self._last_success_at = datetime.now(UTC).timestamp()
            return True
        except Exception as exc:
            with self._health_lock:
                self._write_failures += 1
                self._consecutive_write_failures += 1
                self._last_error = f"{type(exc).__name__}: {exc}"
                self._last_failure_at = datetime.now(UTC).timestamp()
            logger.warning("Failed to write event: %s", exc)
            return False

    def health(self) -> dict[str, Any]:
        """Return process-local write health without exposing event contents."""
        with self._health_lock:
            return {
                "ok": self._consecutive_write_failures == 0,
                "write_failures": self._write_failures,
                "consecutive_write_failures": self._consecutive_write_failures,
                "last_error": self._last_error,
                "last_failure_at": self._last_failure_at,
                "last_success_at": self._last_success_at,
            }

    def query(
        self,
        session_id: str | None = None,
        run_id: str | None = None,
        agent_id: str | None = None,
        task_id: str | None = None,
        group_id: str | None = None,
        event_type: str | None = None,
        limit: int = 500,
    ) -> list[AgentEvent]:
        """Query events by newest day while preserving append order within each day."""
        results: list[AgentEvent] = []
        with self._exclusive_lock():
            files = sorted(self._event_files(), key=self._query_sort_key)
            for event_file in files:
                try:
                    with event_file.path.open(encoding="utf-8") as handle:
                        for line in handle:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                decrypted = self._secrets.decrypt_blob(line.encode("ascii"))
                                data = json.loads(decrypted.decode("utf-8"))
                            except Exception:
                                try:
                                    data = json.loads(line)
                                except json.JSONDecodeError:
                                    continue
                            if session_id and data.get("session_id") != session_id:
                                continue
                            if run_id and data.get("run_id") != run_id:
                                continue
                            if agent_id and data.get("agent_id") != agent_id:
                                continue
                            if task_id and data.get("task_id") != task_id:
                                continue
                            if group_id and data.get("group_id") != group_id:
                                continue
                            if event_type and data.get("event_type") != event_type:
                                continue
                            results.append(AgentEvent(**data))
                            if len(results) >= limit:
                                return results
                except Exception:
                    logger.warning(
                        "Failed to read event file %s",
                        event_file.path,
                        exc_info=True,
                    )
        return results

    def _delete_event_file(self, event_file: _EventFile) -> bool:
        try:
            event_file.path.unlink()
            return True
        except FileNotFoundError:
            return False
        except OSError:
            logger.warning(
                "Failed to prune event file %s",
                event_file.path,
                exc_info=True,
            )
            return False

    def _prune_locked(self, active: Path) -> int:
        cutoff = datetime.now(UTC) - timedelta(days=self._retention_days)
        deleted = 0
        retained: list[_EventFile] = []

        for event_file in self._event_files():
            if event_file.path == active:
                retained.append(event_file)
                continue
            file_time = datetime.combine(event_file.day, time.min, tzinfo=UTC)
            if file_time < cutoff:
                deleted += int(self._delete_event_file(event_file))
            else:
                retained.append(event_file)

        archives = sorted(
            (event_file for event_file in retained if event_file.path != active),
            key=self._archive_sort_key,
        )
        excess = len(archives) - self._max_archives
        if excess > 0:
            for event_file in archives[:excess]:
                deleted += int(self._delete_event_file(event_file))
        return deleted

    def prune(self) -> int:
        """Apply age and archive-count retention without deleting the active file."""
        with self._exclusive_lock():
            return self._prune_locked(self._get_file())
