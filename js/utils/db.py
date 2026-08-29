"""SQLite connection helpers with proper cleanup."""

from __future__ import annotations

import asyncio
import os
import sqlite3
import time
from collections.abc import AsyncGenerator, Generator
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path
from typing import Any

import aiosqlite

_BOOTSTRAP_BUSY_TIMEOUT_MS = 0
_NORMAL_BUSY_TIMEOUT_MS = 5000
_WAL_BOOTSTRAP_TIMEOUT_SECONDS = 1.0
_WAL_MAX_ATTEMPTS = 16
_WAL_RETRY_BASE_DELAY_SECONDS = 0.01
_WAL_RETRY_MAX_DELAY_SECONDS = 0.1
# path -> (st_dev, st_ino, st_mtime_ns) of a file already confirmed WAL.
_WAL_READY: dict[str, tuple[int, int, int]] = {}
_CORRUPTION_MESSAGES = (
    "database disk image is malformed",
    "file is not a database",
)

# Known product SQLite files at state_dir root. Startup WAL checks and the
# governor checkpoint the same set — do not walk the whole tree.
PRODUCT_STATE_DB_NAMES: tuple[str, ...] = (
    "memory_enhanced.db",
    "memory.db",
    "appshell_sessions.db",
    "cron.db",
    "api_keys.db",
    "token_stats.db",
    "audit.db",
    "secrets.db",
    "checkpoints.db",
    "lifecycle.db",
    "review_capsules.db",
    "skills.db",
    "skill_promotions.db",
    "bots.db",
)


def is_recoverable_database_corruption(error: sqlite3.DatabaseError) -> bool:
    """Return whether SQLite positively identified corrupt database bytes."""
    error_code = getattr(error, "sqlite_errorcode", None)
    if isinstance(error_code, int):
        primary_code = error_code & 0xFF
        if primary_code in {sqlite3.SQLITE_CORRUPT, sqlite3.SQLITE_NOTADB}:
            return True
    message = str(error).casefold()
    return any(marker in message for marker in _CORRUPTION_MESSAGES)


def quarantine_corrupt_database(db_path: Path | str) -> Path | None:
    """Move corrupt SQLite bytes and sidecars aside, preserving evidence."""
    path = Path(db_path)
    _wal_cache_drop(path)
    if not path.exists():
        return None
    quarantine_path = path.with_name(f"{path.name}.corrupt-{time.time_ns()}")
    os.replace(path, quarantine_path)
    try:
        os.chmod(quarantine_path, 0o600)
    except OSError:
        pass
    for suffix in ("-wal", "-shm"):
        sidecar = Path(f"{path}{suffix}")
        if not sidecar.exists():
            continue
        quarantined_sidecar = Path(f"{quarantine_path}{suffix}")
        os.replace(sidecar, quarantined_sidecar)
        try:
            os.chmod(quarantined_sidecar, 0o600)
        except OSError:
            pass
    try:
        directory_fd = os.open(
            path.parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
    except OSError:
        return quarantine_path
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    return quarantine_path


def _is_locked_or_busy(error: sqlite3.OperationalError) -> bool:
    error_code = getattr(error, "sqlite_errorcode", None)
    if not isinstance(error_code, int):
        return False
    base_error_code = error_code & 0xFF
    return base_error_code in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED}


def _retry_delay(attempt: int, remaining: float) -> float:
    exponential_delay = _WAL_RETRY_BASE_DELAY_SECONDS * (2**attempt)
    return float(min(exponential_delay, _WAL_RETRY_MAX_DELAY_SECONDS, remaining))


def _wal_identity(db_path: Path) -> tuple[str, int, int, int] | None:
    try:
        resolved = db_path.resolve()
        stat = resolved.stat()
    except OSError:
        return None
    return (str(resolved), stat.st_dev, stat.st_ino, stat.st_mtime_ns)


def _wal_cache_hit(db_path: Path) -> bool:
    identity = _wal_identity(db_path)
    if identity is None:
        return False
    path_key, dev, ino, mtime_ns = identity
    return _WAL_READY.get(path_key) == (dev, ino, mtime_ns)


def _wal_cache_store(db_path: Path) -> None:
    identity = _wal_identity(db_path)
    if identity is None:
        return
    path_key, dev, ino, mtime_ns = identity
    _WAL_READY[path_key] = (dev, ino, mtime_ns)


def _wal_cache_drop(db_path: Path | str) -> None:
    path = Path(db_path)
    try:
        key = str(path.resolve())
    except OSError:
        key = str(path)
    _WAL_READY.pop(key, None)


def _enable_wal(conn: sqlite3.Connection) -> None:
    cursor = conn.execute("PRAGMA journal_mode=WAL")
    try:
        row = cursor.fetchone()
    finally:
        cursor.close()
    if row is None or str(row[0]).lower() != "wal":
        raise sqlite3.OperationalError("SQLite refused WAL journal mode")


def _set_busy_timeout(conn: sqlite3.Connection, timeout_ms: int) -> None:
    cursor = conn.execute(f"PRAGMA busy_timeout={timeout_ms}")
    try:
        return
    finally:
        cursor.close()


def _ensure_wal(conn: sqlite3.Connection, db_path: Path | None = None) -> None:
    """Enable WAL only when the database's persistent mode has drifted."""
    if db_path is not None and _wal_cache_hit(db_path):
        return
    deadline = time.monotonic() + _WAL_BOOTSTRAP_TIMEOUT_SECONDS
    last_lock_error: sqlite3.OperationalError | None = None
    for attempt in range(_WAL_MAX_ATTEMPTS):
        if last_lock_error is not None and time.monotonic() >= deadline:
            raise last_lock_error
        try:
            cursor = conn.execute("PRAGMA journal_mode")
            try:
                row = cursor.fetchone()
            finally:
                cursor.close()
            if row is not None and str(row[0]).lower() == "wal":
                if db_path is not None:
                    _wal_cache_store(db_path)
                return
            _enable_wal(conn)
            if db_path is not None:
                _wal_cache_store(db_path)
            return
        except sqlite3.OperationalError as error:
            if not _is_locked_or_busy(error):
                raise
            last_lock_error = error

        remaining = deadline - time.monotonic()
        if attempt == _WAL_MAX_ATTEMPTS - 1 or remaining <= 0:
            raise last_lock_error
        time.sleep(_retry_delay(attempt, remaining))

    assert last_lock_error is not None
    raise last_lock_error


async def _enable_wal_async(conn: aiosqlite.Connection) -> None:
    cursor = await conn.execute("PRAGMA journal_mode=WAL")
    try:
        row = await cursor.fetchone()
    finally:
        await cursor.close()
    if row is None or str(row[0]).lower() != "wal":
        raise sqlite3.OperationalError("SQLite refused WAL journal mode")


async def _set_busy_timeout_async(conn: aiosqlite.Connection, timeout_ms: int) -> None:
    cursor = await conn.execute(f"PRAGMA busy_timeout={timeout_ms}")
    try:
        return
    finally:
        await cursor.close()


async def _ensure_wal_async(conn: aiosqlite.Connection, db_path: Path | None = None) -> None:
    if db_path is not None and _wal_cache_hit(db_path):
        return
    deadline = time.monotonic() + _WAL_BOOTSTRAP_TIMEOUT_SECONDS
    last_lock_error: sqlite3.OperationalError | None = None
    for attempt in range(_WAL_MAX_ATTEMPTS):
        if last_lock_error is not None and time.monotonic() >= deadline:
            raise last_lock_error
        try:
            cursor = await conn.execute("PRAGMA journal_mode")
            try:
                row = await cursor.fetchone()
            finally:
                await cursor.close()
            if row is not None and str(row[0]).lower() == "wal":
                if db_path is not None:
                    _wal_cache_store(db_path)
                return
            await _enable_wal_async(conn)
            if db_path is not None:
                _wal_cache_store(db_path)
            return
        except sqlite3.OperationalError as error:
            if not _is_locked_or_busy(error):
                raise
            last_lock_error = error

        remaining = deadline - time.monotonic()
        if attempt == _WAL_MAX_ATTEMPTS - 1 or remaining <= 0:
            raise last_lock_error
        await asyncio.sleep(_retry_delay(attempt, remaining))

    assert last_lock_error is not None
    raise last_lock_error


@contextmanager
def db_connection(
    db_path: Path | str, *, row_factory: Any = None
) -> Generator[sqlite3.Connection, None, None]:
    """Open a SQLite connection and guarantee it is closed on exit.

    Usage::
        with db_connection(path) as conn:
            conn.execute(...)
    """
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), timeout=10.0)
    try:
        _set_busy_timeout(conn, _BOOTSTRAP_BUSY_TIMEOUT_MS)
        _ensure_wal(conn, db_path)
        _set_busy_timeout(conn, _NORMAL_BUSY_TIMEOUT_MS)
        if row_factory is not None:
            conn.row_factory = row_factory
        yield conn
    finally:
        conn.close()


@asynccontextmanager
async def adb_connection(
    db_path: Path | str, *, row_factory: Any = None
) -> AsyncGenerator[aiosqlite.Connection, None]:
    """Open an async SQLite connection via aiosqlite.

    Enables WAL mode and 5-second busy timeout for concurrency safety.

    Usage::
        async with adb_connection(path) as conn:
            await conn.execute(...)
    """
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    async with aiosqlite.connect(str(db_path), timeout=15.0) as conn:
        await _set_busy_timeout_async(conn, _BOOTSTRAP_BUSY_TIMEOUT_MS)
        await _ensure_wal_async(conn, db_path)
        await _set_busy_timeout_async(conn, _NORMAL_BUSY_TIMEOUT_MS)
        if row_factory is not None:
            conn.row_factory = row_factory
        yield conn
