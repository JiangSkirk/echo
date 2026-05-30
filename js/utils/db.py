"""SQLite connection helpers with proper cleanup."""

from __future__ import annotations

import sqlite3
from collections.abc import AsyncGenerator, Generator
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path
from typing import Any

import aiosqlite


@contextmanager
def db_connection(db_path: Path | str, *, row_factory: Any = None) -> Generator[sqlite3.Connection, None, None]:
    """Open a SQLite connection and guarantee it is closed on exit.

    Usage::
        with db_connection(path) as conn:
            conn.execute(...)
    """
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), timeout=10.0)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    if row_factory is not None:
        conn.row_factory = row_factory
    try:
        yield conn
    finally:
        conn.close()


@asynccontextmanager
async def adb_connection(db_path: Path | str, *, row_factory: Any = None) -> AsyncGenerator[aiosqlite.Connection, None]:
    """Open an async SQLite connection via aiosqlite.

    Enables WAL mode and 5-second busy timeout for concurrency safety.

    Usage::
        async with adb_connection(path) as conn:
            await conn.execute(...)
    """
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    async with aiosqlite.connect(str(db_path), timeout=15.0) as conn:
        await conn.execute("PRAGMA journal_mode=WAL")
        await conn.execute("PRAGMA busy_timeout=5000")
        if row_factory is not None:
            conn.row_factory = row_factory
        yield conn
