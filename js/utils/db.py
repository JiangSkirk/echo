"""SQLite connection helpers with proper cleanup."""

from __future__ import annotations

import sqlite3
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path
from typing import Any


@contextmanager
def db_connection(db_path: Path | str, *, row_factory: Any = None) -> Generator[sqlite3.Connection, None, None]:
    """Open a SQLite connection and guarantee it is closed on exit.

    Usage::
        with db_connection(path) as conn:
            conn.execute(...)
    """
    conn = sqlite3.connect(str(db_path))
    if row_factory is not None:
        conn.row_factory = row_factory
    try:
        yield conn
    finally:
        conn.close()
