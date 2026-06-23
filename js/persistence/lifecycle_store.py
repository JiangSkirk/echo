"""Lightweight session lifecycle metadata store with owner isolation."""

from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

_LEGACY_LOCAL_OWNER = "__legacy_local__"


class SessionLifecycleStore:
    """Track session lifecycle (started/completed/aborted) per owner/session."""

    def __init__(self, db_path: Path | str) -> None:
        self.db_path = Path(db_path)
        self._local = threading.local()
        self._ensure_db()

    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            conn: sqlite3.Connection = sqlite3.connect(str(self.db_path), check_same_thread=False)
            conn.row_factory = sqlite3.Row
            self._local.conn = conn
        return self._local.conn  # type: ignore[no-any-return]

    def _ensure_db(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                conn.execute("PRAGMA journal_mode=WAL")
        except sqlite3.DatabaseError:
            self.db_path.unlink(missing_ok=True)
            with sqlite3.connect(str(self.db_path)) as conn:
                conn.execute("PRAGMA journal_mode=WAL")
        with self._conn() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS session_lifecycle (
                    session_id TEXT PRIMARY KEY,
                    owner_key_hash TEXT,
                    created_at REAL NOT NULL,
                    completed_at REAL,
                    exit_reason TEXT,
                    status TEXT NOT NULL DEFAULT 'running',
                    last_heartbeat_at REAL NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_lifecycle_status_owner
                ON session_lifecycle(status, owner_key_hash)
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_lifecycle_heartbeat
                ON session_lifecycle(last_heartbeat_at)
                """
            )
            # Backfill legacy NULL-owner rows to the local sentinel.
            try:
                conn.execute(
                    "UPDATE session_lifecycle SET owner_key_hash = ? WHERE owner_key_hash IS NULL",
                    (_LEGACY_LOCAL_OWNER,),
                )
            except Exception:
                pass
            conn.commit()

    def mark_started(self, session_id: str, owner_key_hash: str | None = None) -> None:
        now = time.time()
        owner = owner_key_hash or _LEGACY_LOCAL_OWNER
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO session_lifecycle
                (session_id, owner_key_hash, created_at, completed_at, exit_reason,
                 status, last_heartbeat_at)
                VALUES (?, ?, ?, NULL, NULL, 'running', ?)
                ON CONFLICT(session_id) DO UPDATE SET
                    owner_key_hash=excluded.owner_key_hash,
                    created_at=excluded.created_at,
                    completed_at=NULL,
                    exit_reason=NULL,
                    status='running',
                    last_heartbeat_at=excluded.last_heartbeat_at
                """,
                (session_id, owner, now, now),
            )
            conn.commit()

    def mark_completed(self, session_id: str, exit_reason: str | None = None) -> None:
        now = time.time()
        with self._conn() as conn:
            conn.execute(
                """
                UPDATE session_lifecycle
                SET status='completed',
                    completed_at=?,
                    exit_reason=?,
                    last_heartbeat_at=?
                WHERE session_id=?
                """,
                (now, exit_reason or "", now, session_id),
            )
            conn.commit()

    def mark_aborted(self, session_id: str, reason: str) -> None:
        now = time.time()
        with self._conn() as conn:
            conn.execute(
                """
                UPDATE session_lifecycle
                SET status='aborted',
                    completed_at=?,
                    exit_reason=?,
                    last_heartbeat_at=?
                WHERE session_id=?
                """,
                (now, reason, now, session_id),
            )
            conn.commit()

    def heartbeat(self, session_id: str) -> None:
        now = time.time()
        with self._conn() as conn:
            conn.execute(
                """
                UPDATE session_lifecycle
                SET last_heartbeat_at=?
                WHERE session_id=?
                """,
                (now, session_id),
            )
            conn.commit()

    def get(self, session_id: str, owner_key_hash: str | None = None) -> dict[str, Any] | None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM session_lifecycle WHERE session_id = ?", (session_id,)
            ).fetchone()
        if row is None:
            return None
        row_owner = row["owner_key_hash"] or _LEGACY_LOCAL_OWNER
        if owner_key_hash is not None and row_owner != owner_key_hash:
            return None
        return {
            "session_id": row["session_id"],
            "owner_key_hash": row_owner,
            "created_at": row["created_at"],
            "completed_at": row["completed_at"],
            "exit_reason": row["exit_reason"] or "",
            "status": row["status"],
            "last_heartbeat_at": row["last_heartbeat_at"],
        }

    def list_active(
        self,
        owner_key_hash: str | None = None,
        threshold_seconds: float = 300,
    ) -> list[dict[str, Any]]:
        cutoff = time.time() - threshold_seconds
        if owner_key_hash is not None:
            rows = (
                self._conn()
                .execute(
                    """
                SELECT * FROM session_lifecycle
                WHERE status = 'running' AND owner_key_hash = ? AND last_heartbeat_at >= ?
                ORDER BY last_heartbeat_at DESC
                """,
                    (owner_key_hash, cutoff),
                )
                .fetchall()
            )
        else:
            rows = (
                self._conn()
                .execute(
                    """
                SELECT * FROM session_lifecycle
                WHERE status = 'running' AND last_heartbeat_at >= ?
                ORDER BY last_heartbeat_at DESC
                """,
                    (cutoff,),
                )
                .fetchall()
            )
        return [
            {
                "session_id": r["session_id"],
                "owner_key_hash": r["owner_key_hash"] or _LEGACY_LOCAL_OWNER,
                "created_at": r["created_at"],
                "completed_at": r["completed_at"],
                "exit_reason": r["exit_reason"] or "",
                "status": r["status"],
                "last_heartbeat_at": r["last_heartbeat_at"],
            }
            for r in rows
        ]

    def recover_aborted_sessions(self, threshold_seconds: float = 300) -> list[str]:
        """Mark running sessions with stale heartbeats as aborted."""
        cutoff = time.time() - threshold_seconds
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT session_id FROM session_lifecycle
                WHERE status = 'running' AND last_heartbeat_at < ?
                """,
                (cutoff,),
            ).fetchall()
        recovered: list[str] = []
        for row in rows:
            session_id = row["session_id"]
            self.mark_aborted(session_id, "abnormal_exit_recovery")
            recovered.append(session_id)
        return recovered
