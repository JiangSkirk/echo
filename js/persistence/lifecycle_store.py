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
                    session_id TEXT NOT NULL,
                    owner_key_hash TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    completed_at REAL,
                    exit_reason TEXT,
                    status TEXT NOT NULL DEFAULT 'running',
                    last_heartbeat_at REAL NOT NULL,
                    PRIMARY KEY (session_id, owner_key_hash)
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
            # Migration: if old table has only session_id as PK, recreate.
            cols = conn.execute("PRAGMA table_info(session_lifecycle)").fetchall()
            pk_cols = [c["name"] for c in cols if c["pk"]]
            if pk_cols == ["session_id"]:
                conn.execute("ALTER TABLE session_lifecycle RENAME TO session_lifecycle_old")
                conn.execute(
                    """
                    CREATE TABLE session_lifecycle (
                        session_id TEXT NOT NULL,
                        owner_key_hash TEXT NOT NULL,
                        created_at REAL NOT NULL,
                        completed_at REAL,
                        exit_reason TEXT,
                        status TEXT NOT NULL DEFAULT 'running',
                        last_heartbeat_at REAL NOT NULL,
                        PRIMARY KEY (session_id, owner_key_hash)
                    )
                    """
                )
                conn.execute(
                    """
                    INSERT INTO session_lifecycle
                    (session_id, owner_key_hash, created_at, completed_at, exit_reason, status, last_heartbeat_at)
                    SELECT session_id, COALESCE(owner_key_hash, ?), created_at, completed_at, exit_reason, status, last_heartbeat_at
                    FROM session_lifecycle_old
                    """,
                    (_LEGACY_LOCAL_OWNER,),
                )
                conn.execute("DROP TABLE session_lifecycle_old")
                conn.execute(
                    "CREATE INDEX idx_lifecycle_status_owner ON session_lifecycle(status, owner_key_hash)"
                )
                conn.execute(
                    "CREATE INDEX idx_lifecycle_heartbeat ON session_lifecycle(last_heartbeat_at)"
                )
            conn.commit()

    def _normalize_owner(self, owner_key_hash: str | None) -> str:
        return owner_key_hash or _LEGACY_LOCAL_OWNER

    def mark_started(self, session_id: str, owner_key_hash: str | None = None) -> None:
        now = time.time()
        owner = self._normalize_owner(owner_key_hash)
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO session_lifecycle
                (session_id, owner_key_hash, created_at, completed_at, exit_reason,
                 status, last_heartbeat_at)
                VALUES (?, ?, ?, NULL, NULL, 'running', ?)
                ON CONFLICT(session_id, owner_key_hash) DO UPDATE SET
                    created_at=excluded.created_at,
                    completed_at=NULL,
                    exit_reason=NULL,
                    status='running',
                    last_heartbeat_at=excluded.last_heartbeat_at
                """,
                (session_id, owner, now, now),
            )
            conn.commit()

    def mark_completed(
        self, session_id: str, exit_reason: str | None = None, owner_key_hash: str | None = None
    ) -> None:
        now = time.time()
        owner = self._normalize_owner(owner_key_hash)
        with self._conn() as conn:
            conn.execute(
                """
                UPDATE session_lifecycle
                SET status='completed',
                    completed_at=?,
                    exit_reason=?,
                    last_heartbeat_at=?
                WHERE session_id=? AND owner_key_hash=?
                """,
                (now, exit_reason or "", now, session_id, owner),
            )
            conn.commit()

    def mark_aborted(self, session_id: str, reason: str, owner_key_hash: str | None = None) -> None:
        now = time.time()
        owner = self._normalize_owner(owner_key_hash)
        with self._conn() as conn:
            conn.execute(
                """
                UPDATE session_lifecycle
                SET status='aborted',
                    completed_at=?,
                    exit_reason=?,
                    last_heartbeat_at=?
                WHERE session_id=? AND owner_key_hash=?
                """,
                (now, reason, now, session_id, owner),
            )
            conn.commit()

    def heartbeat(self, session_id: str, owner_key_hash: str | None = None) -> None:
        now = time.time()
        owner = self._normalize_owner(owner_key_hash)
        with self._conn() as conn:
            conn.execute(
                """
                UPDATE session_lifecycle
                SET last_heartbeat_at=?
                WHERE session_id=? AND owner_key_hash=?
                """,
                (now, session_id, owner),
            )
            conn.commit()

    def get(self, session_id: str, owner_key_hash: str | None = None) -> dict[str, Any] | None:
        owner = self._normalize_owner(owner_key_hash)
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM session_lifecycle WHERE session_id = ? AND owner_key_hash = ?",
                (session_id, owner),
            ).fetchone()
        if row is None:
            return None
        return {
            "session_id": row["session_id"],
            "owner_key_hash": row["owner_key_hash"] or _LEGACY_LOCAL_OWNER,
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
        """List active sessions owned by ``owner_key_hash``.

        ``None`` is normalized to the legacy-local sentinel so unauthenticated
        callers cannot read sessions belonging to authenticated owners.
        """
        cutoff = time.time() - threshold_seconds
        owner = self._normalize_owner(owner_key_hash)
        rows = (
            self._conn()
            .execute(
                """
            SELECT * FROM session_lifecycle
            WHERE status = 'running' AND owner_key_hash = ? AND last_heartbeat_at >= ?
            ORDER BY last_heartbeat_at DESC
            """,
                (owner, cutoff),
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

    def recover_aborted_sessions(
        self, threshold_seconds: float = 300, owner_key_hash: str | None = None
    ) -> list[str]:
        """Mark running sessions with stale heartbeats as aborted.

        ``None`` is normalized to the legacy-local sentinel; this never sweeps
        rows belonging to authenticated owners. For admin-style full recovery,
        introduce a dedicated ``recover_all_aborted_sessions`` later.
        """
        cutoff = time.time() - threshold_seconds
        owner = self._normalize_owner(owner_key_hash)
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT session_id, owner_key_hash FROM session_lifecycle
                WHERE status = 'running' AND last_heartbeat_at < ? AND owner_key_hash = ?
                """,
                (cutoff, owner),
            ).fetchall()
        recovered: list[str] = []
        for row in rows:
            session_id = row["session_id"]
            row_owner = row["owner_key_hash"] or _LEGACY_LOCAL_OWNER
            self.mark_aborted(session_id, "abnormal_exit_recovery", row_owner)
            recovered.append(session_id)
        return recovered
