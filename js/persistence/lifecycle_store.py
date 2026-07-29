"""Lightweight session lifecycle metadata store with owner isolation."""

from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from js.utils.db import (
    is_recoverable_database_corruption,
    quarantine_corrupt_database,
)

_LEGACY_LOCAL_OWNER = "__legacy_local__"
_DEFAULT_RETENTION_DAYS = 90
_DEFAULT_MAX_TERMINAL_RECORDS_PER_OWNER = 1_000
_DEFAULT_MAX_TERMINAL_RECORDS_TOTAL = 10_000


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
        except sqlite3.DatabaseError as error:
            if not is_recoverable_database_corruption(error):
                raise
            quarantine_corrupt_database(self.db_path)
            with sqlite3.connect(str(self.db_path)) as conn:
                conn.execute("PRAGMA journal_mode=WAL")
        with self._conn() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS session_lifecycle (
                    session_id TEXT NOT NULL,
                    owner_key_hash TEXT NOT NULL,
                    run_id TEXT NOT NULL DEFAULT '',
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
            try:
                conn.execute(
                    "ALTER TABLE session_lifecycle ADD COLUMN run_id TEXT NOT NULL DEFAULT ''"
                )
            except sqlite3.OperationalError:
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
                        run_id TEXT NOT NULL DEFAULT '',
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
                    (session_id, owner_key_hash, run_id, created_at, completed_at,
                     exit_reason, status, last_heartbeat_at)
                    SELECT session_id, COALESCE(owner_key_hash, ?), COALESCE(run_id, ''),
                           created_at, completed_at, exit_reason, status, last_heartbeat_at
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

    def mark_started(
        self,
        session_id: str,
        owner_key_hash: str | None = None,
        run_id: str | None = None,
    ) -> None:
        now = time.time()
        owner = self._normalize_owner(owner_key_hash)
        run = run_id or ""
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO session_lifecycle
                (session_id, owner_key_hash, run_id, created_at, completed_at, exit_reason,
                 status, last_heartbeat_at)
                VALUES (?, ?, ?, ?, NULL, NULL, 'running', ?)
                ON CONFLICT(session_id, owner_key_hash) DO UPDATE SET
                    run_id=excluded.run_id,
                    created_at=excluded.created_at,
                    completed_at=NULL,
                    exit_reason=NULL,
                    status='running',
                    last_heartbeat_at=excluded.last_heartbeat_at
                """,
                (session_id, owner, run, now, now),
            )
            conn.commit()

    def mark_completed(
        self,
        session_id: str,
        exit_reason: str | None = None,
        owner_key_hash: str | None = None,
        run_id: str | None = None,
    ) -> bool:
        return self.mark_terminal(
            session_id,
            "completed",
            exit_reason,
            owner_key_hash,
            run_id,
        )

    def mark_terminal(
        self,
        session_id: str,
        status: str,
        exit_reason: str | None = None,
        owner_key_hash: str | None = None,
        run_id: str | None = None,
    ) -> bool:
        if status not in {"completed", "cancelled", "error", "aborted"}:
            raise ValueError(f"invalid terminal lifecycle status: {status}")
        now = time.time()
        owner = self._normalize_owner(owner_key_hash)
        run = run_id or ""
        with self._conn() as conn:
            cursor = conn.execute(
                """
                UPDATE session_lifecycle
                SET status=?,
                    completed_at=?,
                    exit_reason=?,
                    last_heartbeat_at=?
                WHERE session_id=?
                  AND owner_key_hash=?
                  AND status='running'
                  AND (? = '' OR run_id = ?)
                """,
                (
                    status,
                    now,
                    exit_reason or "",
                    now,
                    session_id,
                    owner,
                    run,
                    run,
                ),
            )
            conn.commit()
            return cursor.rowcount > 0

    def mark_aborted(
        self,
        session_id: str,
        reason: str,
        owner_key_hash: str | None = None,
        run_id: str | None = None,
    ) -> bool:
        return self.mark_terminal(
            session_id,
            "aborted",
            reason,
            owner_key_hash,
            run_id,
        )

    def heartbeat(
        self,
        session_id: str,
        owner_key_hash: str | None = None,
        run_id: str | None = None,
    ) -> bool:
        now = time.time()
        owner = self._normalize_owner(owner_key_hash)
        run = run_id or ""
        with self._conn() as conn:
            cursor = conn.execute(
                """
                UPDATE session_lifecycle
                SET last_heartbeat_at=?
                WHERE session_id=?
                  AND owner_key_hash=?
                  AND status='running'
                  AND (? = '' OR run_id = ?)
                """,
                (now, session_id, owner, run, run),
            )
            conn.commit()
            return cursor.rowcount > 0

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
            "run_id": row["run_id"] or "",
            "created_at": row["created_at"],
            "completed_at": row["completed_at"],
            "exit_reason": row["exit_reason"] or "",
            "status": row["status"],
            "last_heartbeat_at": row["last_heartbeat_at"],
        }

    def prune(
        self,
        retention_days: int = _DEFAULT_RETENTION_DAYS,
        max_per_owner: int = _DEFAULT_MAX_TERMINAL_RECORDS_PER_OWNER,
        max_total: int = _DEFAULT_MAX_TERMINAL_RECORDS_TOTAL,
    ) -> int:
        """Delete expired or over-limit terminal rows atomically.

        The per-owner limit is applied before the global limit. Running rows are
        never candidates for this maintenance path.
        """
        if retention_days < 0:
            raise ValueError("retention_days must be non-negative")
        if max_per_owner < 0:
            raise ValueError("max_per_owner must be non-negative")
        if max_total < 0:
            raise ValueError("max_total must be non-negative")

        cutoff = time.time() - retention_days * 86_400
        with self._conn() as conn:
            changes_before = conn.total_changes
            conn.execute(
                """
                DELETE FROM session_lifecycle
                WHERE status IN ('completed', 'cancelled', 'error', 'aborted')
                  AND COALESCE(completed_at, last_heartbeat_at, created_at) < ?
                """,
                (cutoff,),
            )
            conn.execute(
                """
                DELETE FROM session_lifecycle
                WHERE rowid IN (
                    SELECT rowid
                    FROM (
                        SELECT
                            rowid,
                            ROW_NUMBER() OVER (
                                PARTITION BY owner_key_hash
                                ORDER BY
                                    COALESCE(completed_at, last_heartbeat_at, created_at) DESC,
                                    created_at DESC,
                                    session_id DESC
                            ) AS retention_rank
                        FROM session_lifecycle
                        WHERE status IN ('completed', 'cancelled', 'error', 'aborted')
                    )
                    WHERE retention_rank > ?
                )
                """,
                (max_per_owner,),
            )
            conn.execute(
                """
                DELETE FROM session_lifecycle
                WHERE rowid IN (
                    SELECT rowid
                    FROM session_lifecycle
                    WHERE status IN ('completed', 'cancelled', 'error', 'aborted')
                    ORDER BY
                        COALESCE(completed_at, last_heartbeat_at, created_at) DESC,
                        created_at DESC,
                        owner_key_hash DESC,
                        session_id DESC
                    LIMIT -1 OFFSET ?
                )
                """,
                (max_total,),
            )
            return conn.total_changes - changes_before

    def running_pairs_for_maintenance(self) -> set[tuple[str, str]]:
        """Return all running owner/session pairs for internal retention guards."""
        rows = (
            self._conn()
            .execute(
                """
            SELECT owner_key_hash, session_id
            FROM session_lifecycle
            WHERE status = 'running'
            """
            )
            .fetchall()
        )
        return {
            (str(row["owner_key_hash"] or _LEGACY_LOCAL_OWNER), str(row["session_id"]))
            for row in rows
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
                "run_id": r["run_id"] or "",
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
        rows belonging to authenticated owners. For admin-style full recovery
        (typically used at process startup), use ``recover_all_aborted_sessions``.
        """
        now = time.time()
        cutoff = now - threshold_seconds
        owner = self._normalize_owner(owner_key_hash)
        with self._conn() as conn:
            rows = conn.execute(
                """
                UPDATE session_lifecycle
                SET status='aborted',
                    completed_at=?,
                    exit_reason='abnormal_exit_recovery',
                    last_heartbeat_at=?
                WHERE status='running'
                  AND last_heartbeat_at < ?
                  AND owner_key_hash = ?
                RETURNING session_id
                """,
                (now, now, cutoff, owner),
            ).fetchall()
        return [str(row["session_id"]) for row in rows]

    def recover_all_aborted_sessions(self, threshold_seconds: float = 300) -> list[tuple[str, str]]:
        """Mark *all* owners' stale-heartbeat running sessions as aborted.

        Intended for process-startup recovery: a crash kills every in-flight
        run regardless of owner, so every stale ``running`` row should flip to
        ``aborted`` with ``exit_reason="abnormal_exit_recovery"``. This is the
        ONLY API in this store that crosses owner boundaries, and it is
        write-only (it does not return per-owner content) — it returns the
        ``(session_id, owner_key_hash)`` pairs that were recovered so callers
        can log/audit. ``owner_key_hash`` in the result is already the stored
        sentinel-normalized value.
        """
        now = time.time()
        cutoff = now - threshold_seconds
        with self._conn() as conn:
            rows = conn.execute(
                """
                UPDATE session_lifecycle
                SET status='aborted',
                    completed_at=?,
                    exit_reason='abnormal_exit_recovery',
                    last_heartbeat_at=?
                WHERE status='running'
                  AND last_heartbeat_at < ?
                RETURNING session_id, owner_key_hash
                """,
                (now, now, cutoff),
            ).fetchall()
        return [
            (
                str(row["session_id"]),
                str(row["owner_key_hash"] or _LEGACY_LOCAL_OWNER),
            )
            for row in rows
        ]
