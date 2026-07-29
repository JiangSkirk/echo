"""Deterministic Task Review Capsule store with owner/session isolation."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from js.utils.db import (
    is_recoverable_database_corruption,
    quarantine_corrupt_database,
)

_LEGACY_LOCAL_OWNER = "__legacy_local__"
_DEFAULT_MAX_CAPSULES_PER_OWNER = 1_000
_DEFAULT_MAX_CAPSULES_TOTAL = 10_000


@dataclass
class ReviewCapsule:
    session_id: str
    run_id: str
    first_user_message: str
    last_assistant_message: str
    tools_used: list[dict[str, Any]]
    total_tokens: int
    turn_count: int
    status: str
    error_message: str
    owner_key_hash: str | None = None
    created_at: float = 0.0


class ReviewStore:
    """Store lightweight, LLM-free review capsules at the end of each run."""

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
                CREATE TABLE IF NOT EXISTS review_capsules (
                    session_id TEXT NOT NULL,
                    run_id TEXT NOT NULL,
                    owner_key_hash TEXT NOT NULL,
                    first_user_message TEXT,
                    last_assistant_message TEXT,
                    tools_used TEXT,
                    total_tokens INTEGER,
                    turn_count INTEGER,
                    status TEXT,
                    error_message TEXT,
                    created_at REAL NOT NULL,
                    PRIMARY KEY (session_id, run_id, owner_key_hash)
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_review_owner
                ON review_capsules(owner_key_hash, created_at)
                """
            )
            try:
                conn.execute(
                    "UPDATE review_capsules SET owner_key_hash = ? WHERE owner_key_hash IS NULL",
                    (_LEGACY_LOCAL_OWNER,),
                )
            except Exception:
                pass
            # Migration: if old table has only (session_id, run_id) as PK, recreate.
            cols = conn.execute("PRAGMA table_info(review_capsules)").fetchall()
            pk_cols = [c["name"] for c in cols if c["pk"]]
            if pk_cols == ["session_id", "run_id"]:
                conn.execute("ALTER TABLE review_capsules RENAME TO review_capsules_old")
                conn.execute(
                    """
                    CREATE TABLE review_capsules (
                        session_id TEXT NOT NULL,
                        run_id TEXT NOT NULL,
                        owner_key_hash TEXT NOT NULL,
                        first_user_message TEXT,
                        last_assistant_message TEXT,
                        tools_used TEXT,
                        total_tokens INTEGER,
                        turn_count INTEGER,
                        status TEXT,
                        error_message TEXT,
                        created_at REAL NOT NULL,
                        PRIMARY KEY (session_id, run_id, owner_key_hash)
                    )
                    """
                )
                conn.execute(
                    """
                    INSERT INTO review_capsules
                    (session_id, run_id, owner_key_hash, first_user_message, last_assistant_message,
                     tools_used, total_tokens, turn_count, status, error_message, created_at)
                    SELECT session_id, run_id, COALESCE(owner_key_hash, ?), first_user_message,
                           last_assistant_message, tools_used, total_tokens, turn_count, status,
                           error_message, created_at
                    FROM review_capsules_old
                    """,
                    (_LEGACY_LOCAL_OWNER,),
                )
                conn.execute("DROP TABLE review_capsules_old")
                conn.execute(
                    "CREATE INDEX idx_review_owner ON review_capsules(owner_key_hash, created_at)"
                )
            conn.commit()

    def _normalize_owner(self, owner_key_hash: str | None) -> str:
        return owner_key_hash or _LEGACY_LOCAL_OWNER

    def store(self, capsule: ReviewCapsule) -> None:
        now = time.time() if capsule.created_at == 0 else capsule.created_at
        owner = self._normalize_owner(capsule.owner_key_hash)
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO review_capsules
                (session_id, run_id, owner_key_hash, first_user_message, last_assistant_message,
                 tools_used, total_tokens, turn_count, status, error_message, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(session_id, run_id, owner_key_hash) DO UPDATE SET
                    first_user_message=excluded.first_user_message,
                    last_assistant_message=excluded.last_assistant_message,
                    tools_used=excluded.tools_used,
                    total_tokens=excluded.total_tokens,
                    turn_count=excluded.turn_count,
                    status=excluded.status,
                    error_message=excluded.error_message,
                    created_at=excluded.created_at
                """,
                (
                    capsule.session_id,
                    capsule.run_id,
                    owner,
                    capsule.first_user_message,
                    capsule.last_assistant_message,
                    json.dumps(capsule.tools_used, ensure_ascii=False),
                    capsule.total_tokens,
                    capsule.turn_count,
                    capsule.status,
                    capsule.error_message,
                    now,
                ),
            )
            conn.commit()

    def _row_to_capsule(self, row: sqlite3.Row) -> ReviewCapsule:
        return ReviewCapsule(
            session_id=row["session_id"],
            run_id=row["run_id"],
            owner_key_hash=row["owner_key_hash"] or _LEGACY_LOCAL_OWNER,
            first_user_message=row["first_user_message"] or "",
            last_assistant_message=row["last_assistant_message"] or "",
            tools_used=json.loads(row["tools_used"] or "[]"),
            total_tokens=row["total_tokens"] or 0,
            turn_count=row["turn_count"] or 0,
            status=row["status"] or "",
            error_message=row["error_message"] or "",
            created_at=row["created_at"] or 0.0,
        )

    def get(
        self, session_id: str, run_id: str, owner_key_hash: str | None = None
    ) -> ReviewCapsule | None:
        owner = self._normalize_owner(owner_key_hash)
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM review_capsules WHERE session_id = ? AND run_id = ? AND owner_key_hash = ?",
                (session_id, run_id, owner),
            ).fetchone()
        if row is None:
            return None
        return self._row_to_capsule(row)

    def prune(
        self,
        max_per_owner: int = _DEFAULT_MAX_CAPSULES_PER_OWNER,
        max_total: int = _DEFAULT_MAX_CAPSULES_TOTAL,
    ) -> int:
        """Enforce per-owner and global hard caps in one transaction."""
        if max_per_owner < 0:
            raise ValueError("max_per_owner must be non-negative")
        if max_total < 0:
            raise ValueError("max_total must be non-negative")

        with self._conn() as conn:
            changes_before = conn.total_changes
            conn.execute(
                """
                DELETE FROM review_capsules
                WHERE rowid IN (
                    SELECT rowid
                    FROM (
                        SELECT
                            rowid,
                            ROW_NUMBER() OVER (
                                PARTITION BY owner_key_hash
                                ORDER BY created_at DESC, rowid DESC
                            ) AS retention_rank
                        FROM review_capsules
                    )
                    WHERE retention_rank > ?
                )
                """,
                (max_per_owner,),
            )
            conn.execute(
                """
                DELETE FROM review_capsules
                WHERE rowid IN (
                    SELECT rowid
                    FROM review_capsules
                    ORDER BY created_at DESC, rowid DESC
                    LIMIT -1 OFFSET ?
                )
                """,
                (max_total,),
            )
            return conn.total_changes - changes_before

    def list_recent(
        self, owner_key_hash: str | None = None, limit: int = 20
    ) -> list[ReviewCapsule]:
        """Recent capsules owned by ``owner_key_hash``.

        ``None`` is normalized to the legacy-local sentinel — it does NOT
        return the union of all owners. Use an explicit ``list_all_recent``
        helper later if admin-style global listing is needed.
        """
        owner = self._normalize_owner(owner_key_hash)
        rows = (
            self._conn()
            .execute(
                """
            SELECT * FROM review_capsules
            WHERE owner_key_hash = ?
            ORDER BY created_at DESC
            LIMIT ?
            """,
                (owner, limit),
            )
            .fetchall()
        )
        return [self._row_to_capsule(r) for r in rows]
