"""Deterministic Task Review Capsule store with owner/session isolation."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_LEGACY_LOCAL_OWNER = "__legacy_local__"


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
        except sqlite3.DatabaseError:
            self.db_path.unlink(missing_ok=True)
            with sqlite3.connect(str(self.db_path)) as conn:
                conn.execute("PRAGMA journal_mode=WAL")
        with self._conn() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS review_capsules (
                    session_id TEXT NOT NULL,
                    run_id TEXT NOT NULL,
                    owner_key_hash TEXT,
                    first_user_message TEXT,
                    last_assistant_message TEXT,
                    tools_used TEXT,
                    total_tokens INTEGER,
                    turn_count INTEGER,
                    status TEXT,
                    error_message TEXT,
                    created_at REAL NOT NULL,
                    PRIMARY KEY (session_id, run_id)
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
            conn.commit()

    def store(self, capsule: ReviewCapsule) -> None:
        now = time.time() if capsule.created_at == 0 else capsule.created_at
        owner = capsule.owner_key_hash or _LEGACY_LOCAL_OWNER
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO review_capsules
                (session_id, run_id, owner_key_hash, first_user_message, last_assistant_message,
                 tools_used, total_tokens, turn_count, status, error_message, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(session_id, run_id) DO UPDATE SET
                    owner_key_hash=excluded.owner_key_hash,
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
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM review_capsules WHERE session_id = ? AND run_id = ?",
                (session_id, run_id),
            ).fetchone()
        if row is None:
            return None
        row_owner = row["owner_key_hash"] or _LEGACY_LOCAL_OWNER
        if owner_key_hash is not None and row_owner != owner_key_hash:
            return None
        return self._row_to_capsule(row)

    def list_recent(
        self, owner_key_hash: str | None = None, limit: int = 20
    ) -> list[ReviewCapsule]:
        if owner_key_hash is not None:
            rows = (
                self._conn()
                .execute(
                    """
                SELECT * FROM review_capsules
                WHERE owner_key_hash = ?
                ORDER BY created_at DESC
                LIMIT ?
                """,
                    (owner_key_hash, limit),
                )
                .fetchall()
            )
        else:
            rows = (
                self._conn()
                .execute(
                    """
                SELECT * FROM review_capsules
                ORDER BY created_at DESC
                LIMIT ?
                """,
                    (limit,),
                )
                .fetchall()
            )
        return [self._row_to_capsule(r) for r in rows]
