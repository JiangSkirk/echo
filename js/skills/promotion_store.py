"""Skill promotion event store with owner isolation.

Tracks proposed / approved / applied / rejected / rolled-back / failed
promotion events for skills (trust-level changes or evolver variant
applications). Owner isolation mirrors :mod:`js.persistence.lifecycle_store`:
a composite primary key on ``(event_id, owner_key_hash)`` plus a
``__legacy_local__`` sentinel for unauthenticated / single-user callers.

This module deliberately stays a thin persistence layer — it never mutates
``SkillSpec`` or touches the tool registry. Higher-level orchestration
(``SkillManager.apply_proposal`` / ``revert_promotion`` etc.) consumes
these rows.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from js.utils.db import (
    is_recoverable_database_corruption,
    quarantine_corrupt_database,
)

_LEGACY_LOCAL_OWNER = "__legacy_local__"


# Status state machine
STATUS_PROPOSED = "proposed"
STATUS_APPROVED = "approved"
STATUS_REJECTED = "rejected"
STATUS_APPLIED = "applied"
STATUS_ROLLED_BACK = "rolled_back"
STATUS_FAILED = "failed"

_OPEN_STATUSES = (STATUS_PROPOSED, STATUS_APPROVED)


@dataclass(frozen=True)
class PromotionEvent:
    """A single promotion event row, exposed as a frozen dataclass.

    ``details`` is decoded from JSON; the rest mirror the DB columns.
    """

    event_id: str
    owner_key_hash: str
    skill_id: str
    from_level: str
    to_level: str
    source: str
    reason: str
    status: str
    variant_id: str | None
    artifact_path: str | None
    details: dict[str, Any]
    created_at: float
    decided_by: str | None
    decided_at: float | None
    applied_at: float | None
    rolled_back_at: float | None


class PromotionStore:
    """SQLite-backed promotion event store with owner isolation."""

    def __init__(self, db_path: Path | str) -> None:
        self.db_path = Path(db_path)
        self._local = threading.local()
        self._ensure_db()

    # ------------------------------------------------------------------
    # Connection / schema
    # ------------------------------------------------------------------

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
                CREATE TABLE IF NOT EXISTS promotion_events (
                    event_id TEXT NOT NULL,
                    owner_key_hash TEXT NOT NULL,
                    skill_id TEXT NOT NULL,
                    from_level TEXT NOT NULL,
                    to_level TEXT NOT NULL,
                    source TEXT NOT NULL,
                    reason TEXT,
                    status TEXT NOT NULL DEFAULT 'proposed',
                    variant_id TEXT,
                    artifact_path TEXT,
                    details_json TEXT NOT NULL DEFAULT '{}',
                    created_at REAL NOT NULL,
                    decided_by TEXT,
                    decided_at REAL,
                    applied_at REAL,
                    rolled_back_at REAL,
                    PRIMARY KEY (event_id, owner_key_hash)
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_promotion_skill_owner_status
                ON promotion_events(skill_id, owner_key_hash, status)
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_promotion_status_created
                ON promotion_events(status, created_at)
                """
            )
            # Backfill: anything that slipped in with NULL owner.
            try:
                conn.execute(
                    "UPDATE promotion_events SET owner_key_hash = ? WHERE owner_key_hash IS NULL",
                    (_LEGACY_LOCAL_OWNER,),
                )
            except Exception:
                pass
            conn.commit()

    def _normalize_owner(self, owner_key_hash: str | None) -> str:
        return owner_key_hash or _LEGACY_LOCAL_OWNER

    def close(self) -> None:
        """Close the thread-local SQLite connection if one is open.

        Safe to call multiple times; subsequent ``propose`` / ``list_*`` calls
        will lazily reopen a fresh connection via :meth:`_conn`. Used by
        ``Agent.close()`` so long-running processes don't leak SQLite handles
        across thread lifetimes.
        """
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
            self._local.conn = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def propose(
        self,
        skill_id: str,
        from_level: str,
        to_level: str,
        source: str,
        reason: str,
        *,
        owner_key_hash: str | None = None,
        decided_by: str = "auto",
        variant_id: str | None = None,
        artifact_path: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> str:
        """Record a new proposal and return its ``event_id``."""
        owner = self._normalize_owner(owner_key_hash)
        event_id = uuid.uuid4().hex
        now = time.time()
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO promotion_events
                    (event_id, owner_key_hash, skill_id, from_level, to_level, source,
                     reason, status, variant_id, artifact_path, details_json,
                     created_at, decided_by, decided_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
                """,
                (
                    event_id,
                    owner,
                    skill_id,
                    from_level,
                    to_level,
                    source,
                    reason or "",
                    STATUS_PROPOSED,
                    variant_id,
                    artifact_path,
                    json.dumps(details or {}, sort_keys=True, default=str),
                    now,
                    decided_by,
                ),
            )
            conn.commit()
        return event_id

    def record_operator_apply(
        self,
        skill_id: str,
        from_level: str,
        to_level: str,
        *,
        owner_key_hash: str | None = None,
        decided_by: str,
        reason: str | None = None,
        source: str = "operator",
        details: dict[str, Any] | None = None,
    ) -> str:
        """Record a direct operator trust change as an already-applied event.

        Used by ``SkillManager.trust_skill`` so that ad-hoc operator changes
        also leave an audit trail without going through the propose → apply
        gate sequence.
        """
        owner = self._normalize_owner(owner_key_hash)
        event_id = uuid.uuid4().hex
        now = time.time()
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO promotion_events
                    (event_id, owner_key_hash, skill_id, from_level, to_level, source,
                     reason, status, details_json,
                     created_at, decided_by, decided_at, applied_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    owner,
                    skill_id,
                    from_level,
                    to_level,
                    source,
                    reason or "",
                    STATUS_APPLIED,
                    json.dumps(details or {}, sort_keys=True, default=str),
                    now,
                    decided_by,
                    now,
                    now,
                ),
            )
            conn.commit()
        return event_id

    def mark_approved(
        self,
        event_id: str,
        *,
        owner_key_hash: str | None = None,
        decided_by: str,
    ) -> bool:
        """Move a proposed event to ``approved``. Returns False if illegal."""
        return self._transition(
            event_id,
            owner_key_hash,
            allowed_from=(STATUS_PROPOSED,),
            new_status=STATUS_APPROVED,
            decided_by=decided_by,
        )

    def mark_rejected(
        self,
        event_id: str,
        *,
        owner_key_hash: str | None = None,
        decided_by: str,
        reason: str | None = None,
    ) -> bool:
        return self._transition(
            event_id,
            owner_key_hash,
            allowed_from=(STATUS_PROPOSED, STATUS_APPROVED),
            new_status=STATUS_REJECTED,
            decided_by=decided_by,
            reason=reason,
        )

    def mark_applied(
        self,
        event_id: str,
        *,
        owner_key_hash: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> bool:
        return self._transition(
            event_id,
            owner_key_hash,
            allowed_from=(STATUS_APPROVED,),
            new_status=STATUS_APPLIED,
            apply_time=True,
            extra_details=details,
        )

    def mark_rolled_back(
        self,
        event_id: str,
        *,
        owner_key_hash: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> bool:
        return self._transition(
            event_id,
            owner_key_hash,
            allowed_from=(STATUS_APPLIED,),
            new_status=STATUS_ROLLED_BACK,
            rollback_time=True,
            extra_details=details,
        )

    def mark_failed(
        self,
        event_id: str,
        *,
        owner_key_hash: str | None = None,
        failed_step: str,
        details: dict[str, Any] | None = None,
    ) -> bool:
        """Mark a proposed/approved event as failed (e.g. gate denied)."""
        merged: dict[str, Any] = {"failed_step": failed_step}
        if details:
            merged.update(details)
        return self._transition(
            event_id,
            owner_key_hash,
            allowed_from=(STATUS_PROPOSED, STATUS_APPROVED),
            new_status=STATUS_FAILED,
            extra_details=merged,
        )

    def get(
        self,
        event_id: str,
        *,
        owner_key_hash: str | None = None,
    ) -> PromotionEvent | None:
        owner = self._normalize_owner(owner_key_hash)
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM promotion_events WHERE event_id = ? AND owner_key_hash = ?",
                (event_id, owner),
            ).fetchone()
        if row is None:
            return None
        return self._row_to_event(row)

    def list_by_skill(
        self,
        skill_id: str,
        *,
        owner_key_hash: str | None = None,
        statuses: tuple[str, ...] | list[str] | None = None,
    ) -> list[PromotionEvent]:
        owner = self._normalize_owner(owner_key_hash)
        sql = "SELECT * FROM promotion_events WHERE skill_id = ? AND owner_key_hash = ?"
        params: list[Any] = [skill_id, owner]
        if statuses:
            placeholders = ",".join("?" for _ in statuses)
            sql += f" AND status IN ({placeholders})"
            params.extend(statuses)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row_to_event(r) for r in rows]

    def list_open_for_skill(
        self,
        skill_id: str,
        *,
        owner_key_hash: str | None = None,
    ) -> list[PromotionEvent]:
        """Open = ``proposed`` or ``approved``. Used by curator/evolver to dedup."""
        return self.list_by_skill(
            skill_id,
            owner_key_hash=owner_key_hash,
            statuses=_OPEN_STATUSES,
        )

    def list_recent(
        self,
        *,
        owner_key_hash: str | None = None,
        limit: int = 50,
    ) -> list[PromotionEvent]:
        owner = self._normalize_owner(owner_key_hash)
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT * FROM promotion_events
                WHERE owner_key_hash = ?
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (owner, int(limit)),
            ).fetchall()
        return [self._row_to_event(r) for r in rows]

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _transition(
        self,
        event_id: str,
        owner_key_hash: str | None,
        *,
        allowed_from: tuple[str, ...],
        new_status: str,
        decided_by: str | None = None,
        reason: str | None = None,
        apply_time: bool = False,
        rollback_time: bool = False,
        extra_details: dict[str, Any] | None = None,
    ) -> bool:
        owner = self._normalize_owner(owner_key_hash)
        now = time.time()
        with self._conn() as conn:
            row = conn.execute(
                "SELECT status, details_json, reason FROM promotion_events "
                "WHERE event_id = ? AND owner_key_hash = ?",
                (event_id, owner),
            ).fetchone()
            if row is None:
                return False
            if row["status"] not in allowed_from:
                return False

            # Merge any extra details into the existing payload so the gate's
            # failure context is preserved without dropping prior fields.
            details_blob = row["details_json"] or "{}"
            try:
                merged = json.loads(details_blob) if details_blob else {}
            except Exception:
                merged = {}
            if extra_details:
                merged.update(extra_details)

            updates: list[str] = ["status = ?", "details_json = ?"]
            params: list[Any] = [new_status, json.dumps(merged, sort_keys=True, default=str)]

            if decided_by is not None:
                updates.append("decided_by = ?")
                params.append(decided_by)
            updates.append("decided_at = ?")
            params.append(now)

            if reason is not None:
                # Append the reason; do not overwrite the original proposal text.
                combined = (row["reason"] or "").strip()
                combined = f"{combined} | {reason}" if combined else reason
                updates.append("reason = ?")
                params.append(combined)

            if apply_time:
                updates.append("applied_at = ?")
                params.append(now)
            if rollback_time:
                updates.append("rolled_back_at = ?")
                params.append(now)

            params.extend([event_id, owner])
            conn.execute(
                f"UPDATE promotion_events SET {', '.join(updates)} "
                f"WHERE event_id = ? AND owner_key_hash = ?",
                params,
            )
            conn.commit()
        return True

    @staticmethod
    def _row_to_event(row: sqlite3.Row) -> PromotionEvent:
        details_blob = row["details_json"] or "{}"
        try:
            details = json.loads(details_blob)
        except Exception:
            details = {}
        return PromotionEvent(
            event_id=row["event_id"],
            owner_key_hash=row["owner_key_hash"] or _LEGACY_LOCAL_OWNER,
            skill_id=row["skill_id"],
            from_level=row["from_level"],
            to_level=row["to_level"],
            source=row["source"],
            reason=row["reason"] or "",
            status=row["status"],
            variant_id=row["variant_id"],
            artifact_path=row["artifact_path"],
            details=details,
            created_at=row["created_at"],
            decided_by=row["decided_by"],
            decided_at=row["decided_at"],
            applied_at=row["applied_at"],
            rolled_back_at=row["rolled_back_at"],
        )
