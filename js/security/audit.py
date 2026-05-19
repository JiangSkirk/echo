"""Immutable audit logging for compliance and forensics."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

from js.utils.db import db_connection


class AuditEventType(StrEnum):
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    MODEL_REQUEST = "model_request"
    MODEL_RESPONSE = "model_response"
    SECURITY_BLOCK = "security_block"
    SECURITY_WARN = "security_warn"
    CONFIG_CHANGE = "config_change"
    USER_MESSAGE = "user_message"
    AGENT_MESSAGE = "agent_message"
    DELEGATION = "delegation"
    ERROR = "error"


@dataclass(frozen=True)
class AuditEvent:
    timestamp: float
    event_type: AuditEventType
    session_id: str
    run_id: str
    actor: str
    action: str
    details: dict[str, Any]
    checksum: str = ""


class AuditLogger:
    """Tamper-evident audit logger using hash chains."""

    def __init__(self, state_dir: Path, retention_days: int = 90) -> None:
        self.state_dir = state_dir
        self.db_path = state_dir / "audit.db"
        self.retention_days = retention_days
        self._lock = threading.RLock()
        self._last_hash: str = "0" * 64
        self._init_db()

    def _init_db(self) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        with db_connection(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    event_type TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    run_id TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    action TEXT NOT NULL,
                    details TEXT NOT NULL,
                    checksum TEXT NOT NULL,
                    prev_checksum TEXT NOT NULL,
                    chain_valid INTEGER DEFAULT 1
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_audit_session ON audit_log(session_id)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_audit_run ON audit_log(run_id)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_log(timestamp)
            """)
            conn.commit()
            # Load last hash for chain continuity
            row = conn.execute(
                "SELECT checksum FROM audit_log ORDER BY id DESC LIMIT 1"
            ).fetchone()
            if row:
                self._last_hash = row[0]
            else:
                self._last_hash = "0" * 64

    def log(
        self,
        event_type: AuditEventType,
        session_id: str,
        run_id: str,
        actor: str,
        action: str,
        details: dict[str, Any] | None = None,
    ) -> AuditEvent:
        """Append an immutable audit event."""
        with self._lock:
            timestamp = time.time()
            details = details or {}
            payload = json.dumps(details, sort_keys=True, default=str)

            # Build chain hash
            data = f"{self._last_hash}:{timestamp}:{event_type.value}:{session_id}:{run_id}:{actor}:{action}:{payload}"
            checksum = hashlib.sha256(data.encode()).hexdigest()

            event = AuditEvent(
                timestamp=timestamp,
                event_type=event_type,
                session_id=session_id,
                run_id=run_id,
                actor=actor,
                action=action,
                details=details,
                checksum=checksum,
            )

            with db_connection(self.db_path) as conn:
                conn.execute(
                    """
                    INSERT INTO audit_log
                    (timestamp, event_type, session_id, run_id, actor, action, details, checksum, prev_checksum)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        timestamp,
                        event_type.value,
                        session_id,
                        run_id,
                        actor,
                        action,
                        payload,
                        checksum,
                        self._last_hash,
                    ),
                )
                conn.commit()

            self._last_hash = checksum
            return event

    def query(
        self,
        session_id: str | None = None,
        run_id: str | None = None,
        event_type: AuditEventType | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[AuditEvent]:
        """Query audit events with filters."""
        conditions: list[str] = []
        params: list[Any] = []

        if session_id:
            conditions.append("session_id = ?")
            params.append(session_id)
        if run_id:
            conditions.append("run_id = ?")
            params.append(run_id)
        if event_type:
            conditions.append("event_type = ?")
            params.append(event_type.value)

        where_clause = " AND ".join(conditions) if conditions else "1=1"

        with db_connection(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                f"""
                SELECT * FROM audit_log
                WHERE {where_clause}
                ORDER BY id DESC
                LIMIT ? OFFSET ?
                """,
                (*params, limit, offset),
            ).fetchall()

        return [
            AuditEvent(
                timestamp=row["timestamp"],
                event_type=AuditEventType(row["event_type"]),
                session_id=row["session_id"],
                run_id=row["run_id"],
                actor=row["actor"],
                action=row["action"],
                details=json.loads(row["details"]),
                checksum=row["checksum"],
            )
            for row in rows
        ]

    def verify_chain(self) -> tuple[bool, int]:
        """Verify the integrity of the audit chain. Returns (valid, first_invalid_id)."""
        with db_connection(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM audit_log ORDER BY id ASC"
            ).fetchall()

        prev_hash = "0" * 64
        for row in rows:
            payload = row["details"]
            data = f"{prev_hash}:{row['timestamp']}:{row['event_type']}:{row['session_id']}:{row['run_id']}:{row['actor']}:{row['action']}:{payload}"
            expected = hashlib.sha256(data.encode()).hexdigest()
            if expected != row["checksum"]:
                return False, row["id"]
            prev_hash = row["checksum"]

        return True, 0

    def prune(self) -> int:
        """Remove entries older than retention_days.

        After pruning, re-anchor the hash chain from the newest remaining record
        so that verify_chain() continues to work.
        """
        cutoff = time.time() - (self.retention_days * 86400)
        with db_connection(self.db_path) as conn:
            cursor = conn.execute(
                "DELETE FROM audit_log WHERE timestamp < ?", (cutoff,)
            )
            conn.commit()
            # Re-anchor chain: the oldest remaining record becomes the new genesis
            row = conn.execute(
                "SELECT checksum FROM audit_log ORDER BY id ASC LIMIT 1"
            ).fetchone()
            if row:
                self._last_hash = row[0]
            else:
                self._last_hash = "0" * 64
            return cursor.rowcount
