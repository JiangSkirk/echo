"""Immutable audit logging for compliance and forensics."""

from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import threading
import time
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

from js.utils.db import db_connection

_DEFAULT_MAX_ENTRIES = 5_000


class AuditEventType(StrEnum):
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    TOOL_BATCH = "tool_batch"
    MODEL_REQUEST = "model_request"
    MODEL_RESPONSE = "model_response"
    SECURITY_BLOCK = "security_block"
    SECURITY_WARN = "security_warn"
    SECURITY_ALERT = "security_alert"
    CONFIG_CHANGE = "config_change"
    USER_MESSAGE = "user_message"
    AGENT_MESSAGE = "agent_message"
    DELEGATION = "delegation"
    CANCELLED = "cancelled"
    ERROR = "error"
    SKILL_PROMOTION = "skill_promotion"
    SKILL_PROMOTION_GATE = "skill_promotion_gate"


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
    """Audit logger with HMAC-SHA256 hash-chain integrity.

    Audit log payloads are encrypted at rest using the same Fernet key
    managed by SecretManager.  The hash chain is authenticated with
    HMAC-SHA256 using a key derived from the SecretManager master secret, so
    an attacker with only database write access cannot recompute the chain
    to forge or rewrite history.  Chain verification fails closed: any
    record whose MAC does not verify (including legacy plain-SHA256 records)
    marks the chain as invalid.
    """

    def __init__(self, state_dir: Path, retention_days: int = 90) -> None:
        self.state_dir = state_dir
        self.db_path = state_dir / "audit.db"
        self.retention_days = retention_days
        self._lock = threading.RLock()
        self._last_hash: str = "0" * 64
        self._chain_mac_key: bytes = self._secrets.derive_mac_key("audit-hash-chain")
        self._init_db()

    @property
    def _secrets(self) -> Any:
        """Lazy-loaded SecretManager for payload encryption."""
        if not hasattr(self, "_secrets_inst"):
            from js.security.secrets import SecretManager

            self._secrets_inst = SecretManager(self.state_dir)
        return self._secrets_inst

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
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_chain_state (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    anchor_log_id INTEGER,
                    anchor_prev_checksum TEXT NOT NULL,
                    chain_tip TEXT NOT NULL
                )
            """)
            state = conn.execute(
                "SELECT anchor_log_id, anchor_prev_checksum, chain_tip "
                "FROM audit_chain_state WHERE id = 1"
            ).fetchone()
            if state is None:
                # Migrate existing SQLite databases by anchoring the current
                # retained chain exactly once. Future prefix deletions must be
                # performed through prune(), which updates this state atomically.
                first_row = conn.execute(
                    "SELECT id, prev_checksum FROM audit_log ORDER BY id ASC LIMIT 1"
                ).fetchone()
                last_row = conn.execute(
                    "SELECT checksum FROM audit_log ORDER BY id DESC LIMIT 1"
                ).fetchone()
                conn.execute(
                    """
                    INSERT INTO audit_chain_state
                    (id, anchor_log_id, anchor_prev_checksum, chain_tip)
                    VALUES (1, ?, ?, ?)
                    """,
                    (
                        first_row[0] if first_row else None,
                        first_row[1] if first_row else "0" * 64,
                        last_row[0] if last_row else "0" * 64,
                    ),
                )
            conn.commit()
            # The persisted tip is authoritative across restarts and pruning.
            self._last_hash = conn.execute(
                "SELECT chain_tip FROM audit_chain_state WHERE id = 1"
            ).fetchone()[0]

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
            raw_payload = json.dumps(details, sort_keys=True, default=str)
            # Encrypt the payload at rest — the hash chain is computed from the
            # encrypted form, so both integrity and confidentiality are preserved.
            payload = self._secrets.encrypt_blob(raw_payload.encode("utf-8"))

            # Build chain hash from the encrypted payload
            # Fernet tokens are URL-safe base64 (ASCII).  The stored form and
            # the hash-chain input are identical ASCII strings.
            _stored = payload.decode("ascii")
            data = f"{self._last_hash}:{timestamp}:{event_type.value}:{session_id}:{run_id}:{actor}:{action}:{_stored}"
            checksum = hmac.new(self._chain_mac_key, data.encode(), hashlib.sha256).hexdigest()

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
                cursor = conn.execute(
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
                        _stored,
                        checksum,
                        self._last_hash,
                    ),
                )
                state = conn.execute(
                    "SELECT anchor_log_id FROM audit_chain_state WHERE id = 1"
                ).fetchone()
                if state[0] is None:
                    conn.execute(
                        """
                        UPDATE audit_chain_state
                        SET anchor_log_id = ?, anchor_prev_checksum = ?
                        WHERE id = 1
                        """,
                        (cursor.lastrowid, self._last_hash),
                    )
                conn.execute("UPDATE audit_chain_state SET chain_tip = ? WHERE id = 1", (checksum,))
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

        _dec = self._secrets.decrypt_blob
        return [
            AuditEvent(
                timestamp=row["timestamp"],
                event_type=AuditEventType(row["event_type"]),
                session_id=row["session_id"],
                run_id=row["run_id"],
                actor=row["actor"],
                action=row["action"],
                details=json.loads(_dec(row["details"].encode("ascii")).decode("utf-8")),
                checksum=row["checksum"],
            )
            for row in rows
        ]

    def verify_chain(self) -> tuple[bool, int]:
        """Verify the integrity of the audit chain. Returns (valid, first_invalid_id).

        The persisted prune anchor prevents an arbitrary prefix deletion from
        becoming a new genesis, while the persisted tip detects truncation.
        """
        with db_connection(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT * FROM audit_log ORDER BY id ASC").fetchall()
            state = conn.execute(
                "SELECT anchor_log_id, anchor_prev_checksum, chain_tip "
                "FROM audit_chain_state WHERE id = 1"
            ).fetchone()

        if state["anchor_log_id"] is None:
            return (not rows, rows[0]["id"] if rows else 0)
        if not rows:
            return False, state["anchor_log_id"]
        if (
            rows[0]["id"] != state["anchor_log_id"]
            or rows[0]["prev_checksum"] != state["anchor_prev_checksum"]
        ):
            return False, rows[0]["id"]

        prev_hash = state["anchor_prev_checksum"]
        for row in rows:
            payload = row["details"]
            if row["prev_checksum"] != prev_hash:
                return False, row["id"]
            data = f"{prev_hash}:{row['timestamp']}:{row['event_type']}:{row['session_id']}:{row['run_id']}:{row['actor']}:{row['action']}:{payload}"
            expected = hmac.new(self._chain_mac_key, data.encode(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected, str(row["checksum"])):
                return False, row["id"]
            prev_hash = row["checksum"]

        if prev_hash != state["chain_tip"]:
            return False, rows[-1]["id"]
        return True, 0

    def prune(self, max_entries: int = _DEFAULT_MAX_ENTRIES) -> int:
        """Remove expired entries and retain at most ``max_entries`` rows.

        A successful deletion atomically records the oldest retained log row as
        the new authorized anchor and preserves the current chain tip.
        """
        if max_entries < 0:
            raise ValueError("max_entries must be non-negative")
        cutoff = time.time() - (self.retention_days * 86400)
        with self._lock, db_connection(self.db_path) as conn:
            changes_before = conn.total_changes
            conn.execute("DELETE FROM audit_log WHERE timestamp < ?", (cutoff,))
            conn.execute(
                """
                DELETE FROM audit_log
                WHERE id IN (
                    SELECT id
                    FROM audit_log
                    ORDER BY id DESC
                    LIMIT -1 OFFSET ?
                )
                """,
                (max_entries,),
            )
            deleted = conn.total_changes - changes_before
            if deleted:
                first_row = conn.execute(
                    "SELECT id, prev_checksum FROM audit_log ORDER BY id ASC LIMIT 1"
                ).fetchone()
                last_row = conn.execute(
                    "SELECT checksum FROM audit_log ORDER BY id DESC LIMIT 1"
                ).fetchone()
                self._last_hash = last_row[0] if last_row else "0" * 64
                conn.execute(
                    """
                    UPDATE audit_chain_state
                    SET anchor_log_id = ?, anchor_prev_checksum = ?, chain_tip = ?
                    WHERE id = 1
                    """,
                    (
                        first_row[0] if first_row else None,
                        first_row[1] if first_row else "0" * 64,
                        self._last_hash,
                    ),
                )
            conn.commit()
            return deleted
