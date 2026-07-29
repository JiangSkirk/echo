"""Optional local SQLite-backed context CAS adapter for Echo.

``PersistentContextCAS`` is a local-machine persistence adapter for Echo
context payload reuse. It is deliberately not wired into the default runtime:
callers must instantiate it explicitly, pass scope information explicitly, and
decide whether storage failures are blocking or non-critical.

Security boundary
-----------------
This adapter stores raw payload bytes in a local SQLite database. It does not
store keys, does not read environment variables, and does not encrypt payloads.
Production-grade payload encryption, key management, and KMS integration are
future work for the caller/runtime layer.
"""

from __future__ import annotations

import hashlib
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import cast

__all__ = ["PersistentCASRecord", "PersistentContextCAS"]


@dataclass(frozen=True, slots=True)
class PersistentCASRecord:
    scope_key: str
    token_unit_id: str
    digest: bytes
    payload: bytes
    tokens: int
    byte_size: int
    created_at_ms: int
    last_accessed_ms: int
    expires_at_ms: int | None


class PersistentContextCAS:
    """SQLite-backed optional CAS adapter scoped by session/tokenizer/digest.

    Records are isolated by ``(scope_key, token_unit_id, digest)``. Identical
    payloads in different scopes or token units do not share rows. Writes use
    ``BEGIN IMMEDIATE`` so concurrent insert-or-fetch calls serialize before
    probing/inserting a digest.

    This is only a local persistence adapter. It does not encrypt stored
    payload bytes and does not manage secrets or keys; production payload
    encryption/KMS remains a future runtime concern.
    """

    def __init__(
        self,
        db_path: str | Path,
        *,
        ttl_ms: int | None = None,
        max_entries_per_scope: int | None = None,
        max_bytes_per_scope: int | None = None,
        timeout_s: float = 5.0,
    ) -> None:
        if ttl_ms is not None and ttl_ms < 0:
            raise ValueError("ttl_ms must be non-negative")
        if max_entries_per_scope is not None and max_entries_per_scope < 0:
            raise ValueError("max_entries_per_scope must be non-negative")
        if max_bytes_per_scope is not None and max_bytes_per_scope < 0:
            raise ValueError("max_bytes_per_scope must be non-negative")

        self.db_path = Path(db_path)
        self.ttl_ms = ttl_ms
        self.max_entries_per_scope = max_entries_per_scope
        self.max_bytes_per_scope = max_bytes_per_scope
        self._lock = threading.RLock()
        self._closed = False

        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(
            str(self.db_path),
            timeout=timeout_s,
            check_same_thread=False,
            isolation_level=None,
        )
        self._conn.row_factory = sqlite3.Row
        self._ensure_schema()

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._conn.close()
            self._closed = True

    def __enter__(self) -> PersistentContextCAS:
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()

    def put_with_status(
        self,
        scope_key: str,
        token_unit_id: str,
        payload: bytes,
        tokens: int,
        now_ms: int | None = None,
    ) -> tuple[PersistentCASRecord, bool]:
        """Insert-or-fetch ``payload`` for ``scope_key`` and ``token_unit_id``.

        Returns ``(record, created)`` where ``created`` is ``True`` only for
        the call that creates the active row. Expired rows are removed before
        lookup, so re-putting the same payload after ``expires_at_ms`` creates
        a fresh row.

        SQLite/corruption/locking errors intentionally propagate. Callers that
        treat this adapter as non-critical must catch them outside this adapter.
        """
        self._validate_scope(scope_key)
        self._validate_token_unit(token_unit_id)
        payload_bytes = self._payload_bytes(payload)
        if type(tokens) is not int or tokens < 0:
            raise ValueError("tokens must be a non-negative int")
        effective_now_ms = self._now_ms() if now_ms is None else self._validate_now_ms(now_ms)
        digest = hashlib.sha256(payload_bytes).digest()
        expires_at_ms = self._expires_at_ms(effective_now_ms)

        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                self._delete_expired_locked(scope_key, token_unit_id, effective_now_ms)
                row = self._select_locked(scope_key, token_unit_id, digest)
                if row is not None:
                    self._conn.execute(
                        """
                        UPDATE echo_context_cas_records
                        SET last_accessed_ms = ?
                        WHERE scope_key = ? AND token_unit_id = ? AND digest = ?
                        """,
                        (effective_now_ms, scope_key, token_unit_id, digest),
                    )
                    updated = self._select_locked(scope_key, token_unit_id, digest)
                    if updated is None:
                        raise sqlite3.DatabaseError("CAS row disappeared during update")
                    record = self._row_to_record(updated)
                    self._evict_scope_locked(scope_key, token_unit_id)
                    self._conn.commit()
                    return record, False

                self._conn.execute(
                    """
                    INSERT INTO echo_context_cas_records (
                        scope_key,
                        token_unit_id,
                        digest,
                        payload,
                        tokens,
                        byte_size,
                        created_at_ms,
                        last_accessed_ms,
                        expires_at_ms
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        scope_key,
                        token_unit_id,
                        digest,
                        payload_bytes,
                        tokens,
                        len(payload_bytes),
                        effective_now_ms,
                        effective_now_ms,
                        expires_at_ms,
                    ),
                )
                row = self._select_locked(scope_key, token_unit_id, digest)
                if row is None:
                    raise sqlite3.DatabaseError("CAS row was not readable after insert")
                record = self._row_to_record(row)
                self._evict_scope_locked(scope_key, token_unit_id)
                self._conn.commit()
                return record, True
            except Exception:
                self._conn.rollback()
                raise

    def _ensure_schema(self) -> None:
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                self._conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS echo_context_cas_records (
                        scope_key TEXT NOT NULL,
                        token_unit_id TEXT NOT NULL,
                        digest BLOB NOT NULL,
                        payload BLOB NOT NULL,
                        tokens INTEGER NOT NULL,
                        byte_size INTEGER NOT NULL,
                        created_at_ms INTEGER NOT NULL,
                        last_accessed_ms INTEGER NOT NULL,
                        expires_at_ms INTEGER,
                        PRIMARY KEY (scope_key, token_unit_id, digest)
                    )
                    """
                )
                self._conn.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_echo_context_cas_lru
                    ON echo_context_cas_records (
                        scope_key,
                        token_unit_id,
                        last_accessed_ms,
                        created_at_ms
                    )
                    """
                )
                self._conn.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_echo_context_cas_expiry
                    ON echo_context_cas_records (
                        scope_key,
                        token_unit_id,
                        expires_at_ms
                    )
                    """
                )
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise

    @staticmethod
    def _now_ms() -> int:
        return time.time_ns() // 1_000_000

    @staticmethod
    def _validate_scope(scope_key: str) -> None:
        if not isinstance(scope_key, str) or not scope_key:
            raise ValueError("scope_key must be a non-empty str")

    @staticmethod
    def _validate_token_unit(token_unit_id: str) -> None:
        if not isinstance(token_unit_id, str) or not token_unit_id:
            raise ValueError("token_unit_id must be a non-empty str")

    @staticmethod
    def _validate_now_ms(now_ms: int) -> int:
        if type(now_ms) is not int or now_ms < 0:
            raise ValueError("now_ms must be a non-negative int")
        return now_ms

    @staticmethod
    def _payload_bytes(payload: bytes) -> bytes:
        if not isinstance(payload, (bytes, bytearray)):
            raise TypeError(f"payload must be bytes or bytearray, got {type(payload).__name__}")
        return bytes(payload)

    def _expires_at_ms(self, now_ms: int) -> int | None:
        if self.ttl_ms is None:
            return None
        return now_ms + self.ttl_ms

    def _delete_expired_locked(self, scope_key: str, token_unit_id: str, now_ms: int) -> None:
        self._conn.execute(
            """
            DELETE FROM echo_context_cas_records
            WHERE scope_key = ?
              AND token_unit_id = ?
              AND expires_at_ms IS NOT NULL
              AND expires_at_ms <= ?
            """,
            (scope_key, token_unit_id, now_ms),
        )

    def _select_locked(
        self,
        scope_key: str,
        token_unit_id: str,
        digest: bytes,
    ) -> sqlite3.Row | None:
        row = self._conn.execute(
            """
            SELECT
                scope_key,
                token_unit_id,
                digest,
                payload,
                tokens,
                byte_size,
                created_at_ms,
                last_accessed_ms,
                expires_at_ms
            FROM echo_context_cas_records
            WHERE scope_key = ? AND token_unit_id = ? AND digest = ?
            """,
            (scope_key, token_unit_id, digest),
        ).fetchone()
        return cast("sqlite3.Row | None", row)

    def _evict_scope_locked(self, scope_key: str, token_unit_id: str) -> None:
        while True:
            stats = self._conn.execute(
                """
                SELECT
                    COUNT(*) AS entry_count,
                    COALESCE(SUM(byte_size), 0) AS total_bytes
                FROM echo_context_cas_records
                WHERE scope_key = ? AND token_unit_id = ?
                """,
                (scope_key, token_unit_id),
            ).fetchone()
            if stats is None:
                return
            entry_count = int(stats["entry_count"])
            total_bytes = int(stats["total_bytes"])
            too_many = (
                self.max_entries_per_scope is not None
                and entry_count > self.max_entries_per_scope
            )
            too_large = (
                self.max_bytes_per_scope is not None
                and total_bytes > self.max_bytes_per_scope
            )
            if not too_many and not too_large:
                return
            if entry_count <= 1 and too_large and not too_many:
                return

            victim = self._conn.execute(
                """
                SELECT digest
                FROM echo_context_cas_records
                WHERE scope_key = ? AND token_unit_id = ?
                ORDER BY last_accessed_ms ASC, created_at_ms ASC, digest ASC
                LIMIT 1
                """,
                (scope_key, token_unit_id),
            ).fetchone()
            if victim is None:
                return
            self._conn.execute(
                """
                DELETE FROM echo_context_cas_records
                WHERE scope_key = ? AND token_unit_id = ? AND digest = ?
                """,
                (scope_key, token_unit_id, bytes(victim["digest"])),
            )

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> PersistentCASRecord:
        return PersistentCASRecord(
            scope_key=str(row["scope_key"]),
            token_unit_id=str(row["token_unit_id"]),
            digest=bytes(row["digest"]),
            payload=bytes(row["payload"]),
            tokens=int(row["tokens"]),
            byte_size=int(row["byte_size"]),
            created_at_ms=int(row["created_at_ms"]),
            last_accessed_ms=int(row["last_accessed_ms"]),
            expires_at_ms=(
                None if row["expires_at_ms"] is None else int(row["expires_at_ms"])
            ),
        )
