"""SQLite-backed persistence for Fleet agent metadata.

Enables fleet recovery after process restarts by re-spawning agents from
their last known configuration.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any

from js.orchestration.fleet import AgentRole
from js.utils.db import (
    is_recoverable_database_corruption,
    quarantine_corrupt_database,
)
from js.utils.log import get_logger

logger = get_logger("js.persistence.agents")

_LEGACY_LOCAL_OWNER = "__legacy_local__"


class AgentStore:
    """Persist and retrieve Fleet agent metadata."""

    def __init__(self, db_path: Path | str) -> None:
        self.db_path = Path(db_path)
        self._local = threading.local()
        self._ensure_db()

    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            conn: sqlite3.Connection = sqlite3.connect(
                str(self.db_path), check_same_thread=False
            )
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
                CREATE TABLE IF NOT EXISTS fleet_agents (
                    id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    role TEXT NOT NULL,
                    model TEXT,
                    capabilities TEXT DEFAULT '[]',
                    owner_key_hash TEXT NOT NULL DEFAULT '__legacy_local__',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (id, owner_key_hash)
                )
                """
            )
            # Migrate: add owner_key_hash column if missing
            try:
                conn.execute(
                    "ALTER TABLE fleet_agents ADD COLUMN owner_key_hash TEXT NOT NULL DEFAULT '__legacy_local__'"
                )
            except sqlite3.OperationalError:
                pass  # Column already exists
            # Backfill legacy empty-owner rows to the local sentinel.
            try:
                conn.execute(
                    "UPDATE fleet_agents SET owner_key_hash = ? WHERE owner_key_hash = ''",
                    (_LEGACY_LOCAL_OWNER,),
                )
            except Exception:
                pass
            # Migration: if the old table has only id as PK, recreate it with a
            # composite (id, owner_key_hash) PK so owners cannot overwrite each
            # other's agent records through the upsert path.
            cols = conn.execute("PRAGMA table_info(fleet_agents)").fetchall()
            pk_cols = [c[1] for c in cols if c[5]]
            if pk_cols == ["id"]:
                conn.execute("ALTER TABLE fleet_agents RENAME TO fleet_agents_old")
                conn.execute(
                    """
                    CREATE TABLE fleet_agents (
                        id TEXT NOT NULL,
                        name TEXT NOT NULL,
                        role TEXT NOT NULL,
                        model TEXT,
                        capabilities TEXT DEFAULT '[]',
                        owner_key_hash TEXT NOT NULL DEFAULT '__legacy_local__',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        PRIMARY KEY (id, owner_key_hash)
                    )
                    """
                )
                conn.execute(
                    """
                    INSERT INTO fleet_agents
                    (id, name, role, model, capabilities, owner_key_hash, created_at)
                    SELECT id, name, role, model, capabilities,
                           COALESCE(NULLIF(owner_key_hash, ''), ?), created_at
                    FROM fleet_agents_old
                    """,
                    (_LEGACY_LOCAL_OWNER,),
                )
                conn.execute("DROP TABLE fleet_agents_old")
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_fleet_agents_role
                ON fleet_agents(role)
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_fleet_agents_owner
                ON fleet_agents(owner_key_hash, created_at)
                """
            )
            conn.commit()

    def _normalize_owner(self, owner_key_hash: str | None) -> str:
        return owner_key_hash or _LEGACY_LOCAL_OWNER

    def save(
        self,
        agent_id: str,
        name: str,
        role: AgentRole,
        model: str | None = None,
        capabilities: list[str] | None = None,
        owner_key_hash: str | None = None,
    ) -> None:
        """Upsert an agent record scoped to ``owner_key_hash``."""
        owner = self._normalize_owner(owner_key_hash)
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO fleet_agents (id, name, role, model, capabilities, owner_key_hash)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(id, owner_key_hash) DO UPDATE SET
                    name=excluded.name,
                    role=excluded.role,
                    model=excluded.model,
                    capabilities=excluded.capabilities
                """,
                (
                    agent_id,
                    name,
                    role.value,
                    model or "",
                    json.dumps(capabilities or [], ensure_ascii=False),
                    owner,
                ),
            )
            conn.commit()

    def delete(self, agent_id: str, owner_key_hash: str | None = None) -> None:
        """Remove an agent record owned by ``owner_key_hash``."""
        owner = self._normalize_owner(owner_key_hash)
        with self._conn() as conn:
            conn.execute(
                "DELETE FROM fleet_agents WHERE id = ? AND owner_key_hash = ?",
                (agent_id, owner),
            )
            conn.commit()

    def list_all(self, owner_key_hash: str | None = None) -> list[dict[str, Any]]:
        """List persisted agent metadata owned by ``owner_key_hash``.

        ``None`` is normalized to the legacy-local sentinel; it does NOT
        return rows belonging to other owners.
        """
        owner = self._normalize_owner(owner_key_hash)
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM fleet_agents WHERE owner_key_hash = ? ORDER BY created_at DESC",
                (owner,),
            ).fetchall()
        return [
            {
                "id": r["id"],
                "name": r["name"],
                "role": r["role"],
                "model": r["model"] or None,
                "capabilities": json.loads(r["capabilities"] or "[]"),
            }
            for r in rows
        ]

    def prune(self, keep: int = 500, owner_key_hash: str | None = None) -> int:
        """Remove oldest agents beyond the keep limit for one owner."""
        owner = self._normalize_owner(owner_key_hash)
        with self._conn() as conn:
            total = conn.execute(
                "SELECT COUNT(*) FROM fleet_agents WHERE owner_key_hash = ?",
                (owner,),
            ).fetchone()[0]
            if total <= keep:
                return 0
            row = conn.execute(
                "SELECT created_at FROM fleet_agents WHERE owner_key_hash = ? ORDER BY created_at DESC LIMIT 1 OFFSET ?",
                (owner, keep),
            ).fetchone()
            if row is None:
                return 0
            cur = conn.execute(
                "DELETE FROM fleet_agents WHERE owner_key_hash = ? AND created_at < ?",
                (owner, row["created_at"]),
            )
            conn.commit()
            return cur.rowcount
