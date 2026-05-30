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
from js.utils.log import get_logger

logger = get_logger("js.persistence.agents")


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
        except sqlite3.DatabaseError:
            self.db_path.unlink(missing_ok=True)
            with sqlite3.connect(str(self.db_path)) as conn:
                conn.execute("PRAGMA journal_mode=WAL")
        with self._conn() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS fleet_agents (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    role TEXT NOT NULL,
                    model TEXT,
                    capabilities TEXT DEFAULT '[]',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_fleet_agents_role
                ON fleet_agents(role)
                """
            )
            conn.commit()

    def save(
        self,
        agent_id: str,
        name: str,
        role: AgentRole,
        model: str | None = None,
        capabilities: list[str] | None = None,
    ) -> None:
        """Upsert an agent record."""
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO fleet_agents (id, name, role, model, capabilities)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
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
                ),
            )
            conn.commit()

    def delete(self, agent_id: str) -> None:
        """Remove an agent record."""
        with self._conn() as conn:
            conn.execute("DELETE FROM fleet_agents WHERE id = ?", (agent_id,))
            conn.commit()

    def list_all(self) -> list[dict[str, Any]]:
        """List all persisted agent metadata."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM fleet_agents ORDER BY created_at DESC"
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

    def prune(self, keep: int = 500) -> int:
        """Remove oldest agents beyond the keep limit."""
        with self._conn() as conn:
            total = conn.execute("SELECT COUNT(*) FROM fleet_agents").fetchone()[0]
            if total <= keep:
                return 0
            row = conn.execute(
                "SELECT created_at FROM fleet_agents ORDER BY created_at DESC LIMIT 1 OFFSET ?",
                (keep,),
            ).fetchone()
            if row is None:
                return 0
            cur = conn.execute(
                "DELETE FROM fleet_agents WHERE created_at < ?",
                (row["created_at"],),
            )
            conn.commit()
            return cur.rowcount
