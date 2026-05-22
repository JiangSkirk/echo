"""SQLite-backed state persistence for checkpoint/resume."""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any


class StateStore:
    """Persist and retrieve AgentState checkpoints per session."""

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
            # File is corrupted or not a database; remove and recreate
            self.db_path.unlink(missing_ok=True)
            with sqlite3.connect(str(self.db_path)) as conn:
                conn.execute("PRAGMA journal_mode=WAL")
        with self._conn() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS checkpoints (
                    session_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    turn_count INTEGER DEFAULT 0,
                    messages TEXT,
                    tool_results TEXT,
                    total_tokens TEXT,
                    cost_estimate REAL DEFAULT 0.0,
                    status TEXT DEFAULT 'running',
                    error_message TEXT DEFAULT '',
                    compression_stats TEXT,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_checkpoint_session
                ON checkpoints(session_id)
                """
            )
            conn.commit()

    def save(
        self,
        session_id: str,
        run_id: str,
        turn_count: int,
        messages: list[dict[str, Any]],
        tool_results: list[dict[str, Any]],
        total_tokens: dict[str, int],
        cost_estimate: float,
        status: str,
        error_message: str,
        compression_stats: dict[str, Any],
    ) -> None:
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO checkpoints (
                    session_id, run_id, turn_count, messages, tool_results,
                    total_tokens, cost_estimate, status, error_message,
                    compression_stats, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(session_id) DO UPDATE SET
                    run_id=excluded.run_id,
                    turn_count=excluded.turn_count,
                    messages=excluded.messages,
                    tool_results=excluded.tool_results,
                    total_tokens=excluded.total_tokens,
                    cost_estimate=excluded.cost_estimate,
                    status=excluded.status,
                    error_message=excluded.error_message,
                    compression_stats=excluded.compression_stats,
                    updated_at=excluded.updated_at
                """,
                (
                    session_id,
                    run_id,
                    turn_count,
                    json.dumps(messages, ensure_ascii=False),
                    json.dumps(tool_results, ensure_ascii=False),
                    json.dumps(total_tokens),
                    cost_estimate,
                    status,
                    error_message,
                    json.dumps(compression_stats, ensure_ascii=False),
                ),
            )
            conn.commit()

    def load(self, session_id: str) -> dict[str, Any] | None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM checkpoints WHERE session_id = ?",
                (session_id,),
            ).fetchone()
        if row is None:
            return None
        return {
            "session_id": row["session_id"],
            "run_id": row["run_id"],
            "turn_count": row["turn_count"],
            "messages": json.loads(row["messages"] or "[]"),
            "tool_results": json.loads(row["tool_results"] or "[]"),
            "total_tokens": json.loads(row["total_tokens"] or "{}"),
            "cost_estimate": row["cost_estimate"],
            "status": row["status"],
            "error_message": row["error_message"] or "",
            "compression_stats": json.loads(row["compression_stats"] or "{}"),
        }

    def delete(self, session_id: str) -> bool:
        with self._conn() as conn:
            cur = conn.execute(
                "DELETE FROM checkpoints WHERE session_id = ?",
                (session_id,),
            )
            conn.commit()
            return cur.rowcount > 0

    def list_sessions(self) -> list[str]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT session_id FROM checkpoints ORDER BY updated_at DESC"
            ).fetchall()
        return [r["session_id"] for r in rows]
