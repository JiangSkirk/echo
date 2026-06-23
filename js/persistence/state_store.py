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

    @property
    def _secrets(self) -> Any:
        """Lazy-loaded SecretManager for checkpoint encryption."""
        if not hasattr(self, "_secrets_inst"):
            from js.security.secrets import SecretManager

            self._secrets_inst = SecretManager(self.db_path.parent)
        return self._secrets_inst

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
            # Migrate: add model column if missing (pre-3.51 schemas)
            try:
                conn.execute("ALTER TABLE checkpoints ADD COLUMN model TEXT DEFAULT ''")
            except sqlite3.OperationalError:
                pass  # Column already exists
            # Migrate: add owner_key_hash column if missing
            try:
                conn.execute("ALTER TABLE checkpoints ADD COLUMN owner_key_hash TEXT")
            except sqlite3.OperationalError:
                pass  # Column already exists
            # Backfill legacy NULL-owner rows to the local sentinel.
            try:
                _legacy_local_owner = "__legacy_local__"

                conn.execute(
                    "UPDATE checkpoints SET owner_key_hash = ? WHERE owner_key_hash IS NULL",
                    (_legacy_local_owner,),
                )
            except Exception:
                pass
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
        model: str = "",
        owner_key_hash: str | None = None,
    ) -> None:
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO checkpoints (
                    session_id, run_id, turn_count, messages, tool_results,
                    total_tokens, cost_estimate, status, error_message,
                    compression_stats, model, owner_key_hash, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
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
                    model=excluded.model,
                    owner_key_hash=excluded.owner_key_hash,
                    updated_at=excluded.updated_at
                """,
                (
                    session_id,
                    run_id,
                    turn_count,
                    self._secrets.encrypt_blob(
                        json.dumps(messages, ensure_ascii=False).encode("utf-8")
                    ),
                    self._secrets.encrypt_blob(
                        json.dumps(tool_results, ensure_ascii=False).encode("utf-8")
                    ),
                    json.dumps(total_tokens),
                    cost_estimate,
                    status,
                    error_message,
                    json.dumps(compression_stats, ensure_ascii=False),
                    model,
                    owner_key_hash,
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
        _dec = self._secrets.decrypt_blob
        _msgs_raw = _dec(row["messages"]) if row["messages"] else b"[]"
        _tools_raw = _dec(row["tool_results"]) if row["tool_results"] else b"[]"
        _msgs_str = _msgs_raw.decode("utf-8") if isinstance(_msgs_raw, bytes) else _msgs_raw
        _tools_str = _tools_raw.decode("utf-8") if isinstance(_tools_raw, bytes) else _tools_raw
        return {
            "session_id": row["session_id"],
            "run_id": row["run_id"],
            "turn_count": row["turn_count"],
            "messages": json.loads(_msgs_str or "[]"),
            "tool_results": json.loads(_tools_str or "[]"),
            "total_tokens": json.loads(row["total_tokens"] or "{}"),
            "cost_estimate": row["cost_estimate"],
            "status": row["status"],
            "error_message": row["error_message"] or "",
            "compression_stats": json.loads(row["compression_stats"] or "{}"),
            "model": row["model"] or "",
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

    def prune(self, keep: int = 1_000) -> int:
        """Remove oldest checkpoints beyond the keep limit."""
        with self._conn() as conn:
            total = conn.execute("SELECT COUNT(*) FROM checkpoints").fetchone()[0]
            if total <= keep:
                return 0
            row = conn.execute(
                "SELECT updated_at FROM checkpoints ORDER BY updated_at DESC LIMIT 1 OFFSET ?",
                (keep,),
            ).fetchone()
            if row is None:
                return 0
            cur = conn.execute(
                "DELETE FROM checkpoints WHERE updated_at < ?",
                (row["updated_at"],),
            )
            conn.commit()
            return cur.rowcount
