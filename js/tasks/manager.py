"""Long-running task manager — track progress, status, and resume capability."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from js.utils.log import get_logger

logger = get_logger("js.tasks")


@dataclass
class LongTask:
    id: str
    name: str
    type: str
    status: str
    progress: float
    created_at: float
    updated_at: float
    session_id: str | None = None
    result_preview: str = ""
    error: str | None = None
    can_resume: bool = False
    checkpoint_data: dict[str, Any] = field(default_factory=dict)


class TaskManager:
    """Track and persist long-running tasks."""

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
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
        with self._conn() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS tasks (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    type TEXT NOT NULL,
                    status TEXT DEFAULT 'pending',
                    progress REAL DEFAULT 0.0,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    session_id TEXT,
                    result_preview TEXT DEFAULT '',
                    error TEXT,
                    can_resume INTEGER DEFAULT 0,
                    checkpoint_data TEXT DEFAULT '{}',
                    owner_key_hash TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_tasks_status
                ON tasks(status)
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_tasks_session
                ON tasks(session_id)
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_tasks_owner
                ON tasks(owner_key_hash)
                """
            )
            # Migration: add owner_key_hash for existing databases
            try:
                conn.execute("SELECT owner_key_hash FROM tasks LIMIT 1")
            except sqlite3.OperationalError:
                conn.execute("ALTER TABLE tasks ADD COLUMN owner_key_hash TEXT")
            # Legacy unowned rows belong only to the local single-user tenant;
            # authenticated owners must never inherit them implicitly.
            conn.execute(
                "UPDATE tasks SET owner_key_hash = ? WHERE owner_key_hash IS NULL",
                ("local-user",),
            )
            conn.commit()

    def register(
        self,
        name: str,
        type: str,
        session_id: str | None = None,
        can_resume: bool = False,
        owner_key_hash: str | None = None,
    ) -> str:
        """Register a new task and return its ID."""
        task_id = f"task-{uuid.uuid4().hex[:12]}"
        now = time.time()
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO tasks (id, name, type, status, progress, created_at, updated_at, session_id, can_resume, owner_key_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    task_id,
                    name,
                    type,
                    "running",
                    0.0,
                    now,
                    now,
                    session_id,
                    1 if can_resume else 0,
                    owner_key_hash or "local-user",
                ),
            )
            conn.commit()
        logger.debug(f"Task registered: {task_id} ({name})")
        return task_id

    def update_progress(self, task_id: str, progress: float, result_preview: str = "") -> bool:
        """Update task progress (0.0 - 1.0)."""
        now = time.time()
        with self._conn() as conn:
            cur = conn.execute(
                "UPDATE tasks SET progress = ?, result_preview = ?, updated_at = ? WHERE id = ?",
                (progress, result_preview, now, task_id),
            )
            conn.commit()
            return cur.rowcount > 0

    def update_checkpoint(self, task_id: str, checkpoint_data: dict[str, Any]) -> bool:
        """Save checkpoint data for resumption."""
        with self._conn() as conn:
            cur = conn.execute(
                "UPDATE tasks SET checkpoint_data = ? WHERE id = ?",
                (json.dumps(checkpoint_data, ensure_ascii=False), task_id),
            )
            conn.commit()
            return cur.rowcount > 0

    def complete(self, task_id: str, result_preview: str = "") -> bool:
        """Mark task as completed."""
        now = time.time()
        with self._conn() as conn:
            cur = conn.execute(
                "UPDATE tasks SET status = ?, progress = 1.0, result_preview = ?, updated_at = ? WHERE id = ?",
                ("completed", result_preview, now, task_id),
            )
            conn.commit()
            return cur.rowcount > 0

    def fail(self, task_id: str, error: str) -> bool:
        """Mark task as failed."""
        now = time.time()
        with self._conn() as conn:
            cur = conn.execute(
                "UPDATE tasks SET status = ?, error = ?, updated_at = ? WHERE id = ?",
                ("failed", error, now, task_id),
            )
            conn.commit()
            return cur.rowcount > 0

    def pause(self, task_id: str, owner_key_hash: str | None = None) -> bool:
        """Mark task as paused (can be resumed)."""
        now = time.time()
        with self._conn() as conn:
            if owner_key_hash:
                cur = conn.execute(
                    "UPDATE tasks SET status = ?, updated_at = ? "
                    "WHERE id = ? AND owner_key_hash = ?",
                    ("paused", now, task_id, owner_key_hash),
                )
            else:
                cur = conn.execute(
                    "UPDATE tasks SET status = ?, updated_at = ? WHERE id = ?",
                    ("paused", now, task_id),
                )
            conn.commit()
            return cur.rowcount > 0

    def resume(self, task_id: str, owner_key_hash: str | None = None) -> bool:
        """Mark task as running again."""
        now = time.time()
        with self._conn() as conn:
            if owner_key_hash:
                cur = conn.execute(
                    "UPDATE tasks SET status = ?, updated_at = ? "
                    "WHERE id = ? AND owner_key_hash = ?",
                    ("running", now, task_id, owner_key_hash),
                )
            else:
                cur = conn.execute(
                    "UPDATE tasks SET status = ?, updated_at = ? WHERE id = ?",
                    ("running", now, task_id),
                )
            conn.commit()
            return cur.rowcount > 0

    def delete(self, task_id: str, owner_key_hash: str | None = None) -> bool:
        """Remove a task."""
        with self._conn() as conn:
            if owner_key_hash:
                cur = conn.execute(
                    "DELETE FROM tasks WHERE id = ? AND owner_key_hash = ?",
                    (task_id, owner_key_hash),
                )
            else:
                cur = conn.execute("DELETE FROM tasks WHERE id = ?", (task_id,))
            conn.commit()
            return cur.rowcount > 0

    def get(self, task_id: str, owner_key_hash: str | None = None) -> dict[str, Any] | None:
        """Get a single task by ID."""
        with self._conn() as conn:
            if owner_key_hash:
                row = conn.execute(
                    "SELECT * FROM tasks WHERE id = ? AND owner_key_hash = ?",
                    (task_id, owner_key_hash),
                ).fetchone()
            else:
                row = conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
        if row is None:
            return None
        return self._row_to_dict(row)

    def list(
        self,
        status: str | None = None,
        type: str | None = None,
        limit: int = 100,
        owner_key_hash: str | None = None,
    ) -> list[dict[str, Any]]:
        """List tasks, optionally filtered."""
        with self._conn() as conn:
            base_sql = "SELECT * FROM tasks"
            conditions: list[str] = []
            params: list[Any] = []
            if owner_key_hash:
                conditions.append("owner_key_hash = ?")
                params.append(owner_key_hash)
            if status:
                conditions.append("status = ?")
                params.append(status)
            if type:
                conditions.append("type = ?")
                params.append(type)
            if conditions:
                base_sql += " WHERE " + " AND ".join(conditions)
            base_sql += " ORDER BY updated_at DESC LIMIT ?"
            params.append(limit)
            rows = conn.execute(base_sql, params).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get_by_session(self, session_id: str) -> list[dict[str, Any]]:  # type: ignore[valid-type]
        """Get all tasks for a session."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM tasks WHERE session_id = ? ORDER BY updated_at DESC",
                (session_id,),
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def prune(self, keep: int = 500) -> int:
        """Remove oldest completed/failed tasks beyond the keep limit."""
        with self._conn() as conn:
            total = conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0]
            if total <= keep:
                return 0
            row = conn.execute(
                "SELECT updated_at, rowid FROM tasks ORDER BY updated_at DESC, rowid DESC LIMIT 1 OFFSET ?",
                (keep,),
            ).fetchone()
            if row is None:
                return 0
            cutoff_time, cutoff_rowid = row[0], row[1]
            cur = conn.execute(
                "DELETE FROM tasks WHERE updated_at < ? OR (updated_at = ? AND rowid <= ?)",
                (cutoff_time, cutoff_time, cutoff_rowid),
            )
            conn.commit()
            return cur.rowcount

    def _row_to_dict(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "name": row["name"],
            "type": row["type"],
            "status": row["status"],
            "progress": row["progress"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "session_id": row["session_id"],
            "result_preview": row["result_preview"],
            "error": row["error"],
            "can_resume": bool(row["can_resume"]),
            "checkpoint_data": json.loads(row["checkpoint_data"] or "{}"),
            "owner_key_hash": row["owner_key_hash"],
        }
