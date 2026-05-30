"""SQLite-backed persistence for Fleet tasks.

Ensures task history survives process restarts and memory cleanups.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any

from js.orchestration.fleet import AgentRole, Task
from js.utils.log import get_logger

logger = get_logger("js.persistence.tasks")


class TaskStore:
    """Persist and retrieve Fleet tasks."""

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
                CREATE TABLE IF NOT EXISTS fleet_tasks (
                    id TEXT PRIMARY KEY,
                    description TEXT NOT NULL,
                    role_hint TEXT NOT NULL,
                    priority INTEGER DEFAULT 5,
                    deps TEXT DEFAULT '[]',
                    result TEXT,
                    status TEXT DEFAULT 'pending',
                    assigned_to TEXT,
                    group_id TEXT,
                    conversation_log TEXT DEFAULT '[]',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            # Schema migration: add missing columns for older databases
            existing_cols = {
                row[1] for row in conn.execute(
                    "PRAGMA table_info(fleet_tasks)"
                ).fetchall()
            }
            required_cols = {
                "conversation_log": "TEXT DEFAULT '[]'",
                "group_id": "TEXT",
                "assigned_to": "TEXT",
                "deps": "TEXT DEFAULT '[]'",
                "result": "TEXT",
            }
            for col, dtype in required_cols.items():
                if col not in existing_cols:
                    conn.execute(f"ALTER TABLE fleet_tasks ADD COLUMN {col} {dtype}")
                    logger.info(f"Migrated fleet_tasks schema: added column {col}")

            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_fleet_tasks_group
                ON fleet_tasks(group_id)
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_fleet_tasks_status
                ON fleet_tasks(status)
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_fleet_tasks_updated
                ON fleet_tasks(updated_at DESC)
                """
            )
            conn.commit()

    def _task_to_row(self, task: Task) -> dict[str, Any]:
        return {
            "id": task.id,
            "description": task.description,
            "role_hint": task.role_hint.value,
            "priority": task.priority,
            "deps": json.dumps(task.deps),
            "result": task.result or "",
            "status": task.status,
            "assigned_to": task.assigned_to or "",
            "group_id": task.group_id or "",
            "conversation_log": json.dumps(task.conversation_log, ensure_ascii=False),
        }

    def _row_to_task(self, row: sqlite3.Row) -> Task:
        return Task(
            id=row["id"],
            description=row["description"],
            role_hint=AgentRole(row["role_hint"]),
            priority=row["priority"],
            deps=json.loads(row["deps"] or "[]"),
            result=row["result"] or None,
            status=row["status"],
            assigned_to=row["assigned_to"] or None,
            group_id=row["group_id"] or None,
            conversation_log=json.loads(row["conversation_log"] or "[]"),
        )

    def save(self, task: Task) -> None:
        """Upsert a task."""
        row = self._task_to_row(task)
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO fleet_tasks (
                    id, description, role_hint, priority, deps, result,
                    status, assigned_to, group_id, conversation_log, updated_at
                ) VALUES (
                    :id, :description, :role_hint, :priority, :deps, :result,
                    :status, :assigned_to, :group_id, :conversation_log, CURRENT_TIMESTAMP
                )
                ON CONFLICT(id) DO UPDATE SET
                    description=excluded.description,
                    role_hint=excluded.role_hint,
                    priority=excluded.priority,
                    deps=excluded.deps,
                    result=excluded.result,
                    status=excluded.status,
                    assigned_to=excluded.assigned_to,
                    group_id=excluded.group_id,
                    conversation_log=excluded.conversation_log,
                    updated_at=CURRENT_TIMESTAMP
                """,
                row,
            )
            conn.commit()

    def load(self, task_id: str) -> Task | None:
        """Load a single task by ID."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM fleet_tasks WHERE id = ?", (task_id,)
            ).fetchone()
        if row is None:
            return None
        return self._row_to_task(row)

    def list_by_group(self, group_id: str) -> list[Task]:
        """List all tasks in a collaboration group."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM fleet_tasks WHERE group_id = ? ORDER BY created_at",
                (group_id,),
            ).fetchall()
        return [self._row_to_task(r) for r in rows]

    def list_recent(self, limit: int = 200) -> list[Task]:
        """List most recently updated tasks."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM fleet_tasks ORDER BY updated_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [self._row_to_task(r) for r in rows]

    def prune(self, keep: int = 2000) -> int:
        """Remove oldest tasks beyond the keep limit."""
        with self._conn() as conn:
            # Count total
            total = conn.execute(
                "SELECT COUNT(*) FROM fleet_tasks"
            ).fetchone()[0]
            if total <= keep:
                return 0
            # Find threshold updated_at of the keep-th newest task
            row = conn.execute(
                "SELECT updated_at FROM fleet_tasks ORDER BY updated_at DESC LIMIT 1 OFFSET ?",
                (keep,),
            ).fetchone()
            if row is None:
                return 0
            threshold = row["updated_at"]
            cur = conn.execute(
                "DELETE FROM fleet_tasks WHERE updated_at < ?",
                (threshold,),
            )
            conn.commit()
            deleted = cur.rowcount
            logger.info(f"Pruned {deleted} old fleet tasks (kept {keep})")
            return deleted
