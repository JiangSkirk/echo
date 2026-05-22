"""SQLite persistence for cron jobs and execution history."""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any

from js.cron.engine import JobResult, JobStatus, ScheduledJob
from js.utils.log import get_logger

logger = get_logger("js.cron.store")


class JobStore:
    """SQLite-backed store for scheduled jobs and execution history."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS cron_jobs (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    cron_expr TEXT NOT NULL,
                    schedule_summary TEXT,
                    task_type TEXT NOT NULL DEFAULT 'custom',
                    payload TEXT DEFAULT '{}',
                    status TEXT DEFAULT 'pending',
                    created_at REAL DEFAULT 0,
                    updated_at REAL DEFAULT 0,
                    last_run_at REAL,
                    next_run_at REAL,
                    run_count INTEGER DEFAULT 0,
                    fail_count INTEGER DEFAULT 0,
                    max_retries INTEGER DEFAULT 0,
                    enabled INTEGER DEFAULT 1,
                    notify_on_success INTEGER DEFAULT 0,
                    notify_on_failure INTEGER DEFAULT 1
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS cron_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    job_id TEXT NOT NULL,
                    run_at REAL NOT NULL,
                    duration_ms REAL DEFAULT 0,
                    success INTEGER DEFAULT 0,
                    output TEXT,
                    error TEXT
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_history_job_id ON cron_history(job_id)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_history_run_at ON cron_history(run_at)"
            )
            conn.commit()

    # ------------------------------------------------------------------
    # Job CRUD
    # ------------------------------------------------------------------

    def save_job(self, job: ScheduledJob) -> None:
        with self._connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO cron_jobs (
                    id, name, description, cron_expr, schedule_summary, task_type,
                    payload, status, created_at, updated_at, last_run_at, next_run_at,
                    run_count, fail_count, max_retries, enabled,
                    notify_on_success, notify_on_failure
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    job.id,
                    job.name,
                    job.description,
                    job.cron_expr,
                    job.schedule_summary,
                    job.task_type,
                    json.dumps(job.payload, ensure_ascii=False),
                    job.status,
                    job.created_at,
                    job.updated_at,
                    job.last_run_at,
                    job.next_run_at,
                    job.run_count,
                    job.fail_count,
                    job.max_retries,
                    1 if job.enabled else 0,
                    1 if job.notify_on_success else 0,
                    1 if job.notify_on_failure else 0,
                ),
            )
            conn.commit()

    def delete_job(self, job_id: str) -> bool:
        with self._connection() as conn:
            cur = conn.execute("DELETE FROM cron_jobs WHERE id = ?", (job_id,))
            conn.commit()
            return cur.rowcount > 0

    def get_job(self, job_id: str) -> ScheduledJob | None:
        with self._connection() as conn:
            row = conn.execute(
                "SELECT * FROM cron_jobs WHERE id = ?", (job_id,)
            ).fetchone()
            if not row:
                return None
            return self._row_to_job(row)

    def list_jobs(self) -> list[ScheduledJob]:
        with self._connection() as conn:
            rows = conn.execute("SELECT * FROM cron_jobs ORDER BY created_at DESC").fetchall()
            return [self._row_to_job(r) for r in rows]

    def _row_to_job(self, row: sqlite3.Row) -> ScheduledJob:
        payload_str = row["payload"] or "{}"
        try:
            payload = json.loads(payload_str)
        except json.JSONDecodeError:
            payload = {}
        return ScheduledJob(
            id=row["id"],
            name=row["name"],
            description=row["description"] or "",
            cron_expr=row["cron_expr"],
            schedule_summary=row["schedule_summary"] or "",
            task_type=row["task_type"],
            payload=payload,
            status=JobStatus(row["status"]),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            last_run_at=row["last_run_at"],
            next_run_at=row["next_run_at"],
            run_count=row["run_count"],
            fail_count=row["fail_count"],
            max_retries=row["max_retries"],
            enabled=bool(row["enabled"]),
            notify_on_success=bool(row["notify_on_success"]),
            notify_on_failure=bool(row["notify_on_failure"]),
        )

    # ------------------------------------------------------------------
    # History
    # ------------------------------------------------------------------

    def save_result(self, result: JobResult) -> None:
        with self._connection() as conn:
            conn.execute(
                """
                INSERT INTO cron_history (job_id, run_at, duration_ms, success, output, error)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    result.job_id,
                    result.run_at,
                    result.duration_ms,
                    1 if result.success else 0,
                    result.output,
                    result.error,
                ),
            )
            conn.commit()

    def get_history(
        self, job_id: str | None = None, limit: int = 50, offset: int = 0
    ) -> list[JobResult]:
        with self._connection() as conn:
            if job_id:
                rows = conn.execute(
                    """
                    SELECT * FROM cron_history
                    WHERE job_id = ?
                    ORDER BY run_at DESC
                    LIMIT ? OFFSET ?
                    """,
                    (job_id, limit, offset),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT * FROM cron_history
                    ORDER BY run_at DESC
                    LIMIT ? OFFSET ?
                    """,
                    (limit, offset),
                ).fetchall()
            return [
                JobResult(
                    job_id=r["job_id"],
                    run_at=r["run_at"],
                    duration_ms=r["duration_ms"],
                    success=bool(r["success"]),
                    output=r["output"] or "",
                    error=r["error"] or "",
                )
                for r in rows
            ]

    def get_stats(self) -> dict[str, Any]:
        """Aggregate statistics for dashboard."""
        with self._connection() as conn:
            total_jobs = conn.execute(
                "SELECT COUNT(*) FROM cron_jobs"
            ).fetchone()[0]
            active_jobs = conn.execute(
                "SELECT COUNT(*) FROM cron_jobs WHERE enabled = 1"
            ).fetchone()[0]
            total_runs = conn.execute(
                "SELECT COUNT(*) FROM cron_history"
            ).fetchone()[0]
            success_runs = conn.execute(
                "SELECT COUNT(*) FROM cron_history WHERE success = 1"
            ).fetchone()[0]
            fail_runs = conn.execute(
                "SELECT COUNT(*) FROM cron_history WHERE success = 0"
            ).fetchone()[0]
            recent_runs = conn.execute(
                """
                SELECT COUNT(*) FROM cron_history
                WHERE run_at > ?
                """,
                (time.time() - 86400,),
            ).fetchone()[0]
        return {
            "total_jobs": total_jobs,
            "active_jobs": active_jobs,
            "total_runs": total_runs,
            "success_runs": success_runs,
            "fail_runs": fail_runs,
            "recent_runs_24h": recent_runs,
            "success_rate": (success_runs / total_runs * 100) if total_runs > 0 else 0.0,
        }
