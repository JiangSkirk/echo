"""SQLite persistence for cron jobs and execution history."""

from __future__ import annotations

import contextlib
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

    _MAX_HISTORY_PER_OWNER = 1_000
    _MAX_HISTORY_TOTAL = 10_000

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    @contextlib.contextmanager
    def _connection(self) -> Any:
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

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
                    owner_key_hash TEXT NOT NULL DEFAULT 'local-user',
                    product_id TEXT NOT NULL DEFAULT 'js-agent',
                    session_id TEXT NOT NULL DEFAULT '',
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
                    status TEXT NOT NULL DEFAULT 'completed',
                    output TEXT,
                    error TEXT,
                    output_truncated INTEGER NOT NULL DEFAULT 0,
                    error_truncated INTEGER NOT NULL DEFAULT 0,
                    owner_key_hash TEXT NOT NULL DEFAULT 'local-user'
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_history_job_id ON cron_history(job_id)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_history_run_at ON cron_history(run_at)"
            )
            job_columns = {row[1] for row in conn.execute("PRAGMA table_info(cron_jobs)")}
            for name, declaration in (
                ("owner_key_hash", "TEXT NOT NULL DEFAULT 'local-user'"),
                ("product_id", "TEXT NOT NULL DEFAULT 'js-agent'"),
                ("session_id", "TEXT NOT NULL DEFAULT ''"),
            ):
                if name not in job_columns:
                    conn.execute(f"ALTER TABLE cron_jobs ADD COLUMN {name} {declaration}")
            history_columns = {
                row[1] for row in conn.execute("PRAGMA table_info(cron_history)")
            }
            if "owner_key_hash" not in history_columns:
                conn.execute(
                    "ALTER TABLE cron_history ADD COLUMN "
                    "owner_key_hash TEXT NOT NULL DEFAULT 'local-user'"
                )
            if "status" not in history_columns:
                conn.execute(
                    "ALTER TABLE cron_history ADD COLUMN "
                    "status TEXT NOT NULL DEFAULT 'completed'"
                )
                conn.execute(
                    """
                    UPDATE cron_history
                    SET status = CASE
                        WHEN success = 1 THEN 'completed'
                        ELSE 'failed'
                    END
                    """
                )
            for name in ("output_truncated", "error_truncated"):
                if name not in history_columns:
                    conn.execute(
                        f"ALTER TABLE cron_history ADD COLUMN {name} "
                        "INTEGER NOT NULL DEFAULT 0"
                    )
            conn.commit()

    # ------------------------------------------------------------------
    # Job CRUD
    # ------------------------------------------------------------------

    @staticmethod
    def _write_job(conn: sqlite3.Connection, job: ScheduledJob) -> None:
        conn.execute(
            """
            INSERT OR REPLACE INTO cron_jobs (
                id, name, description, cron_expr, schedule_summary, task_type,
                payload, owner_key_hash, product_id, session_id,
                status, created_at, updated_at, last_run_at, next_run_at,
                run_count, fail_count, max_retries, enabled,
                notify_on_success, notify_on_failure
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                job.id,
                job.name,
                job.description,
                job.cron_expr,
                job.schedule_summary,
                job.task_type,
                json.dumps(job.payload, ensure_ascii=False),
                job.owner_key_hash,
                job.product_id,
                job.session_id,
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

    def save_job(self, job: ScheduledJob) -> None:
        with self._connection() as conn:
            self._write_job(conn, job)
            conn.commit()

    def delete_job(self, job_id: str, owner_key_hash: str | None = None) -> bool:
        with self._connection() as conn:
            if owner_key_hash is None:
                cur = conn.execute("DELETE FROM cron_jobs WHERE id = ?", (job_id,))
            else:
                cur = conn.execute(
                    "DELETE FROM cron_jobs WHERE id = ? AND owner_key_hash = ?",
                    (job_id, owner_key_hash),
                )
            conn.commit()
            return bool(cur.rowcount > 0)

    def get_job(self, job_id: str, owner_key_hash: str | None = None) -> ScheduledJob | None:
        with self._connection() as conn:
            if owner_key_hash is None:
                row = conn.execute(
                    "SELECT * FROM cron_jobs WHERE id = ?", (job_id,)
                ).fetchone()
            else:
                row = conn.execute(
                    "SELECT * FROM cron_jobs WHERE id = ? AND owner_key_hash = ?",
                    (job_id, owner_key_hash),
                ).fetchone()
            if not row:
                return None
            return self._row_to_job(row)

    def list_jobs(self, owner_key_hash: str | None = None) -> list[ScheduledJob]:
        with self._connection() as conn:
            if owner_key_hash is None:
                rows = conn.execute(
                    "SELECT * FROM cron_jobs ORDER BY created_at DESC"
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM cron_jobs WHERE owner_key_hash = ? ORDER BY created_at DESC",
                    (owner_key_hash,),
                ).fetchall()
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
            owner_key_hash=row["owner_key_hash"],
            product_id=row["product_id"],
            session_id=row["session_id"],
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

    @staticmethod
    def _write_result(conn: sqlite3.Connection, result: JobResult) -> None:
        conn.execute(
            """
            INSERT INTO cron_history (
                job_id, run_at, duration_ms, success, status, output, error,
                output_truncated, error_truncated, owner_key_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                result.job_id,
                result.run_at,
                result.duration_ms,
                1 if result.success else 0,
                result.status,
                result.output,
                result.error,
                1 if result.output_truncated else 0,
                1 if result.error_truncated else 0,
                result.owner_key_hash,
            ),
        )

    def _prune_history(self, conn: sqlite3.Connection) -> None:
        conn.execute(
            """
            DELETE FROM cron_history
            WHERE id IN (
                SELECT id
                FROM (
                    SELECT
                        id,
                        ROW_NUMBER() OVER (
                            PARTITION BY owner_key_hash
                            ORDER BY run_at DESC, id DESC
                        ) AS owner_rank
                    FROM cron_history
                )
                WHERE owner_rank > ?
            )
            """,
            (self._MAX_HISTORY_PER_OWNER,),
        )
        conn.execute(
            """
            DELETE FROM cron_history
            WHERE id IN (
                SELECT id
                FROM cron_history
                ORDER BY run_at DESC, id DESC
                LIMIT -1 OFFSET ?
            )
            """,
            (self._MAX_HISTORY_TOTAL,),
        )

    def save_result(self, result: JobResult) -> None:
        with self._connection() as conn:
            self._write_result(conn, result)
            self._prune_history(conn)
            conn.commit()

    def save_result_and_job(
        self,
        result: JobResult,
        job: ScheduledJob,
    ) -> None:
        """Persist one execution terminal and its job state atomically."""
        if result.job_id != job.id or result.owner_key_hash != job.owner_key_hash:
            raise ValueError("cron result does not match its owning job")
        with self._connection() as conn:
            self._write_result(conn, result)
            self._write_job(conn, job)
            self._prune_history(conn)
            conn.commit()

    def get_history(
        self,
        job_id: str | None = None,
        limit: int = 50,
        offset: int = 0,
        owner_key_hash: str | None = None,
    ) -> list[JobResult]:
        with self._connection() as conn:
            if job_id and owner_key_hash is not None:
                rows = conn.execute(
                    """
                    SELECT * FROM cron_history
                    WHERE job_id = ? AND owner_key_hash = ?
                    ORDER BY run_at DESC
                    LIMIT ? OFFSET ?
                    """,
                    (job_id, owner_key_hash, limit, offset),
                ).fetchall()
            elif job_id:
                rows = conn.execute(
                    """
                    SELECT * FROM cron_history
                    WHERE job_id = ?
                    ORDER BY run_at DESC
                    LIMIT ? OFFSET ?
                    """,
                    (job_id, limit, offset),
                ).fetchall()
            elif owner_key_hash is not None:
                rows = conn.execute(
                    """
                    SELECT * FROM cron_history
                    WHERE owner_key_hash = ?
                    ORDER BY run_at DESC
                    LIMIT ? OFFSET ?
                    """,
                    (owner_key_hash, limit, offset),
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
                    status=JobStatus(r["status"]),
                    output=r["output"] or "",
                    error=r["error"] or "",
                    owner_key_hash=r["owner_key_hash"],
                    output_truncated=bool(r["output_truncated"]),
                    error_truncated=bool(r["error_truncated"]),
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
                "SELECT COUNT(*) FROM cron_history WHERE status = 'failed'"
            ).fetchone()[0]
            cancelled_runs = conn.execute(
                "SELECT COUNT(*) FROM cron_history WHERE status = 'cancelled'"
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
            "failed_runs": fail_runs,
            "cancelled_runs": cancelled_runs,
            "recent_runs_24h": recent_runs,
            "success_rate": (success_runs / total_runs * 100) if total_runs > 0 else 0.0,
        }
