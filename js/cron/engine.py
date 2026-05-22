"""Cron scheduling engine with cron-expression support and SQLite persistence."""

from __future__ import annotations

import asyncio
import re
import time
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any

from js.utils.log import get_logger

logger = get_logger("js.cron")


class JobStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PAUSED = "paused"
    DISABLED = "disabled"


@dataclass
class JobResult:
    """Result of a single job execution."""

    job_id: str
    run_at: float
    duration_ms: float
    success: bool
    output: str = ""
    error: str = ""


@dataclass
class ScheduledJob:
    """A scheduled job definition."""

    id: str = field(default_factory=lambda: f"job_{uuid.uuid4().hex[:12]}")
    name: str = ""
    description: str = ""
    # Cron expression (standard 5-field: min hour day month dow)
    # OR natural language shortcut: "@hourly", "@daily", "@weekly"
    cron_expr: str = ""
    # Human-readable schedule description (auto-generated or user-provided)
    schedule_summary: str = ""
    # Task type determines what callback is invoked
    task_type: str = "custom"  # custom, health_check, backup, report, dream, cleanup, search, skill_evolve
    # JSON payload for the task
    payload: dict[str, Any] = field(default_factory=dict)
    # Runtime state
    status: JobStatus = JobStatus.PENDING
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    last_run_at: float | None = None
    next_run_at: float | None = None
    run_count: int = 0
    fail_count: int = 0
    max_retries: int = 0
    enabled: bool = True
    # Notification settings
    notify_on_success: bool = False
    notify_on_failure: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "cron_expr": self.cron_expr,
            "schedule_summary": self.schedule_summary or self._humanize_cron(),
            "task_type": self.task_type,
            "payload": self.payload,
            "status": self.status,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "last_run_at": self.last_run_at,
            "next_run_at": self.next_run_at,
            "run_count": self.run_count,
            "fail_count": self.fail_count,
            "max_retries": self.max_retries,
            "enabled": self.enabled,
            "notify_on_success": self.notify_on_success,
            "notify_on_failure": self.notify_on_failure,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ScheduledJob:
        return cls(
            id=data.get("id", ""),
            name=data.get("name", ""),
            description=data.get("description", ""),
            cron_expr=data.get("cron_expr", ""),
            schedule_summary=data.get("schedule_summary", ""),
            task_type=data.get("task_type", "custom"),
            payload=data.get("payload", {}),
            status=JobStatus(data.get("status", "pending")),
            created_at=data.get("created_at", 0.0),
            updated_at=data.get("updated_at", 0.0),
            last_run_at=data.get("last_run_at"),
            next_run_at=data.get("next_run_at"),
            run_count=data.get("run_count", 0),
            fail_count=data.get("fail_count", 0),
            max_retries=data.get("max_retries", 0),
            enabled=data.get("enabled", True),
            notify_on_success=data.get("notify_on_success", False),
            notify_on_failure=data.get("notify_on_failure", True),
        )

    def _humanize_cron(self) -> str:
        """Generate a human-readable description of the cron expression."""
        expr = self.cron_expr.strip()
        shortcuts = {
            "@yearly": "每年一次",
            "@monthly": "每月一次",
            "@weekly": "每周一次",
            "@daily": "每天一次",
            "@hourly": "每小时一次",
            "@reboot": "启动时",
        }
        if expr in shortcuts:
            return shortcuts[expr]
        # Basic patterns
        if expr == "0 8 * * *":
            return "每天上午 8:00"
        if expr == "0 9 * * 1":
            return "每周一上午 9:00"
        if expr == "0 0 * * *":
            return "每天午夜"
        if expr == "0 */6 * * *":
            return "每 6 小时"
        if re.match(r"^0 \d+ \* \* \*$", expr):
            hour = expr.split()[1]
            return f"每天 {hour}:00"
        if re.match(r"^\* \* \* \* \*$", expr):
            return "每分钟"
        return f"Cron: {expr}"


class CronExpression:
    """Parse and evaluate standard cron expressions (5 fields)."""

    FIELD_NAMES = ["minute", "hour", "day_of_month", "month", "day_of_week"]
    RANGES = {
        "minute": (0, 59),
        "hour": (0, 23),
        "day_of_month": (1, 31),
        "month": (1, 12),
        "day_of_week": (0, 6),  # 0=Sunday
    }

    def __init__(self, expr: str) -> None:
        self.raw = expr.strip()
        self.fields: dict[str, set[int]] = {}
        self._parse()

    def _parse(self) -> None:
        """Parse cron expression into field sets."""
        # Handle shortcuts
        shortcuts = {
            "@yearly": "0 0 1 1 *",
            "@monthly": "0 0 1 * *",
            "@weekly": "0 0 * * 0",
            "@daily": "0 0 * * *",
            "@hourly": "0 * * * *",
        }
        expr = shortcuts.get(self.raw, self.raw)

        parts = expr.split()
        if len(parts) != 5:
            raise ValueError(f"Invalid cron expression: {self.raw} (expected 5 fields)")

        for name, part in zip(self.FIELD_NAMES, parts, strict=True):
            self.fields[name] = self._parse_field(part, *self.RANGES[name])

    def _parse_field(self, part: str, min_val: int, max_val: int) -> set[int]:
        """Parse a single cron field."""
        result: set[int] = set()
        if part == "*":
            return set(range(min_val, max_val + 1))
        if part == "?":
            return set(range(min_val, max_val + 1))

        for segment in part.split(","):
            segment = segment.strip()
            # Step: */5 or 1-10/2
            if "/" in segment:
                base, step_str = segment.split("/", 1)
                step = int(step_str)
                if base == "*":
                    start, end = min_val, max_val
                elif "-" in base:
                    start, end = map(int, base.split("-"))
                else:
                    start = int(base)
                    end = max_val
                result.update(range(start, end + 1, step))
            # Range: 1-5
            elif "-" in segment:
                start, end = map(int, segment.split("-"))
                result.update(range(start, end + 1))
            # Single value
            else:
                result.add(int(segment))
        return result

    def next_run(self, after: float | None = None) -> float | None:
        """Calculate the next run timestamp after the given time."""
        if after is None:
            after = time.time()

        # Start checking from the next minute boundary
        dt = datetime.fromtimestamp(after) + timedelta(minutes=1)
        dt = dt.replace(second=0, microsecond=0)

        # Search up to 4 years ahead
        limit = dt + timedelta(days=366 * 4)
        while dt < limit:
            if self._matches(dt):
                return dt.timestamp()
            dt += timedelta(minutes=1)
        return None

    def _matches(self, dt: datetime) -> bool:
        """Check if a datetime matches this cron expression."""
        return (
            dt.minute in self.fields["minute"]
            and dt.hour in self.fields["hour"]
            and dt.day in self.fields["day_of_month"]
            and dt.month in self.fields["month"]
            and dt.weekday() in self.fields["day_of_week"]
        )


class CronEngine:
    """Main cron scheduling engine."""

    TICK_INTERVAL = 30.0  # Check every 30 seconds

    def __init__(self, state_dir: Path) -> None:
        self.state_dir = state_dir
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self._jobs: dict[str, ScheduledJob] = {}
        self._running = False
        self._task: asyncio.Task[Any] | None = None
        self._callbacks: dict[str, Callable[[ScheduledJob], Awaitable[Any]]] = {}
        self._history: list[JobResult] = []
        self._max_history = 100

    def register_callback(
        self, task_type: str, callback: Callable[[ScheduledJob], Awaitable[Any]]
    ) -> None:
        """Register a handler for a task type."""
        self._callbacks[task_type] = callback
        logger.info(f"Registered cron callback for task_type='{task_type}'")

    def add_job(self, job: ScheduledJob) -> None:
        """Add a job to the engine."""
        if not job.id:
            job.id = f"job_{uuid.uuid4().hex[:12]}"
        # Pre-calculate next run
        try:
            cron = CronExpression(job.cron_expr)
            job.next_run_at = cron.next_run()
        except Exception as e:
            logger.warning(f"Failed to parse cron for job '{job.name}': {e}")
            job.next_run_at = None
        self._jobs[job.id] = job
        logger.info(f"Added job '{job.name}' (id={job.id}, next_run={job.next_run_at})")

    def remove_job(self, job_id: str) -> bool:
        """Remove a job by ID."""
        if job_id in self._jobs:
            del self._jobs[job_id]
            return True
        return False

    def get_job(self, job_id: str) -> ScheduledJob | None:
        return self._jobs.get(job_id)

    def list_jobs(self) -> list[ScheduledJob]:
        return list(self._jobs.values())

    def start(self) -> None:
        """Start the cron engine in the background."""
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._loop())
        logger.info("Cron engine started")

    def stop(self) -> None:
        """Stop the cron engine."""
        self._running = False
        if self._task:
            self._task.cancel()
            self._task = None
        logger.info("Cron engine stopped")

    async def _loop(self) -> None:
        """Main cron loop."""
        while self._running:
            try:
                await self._tick()
            except Exception as e:
                logger.error(f"Cron tick error: {e}", exc_info=True)
            try:
                await asyncio.wait_for(self._wait_for_stop(), timeout=self.TICK_INTERVAL)
            except TimeoutError:
                pass
            except asyncio.CancelledError:
                break

    async def _wait_for_stop(self) -> None:
        """Wait until stopped (never completes unless cancelled)."""
        while self._running:
            await asyncio.sleep(1)

    async def _tick(self) -> None:
        """Check and execute due jobs."""
        now = time.time()
        for job in list(self._jobs.values()):
            if not job.enabled or job.status == JobStatus.DISABLED:
                continue
            if job.next_run_at is None:
                continue
            if now >= job.next_run_at:
                # Execute the job
                asyncio.create_task(self._execute_job(job))
                # Recalculate next run
                try:
                    cron = CronExpression(job.cron_expr)
                    job.next_run_at = cron.next_run(now)
                except Exception:
                    job.next_run_at = None

    async def _execute_job(self, job: ScheduledJob) -> None:
        """Execute a single job and record result."""
        job.status = JobStatus.RUNNING
        job.last_run_at = time.time()
        job.run_count += 1
        job.updated_at = time.time()

        start = time.perf_counter()
        callback = self._callbacks.get(job.task_type)

        try:
            if callback is None:
                raise RuntimeError(f"No callback registered for task_type='{job.task_type}'")
            await callback(job)
            duration = (time.perf_counter() - start) * 1000
            result = JobResult(
                job_id=job.id,
                run_at=job.last_run_at,
                duration_ms=duration,
                success=True,
            )
            job.status = JobStatus.COMPLETED
            logger.info(f"Job '{job.name}' completed in {duration:.0f}ms")
        except Exception as e:
            duration = (time.perf_counter() - start) * 1000
            result = JobResult(
                job_id=job.id,
                run_at=job.last_run_at,
                duration_ms=duration,
                success=False,
                error=str(e),
            )
            job.fail_count += 1
            job.status = JobStatus.FAILED
            logger.error(f"Job '{job.name}' failed: {e}")

        self._history.append(result)
        if len(self._history) > self._max_history:
            self._history = self._history[-self._max_history :]

    def get_history(self, job_id: str | None = None, limit: int = 50) -> list[JobResult]:
        """Get execution history, optionally filtered by job_id."""
        results = self._history
        if job_id:
            results = [r for r in results if r.job_id == job_id]
        return results[-limit:]

    async def run_job_now(self, job_id: str) -> JobResult:
        """Manually trigger a job immediately."""
        job = self._jobs.get(job_id)
        if not job:
            raise ValueError(f"Job not found: {job_id}")
        await self._execute_job(job)
        return self._history[-1]
