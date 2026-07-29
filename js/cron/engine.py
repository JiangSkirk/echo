"""Cron scheduling engine with cron-expression support and SQLite persistence."""
# noqa: N806 (intentional UPPER_CASE constants in local scope)

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


class CronJobAlreadyRunningError(RuntimeError):
    """Raised when one job would overlap its existing execution."""


class JobStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    PAUSED = "paused"
    DISABLED = "disabled"


@dataclass
class JobResult:
    """Result of a single job execution."""

    job_id: str
    run_at: float
    duration_ms: float
    success: bool
    status: JobStatus
    output: str = ""
    error: str = ""
    owner_key_hash: str = "local-user"
    output_truncated: bool = False
    error_truncated: bool = False


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
    owner_key_hash: str = "local-user"
    product_id: str = "js-agent"
    session_id: str = ""
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
    system_scope: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "cron_expr": self.cron_expr,
            "schedule_summary": self.schedule_summary or self._humanize_cron(),
            "task_type": self.task_type,
            "payload": self.payload,
            "owner_key_hash": self.owner_key_hash,
            "product_id": self.product_id,
            "session_id": self.session_id,
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
            "system_scope": self.system_scope,
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
            owner_key_hash=data.get("owner_key_hash", "local-user"),
            product_id=data.get("product_id", "js-agent"),
            session_id=data.get("session_id", ""),
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
            system_scope=data.get("system_scope", False),
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

        # Hard cap: max 100k iterations (~70 days of minute-by-minute scan).
        # Beyond this, the cron expression is effectively impossible.
        _max_iterations = 100_000
        for _ in range(_max_iterations):
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

    # Resource governance constants
    _MAX_JOBS = 100
    _MAX_CONCURRENT_JOBS = 4
    _JOB_TIMEOUT_SECONDS = 300.0
    _MAX_RESULT_TEXT_BYTES = 262_144

    def __init__(self, state_dir: Path) -> None:
        self.state_dir = state_dir
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self._jobs: dict[str, ScheduledJob] = {}
        self._running = False
        self._task: asyncio.Task[Any] | None = None
        self._callbacks: dict[str, Callable[[ScheduledJob], Awaitable[Any]]] = {}
        self._result_callback: Callable[[JobResult], Any] | None = None
        self._history: list[JobResult] = []
        self._max_history = 100
        self._job_semaphore = asyncio.Semaphore(self._MAX_CONCURRENT_JOBS)
        # Track currently-executing job IDs to prevent re-entrant execution
        self._executing_job_ids: set[str] = set()
        self._execution_tasks: set[asyncio.Task[JobResult]] = set()

    @property
    def active_execution_count(self) -> int:
        return len(self._execution_tasks)

    def register_callback(
        self, task_type: str, callback: Callable[[ScheduledJob], Awaitable[Any]]
    ) -> None:
        """Register a handler for a task type."""
        self._callbacks[task_type] = callback
        logger.info(f"Registered cron callback for task_type='{task_type}'")

    def register_result_callback(self, callback: Callable[[JobResult], Any]) -> None:
        self._result_callback = callback

    def add_job(self, job: ScheduledJob) -> None:
        """Add a job to the engine."""
        if len(self._jobs) >= self._MAX_JOBS:
            raise ValueError(
                f"Maximum job count ({self._MAX_JOBS}) reached. "
                "Remove unused jobs before adding new ones."
            )
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
        try:
            current = asyncio.current_task()
        except RuntimeError:
            current = None
        for task in tuple(self._execution_tasks):
            if task is not current:
                task.cancel()
        logger.info("Cron engine stopped")

    async def stop_and_wait(self) -> None:
        """Cancel and reap the scheduler plus every admitted job execution."""
        current = asyncio.current_task()
        tasks: tuple[asyncio.Task[Any], ...] = tuple(
            task
            for task in (
                *((self._task,) if self._task is not None else ()),
                *self._execution_tasks,
            )
            if task is not current
        )
        self.stop()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

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
                # Re-entrancy guard: skip if this job is already executing
                if job.id in self._executing_job_ids:
                    logger.debug("Job '%s' is already executing — skipping tick", job.name)
                    continue
                # Execute the job
                self._schedule_job(job)
                # Recalculate next run
                try:
                    cron = CronExpression(job.cron_expr)
                    job.next_run_at = cron.next_run(now)
                except Exception:
                    job.next_run_at = None

    async def _execute_job(self, job: ScheduledJob) -> JobResult:
        """Execute a single job and record result."""
        # Concurrency guard: at most _MAX_CONCURRENT_JOBS run simultaneously
        async with self._job_semaphore:
            try:
                return await self._do_execute_job(job)
            finally:
                self._executing_job_ids.discard(job.id)

    def _schedule_job(self, job: ScheduledJob) -> asyncio.Task[JobResult]:
        if job.id in self._executing_job_ids:
            raise CronJobAlreadyRunningError("Cron job is already executing")
        self._executing_job_ids.add(job.id)
        try:
            task = asyncio.create_task(self._execute_job(job))
        except BaseException:
            self._executing_job_ids.discard(job.id)
            raise
        self._execution_tasks.add(task)

        def discard(completed: asyncio.Task[JobResult]) -> None:
            self._execution_tasks.discard(completed)
            self._executing_job_ids.discard(job.id)

        task.add_done_callback(discard)
        return task

    async def _do_execute_job(self, job: ScheduledJob) -> JobResult:
        """Internal: execute a single job with timeout enforcement."""
        job.status = JobStatus.RUNNING
        job.last_run_at = time.time()
        job.run_count += 1
        job.updated_at = time.time()

        start = time.perf_counter()
        callback = self._callbacks.get(job.task_type)
        cancellation: asyncio.CancelledError | None = None

        try:
            if callback is None:
                raise RuntimeError(f"No callback registered for task_type='{job.task_type}'")
            callback_output = await asyncio.wait_for(
                callback(job), timeout=self._JOB_TIMEOUT_SECONDS
            )
            duration = (time.perf_counter() - start) * 1000
            output, output_truncated = self._bound_result_text(
                "" if callback_output is None else str(callback_output)
            )
            result = JobResult(
                job_id=job.id,
                run_at=job.last_run_at,
                duration_ms=duration,
                success=True,
                status=JobStatus.COMPLETED,
                output=output,
                owner_key_hash=job.owner_key_hash,
                output_truncated=output_truncated,
            )
            job.status = JobStatus.COMPLETED
            logger.info(f"Job '{job.name}' completed in {duration:.0f}ms")
        except asyncio.CancelledError as exc:
            duration = (time.perf_counter() - start) * 1000
            result = JobResult(
                job_id=job.id,
                run_at=job.last_run_at,
                duration_ms=duration,
                success=False,
                status=JobStatus.CANCELLED,
                error="Job was cancelled",
                owner_key_hash=job.owner_key_hash,
            )
            job.status = JobStatus.CANCELLED
            cancellation = exc
        except TimeoutError:
            duration = (time.perf_counter() - start) * 1000
            result = JobResult(
                job_id=job.id,
                run_at=job.last_run_at,
                duration_ms=duration,
                success=False,
                status=JobStatus.FAILED,
                error=f"Job timed out after {self._JOB_TIMEOUT_SECONDS}s",
                owner_key_hash=job.owner_key_hash,
            )
            job.fail_count += 1
            job.status = JobStatus.FAILED
            logger.error("Job '%s' timed out after %.0fs", job.name, self._JOB_TIMEOUT_SECONDS)
        except Exception as e:
            duration = (time.perf_counter() - start) * 1000
            result = JobResult(
                job_id=job.id,
                run_at=job.last_run_at,
                duration_ms=duration,
                success=False,
                status=JobStatus.FAILED,
                error="Job execution failed safely",
                owner_key_hash=job.owner_key_hash,
            )
            job.fail_count += 1
            job.status = JobStatus.FAILED
            logger.error("Cron job failed: %s", type(e).__name__)

        job.updated_at = time.time()
        self._history.append(result)
        if len(self._history) > self._max_history:
            self._history = self._history[-self._max_history :]
        if self._result_callback is not None:
            try:
                self._result_callback(result)
            except Exception:
                logger.exception("Cron result callback raised; result was still recorded")
        if cancellation is not None:
            raise cancellation
        return result

    @classmethod
    def _bound_result_text(cls, value: str) -> tuple[str, bool]:
        encoded = value.encode("utf-8")
        if len(encoded) <= cls._MAX_RESULT_TEXT_BYTES:
            return value, False
        bounded = encoded[: cls._MAX_RESULT_TEXT_BYTES].decode(
            "utf-8",
            errors="ignore",
        )
        return bounded, True

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
        return await self._schedule_job(job)
