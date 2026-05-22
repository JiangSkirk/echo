"""24/7 background daemon for JS Agent.

Runs the agent as a persistent process with:
- Signal-based graceful shutdown
- Full cron scheduling engine (expressions, templates, natural language)
- SQLite persistence for jobs and execution history
- State recovery after restart
"""

from __future__ import annotations

import asyncio
import json
import signal
import time
from typing import Any

from js.agent import JSAgent
from js.config import JSSettings
from js.cron.engine import CronEngine, JobResult, ScheduledJob
from js.cron.store import JobStore
from js.cron.templates import TEMPLATE_REGISTRY
from js.utils.log import get_logger

logger = get_logger("js.daemon")


# ---------------------------------------------------------------------------
# Backward compatibility: old ScheduledTask API
# ---------------------------------------------------------------------------

class ScheduledTask:
    """Legacy task wrapper for backward compatibility with tests.

    Internally mapped to CronEngine ScheduledJob.
    """

    def __init__(
        self,
        name: str,
        interval_seconds: float,
        callback: Any,
        last_run: float = 0.0,
        run_count: int = 0,
        enabled: bool = True,
        failures: int = 0,
    ) -> None:
        self.name = name
        self.interval_seconds = interval_seconds
        self.callback = callback
        self.last_run = last_run
        self.run_count = run_count
        self.enabled = enabled
        self.failures = failures
        # Map to internal job
        self._job_id: str | None = None


async def _health_check_task(agent: JSAgent) -> None:
    """Periodic health check: log system status."""
    try:
        provider_count = len(agent.settings.providers)
        logger.info(f"Health check: providers={provider_count}")
    except asyncio.CancelledError:
        raise
    except Exception as e:
        logger.warning(f"Health check failed: {e}")


async def _dream_task(agent: JSAgent) -> None:
    """Trigger memory consolidation (dreaming) if idle."""
    try:
        ds = getattr(agent, "_dream_scheduler", None)
        if ds and hasattr(ds, "force_consolidation"):
            await ds.force_consolidation()
            logger.info("Dream consolidation completed")
        else:
            logger.debug("Dream task skipped")
    except asyncio.CancelledError:
        raise
    except Exception as e:
        logger.warning(f"Dream task failed: {e}")


async def _session_cleanup_task(agent: JSAgent) -> None:
    """Clean up old empty sessions to prevent memory bloat."""
    try:
        removed = agent.memory.enhanced.cleanup_empty_sessions()
        if removed > 0:
            logger.info(f"Daemon cleanup: removed {removed} empty sessions")
    except asyncio.CancelledError:
        raise
    except Exception as e:
        logger.warning(f"Session cleanup failed: {e}")


class DaemonHeartbeat:
    """Snapshot of daemon health written to disk periodically."""

    def __init__(
        self,
        timestamp: float,
        uptime_seconds: float,
        tasks_run: int,
        tasks_failed: int,
        provider_count: int,
        memory_sessions: int,
        version: str = "0.1.0",
    ) -> None:
        self.timestamp = timestamp
        self.uptime_seconds = uptime_seconds
        self.tasks_run = tasks_run
        self.tasks_failed = tasks_failed
        self.provider_count = provider_count
        self.memory_sessions = memory_sessions
        self.version = version

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "uptime_seconds": self.uptime_seconds,
            "tasks_run": self.tasks_run,
            "tasks_failed": self.tasks_failed,
            "provider_count": self.provider_count,
            "memory_sessions": self.memory_sessions,
            "version": self.version,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DaemonHeartbeat:
        return cls(
            timestamp=data.get("timestamp", 0.0),
            uptime_seconds=data.get("uptime_seconds", 0.0),
            tasks_run=data.get("tasks_run", 0),
            tasks_failed=data.get("tasks_failed", 0),
            provider_count=data.get("provider_count", 0),
            memory_sessions=data.get("memory_sessions", 0),
            version=data.get("version", "0.1.0"),
        )


class JSDaemon:
    """Persistent daemon that keeps the agent alive and runs scheduled tasks."""

    HEALTH_CHECK_INTERVAL = 60.0
    HEARTBEAT_FILE = "daemon_heartbeat.json"
    STATE_FILE = "daemon_state.json"

    def __init__(self, settings: JSSettings) -> None:
        self.settings = settings
        self.agent = JSAgent(settings)
        self._running = False
        self._shutdown_event = asyncio.Event()
        self._start_time = time.time()
        self._state_dir = settings.state_dir / "daemon"
        self._state_dir.mkdir(parents=True, exist_ok=True)
        self._heartbeat_path = self._state_dir / self.HEARTBEAT_FILE
        self._state_path = self._state_dir / self.STATE_FILE

        # New cron engine with SQLite persistence
        self.cron = CronEngine(self._state_dir)
        self.store = JobStore(self._state_dir / "cron.db")
        self._register_default_callbacks()
        self._load_jobs_from_store()

        # Backward compat: legacy task list
        self._tasks: list[ScheduledTask] = []

    # ------------------------------------------------------------------
    # Backward compatibility API
    # ------------------------------------------------------------------

    def add_task(self, task: ScheduledTask) -> None:
        """Add a legacy ScheduledTask (mapped to cron engine internally)."""
        self._tasks.append(task)
        # Also register in cron engine for actual execution
        job = ScheduledJob(
            name=task.name,
            cron_expr=f"*/{int(task.interval_seconds)} * * * *",
            task_type="custom",
            payload={},
        )
        task._job_id = job.id
        self.cron.add_job(job)

    def _save_state(self) -> None:
        """Persist legacy task state."""
        try:
            state = {
                "saved_at": time.time(),
                "tasks": [
                    {
                        "name": t.name,
                        "last_run": t.last_run,
                        "run_count": t.run_count,
                        "enabled": t.enabled,
                        "failures": t.failures,
                    }
                    for t in self._tasks
                ],
            }
            self._state_path.write_text(json.dumps(state, indent=2), encoding="utf-8")
        except Exception as e:
            logger.debug(f"Failed to save daemon state: {e}")

    def _load_state(self) -> None:
        """Restore legacy task state from previous run."""
        try:
            if not self._state_path.exists():
                return
            data = json.loads(self._state_path.read_text(encoding="utf-8"))
            saved_tasks = {t["name"]: t for t in data.get("tasks", [])}
            for task in self._tasks:
                if task.name in saved_tasks:
                    st = saved_tasks[task.name]
                    task.last_run = st.get("last_run", 0.0)
                    task.run_count = st.get("run_count", 0)
                    task.failures = st.get("failures", 0)
            logger.info("Daemon state restored from previous run")
        except Exception as e:
            logger.debug(f"Failed to load daemon state: {e}")

    async def _tick(self) -> None:
        """Execute one legacy daemon tick."""
        now = time.time()
        for task in self._tasks:
            if not task.enabled:
                continue
            if now - task.last_run >= task.interval_seconds:
                task.last_run = now
                task.run_count += 1
                try:
                    await task.callback(self.agent)
                except Exception as e:
                    task.failures += 1
                    logger.error(f"Scheduled task '{task.name}' failed: {e}", exc_info=True)

    # ------------------------------------------------------------------
    # Cron callback registrations
    # ------------------------------------------------------------------

    def _register_default_callbacks(self) -> None:
        """Register built-in task type handlers."""
        self.cron.register_callback("health_check", self._cb_health_check)
        self.cron.register_callback("cleanup", self._cb_cleanup)
        self.cron.register_callback("dream", self._cb_dream)
        self.cron.register_callback("backup", self._cb_backup)
        self.cron.register_callback("report", self._cb_report)
        self.cron.register_callback("search", self._cb_search)
        self.cron.register_callback("skill_evolve", self._cb_skill_evolve)
        self.cron.register_callback("shell", self._cb_shell)
        self.cron.register_callback("chat", self._cb_chat)
        self.cron.register_callback("custom", self._cb_custom)

    async def _cb_health_check(self, job: ScheduledJob) -> None:
        provider_count = len(self.agent.settings.providers)
        logger.info(f"[cron] Health check: providers={provider_count}")

    async def _cb_cleanup(self, job: ScheduledJob) -> None:
        try:
            removed = self.agent.memory.enhanced.cleanup_empty_sessions()
            if removed > 0:
                logger.info(f"[cron] Cleanup: removed {removed} empty sessions")
        except Exception as e:
            logger.warning(f"[cron] Cleanup failed: {e}")

    async def _cb_dream(self, job: ScheduledJob) -> None:
        try:
            ds = getattr(self.agent, "_dream_scheduler", None)
            if ds and hasattr(ds, "force_consolidation"):
                await ds.force_consolidation()
                logger.info("[cron] Dream consolidation completed")
            else:
                logger.debug("[cron] Dream scheduler not available")
        except Exception as e:
            logger.warning(f"[cron] Dream task failed: {e}")

    async def _cb_backup(self, job: ScheduledJob) -> None:
        target = job.payload.get("target", "memory")
        fmt = job.payload.get("format", "json")
        logger.info(f"[cron] Backup task: target={target}, format={fmt}")

    async def _cb_report(self, job: ScheduledJob) -> None:
        report_type = job.payload.get("report_type", "daily")
        logger.info(f"[cron] Report task: type={report_type}")

    async def _cb_search(self, job: ScheduledJob) -> None:
        queries = job.payload.get("queries", [])
        for q in queries:
            logger.info(f"[cron] Search task: query={q}")

    async def _cb_skill_evolve(self, job: ScheduledJob) -> None:
        logger.info("[cron] Skill evolution task triggered")

    async def _cb_shell(self, job: ScheduledJob) -> None:
        cmd = job.payload.get("command", "")
        logger.info(f"[cron] Shell task: {cmd[:50]}")

    async def _cb_chat(self, job: ScheduledJob) -> None:
        prompt = job.payload.get("prompt", "")
        logger.info(f"[cron] Chat task: {prompt[:50]}")

    async def _cb_custom(self, job: ScheduledJob) -> None:
        logger.info(f"[cron] Custom task: {job.name}")

    # ------------------------------------------------------------------
    # Job persistence
    # ------------------------------------------------------------------

    def _load_jobs_from_store(self) -> None:
        """Restore jobs from SQLite on startup."""
        jobs = self.store.list_jobs()
        for job in jobs:
            self.cron.add_job(job)
            logger.debug(f"Restored job from store: {job.name} ({job.id})")
        if jobs:
            logger.info(f"Restored {len(jobs)} scheduled jobs from database")

    def _persist_job(self, job: ScheduledJob) -> None:
        """Save a job to SQLite."""
        try:
            self.store.save_job(job)
        except Exception as e:
            logger.warning(f"Failed to persist job {job.id}: {e}")

    def _persist_result(self, result: JobResult) -> None:
        """Save execution result to SQLite."""
        try:
            self.store.save_result(result)
        except Exception as e:
            logger.warning(f"Failed to persist result: {e}")

    # ------------------------------------------------------------------
    # Daemon lifecycle
    # ------------------------------------------------------------------

    def add_job(self, job: ScheduledJob) -> None:
        """Add a job to the daemon and persist it."""
        self.cron.add_job(job)
        self._persist_job(job)
        logger.info(f"Daemon added job: {job.name} ({job.cron_expr})")

    def remove_job(self, job_id: str) -> bool:
        """Remove a job by ID."""
        if self.cron.remove_job(job_id):
            self.store.delete_job(job_id)
            return True
        return False

    def get_job(self, job_id: str) -> ScheduledJob | None:
        return self.cron.get_job(job_id)

    def list_jobs(self) -> list[ScheduledJob]:
        return self.cron.list_jobs()

    async def start(self) -> None:
        """Start the daemon and block until shutdown signal."""
        self._running = True
        logger.info("JS Daemon starting...")

        # Start agent background tasks
        self.agent.start_background_tasks()

        # Start cron engine
        self.cron.start()

        # Register signal handlers
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, self._request_shutdown)
            except NotImplementedError:
                pass  # Windows

        # Main loop: write heartbeat, persist job states
        try:
            while self._running:
                self._write_heartbeat()
                self._persist_job_states()
                try:
                    await asyncio.wait_for(
                        self._shutdown_event.wait(),
                        timeout=self.HEALTH_CHECK_INTERVAL,
                    )
                    if self._shutdown_event.is_set():
                        break
                except TimeoutError:
                    pass
        except asyncio.CancelledError:
            logger.info("Daemon cancelled")
        finally:
            await self._shutdown()

    def _request_shutdown(self) -> None:
        logger.info("Shutdown signal received")
        self._running = False
        self._shutdown_event.set()

    async def _shutdown(self) -> None:
        logger.info("Daemon shutting down gracefully...")
        self._running = False
        self.cron.stop()
        self.agent.stop_background_tasks()
        self._persist_job_states()
        self._save_state()  # Backward compat: legacy state file
        try:
            await self.agent.close()
        except Exception as e:
            logger.warning(f"Error during daemon shutdown: {e}")
        logger.info("Daemon stopped")

    def _write_heartbeat(self) -> None:
        try:
            jobs = self.cron.list_jobs()
            # Combine cron jobs + legacy tasks for backward compat
            total_run = sum(j.run_count for j in jobs) + sum(t.run_count for t in self._tasks)
            total_fail = sum(j.fail_count for j in jobs) + sum(t.failures for t in self._tasks)
            hb = DaemonHeartbeat(
                timestamp=time.time(),
                uptime_seconds=time.time() - self._start_time,
                tasks_run=total_run,
                tasks_failed=total_fail,
                provider_count=len(self.agent.settings.providers),
                memory_sessions=0,
            )
            self._heartbeat_path.write_text(
                json.dumps(hb.to_dict(), indent=2), encoding="utf-8"
            )
        except Exception as e:
            logger.debug(f"Failed to write heartbeat: {e}")

    def _persist_job_states(self) -> None:
        """Persist current state of all jobs to SQLite."""
        for job in self.cron.list_jobs():
            self._persist_job(job)


# ---------------------------------------------------------------------------
# Legacy compatibility: build_default_daemon
# ---------------------------------------------------------------------------

def build_default_daemon(settings: JSSettings) -> JSDaemon:
    """Create a daemon with default scheduled tasks from templates."""
    daemon = JSDaemon(settings)

    # Add default maintenance jobs from templates (new cron engine)
    defaults = [
        ("health_check", "health_check"),
        ("dream_consolidation", "dream"),
        ("session_cleanup", "cleanup"),
    ]
    for template_id, task_type in defaults:
        template = TEMPLATE_REGISTRY.get(template_id)
        if template:
            job = ScheduledJob(
                name=template.name,
                description=template.description,
                cron_expr=template.default_cron,
                task_type=task_type,
                payload=template.default_payload,
                schedule_summary=template.default_cron,
            )
            daemon.add_job(job)

    # Backward compat: also add legacy ScheduledTask entries
    daemon._tasks = [
        ScheduledTask(name="health_check", interval_seconds=JSDaemon.HEALTH_CHECK_INTERVAL, callback=_health_check_task),
        ScheduledTask(name="dream_consolidation", interval_seconds=300.0, callback=_dream_task),
        ScheduledTask(name="session_cleanup", interval_seconds=3600.0, callback=_session_cleanup_task),
    ]

    return daemon
