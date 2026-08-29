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
import os
import re
import signal
import tempfile
import time
import uuid
from typing import Any

from js import __version__
from js.agent import JSAgent
from js.config import JSSettings
from js.cron.engine import CronEngine, JobResult, ScheduledJob
from js.cron.store import JobStore
from js.cron.templates import TEMPLATE_REGISTRY
from js.echo.effect_interpreter import ToolEffect
from js.echo.turn_runtime import run_echo_turn
from js.utils.log import get_logger

logger = get_logger("js.daemon")

# Fields that may be changed via JSDaemon.update_job.  Anything else
# (owner_key_hash, task_type, system_scope, id, counters, timestamps, ...)
# is security- or bookkeeping-sensitive and must never be mutated through
# the generic update path.
UPDATABLE_FIELDS: frozenset[str] = frozenset(
    {
        "name",
        "description",
        "cron_expr",
        "schedule_summary",
        "payload",
        "enabled",
        "notify_on_success",
        "notify_on_failure",
        "max_retries",
    }
)

# Commands matching these patterns are never executed by cron shell jobs,
# even for admin-approved (system_scope) jobs: they can persist code
# execution outside the sandbox (e.g. `git config alias.x '!evil'` or
# `git config core.hooksPath ...`).
_CRON_SHELL_BLOCKED_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"\bgit\s+(-c\s+\S+\s+)*config\b", re.IGNORECASE),
        "git config mutations can persist code execution (aliases/hooks)",
    ),
)


class DaemonHeartbeat:
    """Snapshot of daemon health written to disk periodically.

    This is a non-authoritative derived snapshot; daemon start/stop/degraded
    state transitions are recorded in the EchoLedger.  The JSON file exists
    only for cheap status polling by /api/status.
    """

    SCHEMA = "js.daemon.heartbeat.v1"

    def __init__(
        self,
        timestamp: float,
        uptime_seconds: float,
        tasks_run: int,
        tasks_failed: int,
        provider_count: int,
        memory_sessions: int,
        version: str = __version__,
        *,
        schema: str = SCHEMA,
        instance_id: str = "",
        sequence: int = 0,
        authoritative: bool = False,
    ) -> None:
        self.timestamp = timestamp
        self.uptime_seconds = uptime_seconds
        self.tasks_run = tasks_run
        self.tasks_failed = tasks_failed
        self.provider_count = provider_count
        self.memory_sessions = memory_sessions
        self.version = version
        self.schema = schema
        self.instance_id = instance_id
        self.sequence = sequence
        self.authoritative = authoritative

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "instance_id": self.instance_id,
            "sequence": self.sequence,
            "timestamp": self.timestamp,
            "uptime_seconds": self.uptime_seconds,
            "tasks_run": self.tasks_run,
            "tasks_failed": self.tasks_failed,
            "provider_count": self.provider_count,
            "memory_sessions": self.memory_sessions,
            "version": self.version,
            "authoritative": self.authoritative,
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
            version=data.get("version", __version__),
            schema=data.get("schema", cls.SCHEMA),
            instance_id=data.get("instance_id", ""),
            sequence=data.get("sequence", 0),
            authoritative=data.get("authoritative", False),
        )


class JSDaemon:
    """Persistent daemon that keeps the agent alive and runs scheduled tasks."""

    HEALTH_CHECK_INTERVAL = 60.0
    HEARTBEAT_FILE = "daemon_heartbeat.json"

    def __init__(self, settings: JSSettings, *, agent: Any = None) -> None:
        self.settings = settings
        self.agent = agent if agent is not None else JSAgent(settings)
        self._running = False
        self._shutdown_event = asyncio.Event()
        self._start_time = time.time()
        self._state_dir = settings.state_dir / "daemon"
        self._state_dir.mkdir(parents=True, exist_ok=True)
        self._heartbeat_path = self._state_dir / self.HEARTBEAT_FILE
        self._instance_id = uuid.uuid4().hex
        self._heartbeat_seq = 0

        # The cron engine is the sole scheduler and persisted job state owner.
        self.cron = CronEngine(self._state_dir)
        self.store = JobStore(self._state_dir / "cron.db")
        self.cron.register_result_callback(self._persist_result)
        self._register_default_callbacks()
        self._load_jobs_from_store()
        # Set when the authoritative EchoLedger daemon log becomes
        # unavailable; health checks must report degraded, never healthy.
        self._ledger_degraded = False

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
        self.cron.register_callback("gateway_push", self._cb_gateway_push)

    async def _cb_health_check(self, job: ScheduledJob) -> None:
        provider_count = len(self.agent.settings.providers)
        logger.info(f"[cron] Health check: providers={provider_count}")

    async def _cb_cleanup(self, job: ScheduledJob) -> None:
        owner = job.owner_key_hash
        if not owner or owner == "local-user":
            logger.warning("[cron] cleanup rejected: job has no explicit owner scope")
            return
        try:
            removed = self.agent.memory.enhanced.cleanup_empty_sessions(owner_key_hash=owner)
            if removed > 0:
                logger.info(f"[cron] Cleanup: removed {removed} empty sessions for owner={owner}")
        except Exception as e:
            logger.warning(f"[cron] Cleanup failed: {e}")
            raise

    async def _cb_dream(self, job: ScheduledJob) -> None:
        owner = job.owner_key_hash
        if not owner or owner == "local-user":
            logger.warning("[cron] dream rejected: job has no explicit owner scope")
            return
        from js.orin.stage_c import product_memory_cell_required

        orin = getattr(getattr(self.agent, "settings", None), "orin", None)
        if product_memory_cell_required(orin):
            logger.warning("[cron] dream refused: ambient MemoryStore is closed under enforce")
            return
        try:
            ds = getattr(self.agent, "_dream_scheduler", None)
            if ds and hasattr(ds, "force_consolidation"):
                await ds.force_consolidation(owner_key_hash=owner)
                logger.info(f"[cron] Dream consolidation completed for owner={owner}")
            else:
                logger.debug("[cron] Dream scheduler not available")
        except Exception as e:
            logger.warning(f"[cron] Dream task failed: {e}")
            raise

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
        from js.evolution.cycle import EvolutionCycle

        owner = job.owner_key_hash
        if not owner:
            logger.warning("[cron] skill_evolve rejected: job has no explicit owner scope")
            return
        cycle = EvolutionCycle(self.agent.settings.state_dir)
        created = cycle.generate(owner, learner=getattr(self.agent, "learner", None))
        logger.info("[cron] Skill evolution generated %s proposal(s)", len(created))

    async def _cb_shell(self, job: ScheduledJob) -> str:
        cmd = job.payload.get("command", "")
        logger.info(f"[cron] Shell task: {cmd[:50]}")
        if not cmd:
            raise ValueError("cron shell task requires a command")
        # Fail-closed: arbitrary shell execution is admin-only.  Only jobs
        # created with system_scope=True (admin-approved at creation time;
        # not settable via update_job) may run shell commands.
        if not job.system_scope:
            logger.warning(
                "[cron] shell job %s rejected: not admin-approved (system_scope)",
                job.id,
            )
            raise PermissionError("cron shell jobs require admin approval (system_scope)")
        for pattern, reason in _CRON_SHELL_BLOCKED_PATTERNS:
            if pattern.search(cmd):
                logger.warning(
                    "[cron] shell job %s rejected: %s",
                    job.id,
                    reason,
                )
                raise ValueError(f"cron shell command blocked by policy: {reason}")
        runtime = self.agent.echo_runtime
        context = runtime.build_context(
            channel="cron_shell",
            owner_key_hash=job.owner_key_hash,
            session_id=job.session_id or f"cron:{job.id}",
            capabilities=("shell",),
        )
        _message, result = await runtime.execute_tool_effect(
            ToolEffect.from_arguments(
                "shell",
                {"command": cmd},
                allowed_tools=("shell",),
                user_input=f"scheduled shell job {job.id}",
            ),
            context,
        )
        if not result.success:
            raise RuntimeError(result.error or "scheduled shell command failed")
        return result.output

    async def _cb_chat(self, job: ScheduledJob) -> str:
        prompt = job.payload.get("prompt", "")
        logger.info(f"[cron] Chat task: {prompt[:50]}")
        if not prompt:
            raise ValueError("cron chat task requires a prompt")
        state = await run_echo_turn(
            self.agent,
            prompt,
            channel="cron_chat",
            owner_key_hash=job.owner_key_hash,
            session_id=job.session_id or f"cron:{job.id}",
            disable_tools=not bool(job.payload.get("allow_tools", False)),
        )
        if state.status != "completed":
            raise RuntimeError(state.error_message or f"Echo cron turn ended as {state.status}")
        for message in reversed(state.messages):
            if message.role == "assistant" and isinstance(message.content, str) and message.content:
                return message.content
        raise RuntimeError("Echo cron turn completed without an assistant response")

    async def _cb_gateway_push(self, job: ScheduledJob) -> str:
        from js.agent.tool_executor import CONTROL_GATEWAY_PUSH_TOOL
        from js.gateway.attach import attach_gateway_service
        from js.gateway.push import push_peer_from_payload, render_push_template

        template_id = str(job.payload.get("template") or "")
        render_push_template(template_id)
        peer = push_peer_from_payload(job.payload)
        owner = job.owner_key_hash
        if not owner:
            raise ValueError("gateway push rejected: job has no explicit owner scope")
        attach_gateway_service(self.agent)
        runtime = self.agent.echo_runtime
        context = runtime.build_context(
            channel="cron_gateway_push",
            owner_key_hash=owner,
            session_id=job.session_id or f"cron:{job.id}",
            role="system",
            capabilities=(CONTROL_GATEWAY_PUSH_TOOL,),
        )
        _message, result = await runtime.execute_tool_effect(
            ToolEffect.from_arguments(
                CONTROL_GATEWAY_PUSH_TOOL,
                {
                    "template_id": template_id,
                    "channel": peer.channel,
                    "peer_id": peer.peer_id,
                },
                user_input=f"scheduled gateway push {job.id}",
                allowed_tools=(CONTROL_GATEWAY_PUSH_TOOL,),
            ),
            context,
        )
        if not result.success:
            raise RuntimeError(result.error or "gateway push failed")
        return str(result.output or "sent")

    async def _cb_custom(self, job: ScheduledJob) -> str:
        logger.info(f"[cron] Custom task: {job.name}")
        prompt = str(job.payload.get("prompt", "")).strip()
        if not prompt:
            raise ValueError("custom cron tasks require an Echo prompt")
        return await self._cb_chat(job)

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
        """Save a job to SQLite; raise so callers know persistence failed."""
        self.store.save_job(job)

    def _persist_result(self, result: JobResult) -> None:
        """Atomically save execution history and its job terminal state; raise on failure."""
        job = self.cron.get_job(result.job_id)
        if job is None:
            raise RuntimeError("cron result references an unknown job")
        self.store.save_result_and_job(result, job)

    # ------------------------------------------------------------------
    # Daemon lifecycle
    # ------------------------------------------------------------------

    def add_job(self, job: ScheduledJob) -> None:
        """Add a job to the daemon and persist it.

        Persist first so a disk failure leaves the in-memory cron store
        unchanged (fail-closed).  If the cron in-memory add fails after the
        job is persisted, the persisted job is removed to avoid an orphan.
        """
        self._persist_job(job)
        try:
            self.cron.add_job(job)
        except Exception:
            # Roll back the persisted job so we don't leave an orphan record.
            try:
                self.store.delete_job(job.id, owner_key_hash=job.owner_key_hash)
            except Exception:
                logger.warning(
                    "Failed to roll back persisted job %s after cron add failure",
                    job.id,
                    exc_info=True,
                )
            raise
        logger.info(f"Daemon added job: {job.name} ({job.cron_expr})")

    def remove_job(self, job_id: str, owner_key_hash: str | None = None) -> bool:
        """Remove a job by ID (store-first).

        The SQLite delete commits BEFORE the in-memory removal, so a store
        failure leaves memory and disk consistent (the job stays scheduled,
        matching what a restart would restore).  If the in-memory removal
        fails after a successful delete, the persisted record is restored.
        """
        job = self.cron.get_job(job_id)
        if job is None or (owner_key_hash is not None and job.owner_key_hash != owner_key_hash):
            return False
        self.store.delete_job(job_id, owner_key_hash=owner_key_hash)
        try:
            removed = self.cron.remove_job(job_id)
        except Exception:
            # Roll back the store delete so disk matches memory again.
            try:
                self.store.save_job(job)
            except Exception:
                logger.error(
                    "Failed to roll back store delete for job %s; manual review required",
                    job_id,
                    exc_info=True,
                )
            raise
        if not removed:
            # In-memory job was already gone; restore the store record.
            try:
                self.store.save_job(job)
            except Exception:
                logger.error(
                    "Failed to restore store record for job %s; manual review required",
                    job_id,
                    exc_info=True,
                )
            return False
        return True

    def update_job(
        self,
        job_id: str,
        changes: dict[str, Any],
        *,
        owner_key_hash: str | None = None,
        next_run_at: float | None = None,
    ) -> ScheduledJob:
        """Apply validated changes store-first; mutate memory only after commit.

        Raises KeyError when the job is unknown (or owned by someone else) and
        propagates any store failure with the in-memory job untouched, so a
        restart always reflects the last confirmed state.
        """
        job = self.cron.get_job(job_id)
        if job is None or (owner_key_hash is not None and job.owner_key_hash != owner_key_hash):
            raise KeyError(f"cron job not found: {job_id}")
        rejected = sorted(set(changes) - UPDATABLE_FIELDS)
        if rejected:
            raise ValueError(f"cron job fields are not updatable: {', '.join(rejected)}")
        import copy

        candidate = copy.deepcopy(job)
        for field, value in changes.items():
            setattr(candidate, field, value)
        if next_run_at is not None:
            candidate.next_run_at = next_run_at
        candidate.updated_at = time.time()
        # Store commit first; raises -> memory untouched.
        self._persist_job(candidate)
        # Publish to memory only after the store confirmed.
        for field, value in changes.items():
            setattr(job, field, value)
        if next_run_at is not None:
            job.next_run_at = next_run_at
        job.updated_at = candidate.updated_at
        return job

    def get_job(self, job_id: str, owner_key_hash: str | None = None) -> ScheduledJob | None:
        job = self.cron.get_job(job_id)
        if job is not None and (owner_key_hash is None or job.owner_key_hash == owner_key_hash):
            return job
        return None

    def list_jobs(self, owner_key_hash: str | None = None) -> list[ScheduledJob]:
        jobs = self.cron.list_jobs()
        if owner_key_hash is None:
            return jobs
        return [job for job in jobs if job.owner_key_hash == owner_key_hash]

    @property
    def ledger_degraded(self) -> bool:
        """True when the authoritative EchoLedger daemon log is unavailable."""
        return self._ledger_degraded

    def _record_daemon_lifecycle(self, event_type: str, **payload: Any) -> None:
        """Authoritatively record a daemon lifecycle event in EchoLedger.

        The daemon_heartbeat.json file is only a derived snapshot; this
        ledger is the system of record for daemon_started / daemon_heartbeat
        / daemon_degraded / daemon_stopped.  A ledger failure marks the
        daemon ledger-degraded (fail-closed signal for health checks) and
        re-raises for lifecycle events other than heartbeats.
        """
        service = getattr(self.agent, "echo_safety_service", None)
        if service is None:
            self._ledger_degraded = True
            raise RuntimeError("daemon lifecycle logging requires EchoSafetyService")
        try:
            service.record_daemon_event(
                tenant_id="daemon",
                product_id=str(getattr(self.settings, "product_id", "js-agent")),
                session_id="daemon",
                event_type=event_type,
                payload={
                    "instance_id": self._instance_id,
                    **payload,
                },
            )
        except Exception:
            self._ledger_degraded = True
            raise

    async def start(self) -> None:
        """Start the daemon and block until shutdown signal."""
        self._running = True
        logger.info("JS Daemon starting...")
        self._record_daemon_lifecycle("daemon_started", uptime_seconds=0.0)

        # Start agent background tasks
        self.agent.start_background_tasks()

        # Start cron engine
        self.cron.start()

        # Register signal handlers
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, self._request_shutdown)
            except (NotImplementedError, ValueError, RuntimeError):
                pass  # Windows, non-main thread, or already closed loop

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
        await self.cron.stop_and_wait()
        self.agent.stop_background_tasks()
        self._persist_job_states()
        try:
            await self.agent.close()
        except Exception as e:
            logger.warning(f"Error during daemon shutdown: {e}")
        try:
            self._record_daemon_lifecycle(
                "daemon_stopped",
                uptime_seconds=time.time() - self._start_time,
            )
        except Exception:
            logger.warning("Failed to record daemon_stopped in EchoLedger", exc_info=True)
        logger.info("Daemon stopped")

    def _write_heartbeat(self) -> None:
        """Atomically write heartbeat with fsync, symlink rejection and sequence.

        Fail-closed: if the target path is a symlink or cannot be written
        safely, the heartbeat is not written and the error propagates.
        The JSON file is a non-authoritative derived snapshot only.
        """
        # Reject symlink targets (follow attack vector)
        if os.path.lexists(self._heartbeat_path) and self._heartbeat_path.is_symlink():
            raise ValueError(f"heartbeat target is a symlink: {self._heartbeat_path}")

        jobs = self.cron.list_jobs()
        total_run = sum(job.run_count for job in jobs)
        total_fail = sum(job.fail_count for job in jobs)
        hb = DaemonHeartbeat(
            timestamp=time.time(),
            uptime_seconds=time.time() - self._start_time,
            tasks_run=total_run,
            tasks_failed=total_fail,
            provider_count=len(self.agent.settings.providers),
            memory_sessions=0,
            instance_id=self._instance_id,
            sequence=self._heartbeat_seq,
            authoritative=False,
        )
        payload = json.dumps(hb.to_dict(), indent=2) + "\n"
        # Authoritative record first: every heartbeat is a ledger event.  A
        # ledger failure marks the daemon degraded but must not prevent the
        # derived JSON snapshot from being written for cheap status polling.
        try:
            self._record_daemon_lifecycle(
                "daemon_heartbeat",
                uptime_seconds=hb.uptime_seconds,
                tasks_run=hb.tasks_run,
                tasks_failed=hb.tasks_failed,
                sequence=hb.sequence,
            )
        except Exception:
            logger.warning("EchoLedger daemon heartbeat write failed", exc_info=True)
        self._heartbeat_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

        # Atomic write: temp file in same dir, fsync, os.replace, dir fsync
        fd, tmp_name = tempfile.mkstemp(
            prefix=".heartbeat.",
            suffix=".tmp",
            dir=str(self._heartbeat_path.parent),
        )
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_name, self._heartbeat_path)
            # fsync the directory so the rename is durable
            dir_fd = os.open(str(self._heartbeat_path.parent), os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except BaseException:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise
        self._heartbeat_seq += 1

    def _persist_job_states(self) -> None:
        """Persist current state of all jobs to SQLite."""
        for job in self.cron.list_jobs():
            self._persist_job(job)


def build_default_daemon(settings: JSSettings, *, agent: Any = None) -> JSDaemon:
    """Create a daemon with default scheduled tasks from templates.

    Default jobs use the ``__system__`` principal and stable IDs so that
    repeated calls are idempotent across restarts.
    """
    daemon = JSDaemon(settings, agent=agent)

    defaults = [
        ("__default_health_check__", "health_check", "health_check"),
        ("__default_dream_consolidation__", "dream_consolidation", "dream"),
        ("__default_session_cleanup__", "session_cleanup", "cleanup"),
    ]
    existing_ids = {j.id for j in daemon.list_jobs()}
    for stable_id, template_id, task_type in defaults:
        if stable_id in existing_ids:
            continue
        template = TEMPLATE_REGISTRY.get(template_id)
        if template:
            job = ScheduledJob(
                id=stable_id,
                name=template.name,
                description=template.description,
                cron_expr=template.default_cron,
                task_type=task_type,
                payload=template.default_payload,
                schedule_summary=template.default_cron,
                owner_key_hash="__system__",
                product_id="js-agent",
                system_scope=True,
            )
            daemon.add_job(job)

    return daemon
