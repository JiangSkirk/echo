"""Tests for JSDaemon core logic."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from js import __version__
from js.config import JSSettings
from js.cron.engine import JobResult, JobStatus, ScheduledJob
from js.daemon.core import DaemonHeartbeat, JSDaemon, build_default_daemon

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def settings(tmp_path: Path) -> JSSettings:
    return JSSettings(
        state_dir=tmp_path,
        providers=[],
        skills_dir=tmp_path / "skills",
        memory_dir=tmp_path / "memory",
    )


# ---------------------------------------------------------------------------
# DaemonHeartbeat
# ---------------------------------------------------------------------------


class TestDaemonHeartbeat:
    def test_roundtrip_serialization(self) -> None:
        hb = DaemonHeartbeat(
            timestamp=1234567890.0,
            uptime_seconds=3600.0,
            tasks_run=42,
            tasks_failed=3,
            provider_count=2,
            memory_sessions=5,
            version="0.1.0",
        )
        data = hb.to_dict()
        restored = DaemonHeartbeat.from_dict(data)
        assert restored.timestamp == hb.timestamp
        assert restored.tasks_run == 42
        assert restored.tasks_failed == 3

    def test_from_dict_defaults(self) -> None:
        restored = DaemonHeartbeat.from_dict({})
        assert restored.version == __version__
        assert restored.tasks_run == 0


# ---------------------------------------------------------------------------
# JSDaemon initialization
# ---------------------------------------------------------------------------


class TestJSDaemonInit:
    def test_daemon_creates_state_dir(self, settings: JSSettings) -> None:
        daemon = JSDaemon(settings)
        assert daemon._state_dir.exists()
        assert daemon._state_dir.name == "daemon"

    def test_default_jobs_empty(self, settings: JSSettings) -> None:
        daemon = JSDaemon(settings)
        assert daemon.list_jobs() == []
        assert not hasattr(daemon, "_tasks")

    def test_add_job(self, settings: JSSettings) -> None:
        daemon = JSDaemon(settings)
        job = ScheduledJob(name="t1", cron_expr="*/5 * * * *")
        daemon.add_job(job)
        assert daemon.list_jobs() == [job]
        assert daemon.get_job(job.id) is job


# ---------------------------------------------------------------------------
# State persistence
# ---------------------------------------------------------------------------


class TestDaemonStatePersistence:
    def test_job_state_roundtrips_through_sqlite(self, settings: JSSettings) -> None:
        daemon = JSDaemon(settings)
        job = ScheduledJob(
            name="t1",
            cron_expr="*/5 * * * *",
            run_count=7,
            fail_count=2,
            last_run_at=1234.0,
        )
        daemon.add_job(job)

        # Create fresh daemon pointing at same state dir
        daemon2 = JSDaemon(settings)
        restored = daemon2.get_job(job.id)

        assert restored is not None
        assert restored.last_run_at == 1234.0
        assert restored.run_count == 7
        assert restored.fail_count == 2

    def test_legacy_json_state_is_not_created(self, settings: JSSettings) -> None:
        daemon = JSDaemon(settings)
        daemon.add_job(ScheduledJob(name="health", cron_expr="* * * * *"))
        daemon._persist_job_states()

        assert not (daemon._state_dir / "daemon_state.json").exists()

    def test_result_callback_atomically_persists_cancelled_job_terminal(
        self,
        settings: JSSettings,
    ) -> None:
        daemon = JSDaemon(settings)
        job = ScheduledJob(name="cancelled", cron_expr="@daily")
        daemon.add_job(job)
        job.status = JobStatus.CANCELLED
        result = JobResult(
            job_id=job.id,
            run_at=1.0,
            duration_ms=2.0,
            success=False,
            status=JobStatus.CANCELLED,
            error="Job was cancelled",
            owner_key_hash=job.owner_key_hash,
        )

        daemon._persist_result(result)

        restored = daemon.store.get_job(job.id)
        assert restored is not None
        assert restored.status == JobStatus.CANCELLED
        history = daemon.store.get_history(job.id)
        assert history[0].status == JobStatus.CANCELLED


# ---------------------------------------------------------------------------
# Heartbeat
# ---------------------------------------------------------------------------


class TestDaemonHeartbeatFile:
    def test_heartbeat_written(self, settings: JSSettings) -> None:
        daemon = JSDaemon(settings)
        daemon._write_heartbeat()
        assert daemon._heartbeat_path.exists()

        data = json.loads(daemon._heartbeat_path.read_text())
        assert "timestamp" in data
        assert "uptime_seconds" in data
        assert data["tasks_run"] == 0
        assert data["version"] == __version__

    def test_heartbeat_after_tasks_run(self, settings: JSSettings) -> None:
        daemon = JSDaemon(settings)
        job = ScheduledJob(
            name="t1",
            cron_expr="* * * * *",
            run_count=5,
            fail_count=1,
        )
        daemon.add_job(job)
        daemon._write_heartbeat()

        data = json.loads(daemon._heartbeat_path.read_text())
        assert data["tasks_run"] == 5
        assert data["tasks_failed"] == 1

    def test_heartbeat_rejects_symlink_target(self, settings: JSSettings) -> None:
        """Heartbeat must fail-closed if target path is a symlink (§4 stability)."""
        daemon = JSDaemon(settings)
        # Create a symlink at the heartbeat path
        settings.state_dir.mkdir(parents=True, exist_ok=True)
        link_target = settings.state_dir / "daemon" / "evil_heartbeat.json"
        link_target.parent.mkdir(parents=True, exist_ok=True)
        link_target.write_text("evil")
        daemon._heartbeat_path.unlink(missing_ok=True)
        daemon._heartbeat_path.symlink_to(link_target)
        with pytest.raises((ValueError, OSError)):
            daemon._write_heartbeat()

    def test_heartbeat_atomic_no_partial_write(self, settings: JSSettings) -> None:
        """Heartbeat must be atomic - no partial JSON visible to readers."""
        daemon = JSDaemon(settings)
        daemon._write_heartbeat()
        # The file must be valid JSON (not partial)
        data = json.loads(daemon._heartbeat_path.read_text())
        assert "timestamp" in data
        assert "schema" in data or "version" in data

    def test_heartbeat_includes_schema_and_sequence(self, settings: JSSettings) -> None:
        """Heartbeat must include schema, instance_id, sequence for auditability."""
        daemon = JSDaemon(settings)
        daemon._write_heartbeat()
        data = json.loads(daemon._heartbeat_path.read_text())
        assert "schema" in data, "heartbeat must include schema field"
        assert "instance_id" in data, "heartbeat must include instance_id"
        assert "sequence" in data, "heartbeat must include sequence"
        assert data["sequence"] == 0
        # Second write should increment sequence
        daemon._write_heartbeat()
        data2 = json.loads(daemon._heartbeat_path.read_text())
        assert data2["sequence"] == 1


# ---------------------------------------------------------------------------
# Signal handling
# ---------------------------------------------------------------------------


class TestDaemonShutdown:
    def test_request_shutdown_sets_flags(self, settings: JSSettings) -> None:
        daemon = JSDaemon(settings)
        daemon._running = True
        daemon._request_shutdown()
        assert daemon._running is False

    @pytest.mark.asyncio
    async def test_start_exits_on_shutdown_event(self, settings: JSSettings) -> None:
        daemon = JSDaemon(settings)
        # Pre-trigger shutdown so the loop exits immediately
        daemon._running = True
        daemon._shutdown_event.set()
        # start() should exit quickly because _shutdown_event is already set
        await daemon.start()
        assert daemon._running is False

    @pytest.mark.asyncio
    async def test_graceful_shutdown_persists_cron_state(self, settings: JSSettings) -> None:
        daemon = JSDaemon(settings)
        job = ScheduledJob(name="t1", cron_expr="*/5 * * * *", run_count=3)
        daemon.add_job(job)
        job.run_count = 4
        await daemon._shutdown()
        restored = daemon.store.get_job(job.id)
        assert restored is not None
        assert restored.run_count == 4
        assert not (daemon._state_dir / "daemon_state.json").exists()


# ---------------------------------------------------------------------------
# build_default_daemon
# ---------------------------------------------------------------------------


class TestBuildDefaultDaemon:
    def test_default_jobs_registered_once(self, settings: JSSettings) -> None:
        daemon = build_default_daemon(settings)
        jobs = daemon.list_jobs()
        assert {job.task_type for job in jobs} == {"health_check", "dream", "cleanup"}
        assert len(jobs) == 3
        assert len({job.id for job in jobs}) == 3
        assert not hasattr(daemon, "_tasks")

    def test_default_jobs_use_template_cron(self, settings: JSSettings) -> None:
        daemon = build_default_daemon(settings)
        schedules = {job.task_type: job.cron_expr for job in daemon.list_jobs()}
        assert schedules == {
            "health_check": "0 */6 * * *",
            "dream": "0 4 * * *",
            "cleanup": "0 3 * * *",
        }


# ---------------------------------------------------------------------------
# Built-in task callbacks (isolation tests)
# ---------------------------------------------------------------------------


class TestBuiltInCallbacks:
    @pytest.mark.asyncio
    async def test_health_check_callback_no_crash(self, settings: JSSettings) -> None:
        daemon = JSDaemon(settings)
        await daemon._cb_health_check(ScheduledJob(task_type="health_check"))

    @pytest.mark.asyncio
    async def test_dream_callback_no_crash_without_scheduler(self, settings: JSSettings) -> None:
        daemon = JSDaemon(settings)
        await daemon._cb_dream(ScheduledJob(task_type="dream"))

    @pytest.mark.asyncio
    async def test_session_cleanup_callback_no_crash(self, settings: JSSettings) -> None:
        daemon = JSDaemon(settings)
        await daemon._cb_cleanup(ScheduledJob(task_type="cleanup"))

    def test_default_jobs_use_system_principal(self, settings: JSSettings) -> None:
        """C-fix: 默认任务必须使用 system principal，不能默认 local-user."""
        daemon = build_default_daemon(settings)
        for job in daemon.list_jobs():
            assert job.owner_key_hash == "__system__", (
                f"默认任务 {job.name} owner 应为 __system__, got {job.owner_key_hash}"
            )
            assert job.system_scope is True, (
                f"默认任务 {job.name} 应标记 system_scope=True"
            )

    @pytest.mark.asyncio
    async def test_cleanup_does_not_touch_other_owner(
        self, settings: JSSettings
    ) -> None:
        """C-fix: cleanup 回调必须只清理 job.owner 指定的 owner，不全局遍历."""
        daemon = JSDaemon(settings)
        # Create a job scoped to owner-A
        job_a = ScheduledJob(
            name="cleanup-a",
            cron_expr="0 3 * * *",
            task_type="cleanup",
            owner_key_hash="owner-a",
            product_id="js-agent",
        )
        # Create a job scoped to owner-B
        job_b = ScheduledJob(
            name="cleanup-b",
            cron_expr="0 3 * * *",
            task_type="cleanup",
            owner_key_hash="owner-b",
            product_id="js-agent",
        )
        # cleanup for owner-A should not touch owner-B's sessions
        # We verify the callback respects job.owner_key_hash by checking it
        # doesn't call cleanup_empty_sessions() without an owner filter
        called_owners: list[str] = []
        original_cleanup = daemon.agent.memory.enhanced.cleanup_empty_sessions

        def tracking_cleanup(*args: object, **kwargs: object) -> int:
            owner = kwargs.get("owner_key_hash") or (args[0] if args else None)
            called_owners.append(str(owner))
            return 0

        daemon.agent.memory.enhanced.cleanup_empty_sessions = tracking_cleanup  # type: ignore[method-assign]
        try:
            await daemon._cb_cleanup(job_a)
            await daemon._cb_cleanup(job_b)
        finally:
            daemon.agent.memory.enhanced.cleanup_empty_sessions = original_cleanup  # type: ignore[method-assign]
        assert "owner-a" in called_owners, f"cleanup 应传 owner-a, got {called_owners}"
        assert "owner-b" in called_owners, f"cleanup 应传 owner-b, got {called_owners}"
