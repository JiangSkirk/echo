"""Tests for JSDaemon core logic."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from js import __version__
from js.config import JSSettings
from js.daemon.core import DaemonHeartbeat, JSDaemon, ScheduledTask, build_default_daemon

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
# ScheduledTask
# ---------------------------------------------------------------------------


class TestScheduledTask:
    def test_task_defaults(self) -> None:
        task = ScheduledTask(name="test", interval_seconds=10.0, callback=lambda a: None)
        assert task.last_run == 0.0
        assert task.run_count == 0
        assert task.enabled is True
        assert task.failures == 0


# ---------------------------------------------------------------------------
# JSDaemon initialization
# ---------------------------------------------------------------------------


class TestJSDaemonInit:
    def test_daemon_creates_state_dir(self, settings: JSSettings) -> None:
        daemon = JSDaemon(settings)
        assert daemon._state_dir.exists()
        assert daemon._state_dir.name == "daemon"

    def test_default_tasks_empty(self, settings: JSSettings) -> None:
        daemon = JSDaemon(settings)
        assert daemon._tasks == []

    def test_add_task(self, settings: JSSettings) -> None:
        daemon = JSDaemon(settings)
        task = ScheduledTask(name="t1", interval_seconds=5.0, callback=lambda a: None)
        daemon.add_task(task)
        assert len(daemon._tasks) == 1
        assert daemon._tasks[0].name == "t1"


# ---------------------------------------------------------------------------
# State persistence
# ---------------------------------------------------------------------------


class TestDaemonStatePersistence:
    def test_save_and_load_state(self, settings: JSSettings) -> None:
        daemon = JSDaemon(settings)
        task = ScheduledTask(name="t1", interval_seconds=5.0, callback=lambda a: None)
        task.last_run = 1234.0
        task.run_count = 7
        task.failures = 2
        daemon.add_task(task)
        daemon._save_state()

        # Create fresh daemon pointing at same state dir
        daemon2 = JSDaemon(settings)
        daemon2.add_task(ScheduledTask(name="t1", interval_seconds=5.0, callback=lambda a: None))
        daemon2._load_state()

        assert daemon2._tasks[0].last_run == 1234.0
        assert daemon2._tasks[0].run_count == 7
        assert daemon2._tasks[0].failures == 2

    def test_load_state_missing_file(self, settings: JSSettings) -> None:
        daemon = JSDaemon(settings)
        task = ScheduledTask(name="t1", interval_seconds=5.0, callback=lambda a: None)
        daemon.add_task(task)
        # No state file exists yet
        daemon._load_state()
        assert task.last_run == 0.0

    def test_save_state_file_format(self, settings: JSSettings) -> None:
        daemon = JSDaemon(settings)
        daemon.add_task(ScheduledTask(name="health", interval_seconds=60.0, callback=lambda a: None))
        daemon._save_state()

        content = json.loads(daemon._state_path.read_text())
        assert "saved_at" in content
        assert len(content["tasks"]) == 1
        assert content["tasks"][0]["name"] == "health"


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
        task = ScheduledTask(name="t1", interval_seconds=1.0, callback=lambda a: None)
        task.run_count = 5
        task.failures = 1
        daemon.add_task(task)
        daemon._write_heartbeat()

        data = json.loads(daemon._heartbeat_path.read_text())
        assert data["tasks_run"] == 5
        assert data["tasks_failed"] == 1


# ---------------------------------------------------------------------------
# Tick execution
# ---------------------------------------------------------------------------


class TestDaemonTick:
    @pytest.mark.asyncio
    async def test_tick_executes_due_tasks(self, settings: JSSettings) -> None:
        calls: list[str] = []

        async def callback(agent: Any) -> None:
            calls.append("called")

        daemon = JSDaemon(settings)
        task = ScheduledTask(name="t1", interval_seconds=1.0, callback=callback)
        # Task is way overdue (last_run=0, interval=1)
        daemon.add_task(task)
        await daemon._tick()

        assert calls == ["called"]
        assert task.run_count == 1
        assert task.last_run > 0

    @pytest.mark.asyncio
    async def test_tick_skips_not_due_tasks(self, settings: JSSettings) -> None:
        calls: list[str] = []

        async def callback(agent: Any) -> None:
            calls.append("called")

        import time

        daemon = JSDaemon(settings)
        task = ScheduledTask(name="t1", interval_seconds=9999.0, callback=callback)
        task.last_run = time.time()  # Just ran
        daemon.add_task(task)
        await daemon._tick()

        assert calls == []
        assert task.run_count == 0

    @pytest.mark.asyncio
    async def test_tick_skips_disabled_tasks(self, settings: JSSettings) -> None:
        calls: list[str] = []

        async def callback(agent: Any) -> None:
            calls.append("called")

        daemon = JSDaemon(settings)
        task = ScheduledTask(name="t1", interval_seconds=1.0, callback=callback)
        task.enabled = False
        daemon.add_task(task)
        await daemon._tick()

        assert calls == []

    @pytest.mark.asyncio
    async def test_tick_failure_counted(self, settings: JSSettings) -> None:
        async def failing_callback(agent: Any) -> None:
            raise RuntimeError("boom")

        daemon = JSDaemon(settings)
        task = ScheduledTask(name="fail", interval_seconds=1.0, callback=failing_callback)
        daemon.add_task(task)
        await daemon._tick()

        assert task.failures == 1
        assert task.run_count == 1


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
    async def test_graceful_shutdown_saves_state(self, settings: JSSettings) -> None:
        daemon = JSDaemon(settings)
        daemon.add_task(ScheduledTask(name="t1", interval_seconds=5.0, callback=lambda a: None))
        await daemon._shutdown()
        assert daemon._state_path.exists()


# ---------------------------------------------------------------------------
# build_default_daemon
# ---------------------------------------------------------------------------


class TestBuildDefaultDaemon:
    def test_default_tasks_registered(self, settings: JSSettings) -> None:
        daemon = build_default_daemon(settings)
        names = {t.name for t in daemon._tasks}
        assert "health_check" in names
        assert "dream_consolidation" in names
        assert "session_cleanup" in names
        assert len(daemon._tasks) == 3

    def test_default_task_intervals(self, settings: JSSettings) -> None:
        daemon = build_default_daemon(settings)
        intervals = {t.name: t.interval_seconds for t in daemon._tasks}
        assert intervals["health_check"] == 60.0
        assert intervals["dream_consolidation"] == 300.0
        assert intervals["session_cleanup"] == 3600.0


# ---------------------------------------------------------------------------
# Built-in task callbacks (isolation tests)
# ---------------------------------------------------------------------------


class TestBuiltInCallbacks:
    @pytest.mark.asyncio
    async def test_health_check_task_no_crash(self, settings: JSSettings) -> None:
        from js.daemon.core import _health_check_task

        daemon = JSDaemon(settings)
        # Should not raise even with minimal agent state
        await _health_check_task(daemon.agent)

    @pytest.mark.asyncio
    async def test_dream_task_no_crash_without_scheduler(self, settings: JSSettings) -> None:
        from js.daemon.core import _dream_task

        daemon = JSDaemon(settings)
        # Agent may not have _dream_scheduler or _task
        await _dream_task(daemon.agent)

    @pytest.mark.asyncio
    async def test_session_cleanup_task_no_crash(self, settings: JSSettings) -> None:
        from js.daemon.core import _session_cleanup_task

        daemon = JSDaemon(settings)
        await _session_cleanup_task(daemon.agent)
