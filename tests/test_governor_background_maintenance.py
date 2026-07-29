"""Background lifecycle tests for governor-owned session maintenance."""

from __future__ import annotations

import asyncio
import os
import sqlite3
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from js.agent import JSAgent
from js.config import JSSettings
from js.runtime.governor import ResourceGovernor, ResourceSnapshot


@pytest.mark.parametrize(
    ("daemon_enabled", "expected_dream_starts"),
    [(False, 0), (True, 1)],
)
def test_start_background_tasks_always_starts_governor_but_gates_dreaming(
    daemon_enabled: bool,
    expected_dream_starts: int,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    dream_scheduler = MagicMock()
    governor = MagicMock()
    governor_type = MagicMock(return_value=governor)
    monkeypatch.setattr("js.runtime.governor.ResourceGovernor", governor_type)
    agent = SimpleNamespace(
        settings=SimpleNamespace(
            features=SimpleNamespace(daemon_enabled=daemon_enabled),
            state_dir=tmp_path,
        ),
        _dream_scheduler=dream_scheduler,
        _governor=None,
        _fleet_getter=None,
    )

    JSAgent.start_background_tasks(agent)

    assert dream_scheduler.start.call_count == expected_dream_starts
    governor_type.assert_called_once_with(agent, fleet_getter=None, state_dir=tmp_path)
    governor.start.assert_called_once_with()


def test_stop_background_tasks_stops_dream_scheduler_and_governor() -> None:
    dream_scheduler = MagicMock()
    governor = MagicMock()
    agent = SimpleNamespace(_dream_scheduler=dream_scheduler, _governor=governor)

    JSAgent.stop_background_tasks(agent)

    dream_scheduler.stop.assert_called_once_with()
    governor.stop.assert_called_once_with()


@pytest.mark.asyncio
async def test_agent_close_waits_for_governor_tasks(tmp_path: Path) -> None:
    agent = JSAgent(JSSettings(workspace=tmp_path / "workspace", state_dir=tmp_path / "state"))
    governor = SimpleNamespace(stop=MagicMock(), wait_stopped=AsyncMock())
    agent._governor = governor

    await agent.close()

    governor.stop.assert_called_once_with()
    governor.wait_stopped.assert_awaited_once_with()


def _resource_snapshot(memory_percent: float) -> ResourceSnapshot:
    return ResourceSnapshot(
        timestamp=1.0,
        process_rss_mb=100.0,
        process_vms_mb=200.0,
        system_memory_percent=memory_percent,
        system_memory_available_mb=1_000.0,
        cpu_percent=1.0,
        disk_free_state_dir_gb=100.0,
        disk_free_root_gb=100.0,
        active_sessions=0,
        active_agents=0,
        idle_agents=0,
        in_flight_tasks=0,
    )


@pytest.mark.asyncio
async def test_governor_keeps_monitoring_while_requests_are_paused() -> None:
    governor = ResourceGovernor(SimpleNamespace())
    governor._paused = True
    governor._interval_seconds = 0.0
    cycle_started = asyncio.Event()

    async def one_cycle() -> None:
        cycle_started.set()
        raise asyncio.CancelledError

    governor._run_cycle = one_cycle  # type: ignore[method-assign]
    task = asyncio.create_task(governor._loop())
    try:
        await asyncio.wait_for(cycle_started.wait(), timeout=0.2)
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
async def test_governor_tracks_deduplicates_and_reaps_pressure_tasks() -> None:
    governor = ResourceGovernor(SimpleNamespace())
    started = asyncio.Event()
    release = asyncio.Event()

    async def blocked_pressure_release() -> None:
        started.set()
        await release.wait()

    governor._pressure_decompression = blocked_pressure_release  # type: ignore[method-assign]

    governor._evaluate_pressure(_resource_snapshot(80.0))
    governor._evaluate_pressure(_resource_snapshot(80.0))
    await asyncio.wait_for(started.wait(), timeout=1.0)

    assert len(governor._pressure_tasks) == 1
    task = next(iter(governor._pressure_tasks.values()))

    governor.stop()
    await asyncio.wait_for(governor.wait_stopped(), timeout=1.0)

    assert task.cancelled()
    assert not governor._pressure_tasks


@pytest.mark.asyncio
async def test_governor_serializes_pressure_escalation_tasks() -> None:
    governor = ResourceGovernor(SimpleNamespace())
    pressure_started = asyncio.Event()
    pressure_release = asyncio.Event()
    critical_started = asyncio.Event()

    async def blocked_pressure_release() -> None:
        pressure_started.set()
        await pressure_release.wait()

    async def critical_release() -> None:
        critical_started.set()

    governor._pressure_decompression = blocked_pressure_release  # type: ignore[method-assign]
    governor._critical_decompression = critical_release  # type: ignore[method-assign]

    governor._evaluate_pressure(_resource_snapshot(80.0))
    await asyncio.wait_for(pressure_started.wait(), timeout=1.0)
    governor._evaluate_pressure(_resource_snapshot(90.0))
    await asyncio.sleep(0)

    assert not critical_started.is_set()

    pressure_release.set()
    await asyncio.wait_for(critical_started.wait(), timeout=1.0)
    governor.stop()
    await governor.wait_stopped()


@pytest.mark.asyncio
async def test_session_maintenance_runs_blocking_stores_off_event_loop() -> None:
    import threading

    event_loop_thread = threading.get_ident()
    worker_threads: list[int] = []

    def record_thread(*_args: object, **_kwargs: object) -> int | set[tuple[str, str]]:
        worker_threads.append(threading.get_ident())
        return set() if len(worker_threads) == 1 else 0

    lifecycle_store = SimpleNamespace(running_pairs_for_maintenance=record_thread)
    enhanced = SimpleNamespace(maintain_session_bounds=record_thread)
    quality_scorer = SimpleNamespace(prune=record_thread)
    agent = SimpleNamespace(
        lifecycle_store=lifecycle_store,
        memory=SimpleNamespace(enhanced=enhanced),
        _quality_scorer=quality_scorer,
    )

    await ResourceGovernor(agent)._maintain_session_bounds()

    assert len(worker_threads) == 3
    assert all(thread_id != event_loop_thread for thread_id in worker_threads)


@pytest.mark.asyncio
async def test_full_prune_runs_blocking_stores_off_event_loop() -> None:
    import threading

    event_loop_thread = threading.get_ident()
    worker_threads: list[int] = []

    def prune(*, keep: int) -> int:
        assert keep == 1_000
        worker_threads.append(threading.get_ident())
        return 0

    governor = ResourceGovernor(SimpleNamespace(_state_store=SimpleNamespace(prune=prune)))
    governor._maintain_session_bounds = AsyncMock()  # type: ignore[method-assign]

    await governor._prune_databases()

    assert len(worker_threads) == 1
    assert worker_threads[0] != event_loop_thread


@pytest.mark.asyncio
async def test_cancelled_prune_waits_for_blocking_worker_to_exit() -> None:
    import threading

    started = threading.Event()
    release = threading.Event()
    finished = threading.Event()

    def prune(*, keep: int) -> int:
        assert keep == 1_000
        started.set()
        assert release.wait(timeout=2.0)
        finished.set()
        return 0

    governor = ResourceGovernor(SimpleNamespace(_state_store=SimpleNamespace(prune=prune)))
    governor._maintain_session_bounds = AsyncMock()  # type: ignore[method-assign]
    task = asyncio.create_task(governor._prune_databases())
    assert await asyncio.wait_for(asyncio.to_thread(started.wait, 1.0), timeout=2.0)

    task.cancel()
    await asyncio.sleep(0)

    assert not task.done()
    assert not finished.is_set()

    release.set()
    result = await asyncio.gather(task, return_exceptions=True)

    assert isinstance(result[0], asyncio.CancelledError)
    assert finished.is_set()


@pytest.mark.asyncio
async def test_governor_runs_bounded_maintenance_on_independent_one_minute_clock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    governor = ResourceGovernor(SimpleNamespace())
    clock = [10_000.0]
    monkeypatch.setattr("js.runtime.governor.time.time", lambda: clock[0])
    governor._collect_snapshot = MagicMock(return_value=None)  # type: ignore[method-assign]
    governor._reap_idle_agents = AsyncMock()  # type: ignore[method-assign]
    governor._prune_databases = AsyncMock()  # type: ignore[method-assign]
    bounded_maintenance = AsyncMock()
    governor._maintain_hot_state = bounded_maintenance  # type: ignore[method-assign]
    governor._last_reap_time = clock[0]
    governor._last_prune_time = clock[0]
    governor._last_session_maintenance_time = clock[0] - 60.0

    await governor._run_cycle()
    bounded_maintenance.assert_awaited_once_with()
    governor._prune_databases.assert_not_awaited()

    clock[0] += 59.0
    await governor._run_cycle()
    assert bounded_maintenance.await_count == 1

    clock[0] += 1.0
    await governor._run_cycle()
    assert bounded_maintenance.await_count == 2
    governor._prune_databases.assert_not_awaited()


@pytest.mark.asyncio
async def test_hot_state_maintenance_bounds_every_growing_store_and_checkpoints(
    tmp_path: Path,
) -> None:
    lifecycle = MagicMock()
    lifecycle.prune.side_effect = RuntimeError("lifecycle unavailable")
    review = MagicMock()
    audit = MagicMock()
    learner = MagicMock()
    compression_feedback = MagicMock()
    optimizer = MagicMock()
    metacognition = MagicMock()
    event_store = MagicMock()
    agent = SimpleNamespace(
        lifecycle_store=lifecycle,
        review_store=review,
        audit=audit,
        learner=learner,
        compression_feedback=compression_feedback,
        optimizer=optimizer,
        metacognition=metacognition,
        event_store=event_store,
    )
    governor = ResourceGovernor(agent, state_dir=tmp_path)
    session_maintenance = AsyncMock()
    checkpoint = AsyncMock()
    governor._maintain_session_bounds = session_maintenance  # type: ignore[method-assign]
    governor._checkpoint_wal = checkpoint  # type: ignore[method-assign]

    with patch("js.web.stats_store.TokenStatsStore") as stats_store_type:
        stats_store = stats_store_type.return_value

        await governor._maintain_hot_state()

    session_maintenance.assert_awaited_once_with()
    lifecycle.prune.assert_called_once_with()
    review.prune.assert_called_once_with()
    audit.prune.assert_called_once_with()
    learner.prune.assert_called_once_with()
    compression_feedback.prune.assert_called_once_with()
    optimizer.prune.assert_called_once_with()
    metacognition.prune.assert_called_once_with()
    event_store.prune.assert_called_once_with()
    stats_store_type.assert_called_once_with(tmp_path)
    stats_store.prune.assert_called_once_with()
    checkpoint.assert_awaited_once_with()


def test_wal_checkpoint_skips_symlinked_and_hardlinked_databases(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    real_db = state_dir / "real.db"
    external_db = tmp_path / "external.db"
    for path in (real_db, external_db):
        with sqlite3.connect(path) as conn:
            conn.execute("CREATE TABLE sentinel (value TEXT NOT NULL)")
            conn.execute("INSERT INTO sentinel VALUES ('preserved')")
    symlink_db = state_dir / "symlink.db"
    symlink_db.symlink_to(external_db)
    hardlink_db = state_dir / "hardlink.db"
    os.link(external_db, hardlink_db)

    connected: list[Path] = []
    real_connect = sqlite3.connect

    def recording_connect(path: str, *args: object, **kwargs: object) -> sqlite3.Connection:
        connected.append(Path(path))
        return real_connect(path, *args, **kwargs)

    monkeypatch.setattr(sqlite3, "connect", recording_connect)

    ResourceGovernor(SimpleNamespace(), state_dir=state_dir)._checkpoint_wal_sync()

    assert real_db.resolve() in {path.resolve() for path in connected}
    assert symlink_db not in connected
    assert hardlink_db not in connected
    with real_connect(external_db) as conn:
        assert conn.execute("SELECT value FROM sentinel").fetchone()[0] == "preserved"


@pytest.mark.asyncio
async def test_full_prune_stays_on_six_hour_clock_without_duplicate_session_maintenance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    governor = ResourceGovernor(SimpleNamespace())
    clock = [20_000.0]
    monkeypatch.setattr("js.runtime.governor.time.time", lambda: clock[0])
    governor._collect_snapshot = MagicMock(return_value=None)  # type: ignore[method-assign]
    governor._reap_idle_agents = AsyncMock()  # type: ignore[method-assign]
    session_maintenance = AsyncMock()
    governor._maintain_session_bounds = session_maintenance  # type: ignore[method-assign]

    async def full_prune() -> None:
        await session_maintenance()

    governor._prune_databases = AsyncMock(side_effect=full_prune)  # type: ignore[method-assign]
    governor._last_reap_time = clock[0]
    governor._last_prune_time = clock[0]
    governor._last_session_maintenance_time = clock[0]

    clock[0] += 21_599.0
    governor._last_session_maintenance_time = clock[0]
    await governor._run_cycle()
    governor._prune_databases.assert_not_awaited()

    clock[0] += 1.0
    governor._last_session_maintenance_time = clock[0] - 300.0
    await governor._run_cycle()

    governor._prune_databases.assert_awaited_once_with()
    session_maintenance.assert_awaited_once_with()
    assert governor._last_prune_time == clock[0]
    assert governor._last_session_maintenance_time == clock[0]


@pytest.mark.asyncio
async def test_session_maintenance_protects_running_owner_session_pairs() -> None:
    lifecycle_store = MagicMock()
    protected = {("owner-a", "session-running")}
    lifecycle_store.running_pairs_for_maintenance.return_value = protected
    enhanced = MagicMock()
    enhanced.maintain_session_bounds.return_value = 2
    agent = SimpleNamespace(
        lifecycle_store=lifecycle_store,
        memory=SimpleNamespace(enhanced=enhanced),
    )

    await ResourceGovernor(agent)._maintain_session_bounds()

    lifecycle_store.running_pairs_for_maintenance.assert_called_once_with()
    enhanced.maintain_session_bounds.assert_called_once_with(
        protected_sessions=protected,
    )


@pytest.mark.asyncio
async def test_session_maintenance_also_bounds_quality_history() -> None:
    lifecycle_store = MagicMock()
    lifecycle_store.running_pairs_for_maintenance.return_value = set()
    enhanced = MagicMock()
    enhanced.maintain_session_bounds.return_value = 0
    quality_scorer = MagicMock()
    quality_scorer.prune.return_value = 7
    agent = SimpleNamespace(
        lifecycle_store=lifecycle_store,
        memory=SimpleNamespace(enhanced=enhanced),
        _quality_scorer=quality_scorer,
    )

    await ResourceGovernor(agent)._maintain_session_bounds()

    quality_scorer.prune.assert_called_once_with()


@pytest.mark.asyncio
async def test_quality_history_maintenance_runs_without_memory_store() -> None:
    quality_scorer = MagicMock()
    quality_scorer.prune.return_value = 3
    agent = SimpleNamespace(_quality_scorer=quality_scorer)

    await ResourceGovernor(agent)._maintain_session_bounds()

    quality_scorer.prune.assert_called_once_with()


@pytest.mark.asyncio
async def test_full_prune_runs_session_maintenance_without_memory_store() -> None:
    governor = ResourceGovernor(SimpleNamespace())
    session_maintenance = AsyncMock()
    governor._maintain_session_bounds = session_maintenance  # type: ignore[method-assign]

    await governor._prune_databases()

    session_maintenance.assert_awaited_once_with()


@pytest.mark.parametrize("failed_operation", ["protection_lookup", "session_bounds"])
@pytest.mark.asyncio
async def test_session_maintenance_errors_are_logged_and_contained(
    failed_operation: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lifecycle_store = MagicMock()
    lifecycle_store.running_pairs_for_maintenance.return_value = set()
    enhanced = MagicMock()
    enhanced.maintain_session_bounds.return_value = 0
    if failed_operation == "protection_lookup":
        lifecycle_store.running_pairs_for_maintenance.side_effect = RuntimeError(
            "maintenance unavailable"
        )
    else:
        enhanced.maintain_session_bounds.side_effect = RuntimeError("maintenance unavailable")
    agent = SimpleNamespace(
        lifecycle_store=lifecycle_store,
        memory=SimpleNamespace(enhanced=enhanced),
    )
    logger = MagicMock()
    monkeypatch.setattr("js.runtime.governor.logger", logger)

    await ResourceGovernor(agent)._maintain_session_bounds()

    logger.warning.assert_called_once()
    log_args, log_kwargs = logger.warning.call_args
    assert log_args[0] == "Memory session maintenance failed: %s"
    assert str(log_args[1]) == "maintenance unavailable"
    assert log_kwargs == {"exc_info": True}
    if failed_operation == "protection_lookup":
        enhanced.maintain_session_bounds.assert_not_called()
    else:
        enhanced.maintain_session_bounds.assert_called_once_with(protected_sessions=set())
