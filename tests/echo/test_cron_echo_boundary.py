from __future__ import annotations

import asyncio
import sqlite3
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from js.cron.engine import CronEngine, JobResult, JobStatus, ScheduledJob
from js.cron.store import JobStore
from js.daemon.core import JSDaemon


@pytest.mark.asyncio
async def test_cron_engine_records_callback_output(tmp_path: Path) -> None:
    engine = CronEngine(tmp_path)
    job = ScheduledJob(name="chat", cron_expr="@daily", task_type="chat")
    engine.add_job(job)
    engine.register_callback("chat", AsyncMock(return_value="echo-result"))

    result = await engine.run_job_now(job.id)

    assert result.success
    assert result.output == "echo-result"


@pytest.mark.asyncio
async def test_cron_engine_bounds_utf8_callback_output(tmp_path: Path) -> None:
    engine = CronEngine(tmp_path)
    job = ScheduledJob(name="large", cron_expr="@daily", task_type="chat")
    engine.add_job(job)
    engine.register_callback("chat", AsyncMock(return_value="界" * 400_000))

    result = await engine.run_job_now(job.id)

    assert result.output_truncated is True
    assert len(result.output.encode("utf-8")) <= 262_144


@pytest.mark.asyncio
async def test_cron_engine_records_cancelled_terminal_before_propagating(
    tmp_path: Path,
) -> None:
    engine = CronEngine(tmp_path)
    job = ScheduledJob(name="cancel", cron_expr="@daily", task_type="chat")
    engine.add_job(job)
    started = asyncio.Event()

    async def block(_job: ScheduledJob) -> str:
        started.set()
        await asyncio.Event().wait()
        raise AssertionError("unreachable")

    engine.register_callback("chat", block)
    execution = asyncio.create_task(engine.run_job_now(job.id))
    await started.wait()
    execution.cancel()

    with pytest.raises(asyncio.CancelledError):
        await execution

    assert job.status == JobStatus.CANCELLED
    history = engine.get_history(job.id)
    assert len(history) == 1
    assert history[0].status == JobStatus.CANCELLED
    assert history[0].success is False
    assert history[0].error == "Job was cancelled"


@pytest.mark.asyncio
async def test_cron_shutdown_cancels_and_reaps_active_job(tmp_path: Path) -> None:
    engine = CronEngine(tmp_path)
    job = ScheduledJob(name="shutdown", cron_expr="@daily", task_type="chat")
    engine.add_job(job)
    started = asyncio.Event()

    async def block(_job: ScheduledJob) -> str:
        started.set()
        await asyncio.Event().wait()
        raise AssertionError("unreachable")

    engine.register_callback("chat", block)
    execution = asyncio.create_task(engine.run_job_now(job.id))
    await started.wait()

    await engine.stop_and_wait()

    with pytest.raises(asyncio.CancelledError):
        await execution
    assert job.status == JobStatus.CANCELLED
    assert engine.active_execution_count == 0


@pytest.mark.asyncio
async def test_cron_rejects_overlapping_runs_of_the_same_job(tmp_path: Path) -> None:
    engine = CronEngine(tmp_path)
    job = ScheduledJob(name="single", cron_expr="@daily", task_type="chat")
    engine.add_job(job)
    started = asyncio.Event()

    async def block(_job: ScheduledJob) -> str:
        started.set()
        await asyncio.Event().wait()
        raise AssertionError("unreachable")

    engine.register_callback("chat", block)
    first = asyncio.create_task(engine.run_job_now(job.id))
    await started.wait()

    with pytest.raises(RuntimeError, match="already executing"):
        await asyncio.wait_for(engine.run_job_now(job.id), timeout=0.1)

    first.cancel()
    with pytest.raises(asyncio.CancelledError):
        await first


@pytest.mark.asyncio
async def test_cron_result_callback_exception_does_not_swallow_result(tmp_path: Path) -> None:
    """A raising result_callback must not lose the recorded JobResult."""
    engine = CronEngine(tmp_path)
    job = ScheduledJob(name="bad-cb", cron_expr="@daily", task_type="chat")
    engine.add_job(job)
    engine.register_callback("chat", AsyncMock(return_value="ok"))

    def broken_callback(_result: JobResult) -> None:
        raise RuntimeError("result callback exploded")

    engine.register_result_callback(broken_callback)

    result = await engine.run_job_now(job.id)

    assert result.success
    assert result.status == JobStatus.COMPLETED
    assert job.status == JobStatus.COMPLETED
    history = engine.get_history(job.id)
    assert history and history[0].success


def test_cron_stop_remains_safe_without_a_running_event_loop(tmp_path: Path) -> None:
    engine = CronEngine(tmp_path)

    engine.stop()

    assert engine.active_execution_count == 0


@pytest.mark.asyncio
async def test_daemon_chat_callback_runs_echo_with_job_owner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = SimpleNamespace(
        status="completed",
        error_message=None,
        messages=[SimpleNamespace(role="assistant", content="scheduled answer")],
    )
    run_echo = AsyncMock(return_value=state)
    monkeypatch.setattr("js.daemon.core.run_echo_turn", run_echo)
    daemon = object.__new__(JSDaemon)
    daemon.agent = SimpleNamespace()
    job = ScheduledJob(
        id="job-a",
        name="chat",
        cron_expr="@daily",
        task_type="chat",
        payload={"prompt": "daily summary"},
        owner_key_hash="owner-a",
        product_id="js-agent",
        session_id="cron-session-a",
    )

    output = await daemon._cb_chat(job)

    assert output == "scheduled answer"
    run_echo.assert_awaited_once()
    kwargs = run_echo.await_args.kwargs
    assert kwargs["channel"] == "cron_chat"
    assert kwargs["owner_key_hash"] == "owner-a"
    assert kwargs["session_id"] == "cron-session-a"


def test_cron_store_round_trips_owner_identity(tmp_path: Path) -> None:
    store = JobStore(tmp_path / "cron.db")
    job = ScheduledJob(
        name="owned",
        cron_expr="@daily",
        owner_key_hash="owner-a",
        product_id="js-agent",
        session_id="session-a",
    )

    store.save_job(job)
    loaded = store.get_job(job.id)

    assert loaded is not None
    assert loaded.owner_key_hash == "owner-a"
    assert loaded.product_id == "js-agent"
    assert loaded.session_id == "session-a"


def test_cron_store_round_trips_explicit_cancelled_history_status(
    tmp_path: Path,
) -> None:
    store = JobStore(tmp_path / "cron.db")
    store.save_result(
        JobResult(
            job_id="job-a",
            run_at=1.0,
            duration_ms=2.0,
            success=False,
            status=JobStatus.CANCELLED,
            error="Job was cancelled",
            owner_key_hash="owner-a",
        )
    )

    history = store.get_history(job_id="job-a", owner_key_hash="owner-a")

    assert len(history) == 1
    assert history[0].status == JobStatus.CANCELLED
    stats = store.get_stats()
    assert stats["cancelled_runs"] == 1
    assert stats["failed_runs"] == 0


def test_cron_store_migrates_legacy_history_to_explicit_status(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "cron.db"
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE cron_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id TEXT NOT NULL,
                run_at REAL NOT NULL,
                duration_ms REAL DEFAULT 0,
                success INTEGER DEFAULT 0,
                output TEXT,
                error TEXT,
                owner_key_hash TEXT NOT NULL DEFAULT 'local-user'
            )
            """
        )
        conn.execute(
            """
            INSERT INTO cron_history
            (job_id, run_at, duration_ms, success, output, error, owner_key_hash)
            VALUES ('legacy-failure', 1.0, 2.0, 0, '', 'failed', 'owner-a')
            """
        )

    store = JobStore(db_path)
    history = store.get_history(
        job_id="legacy-failure",
        owner_key_hash="owner-a",
    )

    assert history[0].status == JobStatus.FAILED


def test_cron_store_prunes_history_by_owner_and_global_limits(
    tmp_path: Path,
) -> None:
    store = JobStore(tmp_path / "cron.db")
    store._MAX_HISTORY_PER_OWNER = 2
    store._MAX_HISTORY_TOTAL = 3
    for index, owner in enumerate(("owner-a", "owner-a", "owner-a", "owner-b", "owner-b")):
        store.save_result(
            JobResult(
                job_id=f"job-{index}",
                run_at=float(index),
                duration_ms=1.0,
                success=True,
                status=JobStatus.COMPLETED,
                owner_key_hash=owner,
            )
        )

    all_history = store.get_history(limit=10)

    assert len(all_history) == 3
    assert sum(row.owner_key_hash == "owner-a" for row in all_history) <= 2
    assert sum(row.owner_key_hash == "owner-b" for row in all_history) <= 2
