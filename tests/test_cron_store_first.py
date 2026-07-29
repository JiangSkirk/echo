"""P1-4: cron create/update/delete must commit to the store BEFORE memory.

Previously ``remove_job`` deleted from memory first (a store failure left the
job resurrectable on restart) and the update path mutated the live job object
before persisting (a persist failure split memory from disk).
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import pytest

from js.config import JSSettings
from js.cron.engine import ScheduledJob
from js.daemon.core import JSDaemon


class _StubAgent:
    """Minimal agent stand-in: daemon only touches settings + background hooks."""

    def __init__(self, settings: JSSettings) -> None:
        self.settings = settings
        self.started = False
        self.stopped = False

    def start_background_tasks(self) -> None:
        self.started = True

    def stop_background_tasks(self) -> None:
        self.stopped = True

    async def close(self) -> None:
        return None


def _daemon(tmp_path: Path) -> JSDaemon:
    settings = JSSettings(
        workspace=tmp_path / "workspace",
        state_dir=tmp_path / "state",
        providers=[],
    )
    return JSDaemon(settings, agent=_StubAgent(settings))


def _job(job_id: str = "job-1", *, owner: str = "owner-a") -> ScheduledJob:
    return ScheduledJob(
        id=job_id,
        name="test job",
        cron_expr="*/5 * * * *",
        task_type="memory_optimization",
        payload={},
        next_run_at=time.time() + 60,
        owner_key_hash=owner,
    )


def test_remove_job_store_failure_keeps_memory_and_store_consistent(tmp_path: Path) -> None:
    daemon = _daemon(tmp_path)
    job = _job()
    daemon.add_job(job)

    def broken_delete(*_args: Any, **_kwargs: Any) -> None:
        raise OSError("sqlite locked")

    daemon.store.delete_job = broken_delete  # type: ignore[method-assign]

    with pytest.raises(OSError, match="sqlite locked"):
        daemon.remove_job(job.id)
    # Memory must NOT have been mutated when the store commit failed.
    assert daemon.cron.get_job(job.id) is not None
    # And the store still has the job (restart would restore exactly it).
    assert any(stored.id == job.id for stored in daemon.store.list_jobs())


def test_remove_job_commits_store_before_memory(tmp_path: Path) -> None:
    daemon = _daemon(tmp_path)
    job = _job()
    daemon.add_job(job)
    assert daemon.remove_job(job.id) is True
    assert daemon.cron.get_job(job.id) is None
    assert all(stored.id != job.id for stored in daemon.store.list_jobs())


def test_update_job_store_failure_leaves_memory_unchanged(tmp_path: Path) -> None:
    daemon = _daemon(tmp_path)
    job = _job()
    daemon.add_job(job)
    original_expr = job.cron_expr

    def broken_save(*_args: Any, **_kwargs: Any) -> None:
        raise OSError("disk full")

    daemon.store.save_job = broken_save  # type: ignore[method-assign]

    with pytest.raises(OSError, match="disk full"):
        daemon.update_job(job.id, {"cron_expr": "0 * * * *"}, owner_key_hash="owner-a")
    live = daemon.cron.get_job(job.id)
    assert live is not None
    assert live.cron_expr == original_expr, "memory diverged from store after failed update"


def test_update_job_commits_store_before_memory(tmp_path: Path) -> None:
    daemon = _daemon(tmp_path)
    job = _job()
    daemon.add_job(job)
    daemon.update_job(job.id, {"cron_expr": "0 * * * *"}, owner_key_hash="owner-a")
    live = daemon.cron.get_job(job.id)
    assert live is not None and live.cron_expr == "0 * * * *"
    stored = {stored.id: stored for stored in daemon.store.list_jobs()}
    assert stored[job.id].cron_expr == "0 * * * *"


def test_restart_reflects_last_confirmed_state(tmp_path: Path) -> None:
    daemon = _daemon(tmp_path)
    job = _job()
    daemon.add_job(job)
    daemon.update_job(job.id, {"cron_expr": "15 3 * * *"}, owner_key_hash="owner-a")
    daemon.remove_job(job.id)

    # A fresh daemon over the same state dir sees exactly the confirmed state.
    daemon2 = _daemon(tmp_path)
    assert daemon2.cron.get_job(job.id) is None
