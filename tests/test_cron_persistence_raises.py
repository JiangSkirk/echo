"""RED: Cron daemon must not claim success when persistence fails.

``add_job`` and ``_persist_result`` currently swallow SQLite errors and
return as if the job was durably saved.  A caller that believes the job
is persisted will be surprised when it vanishes after a restart.  The
daemon must raise so the caller can retry or surface the failure.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from js.cron.engine import JobResult, JobStatus, ScheduledJob
from js.cron.store import JobStore
from js.daemon.core import JSDaemon


def _daemon(tmp_path: Path) -> JSDaemon:
    daemon = object.__new__(JSDaemon)
    daemon.store = JobStore(tmp_path / "cron.db")
    daemon.cron = MagicMock()
    daemon.cron.get_job = MagicMock(return_value=None)
    return daemon


def test_add_job_raises_when_persistence_fails(tmp_path: Path) -> None:
    daemon = _daemon(tmp_path)
    daemon.cron.add_job = MagicMock()
    daemon.store.save_job = MagicMock(side_effect=OSError("disk full"))

    job = ScheduledJob(name="fail", cron_expr="@daily")
    with pytest.raises(OSError, match="disk full"):
        daemon.add_job(job)


def test_persist_result_raises_when_persistence_fails(tmp_path: Path) -> None:
    daemon = _daemon(tmp_path)
    job = ScheduledJob(id="j1", name="fail", cron_expr="@daily")
    daemon.cron.get_job = MagicMock(return_value=job)
    daemon.store.save_result_and_job = MagicMock(side_effect=OSError("disk full"))

    result = JobResult(
        job_id="j1",
        run_at=1.0,
        duration_ms=2.0,
        success=True,
        status=JobStatus.COMPLETED,
        owner_key_hash=job.owner_key_hash,
    )
    with pytest.raises(OSError, match="disk full"):
        daemon._persist_result(result)
