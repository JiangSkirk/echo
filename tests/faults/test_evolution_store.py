"""Evolution proposal desk survives truncated DB, ENOSPC, and kill-9 mid-apply."""

from __future__ import annotations

import errno
import sqlite3
from pathlib import Path

import pytest

from js.evolution.cycle import (
    STATUS_APPLIED,
    STATUS_PROPOSED,
    STATUS_REGRESSED,
    EvolutionCycle,
)


def test_truncated_db_fails_closed_and_does_not_cross_owners(tmp_path: Path) -> None:
    cycle = EvolutionCycle(tmp_path)
    first = cycle.generate("owner-a", max_proposals=1)[0]
    cycle.generate("owner-b", max_proposals=1)
    raw = cycle.db_path.read_bytes()
    cycle.db_path.write_bytes(raw[:40])
    with pytest.raises(sqlite3.Error):
        cycle.list_proposals("owner-a")
    with pytest.raises(sqlite3.Error):
        cycle.get(first.proposal_id, "owner-b")


def test_enospc_on_apply_leaves_proposal_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cycle = EvolutionCycle(tmp_path)
    proposal = cycle.generate("owner-a", max_proposals=1)[0]

    def _full(self: Path, *args: object, **kwargs: object) -> None:
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(Path, "write_text", _full)
    with pytest.raises(OSError, match="No space left"):
        cycle.approve_and_apply(
            proposal.proposal_id,
            "owner-a",
            decided_by="admin",
            benchmark=lambda: 1.0,
            baseline_score=1.0,
        )
    leftover = cycle.get(proposal.proposal_id, "owner-a")
    assert leftover is not None
    assert leftover.status == STATUS_PROPOSED
    assert not list((tmp_path / "evolution" / "applied").glob("*.json"))


def test_kill_after_file_write_leaves_proposal_open_for_retry(tmp_path: Path) -> None:
    cycle = EvolutionCycle(tmp_path)
    proposal = cycle.generate("owner-a", max_proposals=1)[0]
    leftover_path = Path(cycle._write_applied(proposal))
    assert leftover_path.is_file()
    assert cycle.get(proposal.proposal_id, "owner-a").status == STATUS_PROPOSED
    updated = cycle.approve_and_apply(
        proposal.proposal_id,
        "owner-a",
        decided_by="admin",
        benchmark=lambda: 1.0,
        baseline_score=1.0,
    )
    assert updated.status == STATUS_APPLIED
    assert Path(updated.applied_path or "").is_file()


def test_kill9_after_file_write_rolls_back_when_benchmark_crashes(tmp_path: Path) -> None:
    cycle = EvolutionCycle(tmp_path)
    proposal = cycle.generate("owner-a", max_proposals=1)[0]
    updated = cycle.approve_and_apply(
        proposal.proposal_id,
        "owner-a",
        decided_by="admin",
        benchmark=lambda: (_ for _ in ()).throw(RuntimeError("killed")),
        baseline_score=1.0,
    )
    assert updated.status == STATUS_REGRESSED
    assert not Path(updated.applied_path or "").is_file()
    revived = EvolutionCycle(tmp_path)
    assert revived.get(proposal.proposal_id, "owner-b") is None
    again = revived.get(proposal.proposal_id, "owner-a")
    assert again is not None
    assert again.status == STATUS_REGRESSED
    assert again.status != STATUS_APPLIED
