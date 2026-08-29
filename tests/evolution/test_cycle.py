"""Proposal-only evolution cycle: generate never applies; approve can roll back."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from js.config import JSSettings
from js.cron.engine import ScheduledJob
from js.daemon.core import JSDaemon, build_default_daemon
from js.evolution.cycle import (
    STATUS_APPLIED,
    STATUS_PROPOSED,
    STATUS_REGRESSED,
    STATUS_REJECTED,
    EvolutionCycle,
    load_baseline_score,
)
from js.evolution.metacognition import MetacognitionLoop


def test_generate_never_writes_applied_files(tmp_path: Path) -> None:
    cycle = EvolutionCycle(tmp_path)
    created = cycle.generate("owner-a")
    assert created
    assert all(item.status == STATUS_PROPOSED for item in created)
    applied = tmp_path / "evolution" / "applied"
    assert not applied.exists() or not list(applied.glob("*.json"))


def test_approve_applies_when_benchmark_holds(tmp_path: Path) -> None:
    cycle = EvolutionCycle(tmp_path)
    proposal = cycle.generate("owner-a", max_proposals=1)[0]
    updated = cycle.approve_and_apply(
        proposal.proposal_id,
        "owner-a",
        decided_by="admin",
        benchmark=lambda: 1.0,
        baseline_score=1.0,
    )
    assert updated.status == STATUS_APPLIED
    assert updated.benchmark_after == 1.0
    applied = Path(updated.applied_path or "")
    assert applied.is_file()


def test_benchmark_exception_rolls_back_applied_file(tmp_path: Path) -> None:
    cycle = EvolutionCycle(tmp_path)
    proposal = cycle.generate("owner-a", max_proposals=1)[0]

    def _boom() -> float:
        raise RuntimeError("runner exited 1")

    updated = cycle.approve_and_apply(
        proposal.proposal_id,
        "owner-a",
        decided_by="admin",
        benchmark=_boom,
        baseline_score=1.0,
    )
    assert updated.status == STATUS_REGRESSED
    assert updated.benchmark_after is None
    assert not Path(updated.applied_path or "").is_file()


def test_run_mock_benchmark_reads_score_on_nonzero_exit(monkeypatch: pytest.MonkeyPatch) -> None:
    from js.evolution import cycle as cycle_mod

    class _Result:
        returncode = 1
        stdout = "Overall score: 0.810\n"
        stderr = "regression detected\n"

    monkeypatch.setattr(
        cycle_mod.subprocess,
        "run",
        lambda *args, **kwargs: _Result(),
    )
    assert cycle_mod.run_mock_benchmark() == 0.81


def test_regression_deletes_applied_file(tmp_path: Path) -> None:
    cycle = EvolutionCycle(tmp_path)
    proposal = cycle.generate("owner-a", max_proposals=1)[0]
    updated = cycle.approve_and_apply(
        proposal.proposal_id,
        "owner-a",
        decided_by="admin",
        benchmark=lambda: 0.5,
        baseline_score=1.0,
    )
    assert updated.status == STATUS_REGRESSED
    assert updated.benchmark_after == 0.5
    assert not Path(updated.applied_path or "").is_file()


def test_reject_leaves_no_applied_file(tmp_path: Path) -> None:
    cycle = EvolutionCycle(tmp_path)
    proposal = cycle.generate("owner-a", max_proposals=1)[0]
    updated = cycle.reject(proposal.proposal_id, "owner-a", decided_by="admin")
    assert updated.status == STATUS_REJECTED
    assert not list((tmp_path / "evolution" / "applied").glob("*.json"))


def test_owner_isolation(tmp_path: Path) -> None:
    cycle = EvolutionCycle(tmp_path)
    alice = cycle.generate("alice", max_proposals=1)[0]
    bob = cycle.generate("bob", max_proposals=1)[0]
    assert cycle.get(alice.proposal_id, "bob") is None
    assert [item.proposal_id for item in cycle.list_proposals("alice")] == [alice.proposal_id]
    assert [item.proposal_id for item in cycle.list_proposals("bob")] == [bob.proposal_id]
    with pytest.raises(ValueError, match="not open"):
        cycle.approve_and_apply(
            alice.proposal_id,
            "bob",
            decided_by="bob",
            benchmark=lambda: 1.0,
            baseline_score=1.0,
        )


def test_generate_caps_open_proposals(tmp_path: Path) -> None:
    learner = SimpleNamespace(
        suggest_improvements=lambda owner_key_hash=None: ["one", "two", "three"]
    )
    cycle = EvolutionCycle(tmp_path)
    first = cycle.generate("owner-a", learner=learner, max_proposals=2)
    second = cycle.generate("owner-a", learner=learner, max_proposals=2)
    assert len(first) == 2
    assert second == []


def test_generate_uses_learner_titles(tmp_path: Path) -> None:
    learner = SimpleNamespace(
        suggest_improvements=lambda owner_key_hash=None: [
            {"title": "Tighten the system prompt"},
            "Drop unused tools",
        ]
    )
    cycle = EvolutionCycle(tmp_path)
    created = cycle.generate("owner-a", learner=learner, max_proposals=2)
    assert [item.title for item in created] == ["Tighten the system prompt", "Drop unused tools"]


def test_load_baseline_score_reads_repo_file() -> None:
    assert load_baseline_score() == 1.0


def test_metacognition_defaults_to_no_auto_apply(tmp_path: Path) -> None:
    loop = MetacognitionLoop(tmp_path)
    assert loop.auto_apply is False


@pytest.mark.asyncio
async def test_daemon_skill_evolve_generates_only(tmp_path: Path) -> None:
    daemon = object.__new__(JSDaemon)
    daemon.agent = SimpleNamespace(
        settings=JSSettings(state_dir=tmp_path),
        learner=None,
    )
    job = ScheduledJob(task_type="skill_evolve", owner_key_hash="owner-a")
    await JSDaemon._cb_skill_evolve(daemon, job)
    rows = EvolutionCycle(tmp_path).list_proposals("owner-a")
    assert rows
    assert all(item.status == STATUS_PROPOSED for item in rows)
    assert not list((tmp_path / "evolution" / "applied").glob("*.json"))


@pytest.mark.asyncio
async def test_daemon_skill_evolve_without_owner_is_noop(tmp_path: Path) -> None:
    daemon = object.__new__(JSDaemon)
    daemon.agent = SimpleNamespace(
        settings=JSSettings(state_dir=tmp_path),
        learner=None,
    )
    job = ScheduledJob(task_type="skill_evolve", owner_key_hash="")
    await JSDaemon._cb_skill_evolve(daemon, job)
    assert not (tmp_path / "evolution_proposals.db").exists()


def test_unscheduled_daemon_does_not_run_evolution(tmp_path: Path) -> None:
    settings = JSSettings(state_dir=tmp_path, providers=[])
    daemon = build_default_daemon(settings, agent=MagicMock())
    assert "skill_evolve" not in {job.task_type for job in daemon.list_jobs()}
    assert not (tmp_path / "evolution_proposals.db").exists()
