"""Integration tests for the v0.1.5-alpha Skill Promotion Gate pipeline.

Covers the end-to-end paths between SkillCurator / SkillEvolver / SkillManager
and PromotionStore:

 * curator never mutates ``spec.trust_level`` directly when a store is wired
 * evolver never overwrites the entry file when a store is wired
 * builtin / hermes skills are protected from auto-overwrite
 * ``apply_proposal`` only flips trust / files when the gate passes
 * ``revert_promotion`` rolls trust + entry file back
 * operator ``trust_skill`` writes a promotion event + audit row
 * owner isolation: two owners don't see each other's proposals
 * quarantine skills remain unexposed as tools after demotion via curator
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from js.skills.curator import SkillCurator
from js.skills.evolver import SkillEvolver, SkillVariant
from js.skills.manager import SkillManager
from js.skills.promotion_gate import GateResult
from js.skills.promotion_store import PromotionStore
from js.skills.spec import SkillSpec, SkillType, TrustLevel

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _write_skill(
    base: Path,
    skill_id: str,
    *,
    body: str = "print('hello')\n",
    trust: str = "community",
) -> SkillSpec:
    sk_dir = base / skill_id
    sk_dir.mkdir(parents=True, exist_ok=True)
    (sk_dir / "SKILL.md").write_text(
        f"""---
id: {skill_id}
name: {skill_id}
description: synthetic test skill
version: 0.1.0
type: code
entry: main.py
trust_level: {trust}
---
# body
""",
        encoding="utf-8",
    )
    (sk_dir / "main.py").write_text(body, encoding="utf-8")
    return SkillSpec(
        id=skill_id,
        name=skill_id,
        description="synthetic test skill",
        type=SkillType.CODE,
        entry="main.py",
        trust_level=TrustLevel(trust),
        path=sk_dir,
    )


def _make_manager(
    tmp_path: Path,
    *,
    store: PromotionStore | None = None,
    audit: Any | None = None,
) -> SkillManager:
    state_dir = tmp_path / "state"
    state_dir.mkdir(exist_ok=True)
    workspace = tmp_path / "ws"
    workspace.mkdir(exist_ok=True)
    return SkillManager(
        state_dir,
        workspace,
        promotion_store=store,
        audit_logger=audit,
    )


# ---------------------------------------------------------------------------
# curator: promotes via proposal, not direct mutation
# ---------------------------------------------------------------------------


def test_curator_proposes_promotion_without_mutating_trust(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    store = PromotionStore(state_dir / "skill_promotions.db")
    mgr = _make_manager(tmp_path, store=store)
    spec = _write_skill(state_dir / "skills", "promote_me", trust="community")
    mgr._skills[spec.id] = spec  # type: ignore[attr-defined]

    curator = SkillCurator(state_dir, promotion_store=store, skill_manager=mgr)
    with patch.object(
        curator,
        "_load_usage_stats",
        return_value={spec.id: {"count": 50, "success_rate": 0.99, "last_used": 0.0}},
    ):
        report = curator.curate({spec.id: spec}, force=True)

    # spec.trust_level untouched
    assert spec.trust_level == TrustLevel.COMMUNITY
    events = store.list_by_skill(spec.id)
    assert len(events) == 1
    assert events[0].status == "proposed"
    assert events[0].source == "auto_curator"
    assert events[0].to_level == TrustLevel.TRUSTED.value
    actions = report["actions_taken"]
    assert any(a.get("action") == "promotion_proposed" for a in actions)


def test_curator_dedupes_existing_open_proposal(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    store = PromotionStore(state_dir / "skill_promotions.db")
    mgr = _make_manager(tmp_path, store=store)
    spec = _write_skill(state_dir / "skills", "dedup_skill", trust="community")
    mgr._skills[spec.id] = spec  # type: ignore[attr-defined]

    store.propose(
        spec.id,
        TrustLevel.COMMUNITY.value,
        TrustLevel.TRUSTED.value,
        "auto_curator",
        "pre-existing",
    )
    curator = SkillCurator(state_dir, promotion_store=store, skill_manager=mgr)
    with patch.object(
        curator,
        "_load_usage_stats",
        return_value={spec.id: {"count": 99, "success_rate": 0.99, "last_used": 0.0}},
    ):
        report = curator.curate({spec.id: spec}, force=True)

    assert len(store.list_by_skill(spec.id)) == 1
    assert any(a.get("action") == "promotion_already_proposed" for a in report["actions_taken"])


def test_curator_legacy_path_without_store(tmp_path: Path) -> None:
    """Without store/manager the legacy direct-mutation path still runs."""
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    spec = _write_skill(state_dir / "skills", "legacy_skill", trust="community")
    curator = SkillCurator(state_dir)
    with patch.object(
        curator,
        "_load_usage_stats",
        return_value={spec.id: {"count": 50, "success_rate": 0.99, "last_used": 0.0}},
    ):
        curator.curate({spec.id: spec}, force=True)
    assert spec.trust_level == TrustLevel.TRUSTED  # legacy behaviour preserved


# ---------------------------------------------------------------------------
# evolver: proposes variant, never overwrites entry file
# ---------------------------------------------------------------------------


def test_evolver_does_not_overwrite_entry_when_store_wired(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    store = PromotionStore(state_dir / "skill_promotions.db")
    proposals_dir = state_dir / "skill_proposals"
    evolver = SkillEvolver(state_dir, promotion_store=store, proposals_dir=proposals_dir)
    skill_dir = state_dir / "skills" / "evo_skill"
    skill_dir.mkdir(parents=True)
    original_code = "print('original')\n"
    (skill_dir / "main.py").write_text(original_code, encoding="utf-8")

    variant = SkillVariant(
        id="variant-xyz",
        skill_id="evo_skill",
        code="print('variant')\n",
        prompt="",
        test_cases=[],
        success_count=8,
        total_count=10,
        avg_score=0.9,
        created_at=0.0,
    )
    with patch.object(evolver, "select_best_variant", return_value=variant):
        result = evolver.promote_variant("evo_skill", skill_path=skill_dir)

    assert result is False
    assert (skill_dir / "main.py").read_text() == original_code
    artifact = proposals_dir / "variant-xyz" / "main.py"
    assert artifact.exists()
    assert artifact.read_text() == "print('variant')\n"
    events = store.list_by_skill("evo_skill")
    assert len(events) == 1
    assert events[0].status == "proposed"
    assert events[0].source == "auto_evolver"
    assert events[0].variant_id == "variant-xyz"
    assert evolver.last_proposal_event_id == events[0].event_id


def test_evolver_legacy_overwrite_when_no_store(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    evolver = SkillEvolver(state_dir)
    skill_dir = state_dir / "skills" / "old_evo"
    skill_dir.mkdir(parents=True)
    (skill_dir / "main.py").write_text("orig\n", encoding="utf-8")
    variant = SkillVariant(
        id="legacy-1",
        skill_id="old_evo",
        code="new\n",
        prompt="",
        test_cases=[],
        success_count=8,
        total_count=10,
        avg_score=0.9,
        created_at=0.0,
    )
    with patch.object(evolver, "select_best_variant", return_value=variant):
        result = evolver.promote_variant("old_evo", skill_path=skill_dir)
    assert result is True
    assert (skill_dir / "main.py").read_text() == "new\n"


def test_evolver_skips_hermes_even_with_store(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    store = PromotionStore(state_dir / "skill_promotions.db")
    evolver = SkillEvolver(state_dir, promotion_store=store)
    skill_dir = state_dir / "skills" / "hermes_x"
    skill_dir.mkdir(parents=True)
    (skill_dir / "main.py").write_text("orig\n", encoding="utf-8")

    with patch.object(evolver, "select_best_variant") as mock_best:
        result = evolver.promote_variant("hermes:x", skill_path=skill_dir)
    assert result is False
    mock_best.assert_not_called()
    assert store.list_by_skill("hermes:x") == []


# ---------------------------------------------------------------------------
# manager.apply_proposal: gate pass → apply, gate fail → no mutation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_apply_proposal_pass_flips_trust(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    store = PromotionStore(state_dir / "skill_promotions.db")
    mgr = _make_manager(tmp_path, store=store)
    spec = _write_skill(state_dir / "skills", "ok_skill", trust="community")
    mgr._skills[spec.id] = spec  # type: ignore[attr-defined]

    event_id = store.propose(
        spec.id,
        TrustLevel.COMMUNITY.value,
        TrustLevel.TRUSTED.value,
        "auto_curator",
        "great-success",
    )

    async def fake_run(_self: Any, _spec: Any) -> GateResult:
        return GateResult(passed=True, failed_step=None, details={"smoke": "ok"})

    with patch("js.skills.promotion_gate.PromotionGate.run", new=fake_run):
        result = await mgr.apply_proposal(event_id, decided_by="op-1")

    assert result["success"] is True
    assert spec.trust_level == TrustLevel.TRUSTED
    ev = store.get(event_id)
    assert ev is not None and ev.status == "applied"
    assert ev.applied_at is not None


@pytest.mark.asyncio
async def test_apply_proposal_fail_leaves_trust_untouched(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    store = PromotionStore(state_dir / "skill_promotions.db")
    mgr = _make_manager(tmp_path, store=store)
    spec = _write_skill(state_dir / "skills", "bad_skill", trust="community")
    mgr._skills[spec.id] = spec  # type: ignore[attr-defined]

    event_id = store.propose(
        spec.id,
        TrustLevel.COMMUNITY.value,
        TrustLevel.TRUSTED.value,
        "auto_curator",
        "should-fail",
    )

    async def fake_run(_self: Any, _spec: Any) -> GateResult:
        return GateResult(passed=False, failed_step="security", details={"reason": "risky"})

    with patch("js.skills.promotion_gate.PromotionGate.run", new=fake_run):
        result = await mgr.apply_proposal(event_id, decided_by="op-1")

    assert result["success"] is False
    assert result["failed_step"] == "security"
    assert spec.trust_level == TrustLevel.COMMUNITY
    ev = store.get(event_id)
    assert ev is not None and ev.status == "failed"


@pytest.mark.asyncio
async def test_apply_proposal_overlays_variant_artifact(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    store = PromotionStore(state_dir / "skill_promotions.db")
    mgr = _make_manager(tmp_path, store=store)
    spec = _write_skill(
        state_dir / "skills", "evo_apply", trust="community", body="print('orig')\n"
    )
    mgr._skills[spec.id] = spec  # type: ignore[attr-defined]

    artifact_dir = state_dir / "proposals" / "var-1"
    artifact_dir.mkdir(parents=True)
    artifact_path = artifact_dir / "main.py"
    artifact_path.write_text("print('NEW')\n", encoding="utf-8")

    event_id = store.propose(
        spec.id,
        "evolver",
        "evolver",  # same level → no trust flip
        "auto_evolver",
        "variant chosen",
        variant_id="var-1",
        artifact_path=str(artifact_path),
    )

    async def fake_run(_self: Any, _spec: Any) -> GateResult:
        return GateResult(passed=True, failed_step=None, details={})

    with patch("js.skills.promotion_gate.PromotionGate.run", new=fake_run):
        result = await mgr.apply_proposal(event_id, decided_by="op-1")

    assert result["success"] is True
    assert spec.path is not None
    entry = spec.path / "main.py"
    assert entry.read_text() == "print('NEW')\n"
    backup = spec.path / ".promotion_backups" / event_id / "main.py"
    assert backup.exists()
    assert backup.read_text() == "print('orig')\n"


# ---------------------------------------------------------------------------
# manager.revert_promotion: trust + file rollback
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_revert_promotion_restores_trust(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    store = PromotionStore(state_dir / "skill_promotions.db")
    mgr = _make_manager(tmp_path, store=store)
    spec = _write_skill(state_dir / "skills", "revert_me", trust="community")
    mgr._skills[spec.id] = spec  # type: ignore[attr-defined]

    event_id = store.propose(
        spec.id,
        TrustLevel.COMMUNITY.value,
        TrustLevel.TRUSTED.value,
        "auto_curator",
        "ok",
    )

    async def fake_run(_self: Any, _spec: Any) -> GateResult:
        return GateResult(passed=True, failed_step=None, details={})

    with patch("js.skills.promotion_gate.PromotionGate.run", new=fake_run):
        await mgr.apply_proposal(event_id, decided_by="op-1")
    assert spec.trust_level == TrustLevel.TRUSTED

    result = mgr.revert_promotion(event_id, decided_by="op-1")
    assert result["success"] is True
    assert result["trust_reverted"] is True
    assert spec.trust_level == TrustLevel.COMMUNITY
    ev = store.get(event_id)
    assert ev is not None and ev.status == "rolled_back"


@pytest.mark.asyncio
async def test_revert_promotion_restores_entry_file(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    store = PromotionStore(state_dir / "skill_promotions.db")
    mgr = _make_manager(tmp_path, store=store)
    spec = _write_skill(
        state_dir / "skills", "evo_revert", trust="community", body="print('orig')\n"
    )
    mgr._skills[spec.id] = spec  # type: ignore[attr-defined]

    artifact_dir = state_dir / "proposals" / "var-r"
    artifact_dir.mkdir(parents=True)
    (artifact_dir / "main.py").write_text("print('NEW')\n", encoding="utf-8")
    event_id = store.propose(
        spec.id,
        "evolver",
        "evolver",
        "auto_evolver",
        "ok",
        variant_id="var-r",
        artifact_path=str(artifact_dir / "main.py"),
    )

    async def fake_run(_self: Any, _spec: Any) -> GateResult:
        return GateResult(passed=True, failed_step=None, details={})

    with patch("js.skills.promotion_gate.PromotionGate.run", new=fake_run):
        await mgr.apply_proposal(event_id, decided_by="op-1")
    assert spec.path is not None
    assert (spec.path / "main.py").read_text() == "print('NEW')\n"

    result = mgr.revert_promotion(event_id, decided_by="op-1")
    assert result["success"] is True
    assert (spec.path / "main.py").read_text() == "print('orig')\n"


# ---------------------------------------------------------------------------
# operator trust_skill: writes audit + promotion event
# ---------------------------------------------------------------------------


def test_operator_trust_skill_records_event(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    store = PromotionStore(state_dir / "skill_promotions.db")
    mgr = _make_manager(tmp_path, store=store)
    spec = _write_skill(state_dir / "skills", "manual_trust", trust="community")
    mgr._skills[spec.id] = spec  # type: ignore[attr-defined]

    ok = mgr.trust_skill(spec.id, TrustLevel.TRUSTED, reason="manual review")
    assert ok is True
    events = store.list_by_skill(spec.id)
    assert len(events) == 1
    assert events[0].status == "applied"
    assert events[0].source == "operator"
    assert events[0].from_level == TrustLevel.COMMUNITY.value
    assert events[0].to_level == TrustLevel.TRUSTED.value


# ---------------------------------------------------------------------------
# owner isolation
# ---------------------------------------------------------------------------


def test_owner_isolation_on_proposals(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    store = PromotionStore(state_dir / "skill_promotions.db")
    e1 = store.propose(
        "sk1",
        TrustLevel.COMMUNITY.value,
        TrustLevel.TRUSTED.value,
        "auto_curator",
        "from owner A",
        owner_key_hash="ownerA",
    )
    store.propose(
        "sk1",
        TrustLevel.COMMUNITY.value,
        TrustLevel.TRUSTED.value,
        "auto_curator",
        "from owner B",
        owner_key_hash="ownerB",
    )
    a_events = store.list_by_skill("sk1", owner_key_hash="ownerA")
    b_events = store.list_by_skill("sk1", owner_key_hash="ownerB")
    assert len(a_events) == 1
    assert len(b_events) == 1
    assert a_events[0].event_id == e1
    assert a_events[0].event_id != b_events[0].event_id


# ---------------------------------------------------------------------------
# quarantine demotion via curator unregisters tool exposure
# ---------------------------------------------------------------------------


def test_curator_demote_unregisters_tool(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    store = PromotionStore(state_dir / "skill_promotions.db")
    mgr = _make_manager(tmp_path, store=store)
    spec = _write_skill(state_dir / "skills", "bad_perf", trust="community")
    mgr._skills[spec.id] = spec  # type: ignore[attr-defined]

    with patch.object(mgr, "_unregister_skill_as_tool") as mock_unreg:
        curator = SkillCurator(state_dir, promotion_store=store, skill_manager=mgr)
        # last_used "just now" so the skill is not flagged stale first;
        # stale takes precedence over underperforming in the health classifier.
        with patch.object(
            curator,
            "_load_usage_stats",
            return_value={spec.id: {"count": 10, "success_rate": 0.1, "last_used": time.time()}},
        ):
            curator.curate({spec.id: spec}, force=True)

    assert spec.trust_level == TrustLevel.QUARANTINE
    mock_unreg.assert_called_once_with(spec.id)
