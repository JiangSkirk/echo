"""Unit tests for js.skills.promotion_store.PromotionStore.

Mirrors the owner-isolation contract verified by
``tests/test_state_store_owner.py`` for the lifecycle store.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from js.skills.promotion_store import (
    STATUS_APPLIED,
    STATUS_APPROVED,
    STATUS_FAILED,
    STATUS_PROPOSED,
    STATUS_REJECTED,
    STATUS_ROLLED_BACK,
    PromotionStore,
)


@pytest.fixture
def store(tmp_path: Path) -> PromotionStore:
    return PromotionStore(tmp_path / "skill_promotions.db")


def _propose(
    store: PromotionStore,
    skill_id: str = "skill-a",
    *,
    owner: str | None = None,
    source: str = "auto_curator",
) -> str:
    return store.propose(
        skill_id=skill_id,
        from_level="community",
        to_level="trusted",
        source=source,
        reason="20 runs / 95% success",
        owner_key_hash=owner,
    )


# ---------------------------------------------------------------------------
# propose + read
# ---------------------------------------------------------------------------


def test_propose_returns_event_id_and_persists(store: PromotionStore) -> None:
    eid = _propose(store, owner="owner-1")
    assert isinstance(eid, str) and len(eid) == 32  # uuid4 hex
    evt = store.get(eid, owner_key_hash="owner-1")
    assert evt is not None
    assert evt.skill_id == "skill-a"
    assert evt.from_level == "community"
    assert evt.to_level == "trusted"
    assert evt.source == "auto_curator"
    assert evt.status == STATUS_PROPOSED
    assert evt.decided_by == "auto"
    assert evt.applied_at is None
    assert evt.rolled_back_at is None


def test_record_operator_apply_lands_as_applied(store: PromotionStore) -> None:
    eid = store.record_operator_apply(
        skill_id="skill-x",
        from_level="quarantine",
        to_level="community",
        owner_key_hash="op-1",
        decided_by="op-1",
        reason="manual review ok",
    )
    evt = store.get(eid, owner_key_hash="op-1")
    assert evt is not None
    assert evt.status == STATUS_APPLIED
    assert evt.source == "operator"
    assert evt.decided_by == "op-1"
    assert evt.decided_at is not None
    assert evt.applied_at is not None


# ---------------------------------------------------------------------------
# owner isolation
# ---------------------------------------------------------------------------


def test_composite_pk_isolates_owners(store: PromotionStore) -> None:
    eid_a = _propose(store, owner="owner-a")
    eid_b = _propose(store, owner="owner-b")
    assert store.get(eid_a, owner_key_hash="owner-b") is None
    assert store.get(eid_b, owner_key_hash="owner-a") is None
    # ...but each owner sees their own.
    assert store.get(eid_a, owner_key_hash="owner-a") is not None
    assert store.get(eid_b, owner_key_hash="owner-b") is not None


def test_none_owner_normalized_to_legacy_sentinel(store: PromotionStore) -> None:
    eid = _propose(store, owner=None)
    # Queried with None or with the explicit sentinel must agree.
    evt_none = store.get(eid, owner_key_hash=None)
    evt_sentinel = store.get(eid, owner_key_hash="__legacy_local__")
    assert evt_none is not None
    assert evt_sentinel is not None
    assert evt_none.event_id == evt_sentinel.event_id
    # And an authenticated owner never sees it.
    assert store.get(eid, owner_key_hash="real-owner") is None


def test_list_by_skill_does_not_cross_owners(store: PromotionStore) -> None:
    _propose(store, "shared-skill", owner="alice")
    _propose(store, "shared-skill", owner="bob")
    alice_rows = store.list_by_skill("shared-skill", owner_key_hash="alice")
    bob_rows = store.list_by_skill("shared-skill", owner_key_hash="bob")
    assert len(alice_rows) == 1
    assert len(bob_rows) == 1
    assert alice_rows[0].owner_key_hash == "alice"
    assert bob_rows[0].owner_key_hash == "bob"


# ---------------------------------------------------------------------------
# state machine
# ---------------------------------------------------------------------------


def test_mark_approved_then_applied(store: PromotionStore) -> None:
    eid = _propose(store, owner="o")
    assert store.mark_approved(eid, owner_key_hash="o", decided_by="op-1") is True
    after_approve = store.get(eid, owner_key_hash="o")
    assert after_approve is not None
    assert after_approve.status == STATUS_APPROVED
    assert after_approve.decided_by == "op-1"

    assert store.mark_applied(eid, owner_key_hash="o") is True
    after_apply = store.get(eid, owner_key_hash="o")
    assert after_apply is not None
    assert after_apply.status == STATUS_APPLIED
    assert after_apply.applied_at is not None


def test_mark_applied_requires_approved(store: PromotionStore) -> None:
    eid = _propose(store, owner="o")
    # Skipping approved → False
    assert store.mark_applied(eid, owner_key_hash="o") is False
    evt = store.get(eid, owner_key_hash="o")
    assert evt is not None
    assert evt.status == STATUS_PROPOSED


def test_mark_rolled_back_requires_applied(store: PromotionStore) -> None:
    eid = _propose(store, owner="o")
    # proposed → rolled_back is illegal
    assert store.mark_rolled_back(eid, owner_key_hash="o") is False
    assert store.mark_approved(eid, owner_key_hash="o", decided_by="op") is True
    # approved → rolled_back still illegal
    assert store.mark_rolled_back(eid, owner_key_hash="o") is False
    assert store.mark_applied(eid, owner_key_hash="o") is True
    assert store.mark_rolled_back(eid, owner_key_hash="o") is True
    evt = store.get(eid, owner_key_hash="o")
    assert evt is not None
    assert evt.status == STATUS_ROLLED_BACK
    assert evt.rolled_back_at is not None


def test_mark_failed_records_failed_step(store: PromotionStore) -> None:
    eid = _propose(store, owner="o")
    ok = store.mark_failed(
        eid,
        owner_key_hash="o",
        failed_step="security",
        details={"risk_flags": ["code_execution"]},
    )
    assert ok is True
    evt = store.get(eid, owner_key_hash="o")
    assert evt is not None
    assert evt.status == STATUS_FAILED
    assert evt.details["failed_step"] == "security"
    assert evt.details["risk_flags"] == ["code_execution"]


def test_mark_rejected_from_proposed_or_approved(store: PromotionStore) -> None:
    eid1 = _propose(store, owner="o")
    assert store.mark_rejected(eid1, owner_key_hash="o", decided_by="op", reason="nope") is True
    evt1 = store.get(eid1, owner_key_hash="o")
    assert evt1 is not None
    assert evt1.status == STATUS_REJECTED
    # reason is appended, not overwritten
    assert "nope" in evt1.reason

    eid2 = _propose(store, owner="o")
    assert store.mark_approved(eid2, owner_key_hash="o", decided_by="op") is True
    assert (
        store.mark_rejected(eid2, owner_key_hash="o", decided_by="op", reason="late veto") is True
    )
    evt2 = store.get(eid2, owner_key_hash="o")
    assert evt2 is not None
    assert evt2.status == STATUS_REJECTED


def test_unknown_event_id_returns_false(store: PromotionStore) -> None:
    assert store.mark_approved("not-a-real-id", owner_key_hash="o", decided_by="op") is False
    assert store.mark_applied("not-a-real-id", owner_key_hash="o") is False


# ---------------------------------------------------------------------------
# list_open_for_skill — used for cooldown / dedup by curator & evolver
# ---------------------------------------------------------------------------


def test_list_open_skips_terminal_states(store: PromotionStore) -> None:
    # proposed → open
    eid_open = _propose(store, "sk1", owner="o")
    # applied → closed
    eid_app = _propose(store, "sk1", owner="o")
    store.mark_approved(eid_app, owner_key_hash="o", decided_by="op")
    store.mark_applied(eid_app, owner_key_hash="o")
    # rejected → closed
    eid_rej = _propose(store, "sk1", owner="o")
    store.mark_rejected(eid_rej, owner_key_hash="o", decided_by="op")
    # failed → closed
    eid_fail = _propose(store, "sk1", owner="o")
    store.mark_failed(eid_fail, owner_key_hash="o", failed_step="tests")

    open_rows = store.list_open_for_skill("sk1", owner_key_hash="o")
    open_ids = {r.event_id for r in open_rows}
    assert eid_open in open_ids
    assert eid_app not in open_ids
    assert eid_rej not in open_ids
    assert eid_fail not in open_ids


def test_approved_event_is_still_open(store: PromotionStore) -> None:
    eid = _propose(store, "sk2", owner="o")
    store.mark_approved(eid, owner_key_hash="o", decided_by="op")
    open_rows = store.list_open_for_skill("sk2", owner_key_hash="o")
    assert any(r.event_id == eid for r in open_rows)


def test_list_recent_per_owner(store: PromotionStore) -> None:
    e1 = _propose(store, "a", owner="o1")
    e2 = _propose(store, "b", owner="o1")
    _propose(store, "c", owner="o2")
    rows = store.list_recent(owner_key_hash="o1")
    ids = {r.event_id for r in rows}
    assert e1 in ids
    assert e2 in ids
    assert all(r.owner_key_hash == "o1" for r in rows)


# ---------------------------------------------------------------------------
# variant_id / artifact_path propagation (evolver use case)
# ---------------------------------------------------------------------------


def test_variant_proposal_round_trip(store: PromotionStore, tmp_path: Path) -> None:
    artifact = tmp_path / "proposals" / "variant-1" / "main.py"
    artifact.parent.mkdir(parents=True)
    artifact.write_text("# evolved\n")
    eid = store.propose(
        skill_id="skill-evo",
        from_level="community",
        to_level="community",
        source="auto_evolver",
        reason="avg_score=0.91",
        owner_key_hash="o",
        variant_id="variant-1",
        artifact_path=str(artifact),
        details={"avg_score": 0.91},
    )
    evt = store.get(eid, owner_key_hash="o")
    assert evt is not None
    assert evt.variant_id == "variant-1"
    assert evt.artifact_path == str(artifact)
    assert evt.from_level == evt.to_level == "community"
    assert evt.details["avg_score"] == 0.91


# ---------------------------------------------------------------------------
# close(): thread-local SQLite handle hygiene
# ---------------------------------------------------------------------------


def test_close_is_idempotent(store: PromotionStore) -> None:
    """close() must be safe to call multiple times (no-op after first call)."""
    # Force a connection to materialize first.
    _propose(store)
    store.close()
    # Second call must NOT raise even though _local.conn is already None.
    store.close()
    # Third call from a "cold" state — still a no-op.
    store.close()


def test_close_then_reuse_reopens_connection(store: PromotionStore) -> None:
    """After close(), the next API call must lazily reopen the connection."""
    eid = _propose(store, skill_id="reuse-skill")
    store.close()
    # If close() leaked or left a stale handle, this would raise
    # ``sqlite3.ProgrammingError: Cannot operate on a closed database``.
    events = store.list_by_skill("reuse-skill")
    assert len(events) == 1
    assert events[0].event_id == eid
    # And we can still write after re-open.
    eid2 = _propose(store, skill_id="reuse-skill-2")
    assert eid2 != eid
