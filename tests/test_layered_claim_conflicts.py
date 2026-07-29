"""Claim conflict state machine tests."""

from __future__ import annotations

from pathlib import Path

from js.memory.layered.conflict import decide_claim_conflict
from js.memory.layered.store import LayeredMemoryStore


def test_decide_no_existing_activates() -> None:
    d = decide_claim_conflict(existing_value=None, incoming_value="x", explicit_correction=False)
    assert d.new_status == "active"
    assert d.retire_existing_as is None


def test_decide_same_value_is_candidate() -> None:
    d = decide_claim_conflict(
        existing_value="peanuts", incoming_value="peanuts", explicit_correction=False
    )
    assert d.new_status == "candidate"


def test_decide_implicit_conflict_disputed() -> None:
    d = decide_claim_conflict(
        existing_value="peanuts",
        incoming_value="tree nuts",
        explicit_correction=False,
    )
    assert d.new_status == "disputed"
    assert d.retire_existing_as == "disputed"


def test_decide_explicit_correction_supersedes() -> None:
    d = decide_claim_conflict(
        existing_value="peanuts",
        incoming_value="tree nuts",
        explicit_correction=True,
    )
    assert d.new_status == "active"
    assert d.retire_existing_as == "superseded"


def test_store_implicit_conflict_marks_disputed(tmp_path: Path) -> None:
    store = LayeredMemoryStore(tmp_path / "m.db")
    first = store.upsert_claim_from_semantic(
        owner_key_hash="o1",
        key="allergy",
        value="peanuts",
        entity_name="user",
        explicit_correction=True,
    )
    assert first["status"] == "active"
    second = store.upsert_claim_from_semantic(
        owner_key_hash="o1",
        key="allergy",
        value="shellfish",
        entity_name="user",
        explicit_correction=False,
    )
    assert second["status"] == "disputed"
    active = store.list_active_claims(owner_key_hash="o1")
    assert active == []


def test_store_explicit_correction_supersedes(tmp_path: Path) -> None:
    store = LayeredMemoryStore(tmp_path / "m.db")
    first = store.upsert_claim_from_semantic(
        owner_key_hash="o1",
        key="allergy",
        value="peanuts",
        entity_name="user",
        explicit_correction=True,
    )
    second = store.upsert_claim_from_semantic(
        owner_key_hash="o1",
        key="allergy",
        value="shellfish",
        entity_name="user",
        explicit_correction=True,
    )
    assert second["status"] == "active"
    assert first["claim_id"] in second["superseded"]
    active = store.list_active_claims(owner_key_hash="o1")
    assert len(active) == 1
    assert active[0].typed_value == "shellfish"
    assert store.retire_claim(active[0].id, owner_key_hash="o1")
    assert store.list_active_claims(owner_key_hash="o1") == []
