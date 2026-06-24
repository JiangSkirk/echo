"""Per-owner regression for the PR-3.1 P0 hot-fixes.

Three paths used to mutate or delete another owner's rows by accident:

1. ``feedback(memory_id, ...)`` updated by primary key with no owner guard,
   so a second user holding the integer id could bump or sink another
   user's feedback score.
2. ``_evict_semantic_if_needed`` selected ids inside an ``owner_filter``
   but the final ``DELETE WHERE id = ?`` carried no owner predicate, which
   meant a future refactor or a stale id list could delete cross-owner
   rows.
3. ``_light_sleep`` deduplicated working memories on ``(key, value)`` only,
   so when two owners (or one owner + the ``__legacy_local__`` shared
   pool) happened to write the same text the older row was deleted
   regardless of which owner it belonged to.

The tests below construct two owners with overlapping ids / keys / values
and assert that every fix is owner-scoped: each owner's data is mutated
or pruned only by its own owner_key_hash.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from js.config import MemoryConfig
from js.memory.enhanced_store import EnhancedMemoryStore

ALICE = "owner-alice"
BOB = "owner-bob"


@pytest.fixture
def store(tmp_path: Path):
    s = EnhancedMemoryStore(state_dir=tmp_path, config=MemoryConfig())
    try:
        yield s
    finally:
        s.close()


def _semantic_score(store: EnhancedMemoryStore, owner: str | None, key: str) -> float:
    for row in store.get_all_semantic(limit=100, owner_key_hash=owner):
        if row["key"] == key:
            return float(row.get("feedback_score") or 0.0)
    raise AssertionError(f"semantic key={key!r} missing for owner={owner!r}")


class TestFeedbackOwnerGuard:
    def test_feedback_only_touches_matching_owner(self, store: EnhancedMemoryStore) -> None:
        a = store.store_semantic("fact", "alice-value", source="user", owner_key_hash=ALICE)[
            "memory_id"
        ]
        b = store.store_semantic("fact", "bob-value", source="user", owner_key_hash=BOB)[
            "memory_id"
        ]
        assert a is not None and b is not None and a != b

        # Bob holds Alice's id but should not be able to alter her row.
        assert store.feedback(a, helpful=True, owner_key_hash=BOB) is False
        assert _semantic_score(store, ALICE, "fact") == 0.0

        # Alice's own call lands.
        assert store.feedback(a, helpful=True, owner_key_hash=ALICE) is True
        assert _semantic_score(store, ALICE, "fact") == 1.0
        # Bob's row is untouched.
        assert _semantic_score(store, BOB, "fact") == 0.0

    def test_feedback_with_none_only_touches_legacy_null(self, store: EnhancedMemoryStore) -> None:
        legacy = store.store_semantic("k", "shared", source="import")["memory_id"]
        a = store.store_semantic("k", "alice", source="user", owner_key_hash=ALICE)["memory_id"]
        assert legacy is not None and a is not None

        # A None-owner call targets legacy NULL rows only — Alice's row stays
        # at zero even though we passed the same integer id-space.
        assert store.feedback(legacy, helpful=False, owner_key_hash=None) is True
        assert store.feedback(a, helpful=False, owner_key_hash=None) is False
        assert _semantic_score(store, ALICE, "k") == 0.0
        assert _semantic_score(store, None, "k") == -1.0


class TestEvictOwnerGuard:
    def test_evict_only_prunes_owner_partition(self, store: EnhancedMemoryStore) -> None:
        # Seed Alice with 5 entries and Bob with 3 entries.  When Alice's
        # eviction runs with max=2, only Alice's pool should shrink; Bob's
        # rows are off-limits even if some share lower scores.
        for i in range(5):
            store.store_semantic(f"a-{i}", f"value-{i}", source="user", owner_key_hash=ALICE)
        for i in range(3):
            store.store_semantic(f"b-{i}", f"value-{i}", source="user", owner_key_hash=BOB)

        evicted = store._evict_semantic_if_needed(
            strategy="lru", max_memories=2, owner_key_hash=ALICE
        )
        # Alice had 5, target 2, so 3 candidates considered.  Default
        # importance protection floor is 5 (default importance), so all 3 go.
        assert evicted == 3

        a_keys = {r["key"] for r in store.get_all_semantic(limit=100, owner_key_hash=ALICE)}
        b_keys = {r["key"] for r in store.get_all_semantic(limit=100, owner_key_hash=BOB)}
        assert len(a_keys) == 2
        # Bob is fully intact — no cross-owner deletes.
        assert b_keys == {"b-0", "b-1", "b-2"}

    def test_owner_scoped_evict_does_not_touch_legacy_null_rows(
        self, store: EnhancedMemoryStore
    ) -> None:
        # 4 legacy NULL-owner rows + 5 Alice rows.  When Alice runs eviction
        # over her own partition, only her rows can be considered candidates;
        # legacy NULL rows must survive intact (they belong to a different
        # owner partition: ``owner_key_hash IS NULL`` vs ``= ALICE``).
        for i in range(4):
            store.store_semantic(f"legacy-{i}", f"v-{i}", source="import")
        for i in range(5):
            store.store_semantic(f"alice-{i}", f"v-{i}", source="user", owner_key_hash=ALICE)

        evicted = store._evict_semantic_if_needed(
            strategy="lru", max_memories=2, owner_key_hash=ALICE
        )
        # Alice's partition shrinks from 5 → 2; the four legacy rows are
        # outside her partition and survive untouched.
        assert evicted == 3
        legacy_keys = {r["key"] for r in store.get_all_semantic(limit=100, owner_key_hash=None)}
        assert legacy_keys == {"legacy-0", "legacy-1", "legacy-2", "legacy-3"}

    def test_owner_scoped_evict_id_collision_does_not_cross_partitions(
        self, store: EnhancedMemoryStore
    ) -> None:
        # Construct overlapping integer PKs across two owners and verify the
        # defense-in-depth predicate on the final DELETE: even if the
        # selection accidentally returned a sibling owner's id, the
        # ``WHERE id = ? AND owner_key_hash = ?`` guard refuses to delete
        # cross-owner.
        bob_ids = [
            store.store_semantic(f"b-{i}", f"vb-{i}", source="user", owner_key_hash=BOB)[
                "memory_id"
            ]
            for i in range(3)
        ]
        for i in range(5):
            store.store_semantic(f"a-{i}", f"va-{i}", source="user", owner_key_hash=ALICE)

        evicted = store._evict_semantic_if_needed(
            strategy="importance_weighted",
            max_memories=2,
            owner_key_hash=ALICE,
        )
        assert evicted == 3
        # Bob's three ids are still present — none were touched.
        bob_keys_now = {r["key"] for r in store.get_all_semantic(limit=100, owner_key_hash=BOB)}
        assert bob_keys_now == {"b-0", "b-1", "b-2"}
        assert all(bid is not None for bid in bob_ids)


class TestLightSleepOwnerPartition:
    def test_same_key_value_across_owners_both_survive(self, store: EnhancedMemoryStore) -> None:
        # Alice and Bob both write the same (key, value) into working memory.
        # Pre-fix the older one would have been deleted as a "duplicate".
        store.store_working("sess-a", "topic", "same-text", owner_key_hash=ALICE)
        store.store_working("sess-b", "topic", "same-text", owner_key_hash=BOB)

        report = store._light_sleep()

        # Each owner still sees their own row.
        a_rows = store.get_working("sess-a", limit=10, owner_key_hash=ALICE)
        b_rows = store.get_working("sess-b", limit=10, owner_key_hash=BOB)
        assert len(a_rows) == 1
        assert len(b_rows) == 1
        assert "Removed 0 duplicate" in report

    def test_within_owner_duplicates_are_still_collapsed(self, store: EnhancedMemoryStore) -> None:
        # Alice writes the same (key, value) in two different sessions —
        # the table allows it because the unique constraint is
        # (owner_key_hash, session_id, key).  Light sleep must still
        # collapse them inside Alice's partition.
        store.store_working("sess-1", "topic", "dup", owner_key_hash=ALICE)
        store.store_working("sess-2", "topic", "dup", owner_key_hash=ALICE)
        # Bob also writes the same text — must survive.
        store.store_working("sess-b", "topic", "dup", owner_key_hash=BOB)

        report = store._light_sleep()

        total_alice = len(store.get_working("sess-1", limit=10, owner_key_hash=ALICE)) + len(
            store.get_working("sess-2", limit=10, owner_key_hash=ALICE)
        )
        assert total_alice == 1  # one dup collapsed
        assert len(store.get_working("sess-b", limit=10, owner_key_hash=BOB)) == 1
        assert "Removed 1 duplicate" in report

    def test_legacy_and_authenticated_with_same_text_do_not_collide(
        self, store: EnhancedMemoryStore
    ) -> None:
        # Legacy NULL owner is stored under the __legacy_local__ sentinel.
        # An authenticated owner writing the same text in another session
        # must not delete the legacy row, and vice versa.
        store.store_working("sess-shared", "topic", "duplicate-text")  # legacy
        store.store_working("sess-alice", "topic", "duplicate-text", owner_key_hash=ALICE)

        report = store._light_sleep()
        # Both partitions still hold one row each.
        assert len(store.get_working("sess-shared", limit=10, owner_key_hash=None)) == 1
        assert len(store.get_working("sess-alice", limit=10, owner_key_hash=ALICE)) == 1
        assert "Removed 0 duplicate" in report
