"""Cross-user isolation tests for the hierarchical memory library.

Verifies that ``owner_key_hash`` partitions semantic memories and proposals:
one user never sees, edits, or evicts another's data.  Legacy NULL-owner rows
are migrated to the ``__legacy_local__`` sentinel and are no longer visible to
authenticated owners.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from js.config import MemoryConfig
from js.memory.enhanced_store import EnhancedMemoryStore

A = "owner-aaa"
B = "owner-bbb"


@pytest.fixture
def store(tmp_path: Path) -> EnhancedMemoryStore:
    store = EnhancedMemoryStore(state_dir=tmp_path, config=MemoryConfig())
    yield store
    store.close()


class TestSemanticIsolation:
    def test_get_all_is_owner_scoped(self, store: EnhancedMemoryStore) -> None:
        store.store_semantic("k", "alice-value", source="user", owner_key_hash=A)
        store.store_semantic("k", "bob-value", source="user", owner_key_hash=B)
        a_vals = {m["value"] for m in store.get_all_semantic(owner_key_hash=A)}
        b_vals = {m["value"] for m in store.get_all_semantic(owner_key_hash=B)}
        assert a_vals == {"alice-value"}
        assert b_vals == {"bob-value"}

    def test_same_key_coexists_across_owners(self, store: EnhancedMemoryStore) -> None:
        store.store_semantic("favorite", "tea", source="user", owner_key_hash=A)
        store.store_semantic("favorite", "coffee", source="user", owner_key_hash=B)
        # Two distinct rows, not an overwrite.
        assert len(store.get_all_semantic(limit=100, owner_key_hash=A)) == 1
        assert len(store.get_all_semantic(limit=100, owner_key_hash=B)) == 1

    def test_legacy_null_owner_visible_to_all(self, store: EnhancedMemoryStore) -> None:
        store.store_semantic("shared", "公共知识", source="import")  # owner None
        store.store_semantic("private_a", "仅A", source="user", owner_key_hash=A)
        a_keys = {m["key"] for m in store.get_all_semantic(owner_key_hash=A)}
        b_keys = {m["key"] for m in store.get_all_semantic(owner_key_hash=B)}
        # Legacy NULL-owner rows are now isolated to the __legacy_local__ sentinel
        # and must not be visible to authenticated owners.
        assert "shared" not in a_keys
        assert "shared" not in b_keys
        assert "private_a" in a_keys and "private_a" not in b_keys
        # No-auth / local anonymous queries see the sentinel-owned legacy row.
        legacy_keys = {m["key"] for m in store.get_all_semantic(owner_key_hash=None)}
        assert "shared" in legacy_keys

    def test_search_is_owner_scoped(self, store: EnhancedMemoryStore) -> None:
        store.store_semantic("project_x", "Alice's secret project", source="user", owner_key_hash=A)
        results = store.search_semantic("project", owner_key_hash=B)
        assert all(m.owner_key_hash != A for m in results)
        assert not any("Alice" in m.value for m in results)

    def test_blocks_are_owner_scoped(self, store: EnhancedMemoryStore) -> None:
        store.store_semantic("老婆", "小红", source="user", owner_key_hash=A)
        a_blocks = {b["block_path"] for b in store.get_blocks(owner_key_hash=A)}
        b_blocks = {b["block_path"] for b in store.get_blocks(owner_key_hash=B)}
        assert "/people" in a_blocks
        assert "/people" not in b_blocks

    def test_authenticated_semantic_write_does_not_touch_legacy_or_other_owner(
        self, store: EnhancedMemoryStore
    ) -> None:
        """Auto-conflict resolution must not delete/update legacy NULL or other-owner rows."""
        # Legacy NULL-owner shared row.
        store.store_semantic("favorite", "tea", source="import")
        # Other owner's row with a similar key.
        store.store_semantic("favorite drink", "coffee", source="user", owner_key_hash=B)

        # Owner A writes a similar key; conflict detection should only consider A's rows.
        result = store.store_semantic("favorite", "oolong", source="user", owner_key_hash=A)
        assert result["memory_id"] is not None

        # Legacy row must remain intact and visible to no-auth queries.
        legacy = store.get_all_semantic(owner_key_hash=None)
        assert any(m["key"] == "favorite" and m["value"] == "tea" for m in legacy)

        # Owner B's row must remain intact.
        b_rows = store.get_all_semantic(owner_key_hash=B)
        assert any(m["key"] == "favorite drink" and m["value"] == "coffee" for m in b_rows)

        # Owner A sees only their own row.
        a_rows = store.get_all_semantic(owner_key_hash=A)
        assert any(m["key"] == "favorite" and m["value"] == "oolong" for m in a_rows)
        assert len(a_rows) == 1

    def test_delete_guard_blocks_other_owner(self, store: EnhancedMemoryStore) -> None:
        store.store_semantic("k", "alice", source="user", owner_key_hash=A)
        row = store.get_all_semantic(owner_key_hash=A)[0]
        assert store.delete_semantic(row["id"], owner_key_hash=B) is False
        assert store.delete_semantic(row["id"], owner_key_hash=A) is True

    def test_update_guard_blocks_other_owner(self, store: EnhancedMemoryStore) -> None:
        store.store_semantic("k", "alice", source="user", owner_key_hash=A)
        row = store.get_all_semantic(owner_key_hash=A)[0]
        assert store.update_semantic(row["id"], "hacked", owner_key_hash=B) is False
        assert store.update_semantic(row["id"], "edited", owner_key_hash=A) is True

    def test_verify_guard_blocks_other_owner(self, store: EnhancedMemoryStore) -> None:
        store.store_semantic("k", "alice", source="agent", owner_key_hash=A)
        row = store.get_all_semantic(owner_key_hash=A)[0]
        assert store.verify_semantic(row["id"], owner_key_hash=B) is False
        assert store.verify_semantic(row["id"], owner_key_hash=A) is True

    def test_no_auth_cannot_modify_authenticated_owner_rows(
        self, store: EnhancedMemoryStore
    ) -> None:
        store.store_semantic("k", "alice", source="user", owner_key_hash=A)
        row = store.get_all_semantic(owner_key_hash=A)[0]

        assert store.update_semantic(row["id"], "hacked", owner_key_hash=None) is False
        assert store.delete_semantic(row["id"], owner_key_hash=None) is False
        assert store.verify_semantic(row["id"], owner_key_hash=None) is False

        a_rows = store.get_all_semantic(owner_key_hash=A)
        assert len(a_rows) == 1
        assert a_rows[0]["value"] == "alice"

    def test_audit_log_is_owner_scoped(self, store: EnhancedMemoryStore) -> None:
        a_id = store.store_semantic("audit", "alice-old", source="user", owner_key_hash=A)[
            "memory_id"
        ]
        b_id = store.store_semantic("audit", "bob-old", source="user", owner_key_hash=B)[
            "memory_id"
        ]
        legacy_id = store.store_semantic("audit-legacy", "legacy-old", source="import")[
            "memory_id"
        ]

        assert store.update_semantic(a_id, "alice-new", owner_key_hash=A) is True
        assert store.update_semantic(b_id, "bob-new", owner_key_hash=B) is True
        assert store.update_semantic(legacy_id, "legacy-new", owner_key_hash=None) is True

        a_entries = store.get_audit_log(table_name="semantic", limit=20, owner_key_hash=A)
        b_entries = store.get_audit_log(table_name="semantic", limit=20, owner_key_hash=B)
        legacy_entries = store.get_audit_log(
            table_name="semantic", limit=20, owner_key_hash=None
        )

        a_text = "\n".join(str(e.get("old_value")) + str(e.get("new_value")) for e in a_entries)
        b_text = "\n".join(str(e.get("old_value")) + str(e.get("new_value")) for e in b_entries)
        legacy_text = "\n".join(
            str(e.get("old_value")) + str(e.get("new_value")) for e in legacy_entries
        )

        assert "alice-old" in a_text and "alice-new" in a_text
        assert "bob-old" not in a_text and "legacy-old" not in a_text

        assert "bob-old" in b_text and "bob-new" in b_text
        assert "alice-old" not in b_text and "legacy-old" not in b_text

        assert "legacy-old" in legacy_text and "legacy-new" in legacy_text
        assert "alice-old" not in legacy_text and "bob-old" not in legacy_text

    def test_context_string_excludes_other_owner(self, store: EnhancedMemoryStore) -> None:
        store.store_semantic(
            "秘密", "Alice的银行卡尾号1234", category="fact", source="user", owner_key_hash=A
        )
        ctx_b = store.get_context_string(query="银行卡", owner_key_hash=B, max_chars=2000)
        assert "1234" not in ctx_b


class TestProposalIsolation:
    def test_proposals_owner_scoped(self, store: EnhancedMemoryStore) -> None:
        store.propose_change(
            action="create", key="生日", value="1990", confidence=0.9, owner_key_hash=A
        )  # sensitive → pending
        assert len(store.list_proposals(owner_key_hash=A)) == 1
        assert len(store.list_proposals(owner_key_hash=B)) == 0

    def test_other_owner_cannot_approve(self, store: EnhancedMemoryStore) -> None:
        res = store.propose_change(
            action="create", key="生日", value="1990", confidence=0.9, owner_key_hash=A
        )
        pid = res["proposal_id"]
        assert store.approve_proposal(pid, owner_key_hash=B)["success"] is False
        assert store.approve_proposal(pid, owner_key_hash=A)["success"] is True

    def test_eviction_does_not_cross_owners(self, store: EnhancedMemoryStore) -> None:
        # B has one memory; flooding A's partition past the limit must not evict B's.
        store.store_semantic("b_keep", "B's only memory", source="user", owner_key_hash=B)
        for _ in range(5):
            store._evict_semantic_if_needed(max_memories=0, owner_key_hash=A)
        # B's memory survives an owner-A eviction sweep.
        assert any(m["key"] == "b_keep" for m in store.get_all_semantic(owner_key_hash=B))


class TestDeepSleepIsolation:
    @pytest.mark.asyncio
    async def test_dream_promotion_is_owner_scoped(self, store: EnhancedMemoryStore) -> None:
        """Deep sleep must promote working memories only into the same owner's semantic partition."""
        store.store_working("session", "promote_a", "value a", importance=8, owner_key_hash=A)
        store.store_working("session", "promote_b", "value b", importance=8, owner_key_hash=B)
        store.store_working(
            "session", "promote_legacy", "value legacy", importance=8, owner_key_hash=None
        )

        await store.dream()

        a_keys = {m["key"] for m in store.get_all_semantic(owner_key_hash=A)}
        b_keys = {m["key"] for m in store.get_all_semantic(owner_key_hash=B)}
        legacy_keys = {m["key"] for m in store.get_all_semantic(owner_key_hash=None)}

        assert "promote_a" in a_keys
        assert "promote_b" not in a_keys
        assert "promote_legacy" not in a_keys

        assert "promote_b" in b_keys
        assert "promote_a" not in b_keys
        assert "promote_legacy" not in b_keys

        # No-auth / local anonymous queries see only the legacy partition.
        assert legacy_keys == {"promote_legacy"}
