"""Cross-user isolation tests for the hierarchical memory library.

Verifies that ``owner_key_hash`` partitions semantic memories and proposals:
one user never sees, edits, or evicts another's data, while legacy NULL-owner
rows remain shared (visible to everyone) for backward compatibility.
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
        assert len(store.get_all_semantic(limit=100, owner_key_hash=None)) == 2

    def test_legacy_null_owner_visible_to_all(self, store: EnhancedMemoryStore) -> None:
        store.store_semantic("shared", "公共知识", source="import")  # owner None
        store.store_semantic("private_a", "仅A", source="user", owner_key_hash=A)
        a_keys = {m["key"] for m in store.get_all_semantic(owner_key_hash=A)}
        b_keys = {m["key"] for m in store.get_all_semantic(owner_key_hash=B)}
        assert "shared" in a_keys and "shared" in b_keys
        assert "private_a" in a_keys and "private_a" not in b_keys

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

    def test_context_string_excludes_other_owner(self, store: EnhancedMemoryStore) -> None:
        store.store_semantic("秘密", "Alice的银行卡尾号1234", category="fact",
                             source="user", owner_key_hash=A)
        ctx_b = store.get_context_string(query="银行卡", owner_key_hash=B, max_chars=2000)
        assert "1234" not in ctx_b


class TestProposalIsolation:
    def test_proposals_owner_scoped(self, store: EnhancedMemoryStore) -> None:
        store.propose_change(action="create", key="生日", value="1990",
                             confidence=0.9, owner_key_hash=A)  # sensitive → pending
        assert len(store.list_proposals(owner_key_hash=A)) == 1
        assert len(store.list_proposals(owner_key_hash=B)) == 0

    def test_other_owner_cannot_approve(self, store: EnhancedMemoryStore) -> None:
        res = store.propose_change(action="create", key="生日", value="1990",
                                   confidence=0.9, owner_key_hash=A)
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
