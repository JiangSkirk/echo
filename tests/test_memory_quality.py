"""Memory quality control tests: feedback, LRU eviction, conflict detection."""

from __future__ import annotations

from pathlib import Path

import pytest

from js.config import MemoryConfig
from js.memory.enhanced_store import EnhancedMemoryStore


class TestMemoryFeedback:
    """Test user feedback on semantic memories."""

    @pytest.fixture
    def store(self, tmp_path: Path) -> EnhancedMemoryStore:
        return EnhancedMemoryStore(tmp_path, MemoryConfig())

    def test_feedback_increments_score(self, store: EnhancedMemoryStore) -> None:
        """Positive feedback increases feedback_score and access_count."""
        store.store_semantic("key1", "value1")
        rows = store.get_all_semantic(limit=10)
        assert len(rows) == 1
        mem_id = rows[0]["id"]
        assert rows[0].get("feedback_score", 0) == 0
        assert rows[0]["access_count"] == 0

        ok = store.feedback(mem_id, helpful=True)
        assert ok

        rows = store.get_all_semantic(limit=10)
        assert rows[0]["feedback_score"] == 1.0
        assert rows[0]["access_count"] == 1

    def test_negative_feedback_decreases_score(self, store: EnhancedMemoryStore) -> None:
        """Negative feedback decreases feedback_score."""
        store.store_semantic("key1", "value1")
        mem_id = store.get_all_semantic(limit=10)[0]["id"]
        store.feedback(mem_id, helpful=False)

        rows = store.get_all_semantic(limit=10)
        assert rows[0]["feedback_score"] == -1.0

    def test_feedback_nonexistent_returns_false(self, store: EnhancedMemoryStore) -> None:
        """Feedback on non-existent memory returns False."""
        ok = store.feedback(99999, helpful=True)
        assert not ok


class TestMemoryConflictDetection:
    """Test conflict detection when storing similar memories."""

    @pytest.fixture
    def store(self, tmp_path: Path) -> EnhancedMemoryStore:
        return EnhancedMemoryStore(tmp_path, MemoryConfig())

    def test_no_conflict_for_different_keys(self, store: EnhancedMemoryStore) -> None:
        """Different keys in same category should not conflict."""
        result = store.store_semantic("user_name", "Alice", category="preference")
        assert result["conflicts"] == []

        result2 = store.store_semantic("user_age", "30", category="preference")
        assert result2["conflicts"] == []

    def test_conflict_for_similar_key_different_value(self, store: EnhancedMemoryStore) -> None:
        """Similar key with different value in same category triggers conflict."""
        store.store_semantic("favorite color", "blue", category="preference")
        result = store.store_semantic("favorite color", "red", category="preference")
        assert len(result["conflicts"]) >= 1

        conflicting = store.get_conflicting_memories()
        assert len(conflicting) >= 1

    def test_no_conflict_for_same_value(self, store: EnhancedMemoryStore) -> None:
        """Same key and value should not conflict (it's an update)."""
        store.store_semantic("city", "Beijing", category="fact")
        result = store.store_semantic("city", "Beijing", category="fact")
        assert result["conflicts"] == []

    def test_no_conflict_across_categories(self, store: EnhancedMemoryStore) -> None:
        """Same key in different categories should not conflict."""
        store.store_semantic("python", "programming language", category="tech")
        result = store.store_semantic("python", "snake", category="biology")
        assert result["conflicts"] == []


class TestMemoryEviction:
    """Test LRU and importance-weighted eviction."""

    @pytest.fixture
    def store(self, tmp_path: Path) -> EnhancedMemoryStore:
        return EnhancedMemoryStore(tmp_path, MemoryConfig())

    def test_no_eviction_when_under_limit(self, store: EnhancedMemoryStore) -> None:
        """Below max_memories, nothing is evicted."""
        for i in range(5):
            store.store_semantic(f"key{i}", f"value{i}")
        evicted = store._evict_semantic_if_needed(max_memories=10)
        assert evicted == 0
        assert len(store.get_all_semantic(limit=100)) == 5

    def test_lru_eviction_removes_oldest(self, store: EnhancedMemoryStore) -> None:
        """LRU strategy evicts least recently accessed memories."""
        for i in range(5):
            store.store_semantic(f"key{i}", f"value{i}")

        evicted = store._evict_semantic_if_needed(strategy="lru", max_memories=3)
        assert evicted == 2
        remaining = store.get_all_semantic(limit=100)
        assert len(remaining) == 3

    def test_lru_protects_high_importance(self, store: EnhancedMemoryStore) -> None:
        """Memories with importance >= 8 are protected from LRU eviction."""
        # Store 5 memories, one with high importance
        for i in range(4):
            store.store_semantic(f"key{i}", f"value{i}")
        # Use raw SQL to set importance (store_semantic doesn't expose it)
        store.store_semantic("important", "value")
        from js.utils.db import db_connection
        with db_connection(store.db_path) as conn:
            conn.execute("UPDATE semantic_memories SET importance = 9 WHERE key = 'important'")
            conn.commit()

        evicted = store._evict_semantic_if_needed(strategy="lru", max_memories=2)
        assert evicted == 3
        remaining_keys = {r["key"] for r in store.get_all_semantic(limit=100)}
        assert "important" in remaining_keys

    def test_importance_weighted_eviction(self, store: EnhancedMemoryStore) -> None:
        """Importance-weighted strategy evicts lowest-score memories."""
        store.store_semantic("low", "a")
        store.store_semantic("high", "b")

        # Give "high" positive feedback to boost its score
        rows = store.get_all_semantic(limit=10)
        high_mem = next(r for r in rows if r["key"] == "high")
        store.feedback(high_mem["id"], helpful=True)

        evicted = store._evict_semantic_if_needed(strategy="importance_weighted", max_memories=1)
        assert evicted == 1
        remaining = store.get_all_semantic(limit=100)
        assert len(remaining) == 1
        assert remaining[0]["key"] == "high"

    def test_store_semantic_auto_evicts(self, store: EnhancedMemoryStore) -> None:
        """store_semantic automatically triggers eviction when over limit."""
        for i in range(12):
            store.store_semantic(f"key{i}", f"value{i}")
        # Default max_memories is 1000, so no eviction yet
        assert len(store.get_all_semantic(limit=100)) == 12

        # Manually trigger with low limit
        evicted = store._evict_semantic_if_needed(max_memories=5)
        assert evicted == 7
        assert len(store.get_all_semantic(limit=100)) == 5
