"""Tests for memory audit log, conflict detection, and trustworthiness."""

from __future__ import annotations

from pathlib import Path

import pytest

from js.config import MemoryConfig
from js.memory.enhanced_store import EnhancedMemoryStore


@pytest.fixture
def store(tmp_path: Path) -> EnhancedMemoryStore:
    """Create an isolated EnhancedMemoryStore for testing."""
    config = MemoryConfig(enabled=True)
    store = EnhancedMemoryStore(state_dir=tmp_path, config=config)
    yield store
    store.close()


class TestMemoryAuditLog:
    """Tests for memory audit logging."""

    def test_create_generates_audit(self, store: EnhancedMemoryStore) -> None:
        store.store_semantic(key="test-key", value="test-value", source="user")
        audits = store.get_audit_log(memory_id=1, limit=10)
        assert len(audits) == 1
        assert audits[0]["action"] == "create"
        assert audits[0]["source"] == "user"
        assert audits[0]["new_value"] == "test-value"

    def test_update_generates_audit(self, store: EnhancedMemoryStore) -> None:
        store.store_semantic(key="test-key", value="original", source="agent")
        store.update_semantic(1, "updated", source="user")
        audits = store.get_audit_log(memory_id=1, limit=10)
        assert len(audits) == 2
        # First: create, Second: update
        assert audits[0]["action"] == "update"
        assert "original" in audits[0]["old_value"]
        assert "updated" in audits[0]["new_value"]

    def test_delete_generates_audit(self, store: EnhancedMemoryStore) -> None:
        store.store_semantic(key="test-key", value="to-delete", source="agent")
        store.delete_semantic(1, source="user")
        audits = store.get_audit_log(memory_id=1, limit=10)
        assert len(audits) == 2
        assert audits[0]["action"] == "delete"
        assert audits[0]["old_value"] == "to-delete"

    def test_upsert_generates_update_audit(self, store: EnhancedMemoryStore) -> None:
        store.store_semantic(key="test-key", value="first", source="agent")
        store.store_semantic(key="test-key", value="second", source="user")
        audits = store.get_audit_log(memory_id=1, limit=10)
        assert len(audits) == 2
        assert audits[0]["action"] == "update"
        assert audits[0]["old_value"] == "first"
        assert audits[0]["new_value"] == "second"

    def test_audit_returns_empty_for_unknown(self, store: EnhancedMemoryStore) -> None:
        audits = store.get_audit_log(memory_id=999, limit=10)
        assert audits == []


class TestMemoryConfidenceDefaults:
    """Tests for source-based confidence defaults."""

    def test_user_source_high_confidence(self, store: EnhancedMemoryStore) -> None:
        store.store_semantic(key="k1", value="v1", source="user")
        memories = store.get_all_semantic(limit=10)
        assert len(memories) == 1
        assert memories[0]["confidence"] == 1.0

    def test_agent_source_medium_confidence(self, store: EnhancedMemoryStore) -> None:
        store.store_semantic(key="k1", value="v1", source="agent")
        memories = store.get_all_semantic(limit=10)
        assert len(memories) == 1
        assert memories[0]["confidence"] == 0.7

    def test_dream_source_low_confidence(self, store: EnhancedMemoryStore) -> None:
        store.store_semantic(key="k1", value="v1", source="dream")
        memories = store.get_all_semantic(limit=10)
        assert len(memories) == 1
        assert memories[0]["confidence"] == 0.5

    def test_explicit_confidence_overrides(self, store: EnhancedMemoryStore) -> None:
        store.store_semantic(key="k1", value="v1", source="user", confidence=0.3)
        memories = store.get_all_semantic(limit=10)
        assert len(memories) == 1
        assert memories[0]["confidence"] == 0.3


class TestMemoryAutoResolve:
    """Tests for automatic conflict resolution (zero-user-intervention)."""

    def test_same_value_no_conflict(self, store: EnhancedMemoryStore) -> None:
        store.store_semantic(key="key1", value="same", category="fact")
        store.store_semantic(key="key2", value="same", category="fact")
        conflicts = store.get_conflicting_memories(limit=10)
        assert len(conflicts) == 0

    def test_same_key_upsert_no_conflict(self, store: EnhancedMemoryStore) -> None:
        """Updating the same key should not trigger conflict resolution."""
        store.store_semantic(key="user likes coffee", value="yes", category="preference")
        store.store_semantic(key="user likes coffee", value="no", category="preference")
        memories = store.get_all_semantic(limit=10)
        assert len(memories) == 1
        assert memories[0]["value"] == "no"

    def test_auto_resolve_dedupe_similar_values(self, store: EnhancedMemoryStore) -> None:
        """Near-duplicate values are deduped, keeping the higher-confidence one."""
        store.store_semantic(key="coffee user likes", value="yes", source="agent")
        store.store_semantic(key="user likes coffee", value="yes", source="user")
        memories = store.get_all_semantic(limit=10)
        assert len(memories) == 1
        assert memories[0]["value"] == "yes"
        assert memories[0]["source"] == "user"
        # Audit log should show the old one was auto-deleted
        audits = store.get_audit_log(memory_id=1, limit=10)
        assert any(a["action"] == "delete" and a["source"] == "auto_resolve" for a in audits)

    def test_auto_resolve_user_wins(self, store: EnhancedMemoryStore) -> None:
        """Existing user memory is sacred; conflicting agent memory is dropped."""
        store.store_semantic(key="coffee user likes", value="user-says", source="user")
        result = store.store_semantic(key="user likes coffee", value="agent-says", source="agent")
        # New memory should be dropped
        assert result.get("dropped") is True
        memories = store.get_all_semantic(limit=10)
        assert len(memories) == 1
        assert memories[0]["value"] == "user-says"

    def test_auto_resolve_high_confidence_overwrites(self, store: EnhancedMemoryStore) -> None:
        """A significantly more trustworthy memory overwrites the old one."""
        store.store_semantic(key="coffee user likes", value="old", source="agent")
        store.store_semantic(key="user likes coffee", value="new", source="user")
        memories = store.get_all_semantic(limit=10)
        assert len(memories) == 1
        assert memories[0]["value"] == "new"
        assert memories[0]["source"] == "user"

    def test_auto_resolve_coexist_when_unclear(self, store: EnhancedMemoryStore) -> None:
        """When neither memory clearly wins, both are kept."""
        store.store_semantic(key="coffee user likes", value="old", source="agent")
        store.store_semantic(key="user likes coffee", value="new", source="agent")
        memories = store.get_all_semantic(limit=10)
        assert len(memories) == 2
        values = {m["value"] for m in memories}
        assert values == {"old", "new"}
