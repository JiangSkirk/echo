"""Tests for structured hierarchical block-based memory system."""

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


class TestAutoBlockInference:
    """Tests for automatic memory block classification."""

    def test_auto_infer_family_block(self, store: EnhancedMemoryStore) -> None:
        """Keywords like 'wife' should auto-route to /people/family."""
        store.store_semantic(key="wife_name", value="Alice", source="user")
        mem = store.get_all_semantic(limit=10)[0]
        assert mem["memory_path"] == "/people/family"
        assert mem["entity_type"] == "family"

    def test_auto_infer_family_block_chinese(self, store: EnhancedMemoryStore) -> None:
        """Chinese keywords like '老婆' should auto-route to /people/family."""
        store.store_semantic(key="老婆姓名", value="小红", source="user")
        mem = store.get_all_semantic(limit=10)[0]
        assert mem["memory_path"] == "/people/family"
        assert mem["entity_type"] == "family"
        assert mem["relation_type"] == "has"

    def test_auto_infer_preference_block(self, store: EnhancedMemoryStore) -> None:
        """Keywords like 'favorite' should auto-route to /user/preferences."""
        store.store_semantic(key="favorite_color", value="blue", source="user")
        mem = store.get_all_semantic(limit=10)[0]
        assert mem["memory_path"] == "/user/preferences"
        assert mem["entity_type"] == "preference"

    def test_auto_infer_preference_block_chinese(self, store: EnhancedMemoryStore) -> None:
        """Chinese keywords like '喜欢' should auto-route to /user/preferences."""
        store.store_semantic(key="喜欢的颜色", value="蓝色", source="user")
        mem = store.get_all_semantic(limit=10)[0]
        assert mem["memory_path"] == "/user/preferences"
        assert mem["entity_type"] == "preference"
        assert mem["relation_type"] == "prefers"

    def test_auto_infer_project_block(self, store: EnhancedMemoryStore) -> None:
        """Keywords like 'project' should auto-route to /work/projects."""
        store.store_semantic(key="project_alpha_status", value="in_progress", source="agent")
        mem = store.get_all_semantic(limit=10)[0]
        assert mem["memory_path"] == "/work/projects"
        assert mem["entity_type"] == "project"

    def test_auto_infer_project_block_chinese(self, store: EnhancedMemoryStore) -> None:
        """Chinese keywords like '项目' should auto-route to /work/projects."""
        store.store_semantic(key="项目进度", value="进行中", source="agent")
        mem = store.get_all_semantic(limit=10)[0]
        assert mem["memory_path"] == "/work/projects"
        assert mem["entity_type"] == "project"
        assert mem["relation_type"] == "part_of"

    def test_auto_infer_device_block(self, store: EnhancedMemoryStore) -> None:
        """Keywords like 'laptop' should auto-route to /user/devices."""
        store.store_semantic(key="laptop_model", value="MacBook Pro", source="user")
        mem = store.get_all_semantic(limit=10)[0]
        assert mem["memory_path"] == "/user/devices"
        assert mem["entity_type"] == "device"

    def test_auto_infer_identity_block(self, store: EnhancedMemoryStore) -> None:
        """Keywords like 'birthday' should auto-route to /user/identity."""
        store.store_semantic(key="user_birthday", value="1990-01-01", source="user")
        mem = store.get_all_semantic(limit=10)[0]
        assert mem["memory_path"] == "/user/identity"
        assert mem["entity_type"] == "identity"

    def test_auto_infer_company_block(self, store: EnhancedMemoryStore) -> None:
        """Keywords like 'company' should auto-route to /work/company."""
        store.store_semantic(key="company_name", value="Acme Corp", source="user")
        mem = store.get_all_semantic(limit=10)[0]
        assert mem["memory_path"] == "/work/company"
        assert mem["entity_type"] == "company"

    def test_auto_infer_colleague_block(self, store: EnhancedMemoryStore) -> None:
        """Keywords like 'boss' should auto-route to /work/colleagues."""
        store.store_semantic(key="boss_name", value="Bob", source="user")
        mem = store.get_all_semantic(limit=10)[0]
        assert mem["memory_path"] == "/work/colleagues"
        assert mem["entity_type"] == "colleague"

    def test_auto_infer_event_block(self, store: EnhancedMemoryStore) -> None:
        """Keywords like 'meeting' should auto-route to /user/events."""
        store.store_semantic(key="meeting_time", value="10:00 AM", source="agent")
        mem = store.get_all_semantic(limit=10)[0]
        assert mem["memory_path"] == "/user/events"
        assert mem["entity_type"] == "event"

    def test_auto_infer_location_block(self, store: EnhancedMemoryStore) -> None:
        """Keywords like 'city' should auto-route to /user/locations."""
        store.store_semantic(key="home_city", value="Shanghai", source="user")
        mem = store.get_all_semantic(limit=10)[0]
        assert mem["memory_path"] == "/user/locations"
        assert mem["entity_type"] == "location"

    def test_default_general_block(self, store: EnhancedMemoryStore) -> None:
        """Unmatched keywords should route to /general."""
        store.store_semantic(key="xyz_unknown", value="something", source="agent")
        mem = store.get_all_semantic(limit=10)[0]
        assert mem["memory_path"] == "/general"
        assert mem["entity_type"] == "general"

    def test_explicit_path_overrides_inference(self, store: EnhancedMemoryStore) -> None:
        """User-provided path should bypass auto-inference."""
        store.store_semantic(
            key="custom", value="val", source="user",
            memory_path="/custom/block", entity_type="custom",
        )
        mem = store.get_all_semantic(limit=10)[0]
        assert mem["memory_path"] == "/custom/block"
        assert mem["entity_type"] == "custom"

    def test_user_source_sets_last_verified(self, store: EnhancedMemoryStore) -> None:
        """User-provided memories should have last_verified_at set."""
        store.store_semantic(key="test", value="v", source="user")
        mem = store.get_all_semantic(limit=10)[0]
        assert mem["last_verified_at"] > 0

    def test_agent_source_does_not_set_last_verified(self, store: EnhancedMemoryStore) -> None:
        """Agent-provided memories should not have last_verified_at set."""
        store.store_semantic(key="test", value="v", source="agent")
        mem = store.get_all_semantic(limit=10)[0]
        assert mem["last_verified_at"] == 0


class TestBlockRetrieval:
    """Tests for block-based memory retrieval."""

    def test_block_prefix_search(self, store: EnhancedMemoryStore) -> None:
        """search_semantic with path_prefix should filter correctly."""
        store.store_semantic(key="a", value="1", memory_path="/user/preferences")
        store.store_semantic(key="b", value="2", memory_path="/work/projects")
        results = store.search_semantic("", path_prefix="/user")
        assert len(results) == 1
        assert results[0].memory_path.startswith("/user")

    def test_get_blocks_grouping(self, store: EnhancedMemoryStore) -> None:
        """get_blocks should return correct hierarchy stats."""
        store.store_semantic(key="a", value="1", memory_path="/user/preferences")
        store.store_semantic(key="b", value="2", memory_path="/user/identity")
        store.store_semantic(key="c", value="3", memory_path="/work/projects")
        blocks = store.get_blocks()
        paths = {b["block_path"] for b in blocks}
        assert "/user" in paths
        assert "/work" in paths

    def test_get_by_block(self, store: EnhancedMemoryStore) -> None:
        """get_by_block should return memories under a prefix."""
        store.store_semantic(key="a", value="1", memory_path="/user/preferences")
        store.store_semantic(key="b", value="2", memory_path="/user/preferences/theme")
        store.store_semantic(key="c", value="3", memory_path="/work/projects")
        results = store.get_by_block("/user/preferences")
        assert len(results) == 2

    def test_block_priority_boost(self, store: EnhancedMemoryStore) -> None:
        """block_priority=True should boost matching entity types."""
        store.store_semantic(key="phone", value="iPhone", memory_path="/user/devices")
        store.store_semantic(key="color", value="blue", memory_path="/user/preferences")
        # Query contains "phone" which matches device entity type
        results = store.search_semantic("phone", block_priority=True)
        assert len(results) >= 1
        assert results[0].entity_type == "device"


class TestVerifySemantic:
    """Tests for memory verification."""

    def test_verify_updates_last_verified(self, store: EnhancedMemoryStore) -> None:
        """verify should update last_verified_at and create audit."""
        store.store_semantic(key="test", value="v", source="agent")
        store.verify_semantic(1)
        mem = store.get_all_semantic(limit=10)[0]
        assert mem["last_verified_at"] > 0
        audits = store.get_audit_log(memory_id=1, limit=10)
        assert any(a["action"] == "verify" for a in audits)

    def test_verify_nonexistent_returns_false(self, store: EnhancedMemoryStore) -> None:
        """verify on non-existent memory should return False."""
        result = store.verify_semantic(999)
        assert result is False


class TestParentIdRelation:
    """Tests for parent-child memory relationships."""

    def test_parent_id_relation(self, store: EnhancedMemoryStore) -> None:
        """parent_id should link memories in hierarchy."""
        store.store_semantic(key="group", value="g", memory_path="/user/preferences")
        store.store_semantic(
            key="item", value="i", memory_path="/user/preferences/theme", parent_id=1
        )
        mems = store.get_all_semantic(limit=10)
        item_mem = next((m for m in mems if m["key"] == "item"), None)
        assert item_mem is not None
        assert item_mem["parent_id"] == 1


class TestUpdateWithNewFields:
    """Tests for updating structured fields."""

    def test_update_memory_path(self, store: EnhancedMemoryStore) -> None:
        """update_semantic should support memory_path updates."""
        store.store_semantic(key="test", value="v", source="user")
        ok = store.update_semantic(1, "v2", memory_path="/custom/path")
        assert ok is True
        mem = store.get_all_semantic(limit=10)[0]
        assert mem["memory_path"] == "/custom/path"

    def test_update_entity_type(self, store: EnhancedMemoryStore) -> None:
        """update_semantic should support entity_type updates."""
        store.store_semantic(key="test", value="v", source="user")
        ok = store.update_semantic(1, "v2", entity_type="family")
        assert ok is True
        mem = store.get_all_semantic(limit=10)[0]
        assert mem["entity_type"] == "family"


class TestRetrieveSemanticWithBlocks:
    """Tests for retrieve_semantic with new fields."""

    def test_retrieve_includes_block_fields(self, store: EnhancedMemoryStore) -> None:
        """retrieve_semantic should return new block fields."""
        store.store_semantic(
            key="test", value="v", source="user",
            memory_path="/user/identity", entity_type="identity",
        )
        mem = store.retrieve_semantic("test")
        assert mem is not None
        assert mem.memory_path == "/user/identity"
        assert mem.entity_type == "identity"
