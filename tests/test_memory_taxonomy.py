"""Taxonomy tests: Chinese auto-partition into the expanded 11-block library.

Covers the new blocks added in the hierarchical-library upgrade
(personality / body / friends / plans / chat history) plus multi-level
sub-blocks, on top of the pre-existing family/work/preference routing.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from js.config import MemoryConfig
from js.memory.enhanced_store import EnhancedMemoryStore


@pytest.fixture
def store(tmp_path: Path) -> EnhancedMemoryStore:
    store = EnhancedMemoryStore(state_dir=tmp_path, config=MemoryConfig())
    yield store
    store.close()


def _path_of(store: EnhancedMemoryStore, key: str, value: str, **kw: object) -> str:
    store.store_semantic(key=key, value=value, source="user", **kw)
    mem = store.get_all_semantic(limit=10)[0]
    return mem["memory_path"]


class TestExpandedChineseTaxonomy:
    """Each new default block must be reachable via Chinese keywords."""

    def test_family_to_people_family(self, store: EnhancedMemoryStore) -> None:
        assert _path_of(store, "老婆姓名", "小红") == "/people/family"

    def test_friend_to_people_friends(self, store: EnhancedMemoryStore) -> None:
        assert _path_of(store, "朋友小明", "大学同学") == "/people/friends"

    def test_personality_block(self, store: EnhancedMemoryStore) -> None:
        assert _path_of(store, "我的性格", "内向，喜欢独处") == "/user/personality"

    def test_body_block(self, store: EnhancedMemoryStore) -> None:
        assert _path_of(store, "身高", "180cm") == "/user/body"

    def test_body_block_allergy(self, store: EnhancedMemoryStore) -> None:
        assert _path_of(store, "过敏源", "花粉过敏") == "/user/body"

    def test_active_plan_block(self, store: EnhancedMemoryStore) -> None:
        assert _path_of(store, "本周计划", "完成记忆库重构") == "/plans/active"

    def test_plan_history_block(self, store: EnhancedMemoryStore) -> None:
        # Completion keywords win over the generic "task/plan" routing.
        assert _path_of(store, "已完成的任务", "上线了 v1") == "/plans/history"

    def test_company_block(self, store: EnhancedMemoryStore) -> None:
        assert _path_of(store, "公司名称", "钛坦科技") == "/work/company"

    def test_colleague_block(self, store: EnhancedMemoryStore) -> None:
        assert _path_of(store, "同事老王", "后端负责人") == "/work/colleagues"

    def test_project_block(self, store: EnhancedMemoryStore) -> None:
        assert _path_of(store, "项目进度", "进行中") == "/work/projects"

    def test_preference_block(self, store: EnhancedMemoryStore) -> None:
        assert _path_of(store, "喜欢的颜色", "蓝色") == "/user/preferences"

    def test_english_friend_keyword(self, store: EnhancedMemoryStore) -> None:
        assert _path_of(store, "best_friend", "Tom from college") == "/people/friends"

    def test_english_personality_keyword(self, store: EnhancedMemoryStore) -> None:
        assert _path_of(store, "personality_type", "INTJ") == "/user/personality"


class TestMultiLevelSubBlocks:
    """Explicit nested paths must be preserved and queryable by prefix."""

    def test_nested_project_subblock(self, store: EnhancedMemoryStore) -> None:
        store.store_semantic(
            key="alpha_status", value="进行中", source="user",
            memory_path="/work/projects/alpha", entity_type="project",
        )
        store.store_semantic(
            key="beta_status", value="规划中", source="user",
            memory_path="/work/projects/beta", entity_type="project",
        )
        # Prefix query returns both nested sub-blocks.
        under = store.get_by_block("/work/projects")
        keys = {m["key"] for m in under}
        assert {"alpha_status", "beta_status"} <= keys

    def test_get_blocks_lists_subblocks(self, store: EnhancedMemoryStore) -> None:
        store.store_semantic(
            key="alpha_status", value="进行中", source="user",
            memory_path="/work/projects/alpha",
        )
        store.store_semantic(
            key="beta_status", value="规划中", source="user",
            memory_path="/work/projects/beta",
        )
        sub = store.get_blocks(path_prefix="/work/projects")
        paths = {b["block_path"] for b in sub}
        assert "/work/projects/alpha" in paths
        assert "/work/projects/beta" in paths

    def test_top_level_grouping(self, store: EnhancedMemoryStore) -> None:
        store.store_semantic(key="老婆", value="小红", source="user")
        store.store_semantic(key="朋友", value="小明", source="user")
        top = {b["block_path"] for b in store.get_blocks()}
        # family and friends both roll up under the /people top-level block.
        assert "/people" in top
