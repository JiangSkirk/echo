"""Progressive context-injection tests.

The assembled context must (a) respect the char budget, (b) order tiers
cheapest-first (block summaries → key facts → raw evidence), and (c) still
produce a useful map under a tiny budget instead of dumping raw rows.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from js.config import MemoryConfig
from js.memory.enhanced_store import EnhancedMemoryStore

OWNER = "owner-1"


@pytest.fixture
def store(tmp_path: Path) -> EnhancedMemoryStore:
    store = EnhancedMemoryStore(state_dir=tmp_path, config=MemoryConfig())
    yield store
    store.close()


def _seed(store: EnhancedMemoryStore) -> None:
    store.store_semantic("喜欢的颜色", "蓝色", category="preference", source="user",
                         owner_key_hash=OWNER, evidence="用户说我喜欢蓝色")
    store.store_semantic("当前项目", "记忆库重构", category="fact", source="user",
                         owner_key_hash=OWNER, evidence="在做记忆库重构")
    store.store_semantic("性格", "内向", source="user", owner_key_hash=OWNER,
                         evidence="我比较内向")


class TestProgressiveInjection:
    def test_respects_char_budget(self, store: EnhancedMemoryStore) -> None:
        _seed(store)
        for limit in (200, 500, 1000, 4000):
            ctx = store.get_context_string(query="项目", owner_key_hash=OWNER, max_chars=limit)
            assert len(ctx) <= limit, f"budget {limit} exceeded: {len(ctx)}"

    def test_tier_order_summaries_then_facts_then_evidence(self, store: EnhancedMemoryStore) -> None:
        _seed(store)
        ctx = store.get_context_string(query="项目", owner_key_hash=OWNER, max_chars=4000)
        i_blocks = ctx.find("## 记忆区块")
        i_facts = ctx.find("## 关键事实")
        i_evidence = ctx.find("## 原始证据")
        assert i_blocks != -1 and i_facts != -1 and i_evidence != -1
        assert i_blocks < i_facts < i_evidence

    def test_small_budget_keeps_cheap_summary_first(self, store: EnhancedMemoryStore) -> None:
        _seed(store)
        # A budget large enough for the block map but not the full evidence dump.
        ctx = store.get_context_string(query="项目", owner_key_hash=OWNER, max_chars=120)
        assert "## 记忆区块" in ctx
        # Evidence (the most expensive tier) is dropped under a tight budget.
        assert "## 原始证据" not in ctx

    def test_evidence_included_when_budget_allows(self, store: EnhancedMemoryStore) -> None:
        _seed(store)
        ctx = store.get_context_string(query="颜色", owner_key_hash=OWNER, max_chars=4000)
        assert "用户说我喜欢蓝色" in ctx

    def test_query_selects_relevant_facts(self, store: EnhancedMemoryStore) -> None:
        _seed(store)
        ctx = store.get_context_string(query="项目", owner_key_hash=OWNER, max_chars=4000)
        assert "记忆库重构" in ctx

    def test_empty_memory_graceful(self, store: EnhancedMemoryStore) -> None:
        ctx = store.get_context_string(owner_key_hash=OWNER, max_chars=4000)
        assert isinstance(ctx, str)
        assert ctx == "暂无记忆。"

    def test_recency_weight_influences_score(self, store: EnhancedMemoryStore) -> None:
        # Two equally-matching facts; the newer one should rank first when a
        # recency weight is configured (default 0.15).
        import time

        store.store_semantic("topic_old", "alpha topic note", source="agent",
                             owner_key_hash=OWNER)
        # Backdate the first by editing created_at directly.
        import sqlite3
        with sqlite3.connect(store.db_path) as c:
            c.execute(
                "UPDATE semantic_memories SET created_at = ? WHERE key = 'topic_old'",
                (time.time() - 400 * 86400,),
            )
            c.commit()
        store.store_semantic("topic_new", "alpha topic note", source="agent",
                             owner_key_hash=OWNER)
        results = store.search_semantic("alpha topic", owner_key_hash=OWNER, limit=2)
        assert results[0].key == "topic_new"
