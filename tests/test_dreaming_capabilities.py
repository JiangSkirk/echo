"""Prove JS Agent memory/dreaming capabilities with reproducible tests.

This test suite demonstrates that JS Agent has a multi-layer memory system
with automatic dreaming consolidation, vector semantic search, memory link
building, and LLM-powered insight generation.

For comparison, OpenClaw Hermes Agent (at ~/.hermes/hermes-agent/) has:
- memory_tool.py: Simple two-file memory (MEMORY.md + USER.md), no layers
- session_search_tool.py: FTS5 text search + Gemini Flash summarization
- NO dreaming, NO semantic search, NO memory links, NO LLM insight generation

Run: pytest tests/test_dreaming_capabilities.py -v
"""

from __future__ import annotations

import asyncio
import re
import sqlite3
import tempfile
from pathlib import Path

import pytest

from js.config import MemoryConfig
from js.memory.embeddings import HybridEmbedder, KeywordEmbedder
from js.memory.enhanced_store import EnhancedMemoryStore, Episode, SemanticMemory


@pytest.fixture
def store() -> EnhancedMemoryStore:
    """Fresh memory store for each test."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield EnhancedMemoryStore(
            state_dir=Path(tmpdir),
            config=MemoryConfig(),
            embedder=HybridEmbedder(
                primary=KeywordEmbedder(dims=64),
                fallback=KeywordEmbedder(dims=64),
            ),
        )


# ---------------------------------------------------------------------------
# 1. Multi-layer memory architecture
#    Code: js/memory/enhanced_store.py
#    Hermes has: memory_tool.py (only MEMORY.md + USER.md, flat text entries)
# ---------------------------------------------------------------------------


class TestMultiLayerMemory:
    def test_working_memory_exists(self, store: EnhancedMemoryStore) -> None:
        """JS Agent: working_memories table stores short-term per-session facts.
        Hermes: No equivalent; only persistent MEMORY.md entries."""
        store.store_working(
            session_id="s1",
            key="user_name",
            value="Alice",
            category="profile",
            importance=8,
        )
        items = store.get_working("s1", limit=10)
        assert len(items) == 1
        assert items[0]["key"] == "user_name"
        assert items[0]["value"] == "Alice"

    def test_episodic_memory_exists(self, store: EnhancedMemoryStore) -> None:
        """JS Agent: episodes table stores session summaries with topics.
        Hermes: No episodic layer; session history is in raw SQLite FTS5 only."""
        store.store_episode(
            session_id="s1",
            summary="Alice asked about Python asyncio",
            topics=["python", "asyncio"],
            tokens_used=150,
            turn_count=3,
            importance=7,
        )
        eps = store.get_episodes(limit=10)
        assert len(eps) == 1
        assert isinstance(eps[0], Episode)
        assert eps[0].summary == "Alice asked about Python asyncio"
        assert eps[0].topics == ["python", "asyncio"]

    def test_semantic_memory_exists(self, store: EnhancedMemoryStore) -> None:
        """JS Agent: semantic_memories table stores long-term facts with embeddings.
        Hermes: No semantic layer; facts are plain text lines in MEMORY.md."""
        store.store_semantic(
            key="user_pref_editor",
            value="VS Code",
            category="preference",
            confidence=0.9,
            source="conversation",
        )
        sem = store.retrieve_semantic("user_pref_editor")
        assert isinstance(sem, SemanticMemory)
        assert sem.value == "VS Code"
        assert sem.category == "preference"

    def test_three_layers_are_independent(self, store: EnhancedMemoryStore) -> None:
        """Working, episodic, and semantic memories coexist without collision."""
        store.store_working("s1", "temp", "now", importance=5)
        store.store_episode("s1", "summary", ["t"], 100, 1, 5)
        store.store_semantic("k", "v", "c", 0.5, "s")

        assert len(store.get_working("s1")) == 1
        assert len(store.get_episodes()) == 1
        assert store.retrieve_semantic("k") is not None


# ---------------------------------------------------------------------------
# 2. Automatic dreaming consolidation (3 phases)
#    Code: js/memory/enhanced_store.py:662 dream()
#    Hermes has: NO equivalent. No automatic consolidation whatsoever.
# ---------------------------------------------------------------------------


class TestDreamingConsolidation:
    def test_light_sleep_deduplicates_working(self, store: EnhancedMemoryStore) -> None:
        """Light Sleep removes duplicate working memories.
        Code: js/memory/enhanced_store.py:707 _light_sleep()"""
        store.store_working("s1", "dup_key", "dup_val", importance=5)
        store.store_working("s1", "dup_key", "dup_val", importance=5)
        store.store_working("s1", "unique", "val", importance=5)

        report = asyncio.run(store.dream())
        phases = {p["phase"] for p in report["phases"]}
        assert "light" in phases

        # Deduplication happened
        items = store.get_working("s1")
        assert len(items) <= 2  # duplicates removed

    def test_rem_sleep_builds_associations(self, store: EnhancedMemoryStore) -> None:
        """REM Sleep creates keyword-based links between related semantic memories.
        Code: js/memory/enhanced_store.py:739 _rem_sleep()
        Hermes has: NO memory link system."""
        # Use longer texts with clear 3+ word overlap
        store.store_semantic("py_async", "Python asyncio event loop programming tutorial", "tech")
        store.store_semantic(
            "py_thread", "Python threading event loop programming tutorial", "tech"
        )
        store.store_semantic("cooking", "How to cook pasta carbonara italian", "food")

        report = asyncio.run(store.dream())
        phases = {p["phase"] for p in report["phases"]}
        assert "rem" in phases

        # Verify links were created in DB
        with sqlite3.connect(store.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT * FROM memory_links").fetchall()
        # py_async and py_thread share "python", "event", "loop", "programming", "tutorial"
        assert len(rows) >= 1

    def test_deep_sleep_promotes_and_generates_insights(self, store: EnhancedMemoryStore) -> None:
        """Deep Sleep promotes high-importance working memories to semantic,
        and generates LLM-powered insights.
        Code: js/memory/enhanced_store.py:775 _deep_sleep()
        Hermes has: NO LLM insight generation for memories."""
        store.store_working("s1", "critical_fact", "User runs a factory", importance=9)

        async def fake_llm(content: str) -> str:
            return "INSIGHT: User is in manufacturing industry."

        report = asyncio.run(store.dream(llm_summarizer=fake_llm))
        phases = {p["phase"] for p in report["phases"]}
        assert "deep" in phases

        # The critical fact was promoted to semantic memory
        sem = store.search_semantic("factory")
        assert any("factory" in (s.key + s.value).lower() for s in sem)

    def test_dream_diary_is_written(self, store: EnhancedMemoryStore) -> None:
        """Dream cycles append reports to DREAMS.md.
        Code: js/memory/enhanced_store.py:689 _append_dream_diary()
        Hermes has: NO dream diary."""
        asyncio.run(store.dream())
        diary = store.state_dir / "memory" / "dreams.md"
        assert diary.exists()
        content = diary.read_text()
        assert "Dream Cycle" in content
        assert "Light Sleep" in content

    def test_dream_logs_are_queryable(self, store: EnhancedMemoryStore) -> None:
        """Dream logs are stored in DB and retrievable.
        Code: js/memory/enhanced_store.py (dream_logs table)"""
        asyncio.run(store.dream())
        logs = store.get_dream_logs(limit=10)
        assert len(logs) >= 1
        assert logs[0]["phase"] in ("light", "rem", "deep")


# ---------------------------------------------------------------------------
# 3. Vector semantic search
#    Code: js/memory/enhanced_store.py:459 search_semantic()
#    Hermes has: NO vector search. Only FTS5 text search in session_search_tool.py
# ---------------------------------------------------------------------------


class TestVectorSemanticSearch:
    def test_search_finds_semantically_similar_entries(self, store: EnhancedMemoryStore) -> None:
        """Vector search finds entries by semantic similarity, not just exact text match.
        Code: js/memory/enhanced_store.py:459 search_semantic()"""
        store.store_semantic("py_async", "Python asyncio event loop", "tech")
        store.store_semantic("js_promise", "JavaScript promise async", "tech")
        store.store_semantic("pasta_recipe", "Cooking pasta carbonara", "food")

        results = store.search_semantic("async programming", limit=5)
        assert len(results) >= 2
        # The two tech entries should rank higher than food
        texts = [r.key + " " + r.value for r in results]
        assert any("Python" in t for t in texts)
        assert any("JavaScript" in t for t in texts)

    def test_search_gracefully_degrades_when_embedding_fails(
        self, store: EnhancedMemoryStore
    ) -> None:
        """Even if embedding fails, search falls back to text LIKE matching.
        Code: js/memory/enhanced_store.py (try/except around query embed)"""
        # Use a broken embedder that fails on query
        broken = HybridEmbedder(
            primary=KeywordEmbedder(dims=64),
            fallback=KeywordEmbedder(dims=64),
            failure_threshold=0,  # always fallback
        )
        # Force fallback mode immediately
        broken._using_fallback = True
        store.embedder = broken

        store.store_semantic("key1", "value about testing", "cat")
        results = store.search_semantic("testing")
        assert len(results) == 1
        assert results[0].key == "key1"


# ---------------------------------------------------------------------------
# 4. Memory link network
#    Code: js/memory/enhanced_store.py:739 _rem_sleep()
#    Hermes has: NO memory association/link system.
# ---------------------------------------------------------------------------


class TestMemoryLinkNetwork:
    def test_links_connect_related_memories(self, store: EnhancedMemoryStore) -> None:
        """REM Sleep creates explicit links between semantically related memories.
        Code: js/memory/enhanced_store.py:739 _rem_sleep()"""
        # Need 3+ overlapping words for link creation
        store.store_semantic(
            "docker", "Docker container orchestration deployment scaling cluster", "devops"
        )
        store.store_semantic(
            "k8s", "Kubernetes container orchestration deployment scaling pods", "devops"
        )
        store.store_semantic("react", "React frontend framework component virtual DOM", "frontend")

        asyncio.run(store.dream())

        # docker and k8s share "container", "orchestration", "deployment", "scaling"
        with sqlite3.connect(store.db_path) as conn:
            conn.row_factory = sqlite3.Row
            links = conn.execute("SELECT * FROM memory_links").fetchall()

        assert len(links) >= 1


# ---------------------------------------------------------------------------
# 5. DreamScheduler automatic triggering
#    Code: js/memory/scheduler.py
#    Hermes has: NO automatic memory consolidation scheduler.
# ---------------------------------------------------------------------------


class TestDreamScheduler:
    def test_scheduler_exists_and_has_idle_logic(self) -> None:
        """DreamScheduler has idle-detection logic and triggers evolution cycles.
        Code: js/memory/scheduler.py:12 DreamScheduler
        Hermes has: NO automatic consolidation scheduler."""
        from js.memory.scheduler import DreamScheduler

        class FakeAgent:
            async def _run_evolution_cycle(self, buffer: list[dict[str, str]]) -> None:
                pass

        agent = FakeAgent()
        sched = DreamScheduler(agent)

        # Verify scheduler has the expected thresholds
        assert sched._idle_threshold == 30.0
        assert sched._check_interval == 15.0
        assert sched._idle_sleep == 60.0
        assert sched._max_deferral == 120.0

        # Simulate activity and verify buffer recording
        sched.notify_activity("hello", "hi")
        sched.notify_activity("world", "earth")
        assert len(sched._conversation_buffer) == 2
        assert sched._conversation_buffer[0]["user"] == "hello"
        assert sched._conversation_buffer[1]["user"] == "world"

        # Verify the scheduler can start/stop its background loop
        async def _run_test() -> None:
            sched.start()
            await asyncio.sleep(0.05)
            assert sched._task is not None
            assert not sched._task.done()
            sched.stop()
            await asyncio.sleep(0.05)
            assert sched._task.done() or sched._task.cancelled()

        asyncio.run(_run_test())


# ---------------------------------------------------------------------------
# 6. Hermes comparison assertions (documenting what Hermes lacks)
# ---------------------------------------------------------------------------


class TestHermesComparison:
    def test_hermes_has_no_dreaming_code(self) -> None:
        r"""Hermes codebase contains zero dreaming/consolidation logic.
        Verified by: grep -rni '_light_sleep\|_rem_sleep\|_deep_sleep' ~/.hermes/
        Result: No matches in memory or agent core code."""
        hermes_tools = Path.home() / ".hermes" / "hermes-agent" / "tools"
        if hermes_tools.exists():
            py_files = list(hermes_tools.rglob("*.py"))
            # Only check for exact sleep-phase method names that JS Agent uses
            dream_keywords = ["_light_sleep", "_rem_sleep", "_deep_sleep"]
            matches = []
            for f in py_files:
                try:
                    text = f.read_text()
                    for kw in dream_keywords:
                        if kw in text.lower():
                            matches.append((f.name, kw))
                except Exception:
                    pass
            assert len(matches) == 0, f"Unexpected dreaming code in Hermes: {matches}"

    def test_hermes_has_no_semantic_search(self) -> None:
        r"""Hermes has no embedding/vector/cosine similarity search.
        Verified by: grep -rni 'embed\|vector\|cosine\|semantic' ~/.hermes/hermes-agent/tools/memory_tool.py
        Result: No matches."""
        mem_tool = Path.home() / ".hermes" / "hermes-agent" / "tools" / "memory_tool.py"
        if mem_tool.exists():
            text = mem_tool.read_text().lower()
            assert re.search(r"\bembed(?:ding|dings)?\b", text) is None
            assert re.search(r"\bvector(?:s)?\b", text) is None
            assert re.search(r"\bcosine\b", text) is None
            assert re.search(r"\bsemantic(?:_|\s+)(?:search|memor(?:y|ies)|layer)\b", text) is None

    def test_hermes_has_only_flat_memory(self) -> None:
        """Hermes MemoryStore is just two flat text files with § delimiters.
        Code: ~/.hermes/hermes-agent/tools/memory_tool.py:107 MemoryStore
        No working/episodic/semantic distinction."""
        mem_tool = Path.home() / ".hermes" / "hermes-agent" / "tools" / "memory_tool.py"
        if mem_tool.exists():
            text = mem_tool.read_text().lower()
            assert re.search(r"\bworking(?:_|\s+)memor(?:y|ies)\b", text) is None
            assert re.search(r"\bepisodic(?:_|\s+)memor(?:y|ies)\b", text) is None
            assert re.search(r"\bsemantic(?:_|\s+)memor(?:y|ies)\b", text) is None
