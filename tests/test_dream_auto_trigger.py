"""Test automatic dreaming trigger and semantic memory context injection.

These tests verify:
1. DreamScheduler automatically triggers evolution after idle threshold
2. Semantic memories produced by dreaming are injected into agent context
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

import pytest

from js.config import MemoryConfig
from js.memory.embeddings import HybridEmbedder, KeywordEmbedder
from js.memory.enhanced_store import EnhancedMemoryStore
from js.memory.scheduler import DreamScheduler


@pytest.fixture
def store() -> EnhancedMemoryStore:
    with tempfile.TemporaryDirectory() as tmpdir:
        yield EnhancedMemoryStore(
            state_dir=Path(tmpdir),
            config=MemoryConfig(),
            embedder=HybridEmbedder(
                primary=KeywordEmbedder(dims=64),
                fallback=KeywordEmbedder(dims=64),
            ),
        )


class TestDreamSchedulerAutoTrigger:
    """Verify DreamScheduler triggers evolution cycle automatically after idle."""

    @pytest.mark.asyncio
    async def test_scheduler_triggers_evolution_after_idle(self) -> None:
        """DreamScheduler calls _run_evolution_cycle when idle threshold is met."""
        evolution_calls: list[list[dict[str, str]]] = []

        class FakeAgent:
            async def _run_evolution_cycle(
                self, conversation_buffer: list[dict[str, str]]
            ) -> dict:
                evolution_calls.append(list(conversation_buffer))
                return {"ok": True}

        agent = FakeAgent()
        sched = DreamScheduler(agent)
        # Speed up for test
        sched._check_interval = 0.05
        sched._idle_threshold = 0.1
        sched._max_deferral = 0.3

        # Simulate conversation
        sched.notify_activity("hello", "hi")
        sched.notify_activity("world", "earth")

        # Start scheduler
        sched.start()

        # Wait for idle threshold + margin
        await asyncio.sleep(0.2)

        # Evolution should have been triggered
        assert len(evolution_calls) >= 1, "Evolution cycle was not triggered"
        # Buffer entries now also carry owner/session provenance for the
        # organizer; assert on the conversational content specifically.
        captured = [
            {"user": t["user"], "assistant": t["assistant"]}
            for t in evolution_calls[0]
        ]
        assert captured == [
            {"user": "hello", "assistant": "hi"},
            {"user": "world", "assistant": "earth"},
        ]

        sched.stop()

    @pytest.mark.asyncio
    async def test_scheduler_defers_until_max_deferral(self) -> None:
        """If idle threshold is never met, evolution still triggers at max_deferral."""
        evolution_calls: list[list[dict[str, str]]] = []

        class FakeAgent:
            async def _run_evolution_cycle(
                self, conversation_buffer: list[dict[str, str]]
            ) -> dict:
                evolution_calls.append(list(conversation_buffer))
                return {"ok": True}

        agent = FakeAgent()
        sched = DreamScheduler(agent)
        sched._check_interval = 0.05
        sched._idle_threshold = 10.0  # Very long idle threshold
        sched._max_deferral = 0.15    # Short max deferral

        sched.notify_activity("test", "reply")
        sched.start()

        # Wait for max_deferral (not idle_threshold)
        await asyncio.sleep(0.2)

        assert len(evolution_calls) >= 1, "Evolution was not triggered by max_deferral"

        sched.stop()

    @pytest.mark.asyncio
    async def test_scheduler_clears_buffer_after_run(self) -> None:
        """After evolution runs, the conversation buffer is cleared."""
        class FakeAgent:
            async def _run_evolution_cycle(
                self, conversation_buffer: list[dict[str, str]]
            ) -> dict:
                return {"ok": True}

        agent = FakeAgent()
        sched = DreamScheduler(agent)
        sched._check_interval = 0.05
        sched._idle_threshold = 0.1
        sched._max_deferral = 0.3

        sched.notify_activity("a", "b")
        sched.start()
        await asyncio.sleep(0.2)
        sched.stop()

        # Buffer should be cleared after evolution
        assert len(sched._conversation_buffer) == 0

    @pytest.mark.asyncio
    async def test_scheduler_preserves_activity_added_during_evolution(self) -> None:
        """A sixth turn added during success keeps the scheduler pending."""
        evolution_started = asyncio.Event()
        allow_evolution_to_finish = asyncio.Event()

        class FakeAgent:
            async def _run_evolution_cycle(
                self, conversation_buffer: list[dict[str, str]]
            ) -> dict:
                evolution_started.set()
                await allow_evolution_to_finish.wait()
                return {"ok": True}

        sched = DreamScheduler(FakeAgent())
        for index in range(5):
            sched.notify_activity(f"user-{index}", f"assistant-{index}")

        evolution_task = asyncio.create_task(sched._run_once())
        await evolution_started.wait()
        sched.notify_activity("user-new", "assistant-new")
        new_activity_at = sched._last_activity
        allow_evolution_to_finish.set()
        await evolution_task

        assert sched._conversation_buffer == [
            {
                "user": "user-new",
                "assistant": "assistant-new",
                "owner_key_hash": None,
                "session_id": "",
            }
        ]
        assert sched._pending is True
        assert sched._pending_since == new_activity_at

    @pytest.mark.asyncio
    async def test_scheduler_preserves_activity_added_during_failure(self) -> None:
        """A sixth turn added during an ordinary failure keeps the scheduler pending."""
        evolution_started = asyncio.Event()
        allow_evolution_to_fail = asyncio.Event()

        class FakeAgent:
            async def _run_evolution_cycle(
                self, conversation_buffer: list[dict[str, str]]
            ) -> dict:
                evolution_started.set()
                await allow_evolution_to_fail.wait()
                raise RuntimeError("evolution failed")

        sched = DreamScheduler(FakeAgent())
        for index in range(5):
            sched.notify_activity(f"user-{index}", f"assistant-{index}")

        evolution_task = asyncio.create_task(sched._run_once())
        await evolution_started.wait()
        sched.notify_activity("user-new", "assistant-new")
        new_activity_at = sched._last_activity
        allow_evolution_to_fail.set()
        await evolution_task

        assert sched._conversation_buffer == [
            {
                "user": "user-new",
                "assistant": "assistant-new",
                "owner_key_hash": None,
                "session_id": "",
            }
        ]
        assert sched._pending is True
        assert sched._pending_since == new_activity_at

    @pytest.mark.asyncio
    async def test_scheduler_preserves_activity_added_during_cancellation(self) -> None:
        """Cancellation removes only the snapshot and propagates after preserving new work."""
        evolution_started = asyncio.Event()
        evolution_never_finishes = asyncio.Event()

        class FakeAgent:
            async def _run_evolution_cycle(
                self, conversation_buffer: list[dict[str, str]]
            ) -> dict:
                evolution_started.set()
                await evolution_never_finishes.wait()
                return {"ok": True}

        sched = DreamScheduler(FakeAgent())
        for index in range(5):
            sched.notify_activity(f"user-{index}", f"assistant-{index}")

        evolution_task = asyncio.create_task(sched._run_once())
        await evolution_started.wait()
        sched.notify_activity("user-new", "assistant-new")
        new_activity_at = sched._last_activity
        evolution_task.cancel()

        with pytest.raises(asyncio.CancelledError):
            await evolution_task

        assert sched._conversation_buffer == [
            {
                "user": "user-new",
                "assistant": "assistant-new",
                "owner_key_hash": None,
                "session_id": "",
            }
        ]
        assert sched._pending is True
        assert sched._pending_since == new_activity_at

    def test_snapshot_buffer_is_readonly_copy(self) -> None:
        """snapshot_buffer returns the recent turns without consuming them."""
        class FakeAgent:
            async def _run_evolution_cycle(
                self, conversation_buffer: list[dict[str, str]]
            ) -> dict:
                return {"ok": True}

        sched = DreamScheduler(FakeAgent())
        sched.notify_activity("hi", "yo", owner_key_hash="U1", session_id="s1")
        snap = sched.snapshot_buffer()
        assert snap[0]["user"] == "hi"
        assert snap[0]["owner_key_hash"] == "U1"
        # Mutating the snapshot must not touch the live buffer.
        snap.clear()
        assert len(sched._conversation_buffer) == 1

    @pytest.mark.asyncio
    async def test_force_consolidation_bypasses_idle_wait(self) -> None:
        """force_consolidation immediately triggers evolution without waiting."""
        evolution_called = False

        class FakeAgent:
            async def _run_evolution_cycle(
                self, conversation_buffer: list[dict[str, str]]
            ) -> dict:
                nonlocal evolution_called
                evolution_called = True
                return {"ok": True}

        agent = FakeAgent()
        sched = DreamScheduler(agent)
        sched._check_interval = 10.0  # Long interval
        sched._idle_threshold = 10.0

        sched.notify_activity("x", "y")
        sched.start()

        # Without force, evolution would not trigger for 10s
        await sched.force_consolidation()

        assert evolution_called is True
        sched.stop()


class TestSemanticMemoryContextInjection:
    """Verify semantic memories are injected into agent context."""

    def test_semantic_memories_appear_in_context_string(self, store: EnhancedMemoryStore) -> None:
        """get_context_string includes semantic memories of relevant categories."""
        store.store_semantic("user_name", "Alice", category="preference", confidence=0.9)
        store.store_semantic("project", "Factory ERP", category="fact", confidence=0.8)
        store.store_semantic("industry", "Manufacturing", category="fact", confidence=0.85)

        ctx = store.get_context_string(query="factory", max_chars=4000)

        # Preferences should appear
        assert "用户偏好" in ctx or "## About User" in ctx or "preference" in ctx.lower()
        # Facts should appear
        assert "Factory ERP" in ctx or "Manufacturing" in ctx
        # Query-relevant results should appear when query is provided
        assert "factory" in ctx.lower() or "Manufacturing" in ctx

    def test_dream_produced_semantic_is_searchable(self, store: EnhancedMemoryStore) -> None:
        """Memories promoted by dreaming can be found via search_semantic."""
        # Seed a high-importance working memory
        store.store_working("s1", "critical_fact", "User manages 3 factories", importance=9)

        # Run dreaming cycle
        report = asyncio.run(store.dream())
        phases = {p["phase"] for p in report["phases"]}
        assert "deep" in phases

        # The promoted memory should be searchable
        results = store.search_semantic("factories")
        assert any("factories" in (r.key + r.value).lower() for r in results)

    def test_semantic_insight_from_llm_is_stored(self, store: EnhancedMemoryStore) -> None:
        """Deep sleep with LLM summarizer stores insights as semantic memories."""
        store.store_working("s1", "fact1", "User likes coffee", importance=9)

        async def fake_llm(content: str) -> str:
            return "INSIGHT: User is a caffeine enthusiast."

        asyncio.run(store.dream(llm_summarizer=fake_llm))

        insights = store.search_semantic("", category="insight", limit=10)
        assert any("caffeine" in i.value.lower() for i in insights)

    def test_empty_semantic_graceful(self, store: EnhancedMemoryStore) -> None:
        """get_context_string handles empty semantic memory gracefully."""
        ctx = store.get_context_string(max_chars=4000)
        assert isinstance(ctx, str)
