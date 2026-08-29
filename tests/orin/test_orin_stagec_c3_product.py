"""Memory Cell product paths refuse ambient writes under enforce."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from js.config import MemoryConfig
from js.memory.enhanced_store.store import EnhancedMemoryStore
from js.memory.provider import BuiltinMemoryProvider
from js.memory.scheduler import DreamScheduler
from js.orin.stage_c import bind_product_enforce, reset_product_enforce


def test_enhanced_store_write_blocked_under_product_enforce(tmp_path: Path) -> None:
    store = EnhancedMemoryStore(tmp_path, MemoryConfig())
    store.store_working("s1", "k", "v", owner_key_hash="owner-a")
    token = bind_product_enforce(True)
    try:
        with pytest.raises(RuntimeError, match="orin.enforce"):
            store.store_working("s1", "k2", "nope", owner_key_hash="owner-a")
        with pytest.raises(RuntimeError, match="orin.enforce"):
            store.store_semantic("fact", "nope", owner_key_hash="owner-a")
    finally:
        reset_product_enforce(token)


@pytest.mark.asyncio
async def test_provider_sync_and_prefetch_blocked_under_enforce(tmp_path: Path) -> None:
    provider = BuiltinMemoryProvider(tmp_path, MemoryConfig())
    token = bind_product_enforce(True)
    try:
        with pytest.raises(RuntimeError, match="orin.enforce"):
            await provider.prefetch("hello")
        with pytest.raises(RuntimeError, match="orin.enforce"):
            await provider.sync_turn("s1", "hi", "there")
    finally:
        reset_product_enforce(token)
        await provider.shutdown()


@pytest.mark.asyncio
async def test_scheduler_refuses_dream_when_memory_cell_required() -> None:
    agent = SimpleNamespace(
        settings=SimpleNamespace(orin=SimpleNamespace(enforce=True, cell_memory=True)),
        _run_evolution_cycle=None,
    )
    scheduler = DreamScheduler(agent)
    await scheduler.force_consolidation(owner_key_hash="owner-a")
    assert scheduler._pending is False


def test_memory_cell_backend_requires_task_prefix() -> None:
    from js.orin.client import OrinMemoryCellBackend

    with pytest.raises(ValueError, match="task id"):
        OrinMemoryCellBackend(SimpleNamespace(), task_id="not-a-task")
