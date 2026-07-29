"""Retrieve flag: default off keeps context baseline unchanged."""

from __future__ import annotations

from pathlib import Path

from js.config import MemoryConfig
from js.memory.enhanced_store import EnhancedMemoryStore


def test_retrieve_flag_off_omits_layered_section(tmp_path: Path) -> None:
    cfg = MemoryConfig(layered_memory_dual_write=True, layered_memory_retrieve=False)
    store = EnhancedMemoryStore(tmp_path, cfg)
    store.store_semantic(
        key="language",
        value="zh-CN",
        source="user",
        owner_key_hash="owner-1",
        entity_name="user",
    )
    ctx = store.get_context_string(query="language", owner_key_hash="owner-1")
    assert "Layered Claims" not in ctx
    assert "language" in ctx or "zh-CN" in ctx or "关键事实" in ctx


def test_retrieve_flag_on_includes_layered_section(tmp_path: Path) -> None:
    cfg = MemoryConfig(layered_memory_dual_write=True, layered_memory_retrieve=True)
    store = EnhancedMemoryStore(tmp_path, cfg)
    store.store_semantic(
        key="language",
        value="zh-CN",
        source="user",
        owner_key_hash="owner-1",
        entity_name="user",
    )
    ctx = store.get_context_string(query="language", owner_key_hash="owner-1")
    assert "Layered Claims" in ctx
    assert "zh-CN" in ctx
