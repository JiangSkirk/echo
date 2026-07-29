"""Dual-write: legacy semantic remains authoritative."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import patch

from js.config import MemoryConfig
from js.memory.enhanced_store import EnhancedMemoryStore


def test_dual_write_creates_claim_beside_semantic(tmp_path: Path) -> None:
    cfg = MemoryConfig(layered_memory_dual_write=True, layered_memory_retrieve=False)
    store = EnhancedMemoryStore(tmp_path, cfg)
    result = store.store_semantic(
        key="favorite_color",
        value="blue",
        category="preference",
        source="user",
        owner_key_hash="owner-1",
        entity_name="user",
        entity_type="person",
    )
    assert result.get("memory_id") is not None
    assert result.get("dropped") is not True
    layered = result.get("layered")
    assert isinstance(layered, dict)
    assert layered.get("status") == "active"
    claims = store._layered_store().list_active_claims(owner_key_hash="owner-1")
    assert len(claims) == 1
    assert claims[0].typed_value == "blue"
    # Legacy path still readable.
    found = store.search_semantic("favorite", owner_key_hash="owner-1")
    assert any(m.key == "favorite_color" for m in found)


def test_dual_write_failure_does_not_break_semantic(tmp_path: Path) -> None:
    cfg = MemoryConfig(layered_memory_dual_write=True)
    store = EnhancedMemoryStore(tmp_path, cfg)

    def _boom(*_a: Any, **_k: Any) -> None:
        raise RuntimeError("layered exploded")

    with patch.object(store._layered_store(), "upsert_claim_from_semantic", side_effect=_boom):
        result = store.store_semantic(
            key="city",
            value="Shanghai",
            category="fact",
            source="user",
            owner_key_hash="owner-1",
        )
    assert result.get("memory_id") is not None
    assert result.get("layered") is None
    found = store.search_semantic("city", owner_key_hash="owner-1")
    assert any(m.key == "city" and "Shanghai" in m.value for m in found)


def test_dual_write_disabled_skips_layered(tmp_path: Path) -> None:
    cfg = MemoryConfig(layered_memory_dual_write=False)
    store = EnhancedMemoryStore(tmp_path, cfg)
    result = store.store_semantic(
        key="pet",
        value="cat",
        source="user",
        owner_key_hash="owner-1",
    )
    assert result.get("layered") is None
    with __import__("js.utils.db", fromlist=["db_connection"]).db_connection(
        tmp_path / "memory_enhanced.db"
    ) as conn:
        tables = {
            r[0]
            for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        }
    assert "mem_claims" not in tables
