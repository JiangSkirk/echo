"""Layered memory schema + owner isolation tests."""

from __future__ import annotations

from pathlib import Path

from js.config import MemoryConfig
from js.memory.enhanced_store import EnhancedMemoryStore
from js.memory.layered.schema import SCHEMA_VERSION, ensure_layered_schema
from js.memory.layered.store import LayeredMemoryStore
from js.utils.db import db_connection


def test_ensure_layered_schema_idempotent(tmp_path: Path) -> None:
    db = tmp_path / "memory_enhanced.db"
    with db_connection(db) as conn:
        ensure_layered_schema(conn)
        ensure_layered_schema(conn)
        ver = conn.execute(
            "SELECT value FROM mem_schema_meta WHERE key = 'schema_version'"
        ).fetchone()
        assert ver is not None
        assert int(ver[0]) == SCHEMA_VERSION
        tables = {
            r[0]
            for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        }
    assert {
        "mem_entities",
        "mem_claims",
        "mem_relations",
        "mem_episodes",
        "mem_tombstones",
        "mem_schema_meta",
    }.issubset(tables)


def test_layered_owner_isolation(tmp_path: Path) -> None:
    store = LayeredMemoryStore(tmp_path / "memory_enhanced.db")
    a = store.upsert_claim_from_semantic(
        owner_key_hash="owner-a",
        key="allergy",
        value="peanuts",
        entity_name="user",
        explicit_correction=True,
    )
    b = store.upsert_claim_from_semantic(
        owner_key_hash="owner-b",
        key="allergy",
        value="shellfish",
        entity_name="user",
        explicit_correction=True,
    )
    assert a["claim_id"] != b["claim_id"]
    claims_a = store.list_active_claims(owner_key_hash="owner-a")
    claims_b = store.list_active_claims(owner_key_hash="owner-b")
    assert len(claims_a) == 1
    assert claims_a[0].typed_value == "peanuts"
    assert len(claims_b) == 1
    assert claims_b[0].typed_value == "shellfish"


def test_legacy_tables_still_created(tmp_path: Path) -> None:
    cfg = MemoryConfig(layered_memory_dual_write=False, layered_memory_retrieve=False)
    EnhancedMemoryStore(tmp_path, cfg)
    with db_connection(tmp_path / "memory_enhanced.db") as conn:
        tables = {
            r[0]
            for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        }
    assert "semantic_memories" in tables
    assert "working_memories" in tables
    # Layered tables are created lazily only when dual-write runs.
    assert "mem_claims" not in tables
