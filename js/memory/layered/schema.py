"""Side-car layered memory schema (does not mutate legacy tables)."""

from __future__ import annotations

import sqlite3

SCHEMA_VERSION = 1

_DDL = """
CREATE TABLE IF NOT EXISTS mem_schema_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS mem_entities (
    id TEXT PRIMARY KEY,
    owner_key_hash TEXT NOT NULL,
    type TEXT NOT NULL DEFAULT 'concept',
    canonical_name TEXT NOT NULL,
    aliases TEXT NOT NULL DEFAULT '[]',
    revision INTEGER NOT NULL DEFAULT 1,
    lifecycle_state TEXT NOT NULL DEFAULT 'active',
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_mem_entities_owner_name
    ON mem_entities(owner_key_hash, canonical_name);

CREATE TABLE IF NOT EXISTS mem_claims (
    id TEXT PRIMARY KEY,
    owner_key_hash TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    predicate TEXT NOT NULL,
    typed_value TEXT NOT NULL,
    valid_from REAL,
    valid_to REAL,
    observed_at REAL NOT NULL,
    retired_at REAL,
    status TEXT NOT NULL DEFAULT 'candidate',
    confidence REAL NOT NULL DEFAULT 0.5,
    source_episode_ids TEXT NOT NULL DEFAULT '[]',
    source_semantic_id INTEGER,
    source_authority TEXT NOT NULL DEFAULT 'inferred',
    supersedes_claim_ids TEXT NOT NULL DEFAULT '[]',
    evidence TEXT NOT NULL DEFAULT '',
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    FOREIGN KEY(subject_id) REFERENCES mem_entities(id)
);
CREATE INDEX IF NOT EXISTS idx_mem_claims_owner_subject_pred
    ON mem_claims(owner_key_hash, subject_id, predicate, status);

CREATE TABLE IF NOT EXISTS mem_relations (
    id TEXT PRIMARY KEY,
    owner_key_hash TEXT NOT NULL,
    source_entity_id TEXT NOT NULL,
    target_entity_id TEXT NOT NULL,
    relation_type TEXT NOT NULL,
    valid_from REAL,
    valid_to REAL,
    state TEXT NOT NULL DEFAULT 'active',
    provenance TEXT NOT NULL DEFAULT '',
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_mem_relations_owner
    ON mem_relations(owner_key_hash, relation_type);

CREATE TABLE IF NOT EXISTS mem_episodes (
    id TEXT PRIMARY KEY,
    owner_key_hash TEXT NOT NULL,
    source_role TEXT NOT NULL DEFAULT 'system_event',
    source_type TEXT NOT NULL DEFAULT 'event',
    occurred_at REAL NOT NULL,
    ingested_at REAL NOT NULL,
    content_hash TEXT NOT NULL DEFAULT '',
    summary TEXT NOT NULL DEFAULT '',
    sensitivity INTEGER NOT NULL DEFAULT 0,
    retention_class TEXT NOT NULL DEFAULT 'default'
);
CREATE INDEX IF NOT EXISTS idx_mem_episodes_owner
    ON mem_episodes(owner_key_hash, occurred_at DESC);

CREATE TABLE IF NOT EXISTS mem_tombstones (
    id TEXT PRIMARY KEY,
    owner_key_hash TEXT NOT NULL,
    object_type TEXT NOT NULL,
    object_id TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    retired_at REAL NOT NULL,
    content_hash TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_mem_tombstones_owner
    ON mem_tombstones(owner_key_hash, object_type, object_id);
"""

CLAIM_STATUSES = frozenset({"candidate", "active", "superseded", "disputed", "retracted"})


def ensure_layered_schema(conn: sqlite3.Connection) -> None:
    """Create layered tables if missing; idempotent."""
    conn.executescript(_DDL)
    row = conn.execute("SELECT value FROM mem_schema_meta WHERE key = 'schema_version'").fetchone()
    if row is None:
        conn.execute(
            "INSERT INTO mem_schema_meta(key, value) VALUES ('schema_version', ?)",
            (str(SCHEMA_VERSION),),
        )
    conn.commit()
