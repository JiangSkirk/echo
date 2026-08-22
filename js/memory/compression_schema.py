"""R6 compression schema: additive migration and immutable repository.

Four-table additive migration with single-transaction CAS.
Source tables are never deleted or overwritten; terminal rows never revive.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from js.memory.layers.contracts import (
    ColdCapsule,
    CompressionProposal,
    MemoryRecordKind,
    MemorySourceRefV1,
)
from js.utils.db import db_connection

COMPRESSION_SCHEMA_VERSION = 2


_DDL_PROPOSALS_V2 = """
CREATE TABLE IF NOT EXISTS compression_proposals (
    proposal_id TEXT PRIMARY KEY,
    owner TEXT NOT NULL,
    mode TEXT NOT NULL,
    workspace TEXT,
    source_records_json TEXT NOT NULL,
    source_hashes_json TEXT NOT NULL,
    coverage REAL NOT NULL,
    conflicts_json TEXT NOT NULL,
    token_savings INTEGER NOT NULL,
    proposed_summary TEXT NOT NULL,
    summary_hash TEXT NOT NULL,
    tokenizer_id TEXT,
    real_token_count INTEGER,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at REAL NOT NULL,
    approved_by TEXT,
    approved_at REAL,
    format_version INTEGER NOT NULL DEFAULT 2,
    policy_version TEXT NOT NULL DEFAULT 'r6-v1',
    proposal_digest TEXT,
    scope_hash TEXT,
    source_set_hash TEXT,
    source_token_count INTEGER,
    summary_token_count INTEGER,
    coverage_numerator INTEGER,
    coverage_denominator INTEGER,
    creator_task_ref_hash TEXT,
    creator_session TEXT,
    creator_run TEXT,
    creator_role TEXT,
    decision_task_ref_hash TEXT,
    decision_session TEXT,
    decision_run TEXT,
    decision_role TEXT,
    decision_reason TEXT,
    supersedes_proposal_id TEXT
)
"""

_DDL_PROPOSAL_SOURCES = """
CREATE TABLE IF NOT EXISTS compression_proposal_sources (
    proposal_id TEXT NOT NULL REFERENCES compression_proposals(proposal_id),
    ordinal INTEGER NOT NULL,
    source_kind TEXT NOT NULL,
    source_record_id TEXT NOT NULL,
    source_hash TEXT NOT NULL,
    lifecycle_state TEXT NOT NULL,
    sensitivity TEXT NOT NULL,
    retention TEXT NOT NULL,
    required_fields_present INTEGER NOT NULL,
    required_fields_total INTEGER NOT NULL,
    conflict_flags_json TEXT NOT NULL,
    PRIMARY KEY (proposal_id, ordinal),
    UNIQUE (proposal_id, source_kind, source_record_id)
)
"""

_DDL_CAPSULES_V2 = """
CREATE TABLE IF NOT EXISTS compression_capsules (
    capsule_id TEXT PRIMARY KEY,
    proposal_id TEXT NOT NULL,
    owner TEXT NOT NULL,
    mode TEXT NOT NULL,
    workspace TEXT,
    source_record_ids_json TEXT NOT NULL,
    source_hashes_json TEXT NOT NULL,
    summary_hash TEXT NOT NULL,
    recovery_index_json TEXT NOT NULL,
    created_at REAL NOT NULL,
    approved_by TEXT NOT NULL,
    format_version INTEGER NOT NULL DEFAULT 2,
    capsule_digest TEXT,
    source_set_hash TEXT,
    summary_text TEXT,
    tokenizer_id TEXT,
    source_token_count INTEGER,
    summary_token_count INTEGER,
    recovery_index_digest TEXT,
    approved_task_ref_hash TEXT,
    approved_session TEXT,
    approved_run TEXT,
    approved_role TEXT,
    FOREIGN KEY (proposal_id) REFERENCES compression_proposals(proposal_id)
)
"""

_DDL_CAPSULE_SOURCES = """
CREATE TABLE IF NOT EXISTS compression_capsule_sources (
    capsule_id TEXT NOT NULL REFERENCES compression_capsules(capsule_id),
    ordinal INTEGER NOT NULL,
    source_kind TEXT NOT NULL,
    source_record_id TEXT NOT NULL,
    source_hash TEXT NOT NULL,
    snapshot_json TEXT NOT NULL,
    snapshot_hash TEXT NOT NULL,
    lifecycle_state TEXT NOT NULL,
    sensitivity TEXT NOT NULL,
    retention TEXT NOT NULL,
    PRIMARY KEY (capsule_id, ordinal),
    UNIQUE (capsule_id, source_kind, source_record_id)
)
"""

_DDL_SCHEMA_META = """
CREATE TABLE IF NOT EXISTS compression_schema_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
)
"""

_DDL_INDEXES = """
CREATE INDEX IF NOT EXISTS idx_proposals_owner_mode
    ON compression_proposals(owner, mode);
CREATE INDEX IF NOT EXISTS idx_capsules_owner_mode
    ON compression_capsules(owner, mode);
CREATE UNIQUE INDEX IF NOT EXISTS idx_capsules_proposal_v2
    ON compression_capsules(proposal_id) WHERE format_version = 2;
CREATE INDEX IF NOT EXISTS idx_proposal_sources_pid
    ON compression_proposal_sources(proposal_id);
CREATE INDEX IF NOT EXISTS idx_capsule_sources_cid
    ON compression_capsule_sources(capsule_id);
"""


def _additive_columns(conn: sqlite3.Connection, table: str, needed: set[str]) -> None:
    """Add missing columns additively (ALTER TABLE ADD COLUMN)."""
    cur = conn.execute(f"PRAGMA table_info({table})")
    existing = {str(row[1]) for row in cur.fetchall()}
    column_defs: dict[str, str] = {
        "format_version": "INTEGER NOT NULL DEFAULT 2",
        "policy_version": "TEXT NOT NULL DEFAULT 'r6-v1'",
        "proposal_digest": "TEXT",
        "scope_hash": "TEXT",
        "source_set_hash": "TEXT",
        "source_token_count": "INTEGER",
        "summary_token_count": "INTEGER",
        "coverage_numerator": "INTEGER",
        "coverage_denominator": "INTEGER",
        "creator_task_ref_hash": "TEXT",
        "creator_session": "TEXT",
        "creator_run": "TEXT",
        "creator_role": "TEXT",
        "decision_task_ref_hash": "TEXT",
        "decision_session": "TEXT",
        "decision_run": "TEXT",
        "decision_role": "TEXT",
        "decision_reason": "TEXT",
        "supersedes_proposal_id": "TEXT",
        "capsule_digest": "TEXT",
        "summary_text": "TEXT",
        "recovery_index_digest": "TEXT",
        "approved_task_ref_hash": "TEXT",
        "approved_session": "TEXT",
        "approved_run": "TEXT",
        "approved_role": "TEXT",
    }
    for col in needed:
        if col not in existing and col in column_defs:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {column_defs[col]}")


def ensure_compression_schema(db_path: Path) -> None:
    """Idempotent additive migration. Creates tables and adds missing columns."""
    with db_connection(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.execute(_DDL_PROPOSALS_V2)
            conn.execute(_DDL_PROPOSAL_SOURCES)
            conn.execute(_DDL_CAPSULES_V2)
            conn.execute(_DDL_CAPSULE_SOURCES)
            conn.execute(_DDL_SCHEMA_META)
            conn.executescript(_DDL_INDEXES)

            _additive_columns(conn, "compression_proposals", {
                "format_version", "policy_version", "proposal_digest", "scope_hash",
                "source_set_hash", "source_token_count", "summary_token_count",
                "coverage_numerator", "coverage_denominator",
                "creator_task_ref_hash", "creator_session", "creator_run", "creator_role",
                "decision_task_ref_hash", "decision_session", "decision_run",
                "decision_role", "decision_reason", "supersedes_proposal_id",
            })
            _additive_columns(conn, "compression_capsules", {
                "format_version", "capsule_digest", "source_set_hash", "summary_text",
                "tokenizer_id", "source_token_count", "summary_token_count",
                "recovery_index_digest",
                "approved_task_ref_hash", "approved_session", "approved_run", "approved_role",
            })

            row = conn.execute(
                "SELECT value FROM compression_schema_meta WHERE key = 'schema_version'"
            ).fetchone()
            if row is None:
                conn.execute(
                    "INSERT INTO compression_schema_meta(key, value) VALUES ('schema_version', ?)",
                    (str(COMPRESSION_SCHEMA_VERSION),),
                )
            conn.commit()
        except Exception:
            conn.rollback()
            raise


class CompressionRepository:
    """Immutable repository for compression proposals and capsules.

    All writes use plain INSERT (ON CONFLICT DO NOTHING for idempotent retry).
    Terminal status uses CAS (UPDATE ... WHERE status='pending' AND proposal_digest=?).
    No destructive SQL, no DELETE of source tables.
    """

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        ensure_compression_schema(db_path)

    def count_pending(self, conn: sqlite3.Connection, *, owner: str, mode: str, workspace: str | None) -> int:
        ws_clause = "AND workspace IS ?" if workspace is None else "AND workspace = ?"
        row = conn.execute(
            f"SELECT COUNT(*) FROM compression_proposals WHERE owner=? AND mode=? {ws_clause} AND status='pending'",
            (owner, mode, workspace),
        ).fetchone()
        return int(row[0])

    def insert_proposal(
        self,
        conn: sqlite3.Connection,
        *,
        proposal: CompressionProposal,
    ) -> bool:
        """Insert proposal parent + child rows. Returns True if new, False if idempotent."""
        cursor = conn.execute(
            """
            INSERT INTO compression_proposals (
                proposal_id, owner, mode, workspace,
                source_records_json, source_hashes_json, coverage, conflicts_json,
                token_savings, proposed_summary, summary_hash, tokenizer_id,
                real_token_count, status, created_at,
                format_version, policy_version, proposal_digest, scope_hash,
                source_set_hash, source_token_count, summary_token_count,
                coverage_numerator, coverage_denominator,
                creator_session, creator_run, creator_role
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 2, 'r6-v1', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(proposal_id) DO NOTHING
            """,
            (
                proposal.proposal_id,
                proposal.owner,
                proposal.mode,
                proposal.workspace,
                json.dumps([r.record_id for r in proposal.source_refs]),
                json.dumps(list(proposal.source_hashes)),
                proposal.coverage_estimate,
                json.dumps(list(proposal.conflict_flags)),
                proposal.token_savings,
                proposal.proposed_summary,
                proposal.summary_hash,
                proposal.token_unit_id,
                proposal.summary_token_count,
                proposal.status,
                proposal.created_at,
                proposal.proposal_digest,
                proposal.source_set_hash,
                proposal.source_set_hash,
                proposal.source_token_count,
                proposal.summary_token_count,
                proposal.coverage_numerator,
                proposal.coverage_denominator,
                proposal.creator_session,
                proposal.creator_run,
                proposal.creator_role,
            ),
        )
        if cursor.rowcount == 0:
            return False

        for ordinal, (ref, source_hash) in enumerate(
            zip(proposal.source_refs, proposal.source_hashes, strict=True)
        ):
            conn.execute(
                """
                INSERT INTO compression_proposal_sources (
                    proposal_id, ordinal, source_kind, source_record_id,
                    source_hash, lifecycle_state, sensitivity, retention,
                    required_fields_present, required_fields_total, conflict_flags_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    proposal.proposal_id,
                    ordinal,
                    str(ref.kind),
                    ref.record_id,
                    source_hash,
                    "active",
                    "internal",
                    "medium",
                    1,
                    1,
                    "[]",
                ),
            )
        return True

    def read_proposal(
        self, conn: sqlite3.Connection, proposal_id: str, *, owner: str, mode: str, workspace: str | None
    ) -> CompressionProposal | None:
        """Read a v2 proposal with scope qualification."""
        ws_clause = "AND workspace IS ?" if workspace is None else "AND workspace = ?"
        row = conn.execute(
            f"""
            SELECT proposal_id, owner, mode, workspace, source_records_json,
                   source_hashes_json, coverage, conflicts_json, token_savings,
                   proposed_summary, summary_hash, tokenizer_id, real_token_count,
                   status, created_at, proposal_digest, source_set_hash,
                   source_token_count, summary_token_count,
                   coverage_numerator, coverage_denominator,
                   creator_session, creator_run, creator_role
            FROM compression_proposals
            WHERE proposal_id=? AND owner=? AND mode=? {ws_clause}
            """,
            (proposal_id, owner, mode, workspace),
        ).fetchone()
        if row is None:
            return None
        source_ids = tuple(json.loads(str(row[4])))
        source_hashes = tuple(json.loads(str(row[5])))
        source_refs = tuple(
            MemorySourceRefV1(
                kind=MemoryRecordKind("claim"),
                record_id=rid,
            )
            for rid in source_ids
        )
        return CompressionProposal(
            schema_version=2,
            proposal_id=str(row[0]),
            proposal_digest=str(row[15]) if row[15] else "",
            owner=str(row[1]),
            mode=str(row[2]),
            workspace=str(row[3]) if row[3] else None,
            source_refs=source_refs,
            source_hashes=source_hashes,
            source_set_hash=str(row[16]) if row[16] else "",
            coverage_numerator=int(row[19]) if row[19] is not None else 0,
            coverage_denominator=int(row[20]) if row[20] is not None else 1,
            conflict_flags=tuple(json.loads(str(row[7]))),
            source_token_count=int(row[17]) if row[17] is not None else 0,
            summary_token_count=int(row[18]) if row[18] is not None else 0,
            token_savings=int(row[8]),
            token_unit_id=str(row[11]) if row[11] else "unknown",
            summary_hash=str(row[10]),
            proposed_summary=str(row[9]),
            status=str(row[13]),
            created_at=float(row[14]),
            creator_session=str(row[21]) if row[21] else "",
            creator_run=str(row[22]) if row[22] else "",
            creator_role=str(row[23]) if row[23] else "user",
        )

    def cas_status(
        self,
        conn: sqlite3.Connection,
        *,
        proposal_id: str,
        proposal_digest: str,
        old_status: str,
        new_status: str,
        decision_session: str = "",
        decision_run: str = "",
        decision_role: str = "",
        decision_reason: str = "",
    ) -> bool:
        """CAS terminal status transition. Returns True if exactly one row changed."""
        cursor = conn.execute(
            """
            UPDATE compression_proposals
            SET status = ?,
                decision_session = ?, decision_run = ?, decision_role = ?,
                decision_reason = ?
            WHERE proposal_id = ? AND status = ? AND proposal_digest = ?
            """,
            (new_status, decision_session, decision_run, decision_role, decision_reason,
             proposal_id, old_status, proposal_digest),
        )
        return cursor.rowcount == 1

    def insert_capsule(
        self,
        conn: sqlite3.Connection,
        *,
        capsule: ColdCapsule,
    ) -> None:
        """Insert capsule parent + child rows (plain INSERT)."""
        conn.execute(
            """
            INSERT INTO compression_capsules (
                capsule_id, proposal_id, owner, mode, workspace,
                source_record_ids_json, source_hashes_json, summary_hash,
                recovery_index_json, created_at, approved_by,
                format_version, capsule_digest, source_set_hash, summary_text,
                tokenizer_id, source_token_count, summary_token_count,
                recovery_index_digest,
                approved_session, approved_run, approved_role
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 2, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                capsule.capsule_id,
                capsule.proposal_id,
                capsule.owner,
                capsule.mode,
                capsule.workspace,
                json.dumps(list(capsule.source_record_ids)),
                json.dumps(list(capsule.source_hashes)),
                capsule.summary_hash,
                json.dumps(capsule.recovery_index),
                capsule.created_at,
                capsule.owner,
                capsule.capsule_digest,
                capsule.source_set_hash,
                capsule.summary_text,
                capsule.token_unit_id,
                capsule.source_token_count,
                capsule.summary_token_count,
                capsule.recovery_index_digest,
                capsule.approved_session,
                capsule.approved_run,
                capsule.approved_role,
            ),
        )

    def read_capsule(
        self, conn: sqlite3.Connection, capsule_id: str, *, owner: str, mode: str, workspace: str | None
    ) -> ColdCapsule | None:
        """Read a v2 capsule with scope qualification."""
        ws_clause = "AND workspace IS ?" if workspace is None else "AND workspace = ?"
        row = conn.execute(
            f"""
            SELECT capsule_id, proposal_id, owner, mode, workspace,
                   source_record_ids_json, source_hashes_json, summary_hash,
                   recovery_index_json, created_at, approved_by,
                   capsule_digest, source_set_hash, summary_text,
                   tokenizer_id, source_token_count, summary_token_count,
                   recovery_index_digest,
                   approved_session, approved_run, approved_role
            FROM compression_capsules
            WHERE capsule_id = ? AND owner = ? AND mode = ? {ws_clause}
            """,
            (capsule_id, owner, mode, workspace),
        ).fetchone()
        if row is None:
            return None
        return ColdCapsule(
            schema_version=2,
            capsule_id=str(row[0]),
            capsule_digest=str(row[11]) if row[11] else "",
            proposal_id=str(row[1]),
            owner=str(row[2]),
            mode=str(row[3]),
            workspace=str(row[4]) if row[4] else None,
            source_record_ids=tuple(json.loads(str(row[5]))),
            source_hashes=tuple(json.loads(str(row[6]))),
            source_set_hash=str(row[12]) if row[12] else "",
            summary_hash=str(row[7]),
            summary_text=str(row[13]) if row[13] else "",
            token_unit_id=str(row[14]) if row[14] else "unknown",
            source_token_count=int(row[15]) if row[15] is not None else 0,
            summary_token_count=int(row[16]) if row[16] is not None else 0,
            recovery_index=json.loads(str(row[8])),
            recovery_index_digest=str(row[17]) if row[17] else "",
            created_at=float(row[9]),
            approved_session=str(row[18]) if row[18] else "",
            approved_run=str(row[19]) if row[19] else "",
            approved_role=str(row[20]) if row[20] else "",
        )

    def read_capsule_sources(
        self, conn: sqlite3.Connection, capsule_id: str
    ) -> list[dict[str, Any]]:
        """Read capsule child source rows with snapshots."""
        rows = conn.execute(
            """
            SELECT ordinal, source_kind, source_record_id, source_hash,
                   snapshot_json, snapshot_hash, lifecycle_state, sensitivity, retention
            FROM compression_capsule_sources
            WHERE capsule_id = ?
            ORDER BY ordinal
            """,
            (capsule_id,),
        ).fetchall()
        return [
            {
                "ordinal": int(r[0]),
                "source_kind": str(r[1]),
                "source_record_id": str(r[2]),
                "source_hash": str(r[3]),
                "snapshot": json.loads(str(r[4])),
                "snapshot_hash": str(r[5]),
                "lifecycle_state": str(r[6]),
                "sensitivity": str(r[7]),
                "retention": str(r[8]),
            }
            for r in rows
        ]
