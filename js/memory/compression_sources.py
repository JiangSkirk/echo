"""R6 authoritative source resolver.

Resolves MemorySourceRefV1 to ResolvedMemorySourceV1 by reading real mem_* tables
on the same SQLite connection as the compression repository.
"""

from __future__ import annotations

import sqlite3
from typing import Any

from js.memory.layers.contracts import (
    CompressionScopeV1,
    MemoryRecordKind,
    MemorySourceRefV1,
    ResolvedMemorySourceV1,
    compute_source_hash,
)

# ── Coverage policy v1 ──

_COVERAGE_FIELDS: dict[MemoryRecordKind, list[str]] = {
    MemoryRecordKind.ENTITY: ["type", "canonical_name", "aliases", "lifecycle_state", "revision"],
    MemoryRecordKind.CLAIM: ["subject_id", "predicate", "typed_value", "status", "confidence", "source_authority", "evidence"],
    MemoryRecordKind.RELATION: ["source_entity_id", "target_entity_id", "relation_type", "state", "provenance"],
    MemoryRecordKind.EPISODE: ["source_role", "source_type", "occurred_at", "content_hash", "summary", "sensitivity", "retention_class"],
}

# ── Production source allowlist (only entity + claim have real writers) ──

_PRODUCTION_ALLOWED_KINDS = frozenset({MemoryRecordKind.ENTITY, MemoryRecordKind.CLAIM})


class SourceNotFoundError(Exception):
    pass


class UnsupportedSourceKindError(Exception):
    pass


class SourceCorruptionError(Exception):
    pass


class LayeredMemorySourceResolver:
    """Resolves source refs from durable mem_* tables on the same connection."""

    def resolve_sources(
        self,
        conn: sqlite3.Connection,
        *,
        scope: CompressionScopeV1,
        refs: tuple[MemorySourceRefV1, ...],
    ) -> tuple[ResolvedMemorySourceV1, ...]:
        resolved: list[ResolvedMemorySourceV1] = []
        for ref in refs:
            if ref.kind not in _PRODUCTION_ALLOWED_KINDS:
                raise UnsupportedSourceKindError(
                    f"source kind '{ref.kind}' is not supported in production"
                )
            resolved.append(self._resolve_one(conn, scope=scope, ref=ref))
        return tuple(resolved)

    def _resolve_one(
        self,
        conn: sqlite3.Connection,
        *,
        scope: CompressionScopeV1,
        ref: MemorySourceRefV1,
    ) -> ResolvedMemorySourceV1:
        if ref.kind == MemoryRecordKind.ENTITY:
            return self._resolve_entity(conn, scope=scope, ref=ref)
        return self._resolve_claim(conn, scope=scope, ref=ref)

    @staticmethod
    def _resolve_entity(
        conn: sqlite3.Connection,
        *,
        scope: CompressionScopeV1,
        ref: MemorySourceRefV1,
    ) -> ResolvedMemorySourceV1:
        row = conn.execute(
            """
            SELECT id, owner_key_hash, type, canonical_name, aliases, revision,
                   lifecycle_state, created_at, updated_at
            FROM mem_entities
            WHERE id = ? AND owner_key_hash = ?
            """,
            (ref.record_id, scope.owner),
        ).fetchone()
        if row is None:
            raise SourceNotFoundError(f"entity {ref.record_id} not found")
        snapshot: dict[str, Any] = {
            "id": str(row[0]),
            "type": str(row[2]),
            "canonical_name": str(row[3]),
            "aliases": str(row[4]),
            "revision": int(row[5]),
            "lifecycle_state": str(row[6]),
            "created_at": float(row[7]),
            "updated_at": float(row[8]),
        }
        lifecycle_state = str(row[6])
        sensitivity = "internal"
        retention = "medium"
        source_hash = compute_source_hash(snapshot)
        coverage_fields = _COVERAGE_FIELDS[MemoryRecordKind.ENTITY]
        present = sum(1 for f in coverage_fields if snapshot.get(f) is not None and str(snapshot.get(f, "")).strip())
        total = len(coverage_fields)
        conflict_flags: list[str] = []
        if lifecycle_state != "active":
            conflict_flags.append(f"inactive_source:entity:{ref.record_id}")
        if present < total:
            conflict_flags.append(f"incomplete_coverage:entity:{ref.record_id}")
        return ResolvedMemorySourceV1(
            ref=ref,
            owner=scope.owner,
            mode=scope.mode,
            workspace=scope.workspace,
            lifecycle_state=lifecycle_state,
            sensitivity=sensitivity,
            retention=retention,
            canonical_snapshot=snapshot,
            content_hash=source_hash,
            required_fields_present=present,
            required_fields_total=total,
            conflict_flags=tuple(conflict_flags),
        )

    @staticmethod
    def _resolve_claim(
        conn: sqlite3.Connection,
        *,
        scope: CompressionScopeV1,
        ref: MemorySourceRefV1,
    ) -> ResolvedMemorySourceV1:
        row = conn.execute(
            """
            SELECT id, owner_key_hash, subject_id, predicate, typed_value,
                   valid_from, valid_to, observed_at, retired_at, status,
                   confidence, source_episode_ids, source_semantic_id,
                   source_authority, supersedes_claim_ids, evidence,
                   created_at, updated_at
            FROM mem_claims
            WHERE id = ? AND owner_key_hash = ?
            """,
            (ref.record_id, scope.owner),
        ).fetchone()
        if row is None:
            raise SourceNotFoundError(f"claim {ref.record_id} not found")
        snapshot: dict[str, Any] = {
            "id": str(row[0]),
            "subject_id": str(row[2]),
            "predicate": str(row[3]),
            "typed_value": str(row[4]),
            "valid_from": row[5],
            "valid_to": row[6],
            "observed_at": float(row[7]),
            "retired_at": row[8],
            "status": str(row[9]),
            "confidence": float(row[10]),
            "source_episode_ids": str(row[11]),
            "source_authority": str(row[13]),
            "evidence": str(row[15]),
            "created_at": float(row[16]),
            "updated_at": float(row[17]),
        }
        lifecycle_state = str(row[9])
        sensitivity = "internal"
        retention = "medium"
        source_hash = compute_source_hash(snapshot)
        coverage_fields = _COVERAGE_FIELDS[MemoryRecordKind.CLAIM]
        present = sum(1 for f in coverage_fields if snapshot.get(f) is not None and str(snapshot.get(f, "")).strip())
        total = len(coverage_fields)
        conflict_flags: list[str] = []
        if lifecycle_state in ("disputed", "retracted", "candidate"):
            conflict_flags.append(f"disputed_source:claim:{ref.record_id}")
        if lifecycle_state == "superseded":
            conflict_flags.append(f"superseded_source:claim:{ref.record_id}")
        if present < total:
            conflict_flags.append(f"incomplete_coverage:claim:{ref.record_id}")
        return ResolvedMemorySourceV1(
            ref=ref,
            owner=scope.owner,
            mode=scope.mode,
            workspace=scope.workspace,
            lifecycle_state=lifecycle_state,
            sensitivity=sensitivity,
            retention=retention,
            canonical_snapshot=snapshot,
            content_hash=source_hash,
            required_fields_present=present,
            required_fields_total=total,
            conflict_flags=tuple(conflict_flags),
        )
