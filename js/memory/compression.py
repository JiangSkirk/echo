"""Persistent reversible memory compression pipeline v2.

R6: domain-separated canonical SHA-256 IDs, real TokenCounter injection,
same-connection source resolution, single-transaction CAS approval,
restart-safe rehydrate with full summary and source payload.
"""

from __future__ import annotations

import sqlite3
import time
import unicodedata
from collections.abc import Callable
from pathlib import Path
from typing import Any

from js.memory.compression_schema import CompressionRepository
from js.memory.compression_sources import (
    LayeredMemorySourceResolver,
)
from js.memory.layers.contracts import (
    MAX_PENDING_PROPOSALS_PER_SCOPE,
    MAX_SOURCES_PER_PROPOSAL,
    MAX_SUMMARY_UTF8_BYTES,
    ColdCapsule,
    CompressionProposal,
    CompressionResult,
    CompressionScopeV1,
    MemoryCompressionAuthorityV1,
    MemoryRecordKind,
    MemorySourceRefV1,
    RehydratedCapsuleV1,
    ResolvedMemorySourceV1,
    compute_capsule_digest,
    compute_capsule_id,
    compute_proposal_digest,
    compute_proposal_id,
    compute_recovery_index_digest,
    compute_source_set_hash,
    compute_summary_hash,
)
from js.utils.db import db_connection

TokenCounterFactory = Callable[[], Any]


def _nfc(text: str) -> str:
    return unicodedata.normalize("NFC", text)


def _validate_summary(summary: str) -> str:
    if not isinstance(summary, str) or not summary.strip():
        raise ValueError("summary must be non-empty string")
    nfc_summary = _nfc(summary)
    if "\x00" in nfc_summary or any(ord(c) < 0x20 and c not in "\n\r\t" for c in nfc_summary):
        raise ValueError("summary contains NUL or control characters")
    if len(nfc_summary.encode("utf-8")) > MAX_SUMMARY_UTF8_BYTES:
        raise ValueError(f"summary exceeds {MAX_SUMMARY_UTF8_BYTES} bytes")
    return nfc_summary


def _validate_source_refs(refs: tuple[MemorySourceRefV1, ...]) -> tuple[MemorySourceRefV1, ...]:
    if not refs:
        raise ValueError("source_refs must not be empty")
    if len(refs) > MAX_SOURCES_PER_PROPOSAL:
        raise ValueError(f"source_refs exceeds {MAX_SOURCES_PER_PROPOSAL}")
    seen: set[tuple[str, str]] = set()
    for ref in refs:
        key = (str(ref.kind), ref.record_id)
        if key in seen:
            raise ValueError(f"duplicate_source_ref: {ref.kind}:{ref.record_id}")
        seen.add(key)
    return refs


def _sort_sources(refs: tuple[MemorySourceRefV1, ...]) -> tuple[MemorySourceRefV1, ...]:
    return tuple(sorted(refs, key=lambda r: (str(r.kind), r.record_id)))


class CompressionPipeline:
    """Persistent reversible memory compression pipeline v2.

    All proposals and capsules are persisted. Closing and reopening the
    database preserves all state. Uses real TokenCounter for BPE token counting.
    """

    def __init__(
        self,
        db_path: Path,
        *,
        token_counter_factory: TokenCounterFactory | None = None,
    ) -> None:
        self._db_path = db_path
        self._repo = CompressionRepository(db_path)
        self._resolver = LayeredMemorySourceResolver()
        self._token_factory = token_counter_factory
        self._cached_counter: Any = None

    def _get_counter(self) -> Any:
        if self._cached_counter is not None:
            return self._cached_counter
        if self._token_factory is None:
            from js.echo.context_tokenizer import conservative_counter_factory
            self._token_factory = conservative_counter_factory
        self._cached_counter = self._token_factory()
        return self._cached_counter

    def create_proposal(
        self,
        *,
        authority: MemoryCompressionAuthorityV1,
        source_refs: tuple[MemorySourceRefV1, ...],
        proposed_summary: str,
    ) -> CompressionProposal:
        """Create and persist a compression proposal from source refs."""
        summary = _validate_summary(proposed_summary)
        refs = _validate_source_refs(source_refs)
        refs = _sort_sources(refs)

        counter = self._get_counter()
        token_unit_id = counter.token_unit_id

        now = time.time()
        with db_connection(self._db_path) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                pending_count = self._repo.count_pending(
                    conn, owner=authority.owner, mode=authority.mode, workspace=authority.workspace
                )
                if pending_count >= MAX_PENDING_PROPOSALS_PER_SCOPE:
                    raise ValueError(f"pending proposals exceed {MAX_PENDING_PROPOSALS_PER_SCOPE} per scope")
                scope = authority.scope

                resolved = self._resolver.resolve_sources(conn, scope=scope, refs=refs)

                source_hashes = tuple(r.content_hash for r in resolved)
                source_set_hash = compute_source_set_hash(source_hashes)
                summary_hash = compute_summary_hash(summary)

                source_token_count = 0
                for r in resolved:
                    snapshot_bytes = _snapshot_to_bytes(r.canonical_snapshot)
                    count = counter(snapshot_bytes)
                    if not isinstance(count, int) or count < 0 or count > (2**63 - 1):
                        raise ValueError("tokenizer returned invalid count")
                    source_token_count += count

                summary_count = counter(summary.encode("utf-8"))
                if not isinstance(summary_count, int) or summary_count < 0 or summary_count > (2**63 - 1):
                    raise ValueError("tokenizer returned invalid count for summary")

                token_savings = max(0, source_token_count - summary_count)

                coverage_num = sum(r.required_fields_present for r in resolved)
                coverage_den = sum(r.required_fields_total for r in resolved)

                conflict_flags: list[str] = []
                for r in resolved:
                    conflict_flags.extend(r.conflict_flags)

                seen_hashes: dict[str, str] = {}
                for r in resolved:
                    if r.content_hash in seen_hashes:
                        conflict_flags.append(f"duplicate_content:{r.ref.kind}:{r.ref.record_id}")
                    seen_hashes[r.content_hash] = r.ref.record_id

                conflict_flags = sorted(set(conflict_flags))

                source_entries = [
                    {"kind": str(r.ref.kind), "record_id": r.ref.record_id, "content_hash": r.content_hash}
                    for r in resolved
                ]

                proposal_digest = compute_proposal_digest(
                    owner=authority.owner,
                    mode=authority.mode,
                    workspace=authority.workspace,
                    source_entries=source_entries,
                    source_set_hash=source_set_hash,
                    summary_hash=summary_hash,
                    token_unit_id=token_unit_id,
                    source_token_count=source_token_count,
                    summary_token_count=summary_count,
                    token_savings=token_savings,
                    coverage_numerator=coverage_num,
                    coverage_denominator=coverage_den,
                    conflict_flags=tuple(conflict_flags),
                )
                proposal_id = compute_proposal_id(proposal_digest)

                proposal = CompressionProposal(
                    schema_version=2,
                    proposal_id=proposal_id,
                    proposal_digest=proposal_digest,
                    owner=authority.owner,
                    mode=authority.mode,
                    workspace=authority.workspace,
                    source_refs=refs,
                    source_hashes=source_hashes,
                    source_set_hash=source_set_hash,
                    coverage_numerator=coverage_num,
                    coverage_denominator=coverage_den,
                    conflict_flags=tuple(conflict_flags),
                    source_token_count=source_token_count,
                    summary_token_count=summary_count,
                    token_savings=token_savings,
                    token_unit_id=token_unit_id,
                    summary_hash=summary_hash,
                    proposed_summary=summary,
                    status="pending",
                    created_at=now,
                    creator_session=authority.session,
                    creator_run=authority.run,
                    creator_role=authority.role,
                )

                inserted = self._repo.insert_proposal(conn, proposal=proposal)
                if not inserted:
                    existing = self._repo.read_proposal(
                        conn, proposal_id,
                        owner=authority.owner,
                        mode=authority.mode,
                        workspace=authority.workspace,
                    )
                    if existing is None or existing.proposal_digest != proposal_digest:
                        raise ValueError("corrupt_compression_state: proposal_id collision with different digest")

                conn.commit()
                return proposal
            except Exception:
                conn.rollback()
                raise

    def approve_proposal(
        self,
        proposal_id: str,
        *,
        authority: MemoryCompressionAuthorityV1,
    ) -> CompressionResult:
        """Approve a proposal: re-resolve sources, recompute tokens, CAS, insert capsule."""
        if authority.role != "admin":
            return CompressionResult(
                success=False,
                error_code="insufficient_role",
                error="only admin can approve proposals",
            )

        with db_connection(self._db_path) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                proposal = self._repo.read_proposal(
                    conn, proposal_id,
                    owner=authority.owner,
                    mode=authority.mode,
                    workspace=authority.workspace,
                )
                if proposal is None:
                    return CompressionResult(
                        success=False, error_code="not_found", error="proposal not found"
                    )
                if proposal.status != "pending":
                    if proposal.status == "approved":
                        return self._return_existing_capsule(conn, proposal, authority)
                    return CompressionResult(
                        success=False,
                        error_code="terminal_conflict",
                        error=f"proposal is {proposal.status}",
                    )

                if proposal.conflict_flags:
                    return CompressionResult(
                        success=False,
                        error_code="unresolved_conflicts",
                        error="conflicts must be resolved before approval",
                    )

                counter = self._get_counter()
                if counter.token_unit_id != proposal.token_unit_id:
                    return self._stale_proposal(conn, proposal, authority, "token_unit_drift")

                resolved = self._resolver.resolve_sources(
                    conn, scope=authority.scope, refs=proposal.source_refs
                )

                current_hashes = tuple(r.content_hash for r in resolved)
                if current_hashes != proposal.source_hashes:
                    return self._stale_proposal(conn, proposal, authority, "source_hash_mismatch")

                # Verify proposal_sources child rows match resolved sources
                child_rows = conn.execute(
                    "SELECT ordinal, source_hash FROM compression_proposal_sources "
                    "WHERE proposal_id = ? ORDER BY ordinal",
                    (proposal.proposal_id,),
                ).fetchall()
                if len(child_rows) != len(resolved):
                    return self._stale_proposal(conn, proposal, authority, "child_row_count_mismatch")
                for _idx, (cr, r) in enumerate(zip(child_rows, resolved, strict=True)):
                    if str(cr[1]) != r.content_hash:
                        return self._stale_proposal(conn, proposal, authority, "child_hash_mismatch")

                source_token_count = 0
                for r in resolved:
                    snapshot_bytes = _snapshot_to_bytes(r.canonical_snapshot)
                    count = counter(snapshot_bytes)
                    if not isinstance(count, int) or count < 0:
                        return self._stale_proposal(conn, proposal, authority, "token_count_invalid")
                    source_token_count += count

                if source_token_count != proposal.source_token_count:
                    return self._stale_proposal(conn, proposal, authority, "source_token_count_drift")

                summary_count = counter(proposal.proposed_summary.encode("utf-8"))
                if summary_count != proposal.summary_token_count:
                    return self._stale_proposal(conn, proposal, authority, "summary_token_count_drift")

                source_set_hash = compute_source_set_hash(current_hashes)
                if source_set_hash != proposal.source_set_hash:
                    return self._stale_proposal(conn, proposal, authority, "source_set_hash_mismatch")

                capsule_id = compute_capsule_id(
                    proposal_id=proposal.proposal_id,
                    owner=authority.owner,
                    mode=authority.mode,
                    workspace=authority.workspace,
                    approved_role=authority.role,
                )

                recovery_index: dict[str, Any] = {}
                for ordinal, r in enumerate(resolved):
                    recovery_index[str(ordinal)] = {
                        "ordinal": ordinal,
                        "kind": str(r.ref.kind),
                        "id": r.ref.record_id,
                        "source_hash": r.content_hash,
                        "snapshot_hash": compute_snapshot_hash_safe(r.canonical_snapshot),
                        "lifecycle_state": r.lifecycle_state,
                        "sensitivity": r.sensitivity,
                        "retention": r.retention,
                    }
                recovery_index_digest = compute_recovery_index_digest(recovery_index)

                capsule_digest = compute_capsule_digest(
                    capsule_id=capsule_id,
                    proposal_id=proposal.proposal_id,
                    owner=authority.owner,
                    mode=authority.mode,
                    workspace=authority.workspace,
                    source_set_hash=source_set_hash,
                    summary_hash=proposal.summary_hash,
                    summary_text=proposal.proposed_summary,
                    token_unit_id=proposal.token_unit_id,
                    source_token_count=source_token_count,
                    summary_token_count=summary_count,
                    recovery_index_digest=recovery_index_digest,
                    approved_role=authority.role,
                )

                now = time.time()
                capsule = ColdCapsule(
                    schema_version=2,
                    capsule_id=capsule_id,
                    capsule_digest=capsule_digest,
                    proposal_id=proposal.proposal_id,
                    owner=authority.owner,
                    mode=authority.mode,
                    workspace=authority.workspace,
                    source_record_ids=tuple(r.ref.record_id for r in resolved),
                    source_hashes=current_hashes,
                    source_set_hash=source_set_hash,
                    summary_hash=proposal.summary_hash,
                    summary_text=proposal.proposed_summary,
                    token_unit_id=proposal.token_unit_id,
                    source_token_count=source_token_count,
                    summary_token_count=summary_count,
                    recovery_index=recovery_index,
                    recovery_index_digest=recovery_index_digest,
                    created_at=now,
                    approved_session=authority.session,
                    approved_run=authority.run,
                    approved_role=authority.role,
                )

                self._repo.insert_capsule(conn, capsule=capsule)

                for ordinal, r in enumerate(resolved):
                    snapshot_json = _snapshot_to_json(r.canonical_snapshot)
                    snapshot_hash = compute_snapshot_hash_safe(r.canonical_snapshot)
                    conn.execute(
                        """
                        INSERT INTO compression_capsule_sources (
                            capsule_id, ordinal, source_kind, source_record_id,
                            source_hash, snapshot_json, snapshot_hash,
                            lifecycle_state, sensitivity, retention
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            capsule_id,
                            ordinal,
                            str(r.ref.kind),
                            r.ref.record_id,
                            r.content_hash,
                            snapshot_json,
                            snapshot_hash,
                            r.lifecycle_state,
                            r.sensitivity,
                            r.retention,
                        ),
                    )

                cas_ok = self._repo.cas_status(
                    conn,
                    proposal_id=proposal.proposal_id,
                    proposal_digest=proposal.proposal_digest,
                    old_status="pending",
                    new_status="approved",
                    decision_session=authority.session,
                    decision_run=authority.run,
                    decision_role=authority.role,
                    decision_reason="approved",
                )
                if not cas_ok:
                    return self._return_existing_capsule(conn, proposal, authority)

                conn.commit()
                return CompressionResult(success=True, proposal=proposal, capsule=capsule)
            except Exception:
                conn.rollback()
                raise

    def reject_proposal(
        self,
        proposal_id: str,
        *,
        authority: MemoryCompressionAuthorityV1,
    ) -> CompressionProposal | None:
        """Reject a pending proposal (admin only)."""
        if authority.role != "admin":
            raise PermissionError("only admin can reject proposals")
        with db_connection(self._db_path) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                proposal = self._repo.read_proposal(
                    conn, proposal_id,
                    owner=authority.owner,
                    mode=authority.mode,
                    workspace=authority.workspace,
                )
                if proposal is None:
                    return None
                if proposal.status == "rejected":
                    return proposal
                if proposal.status != "pending":
                    raise ValueError(f"proposal is {proposal.status}")
                self._repo.cas_status(
                    conn,
                    proposal_id=proposal.proposal_id,
                    proposal_digest=proposal.proposal_digest,
                    old_status="pending",
                    new_status="rejected",
                    decision_session=authority.session,
                    decision_run=authority.run,
                    decision_role=authority.role,
                    decision_reason="rejected",
                )
                conn.commit()
                return self._repo.read_proposal(
                    conn, proposal_id,
                    owner=authority.owner,
                    mode=authority.mode,
                    workspace=authority.workspace,
                )
            except Exception:
                conn.rollback()
                raise

    def rehydrate_capsule(
        self,
        capsule_id: str,
        *,
        authority: MemoryCompressionAuthorityV1,
    ) -> RehydratedCapsuleV1 | None:
        """Rehydrate a capsule with full summary and source payloads."""
        with db_connection(self._db_path) as conn:
            capsule = self._repo.read_capsule(
                conn, capsule_id,
                owner=authority.owner,
                mode=authority.mode,
                workspace=authority.workspace,
            )
            if capsule is None:
                return None

            source_rows = self._repo.read_capsule_sources(conn, capsule_id)

            sources: list[ResolvedMemorySourceV1] = []
            for sr in source_rows:
                snapshot = sr["snapshot"]
                sources.append(
                    ResolvedMemorySourceV1(
                        ref=MemorySourceRefV1(
                            kind=MemoryRecordKind(sr["source_kind"]),
                            record_id=sr["source_record_id"],
                        ),
                        owner=authority.owner,
                        mode=authority.mode,
                        workspace=authority.workspace,
                        lifecycle_state=sr["lifecycle_state"],
                        sensitivity=sr["sensitivity"],
                        retention=sr["retention"],
                        canonical_snapshot=snapshot,
                        content_hash=sr["source_hash"],
                        required_fields_present=0,
                        required_fields_total=0,
                        conflict_flags=(),
                    )
                )

            recovery_index_digest = compute_recovery_index_digest(capsule.recovery_index)
            if recovery_index_digest != capsule.recovery_index_digest:
                raise ValueError("corrupt_compression_state: recovery_index_digest mismatch")

            capsule_digest = compute_capsule_digest(
                capsule_id=capsule.capsule_id,
                proposal_id=capsule.proposal_id,
                owner=capsule.owner,
                mode=capsule.mode,
                workspace=capsule.workspace,
                source_set_hash=capsule.source_set_hash,
                summary_hash=capsule.summary_hash,
                summary_text=capsule.summary_text,
                token_unit_id=capsule.token_unit_id,
                source_token_count=capsule.source_token_count,
                summary_token_count=capsule.summary_token_count,
                recovery_index_digest=recovery_index_digest,
                approved_role=capsule.approved_role,
            )
            if capsule_digest != capsule.capsule_digest:
                raise ValueError("corrupt_compression_state: capsule_digest mismatch")

            return RehydratedCapsuleV1(
                capsule_id=capsule.capsule_id,
                proposal_id=capsule.proposal_id,
                owner=capsule.owner,
                mode=capsule.mode,
                workspace=capsule.workspace,
                proposed_summary=capsule.summary_text,
                sources=tuple(sources),
                summary_hash=capsule.summary_hash,
                source_set_hash=capsule.source_set_hash,
                capsule_digest=capsule.capsule_digest,
            )

    def list_proposals(
        self,
        *,
        scope: CompressionScopeV1,
        status: str = "pending",
        limit: int = 50,
    ) -> list[CompressionProposal]:
        """List proposals for a scope."""
        if limit < 1 or limit > 100:
            limit = min(max(limit, 1), 100)
        ws_clause = "AND workspace IS ?" if scope.workspace is None else "AND workspace = ?"
        with db_connection(self._db_path) as conn:
            rows = conn.execute(
                f"""
                SELECT proposal_id, owner, mode, workspace, source_records_json,
                       source_hashes_json, coverage, conflicts_json, token_savings,
                       proposed_summary, summary_hash, tokenizer_id, real_token_count,
                       status, created_at, proposal_digest, source_set_hash,
                       source_token_count, summary_token_count,
                       coverage_numerator, coverage_denominator,
                       creator_session, creator_run, creator_role
                FROM compression_proposals
                WHERE owner=? AND mode=? {ws_clause} AND status=?
                ORDER BY created_at DESC LIMIT ?
                """,
                (scope.owner, scope.mode, scope.workspace, status, limit),
            ).fetchall()
        return [self._row_to_proposal(r) for r in rows]

    def list_capsules(
        self,
        *,
        scope: CompressionScopeV1,
    ) -> list[ColdCapsule]:
        """List capsules for a scope."""
        ws_clause = "AND workspace IS ?" if scope.workspace is None else "AND workspace = ?"
        with db_connection(self._db_path) as conn:
            rows = conn.execute(
                f"""
                SELECT capsule_id, proposal_id, owner, mode, workspace,
                       source_record_ids_json, source_hashes_json, summary_hash,
                       recovery_index_json, created_at, approved_by,
                       capsule_digest, source_set_hash, summary_text,
                       tokenizer_id, source_token_count, summary_token_count,
                       recovery_index_digest,
                       approved_session, approved_run, approved_role
                FROM compression_capsules
                WHERE owner=? AND mode=? {ws_clause}
                ORDER BY created_at DESC
                """,
                (scope.owner, scope.mode, scope.workspace),
            ).fetchall()
        return [self._row_to_capsule(r) for r in rows]

    def get_capsule(self, capsule_id: str) -> ColdCapsule | None:
        """Get a capsule without scope qualification (for tests only)."""
        with db_connection(self._db_path) as conn:
            row = conn.execute(
                """
                SELECT capsule_id, proposal_id, owner, mode, workspace,
                       source_record_ids_json, source_hashes_json, summary_hash,
                       recovery_index_json, created_at, approved_by,
                       capsule_digest, source_set_hash, summary_text,
                       tokenizer_id, source_token_count, summary_token_count,
                       recovery_index_digest,
                       approved_session, approved_run, approved_role
                FROM compression_capsules WHERE capsule_id = ?
                """,
                (capsule_id,),
            ).fetchone()
        if row is None:
            return None
        return self._row_to_capsule(row)

    def _return_existing_capsule(
        self, conn: sqlite3.Connection, proposal: CompressionProposal, authority: MemoryCompressionAuthorityV1
    ) -> CompressionResult:
        """Return existing approved capsule for idempotent retry."""
        ws_clause = "AND workspace IS ?" if authority.workspace is None else "AND workspace = ?"
        row = conn.execute(
            f"""
            SELECT capsule_id FROM compression_capsules
            WHERE proposal_id = ? AND owner = ? AND mode = ? {ws_clause}
            """,
            (proposal.proposal_id, authority.owner, authority.mode, authority.workspace),
        ).fetchone()
        if row is None:
            return CompressionResult(
                success=False, error_code="corrupt_state",
                error="proposal marked approved but no capsule found",
            )
        capsule = self._repo.read_capsule(
            conn, str(row[0]),
            owner=authority.owner, mode=authority.mode, workspace=authority.workspace,
        )
        if capsule is None:
            return CompressionResult(
                success=False, error_code="corrupt_state",
                error="capsule not found after approved status",
            )
        return CompressionResult(success=True, proposal=proposal, capsule=capsule)

    def _stale_proposal(
        self, conn: sqlite3.Connection, proposal: CompressionProposal,
        authority: MemoryCompressionAuthorityV1, reason: str,
    ) -> CompressionResult:
        """CAS proposal to stale and return error."""
        self._repo.cas_status(
            conn,
            proposal_id=proposal.proposal_id,
            proposal_digest=proposal.proposal_digest,
            old_status="pending",
            new_status="stale",
            decision_session=authority.session,
            decision_run=authority.run,
            decision_role=authority.role,
            decision_reason=reason,
        )
        conn.commit()
        return CompressionResult(
            success=False, error_code="stale_proposal",
            error=f"proposal is stale: {reason}",
        )

    @staticmethod
    def _row_to_proposal(row: tuple[Any, ...]) -> CompressionProposal:
        import json as _json
        source_ids = tuple(_json.loads(str(row[4])))
        source_hashes = tuple(_json.loads(str(row[5])))
        source_refs = tuple(
            MemorySourceRefV1(kind=MemoryRecordKind("claim"), record_id=rid)
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
            conflict_flags=tuple(_json.loads(str(row[7]))),
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

    @staticmethod
    def _row_to_capsule(row: tuple[Any, ...]) -> ColdCapsule:
        import json as _json
        return ColdCapsule(
            schema_version=2,
            capsule_id=str(row[0]),
            capsule_digest=str(row[11]) if row[11] else "",
            proposal_id=str(row[1]),
            owner=str(row[2]),
            mode=str(row[3]),
            workspace=str(row[4]) if row[4] else None,
            source_record_ids=tuple(_json.loads(str(row[5]))),
            source_hashes=tuple(_json.loads(str(row[6]))),
            source_set_hash=str(row[12]) if row[12] else "",
            summary_hash=str(row[7]),
            summary_text=str(row[13]) if row[13] else "",
            token_unit_id=str(row[14]) if row[14] else "unknown",
            source_token_count=int(row[15]) if row[15] is not None else 0,
            summary_token_count=int(row[16]) if row[16] is not None else 0,
            recovery_index=_json.loads(str(row[8])),
            recovery_index_digest=str(row[17]) if row[17] else "",
            created_at=float(row[9]),
            approved_session=str(row[18]) if row[18] else "",
            approved_run=str(row[19]) if row[19] else "",
            approved_role=str(row[20]) if row[20] else "",
        )


def _snapshot_to_bytes(snapshot: Any) -> bytes:
    from js.echo.primitives import canonical_json_bytes
    return canonical_json_bytes(dict(snapshot))


def _snapshot_to_json(snapshot: Any) -> str:
    from js.echo.primitives import canonical_json_bytes
    return canonical_json_bytes(dict(snapshot)).decode("utf-8")


def compute_snapshot_hash_safe(snapshot: Any) -> str:
    from js.memory.layers.contracts import compute_snapshot_hash
    return compute_snapshot_hash(dict(snapshot))
