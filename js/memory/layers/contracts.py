"""Layered reversible memory contracts.

R6 scope: Entity/Claim/Relation/Episode/Revision/Summary/Cold Capsule.
Compression pipeline: detect -> propose -> show coverage/conflict/token savings ->
user approve -> write cold capsule -> keep recovery index -> rehydrate on demand.

No auto-delete, no auto-merge conflicts, no cross-mode injection without authorization.
"""

from __future__ import annotations

import hashlib
import re
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from js.echo.primitives import canonical_json_bytes

JsonValue = Any  # type alias for JSON-compatible values

LAYERED_MEMORY_SCHEMA_VERSION = 1
LAYERED_MEMORY_HASH_DOMAIN = b"js-agent:layered-memory:v1\0"

_OWNER_RE = re.compile(r"^[a-f0-9]{16,128}$")
_MODE_RE = re.compile(r"^(personal|work)$")
_SENSITIVITY_LEVELS = frozenset({"public", "internal", "confidential", "restricted"})
_RETENTION_POLICIES = frozenset({"forever", "long", "medium", "short", "ephemeral"})

# ── R6 hard bounds ──

MAX_SOURCES_PER_PROPOSAL = 256
MAX_SOURCE_ID_UTF8_BYTES = 192
MAX_SUMMARY_UTF8_BYTES = 65_536
MAX_SOURCE_SNAPSHOT_UTF8_BYTES = 131_072
MAX_TOTAL_SOURCE_SNAPSHOT_UTF8_BYTES = 4_194_304
MAX_RECOVERY_INDEX_UTF8_BYTES = 1_048_576
MAX_PENDING_PROPOSALS_PER_SCOPE = 256
MAX_LIST_LIMIT = 100
MAX_TOKEN_COUNT = 2**63 - 1


class MemoryLayer(StrEnum):
    """Memory layer classification."""

    WORKING = "working"
    EPISODIC = "episodic"
    SEMANTIC = "semantic"
    COLD = "cold"


class MemoryRecordKind(StrEnum):
    """Kind of layered memory record."""

    ENTITY = "entity"
    CLAIM = "claim"
    RELATION = "relation"
    EPISODE = "episode"
    REVISION = "revision"
    SUMMARY = "summary"
    COLD_CAPSULE = "cold_capsule"


# ── R6 domain-separated hash constants ──

_PROPOSAL_DOMAIN = b"js-agent:memory-compression:proposal:v2\0"
_CAPSULE_DOMAIN = b"js-agent:memory-compression:capsule:v2\0"
_SNAPSHOT_DOMAIN = b"js-agent:memory-compression:source-snapshot:v1\0"
_SOURCE_SET_DOMAIN = b"js-agent:memory-compression:source-set:v1\0"


def _domain_hash(domain: bytes, payload: Any) -> str:
    return "sha256:" + hashlib.sha256(domain + canonical_json_bytes(payload)).hexdigest()


# ── R6 authority and scope contracts ──


CompressionProposalStatus = str  # "pending" | "approved" | "rejected" | "stale" | "superseded"


@dataclass(frozen=True, slots=True)
class MemorySourceRefV1:
    """A reference to a layered memory source record."""

    kind: MemoryRecordKind
    record_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.kind, MemoryRecordKind):
            raise ValueError("kind must be MemoryRecordKind")
        if not isinstance(self.record_id, str) or not self.record_id:
            raise ValueError("record_id must be non-empty string")
        if len(self.record_id.encode("utf-8")) > MAX_SOURCE_ID_UTF8_BYTES:
            raise ValueError(f"record_id exceeds {MAX_SOURCE_ID_UTF8_BYTES} bytes")
        if "\x00" in self.record_id or any(ord(c) < 0x20 for c in self.record_id):
            raise ValueError("record_id contains NUL or control characters")


@dataclass(frozen=True, slots=True)
class CompressionScopeV1:
    """Owner/mode/workspace scope for compression operations."""

    owner: str
    mode: str
    workspace: str | None

    def __post_init__(self) -> None:
        if not isinstance(self.owner, str) or not _OWNER_RE.fullmatch(self.owner):
            raise ValueError("owner must be hex hash (16-128 chars)")
        if not isinstance(self.mode, str) or not _MODE_RE.fullmatch(self.mode):
            raise ValueError("mode must be 'personal' or 'work'")
        if self.mode == "personal" and self.workspace is not None:
            raise ValueError("personal mode must not have workspace")
        if self.mode == "work":
            if self.workspace is None or not isinstance(self.workspace, str):
                raise ValueError("work mode requires non-empty workspace")
            if "\x00" in self.workspace or any(ord(c) < 0x20 for c in self.workspace):
                raise ValueError("workspace contains NUL or control characters")


@dataclass(frozen=True, slots=True)
class MemoryCompressionAuthorityV1:
    """Authority derived from a signed TaskRef for compression operations."""

    task_ref_hash: str
    owner: str
    mode: str
    workspace: str | None
    role: str  # "user" | "admin"
    session: str
    run: str

    def __post_init__(self) -> None:
        if not isinstance(self.task_ref_hash, str) or not self.task_ref_hash.startswith("sha256:"):
            raise ValueError("task_ref_hash must be sha256-prefixed")
        if self.role not in ("user", "admin"):
            raise ValueError("role must be 'user' or 'admin'")
        if not isinstance(self.session, str) or not self.session:
            raise ValueError("session must be non-empty string")
        if not isinstance(self.run, str) or not self.run:
            raise ValueError("run must be non-empty string")
        CompressionScopeV1(owner=self.owner, mode=self.mode, workspace=self.workspace)

    @property
    def scope(self) -> CompressionScopeV1:
        return CompressionScopeV1(owner=self.owner, mode=self.mode, workspace=self.workspace)


@dataclass(frozen=True, slots=True)
class ResolvedMemorySourceV1:
    """A resolved memory source with canonical snapshot."""

    ref: MemorySourceRefV1
    owner: str
    mode: str
    workspace: str | None
    lifecycle_state: str
    sensitivity: str
    retention: str
    canonical_snapshot: Mapping[str, JsonValue]
    content_hash: str
    required_fields_present: int
    required_fields_total: int
    conflict_flags: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class RehydratedCapsuleV1:
    """A fully rehydrated capsule with summary and source payloads."""

    capsule_id: str
    proposal_id: str
    owner: str
    mode: str
    workspace: str | None
    proposed_summary: str
    sources: tuple[ResolvedMemorySourceV1, ...]
    summary_hash: str
    source_set_hash: str
    capsule_digest: str


@dataclass(frozen=True, slots=True)
class CompressionListCursorV1:
    """Cursor for paginated proposal listing."""

    created_at: float
    proposal_id: str


@dataclass(frozen=True, slots=True)
class CompressionProposalPageV1:
    """A page of compression proposals."""

    items: tuple[CompressionProposal, ...]
    next_cursor: CompressionListCursorV1 | None


# ── Legacy MemoryRecord (kept for compatibility) ──


@dataclass(frozen=True)
class MemoryRecord:
    """One layered memory record.

    Each record binds owner/mode/workspace/entity/claim/relation/episode/revision/
    sensitivity/retention policy.
    """

    record_id: str
    kind: MemoryRecordKind
    owner: str
    mode: str
    workspace: str | None
    layer: MemoryLayer
    content_hash: str
    sensitivity: str
    retention: str
    created_at: float
    revised_at: float | None = None
    revision_of: str | None = None
    source_episode: str | None = None
    tags: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)

    def __init_subclass__(cls, **kwargs: object) -> None:
        raise TypeError("MemoryRecord cannot be subclassed")

    def __init__(
        self,
        *,
        record_id: str,
        kind: MemoryRecordKind,
        owner: str,
        mode: str,
        workspace: str | None,
        layer: MemoryLayer,
        content_hash: str,
        sensitivity: str = "internal",
        retention: str = "medium",
        created_at: float = 0.0,
        revised_at: float | None = None,
        revision_of: str | None = None,
        source_episode: str | None = None,
        tags: tuple[str, ...] = (),
        metadata: dict[str, Any] | None = None,
    ) -> None:
        if type(record_id) is not str or not record_id:
            raise ValueError("record_id must be non-empty string")
        if type(owner) is not str or not _OWNER_RE.fullmatch(owner):
            raise ValueError("owner must be hex hash (16-128 chars)")
        if type(mode) is not str or not _MODE_RE.fullmatch(mode):
            raise ValueError("mode must be 'personal' or 'work'")
        if mode == "personal" and workspace is not None:
            raise ValueError("personal mode must not have workspace")
        if mode == "work" and workspace is not None:
            if not isinstance(workspace, str) or not workspace:
                raise ValueError("work mode workspace must be non-empty string")
            if "\x00" in workspace or any(ord(c) < 0x20 for c in workspace):
                raise ValueError("workspace contains NUL or control characters")
        if sensitivity not in _SENSITIVITY_LEVELS:
            raise ValueError(f"sensitivity must be one of {_SENSITIVITY_LEVELS}")
        if retention not in _RETENTION_POLICIES:
            raise ValueError(f"retention must be one of {_RETENTION_POLICIES}")
        if type(content_hash) is not str or not content_hash.startswith("sha256:"):
            raise ValueError("content_hash must be sha256-prefixed")
        object.__setattr__(self, "record_id", record_id)
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "owner", owner)
        object.__setattr__(self, "mode", mode)
        object.__setattr__(self, "workspace", workspace)
        object.__setattr__(self, "layer", layer)
        object.__setattr__(self, "content_hash", content_hash)
        object.__setattr__(self, "sensitivity", sensitivity)
        object.__setattr__(self, "retention", retention)
        object.__setattr__(self, "created_at", created_at if created_at > 0 else time.time())
        object.__setattr__(self, "revised_at", revised_at)
        object.__setattr__(self, "revision_of", revision_of)
        object.__setattr__(self, "source_episode", source_episode)
        object.__setattr__(self, "tags", tuple(tags))
        object.__setattr__(self, "metadata", dict(metadata) if metadata else {})

    @property
    def schema_version(self) -> int:
        return LAYERED_MEMORY_SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "record_id": self.record_id,
            "kind": str(self.kind),
            "owner": self.owner,
            "mode": self.mode,
            "workspace": self.workspace,
            "layer": str(self.layer),
            "content_hash": self.content_hash,
            "sensitivity": self.sensitivity,
            "retention": self.retention,
            "created_at": self.created_at,
            "revised_at": self.revised_at,
            "revision_of": self.revision_of,
            "source_episode": self.source_episode,
            "tags": list(self.tags),
            "metadata": dict(self.metadata),
        }

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict())

    def canonical_hash(self) -> str:
        return "sha256:" + hashlib.sha256(
            LAYERED_MEMORY_HASH_DOMAIN + self.canonical_bytes()
        ).hexdigest()


# ── CompressionProposal v2 ──


@dataclass(frozen=True, slots=True)
class CompressionProposal:
    """A compression proposal v2 with canonical identity.

    proposal_id is a domain-separated SHA-256 that binds source hashes, summary,
    tokenizer, token counts, coverage and conflicts.  Changing any of these
    produces a different proposal_id.
    """

    schema_version: int
    proposal_id: str
    proposal_digest: str
    owner: str
    mode: str
    workspace: str | None
    source_refs: tuple[MemorySourceRefV1, ...]
    source_hashes: tuple[str, ...]
    source_set_hash: str
    coverage_numerator: int
    coverage_denominator: int
    conflict_flags: tuple[str, ...]
    source_token_count: int
    summary_token_count: int
    token_savings: int
    token_unit_id: str
    summary_hash: str
    proposed_summary: str
    status: str = "pending"
    created_at: float = 0.0
    creator_session: str = ""
    creator_run: str = ""
    creator_role: str = "user"

    @property
    def coverage_estimate(self) -> float:
        if self.coverage_denominator == 0:
            return 0.0
        return self.coverage_numerator / self.coverage_denominator

    @property
    def token_savings_estimate(self) -> int:
        return self.token_savings

    @property
    def source_records(self) -> tuple[str, ...]:
        return tuple(r.record_id for r in self.source_refs)

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "proposal_id": self.proposal_id,
            "proposal_digest": self.proposal_digest,
            "owner": self.owner,
            "mode": self.mode,
            "workspace": self.workspace,
            "source_refs": [{"kind": str(r.kind), "record_id": r.record_id} for r in self.source_refs],
            "source_hashes": list(self.source_hashes),
            "source_set_hash": self.source_set_hash,
            "coverage_numerator": self.coverage_numerator,
            "coverage_denominator": self.coverage_denominator,
            "coverage_estimate": self.coverage_estimate,
            "conflict_flags": list(self.conflict_flags),
            "source_token_count": self.source_token_count,
            "summary_token_count": self.summary_token_count,
            "token_savings": self.token_savings,
            "token_unit_id": self.token_unit_id,
            "summary_hash": self.summary_hash,
            "proposed_summary": self.proposed_summary,
            "status": self.status,
            "created_at": self.created_at,
            "creator_session": self.creator_session,
            "creator_run": self.creator_run,
            "creator_role": self.creator_role,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> CompressionProposal:
        return cls(
            schema_version=int(d["schema_version"]),
            proposal_id=str(d["proposal_id"]),
            proposal_digest=str(d["proposal_digest"]),
            owner=str(d["owner"]),
            mode=str(d["mode"]),
            workspace=d.get("workspace"),
            source_refs=tuple(
                MemorySourceRefV1(
                    kind=MemoryRecordKind(r["kind"]),
                    record_id=str(r["record_id"]),
                )
                for r in d.get("source_refs", [])
            ),
            source_hashes=tuple(str(h) for h in d.get("source_hashes", [])),
            source_set_hash=str(d["source_set_hash"]),
            coverage_numerator=int(d["coverage_numerator"]),
            coverage_denominator=int(d["coverage_denominator"]),
            conflict_flags=tuple(str(f) for f in d.get("conflict_flags", [])),
            source_token_count=int(d["source_token_count"]),
            summary_token_count=int(d["summary_token_count"]),
            token_savings=int(d["token_savings"]),
            token_unit_id=str(d["token_unit_id"]),
            summary_hash=str(d["summary_hash"]),
            proposed_summary=str(d["proposed_summary"]),
            status=str(d.get("status", "pending")),
            created_at=float(d.get("created_at", 0.0)),
            creator_session=str(d.get("creator_session", "")),
            creator_run=str(d.get("creator_run", "")),
            creator_role=str(d.get("creator_role", "user")),
        )


# ── ColdCapsule v2 ──


@dataclass(frozen=True, slots=True)
class ColdCapsule:
    """A cold capsule v2 with deterministic identity (no wall time)."""

    schema_version: int
    capsule_id: str
    capsule_digest: str
    proposal_id: str
    owner: str
    mode: str
    workspace: str | None
    source_record_ids: tuple[str, ...]
    source_hashes: tuple[str, ...]
    source_set_hash: str
    summary_hash: str
    summary_text: str
    token_unit_id: str
    source_token_count: int
    summary_token_count: int
    recovery_index: dict[str, Any]
    recovery_index_digest: str
    created_at: float
    approved_session: str
    approved_run: str
    approved_role: str

    @property
    def approved_by(self) -> str:
        return self.owner

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "capsule_id": self.capsule_id,
            "capsule_digest": self.capsule_digest,
            "proposal_id": self.proposal_id,
            "owner": self.owner,
            "mode": self.mode,
            "workspace": self.workspace,
            "source_record_ids": list(self.source_record_ids),
            "source_hashes": list(self.source_hashes),
            "source_set_hash": self.source_set_hash,
            "summary_hash": self.summary_hash,
            "summary_text": self.summary_text,
            "token_unit_id": self.token_unit_id,
            "source_token_count": self.source_token_count,
            "summary_token_count": self.summary_token_count,
            "recovery_index": dict(self.recovery_index),
            "recovery_index_digest": self.recovery_index_digest,
            "created_at": self.created_at,
            "approved_session": self.approved_session,
            "approved_run": self.approved_run,
            "approved_role": self.approved_role,
        }


# ── CompressionResult ──


@dataclass(frozen=True)
class CompressionResult:
    """Result of a compression approve operation."""

    success: bool
    proposal: CompressionProposal | None = None
    capsule: ColdCapsule | None = None
    error_code: str | None = None
    error: str | None = None


# ── Canonical hash helpers ──


def compute_content_hash(content: str) -> str:
    """Compute content hash for memory records."""
    return "sha256:" + hashlib.sha256(content.encode("utf-8")).hexdigest()


def compute_summary_hash(summary: str) -> str:
    """Compute domain-separated hash for a proposed summary."""
    return _domain_hash(b"js-agent:memory-compression:summary:v1\0", {"summary": summary})


def compute_source_set_hash(source_hashes: tuple[str, ...]) -> str:
    """Compute domain-separated hash for a set of source hashes."""
    return _domain_hash(_SOURCE_SET_DOMAIN, {"source_hashes": sorted(source_hashes)})


def compute_proposal_digest(
    *,
    owner: str,
    mode: str,
    workspace: str | None,
    source_entries: list[dict[str, str]],
    source_set_hash: str,
    summary_hash: str,
    token_unit_id: str,
    source_token_count: int,
    summary_token_count: int,
    token_savings: int,
    coverage_numerator: int,
    coverage_denominator: int,
    conflict_flags: tuple[str, ...],
) -> str:
    """Compute the canonical proposal digest (not the proposal_id).

    proposal_id = sha256(domain + canonical_json(proposal_digest_payload))
    """
    payload = {
        "schema_version": 2,
        "policy_version": "r6-v1",
        "owner": owner,
        "mode": mode,
        "workspace": workspace,
        "sources": sorted(source_entries, key=lambda e: (e["kind"], e["record_id"])),
        "source_set_hash": source_set_hash,
        "summary_hash": summary_hash,
        "token_unit_id": token_unit_id,
        "source_token_count": source_token_count,
        "summary_token_count": summary_token_count,
        "token_savings": token_savings,
        "coverage_numerator": coverage_numerator,
        "coverage_denominator": coverage_denominator,
        "conflict_flags": sorted(set(conflict_flags)),
    }
    return _domain_hash(_PROPOSAL_DOMAIN, payload)


def compute_proposal_id(proposal_digest: str) -> str:
    """proposal_id is the hex digest of the proposal_digest (without prefix)."""
    return proposal_digest[len("sha256:"):]


def compute_capsule_id(
    *,
    proposal_id: str,
    owner: str,
    mode: str,
    workspace: str | None,
    approved_role: str,
) -> str:
    """Compute deterministic capsule_id (no wall time)."""
    payload = {
        "proposal_id": proposal_id,
        "owner": owner,
        "mode": mode,
        "workspace": workspace,
        "approved_role": approved_role,
    }
    return _domain_hash(_CAPSULE_DOMAIN, payload)[len("sha256:"):]


def compute_capsule_digest(
    *,
    capsule_id: str,
    proposal_id: str,
    owner: str,
    mode: str,
    workspace: str | None,
    source_set_hash: str,
    summary_hash: str,
    summary_text: str,
    token_unit_id: str,
    source_token_count: int,
    summary_token_count: int,
    recovery_index_digest: str,
    approved_role: str,
) -> str:
    """Compute the canonical capsule digest."""
    payload = {
        "schema_version": 2,
        "capsule_id": capsule_id,
        "proposal_id": proposal_id,
        "owner": owner,
        "mode": mode,
        "workspace": workspace,
        "source_set_hash": source_set_hash,
        "summary_hash": summary_hash,
        "summary_text_hash": hashlib.sha256(summary_text.encode("utf-8")).hexdigest(),
        "token_unit_id": token_unit_id,
        "source_token_count": source_token_count,
        "summary_token_count": summary_token_count,
        "recovery_index_digest": recovery_index_digest,
        "approved_role": approved_role,
    }
    return _domain_hash(_CAPSULE_DOMAIN, payload)


def compute_snapshot_hash(snapshot: Mapping[str, JsonValue]) -> str:
    """Compute domain-separated hash for a source snapshot."""
    return _domain_hash(_SNAPSHOT_DOMAIN, dict(snapshot))


def compute_source_hash(snapshot: Mapping[str, JsonValue]) -> str:
    """Compute domain-separated R6 source hash (not the row's content_hash)."""
    return _domain_hash(b"js-agent:memory-compression:source-hash:v1\0", dict(snapshot))


def compute_recovery_index_digest(recovery_index: dict[str, Any]) -> str:
    """Compute domain-separated hash for the recovery index."""
    return _domain_hash(b"js-agent:memory-compression:recovery-index:v1\0", recovery_index)
