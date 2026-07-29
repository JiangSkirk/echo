from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

MemoryCreator = Literal["model", "tool", "user", "system", "third_party"]
MemoryState = Literal[
    "candidate",
    "quarantine",
    "pending_owner_review",
    "active",
    "rejected",
    "expired",
    "archived",
    "deleted",
    "superseded",
]


@dataclass(frozen=True)
class MemoryCandidate:
    candidate_id: str
    tenant_id: str
    source_parcel_id: str
    extracted_claims_ref: str
    trust_level: str
    taint_labels: tuple[str, ...]
    owner_visible_summary: str
    proposed_retention: str
    confidence: float
    created_by: MemoryCreator
    promotion_policy_id: str


@dataclass(frozen=True)
class MemoryRecord:
    candidate_id: str
    tenant_id: str
    source_parcel_id: str
    extracted_claims_ref: str
    trust_level: str
    taint_labels: tuple[str, ...]
    owner_visible_summary: str
    proposed_retention: str
    confidence: float
    created_by: MemoryCreator
    promotion_policy_id: str
    state: MemoryState
    revoke_reason: str | None = None


class MemoryGate:
    def __init__(self) -> None:
        self._records: dict[tuple[str, str], MemoryRecord] = {}

    def submit(self, candidate: MemoryCandidate) -> MemoryRecord:
        state: MemoryState = (
            "quarantine"
            if candidate.created_by in ("model", "tool", "third_party")
            else "pending_owner_review"
        )
        record = MemoryRecord(
            candidate_id=candidate.candidate_id,
            tenant_id=candidate.tenant_id,
            source_parcel_id=candidate.source_parcel_id,
            extracted_claims_ref=candidate.extracted_claims_ref,
            trust_level=candidate.trust_level,
            taint_labels=candidate.taint_labels,
            owner_visible_summary=candidate.owner_visible_summary,
            proposed_retention=candidate.proposed_retention,
            confidence=candidate.confidence,
            created_by=candidate.created_by,
            promotion_policy_id=candidate.promotion_policy_id,
            state=state,
        )
        self._records[(record.tenant_id, record.candidate_id)] = record
        return record

    def promote(
        self,
        tenant_id: str,
        candidate_id: str,
        *,
        owner_review: bool = False,
    ) -> MemoryRecord:
        key = (tenant_id, candidate_id)
        record = self._records[key]
        if record.state == "quarantine" and not owner_review:
            raise PermissionError("model/tool memories require owner review before promotion")
        promoted = MemoryRecord(
            candidate_id=record.candidate_id,
            tenant_id=record.tenant_id,
            source_parcel_id=record.source_parcel_id,
            extracted_claims_ref=record.extracted_claims_ref,
            trust_level=record.trust_level,
            taint_labels=record.taint_labels,
            owner_visible_summary=record.owner_visible_summary,
            proposed_retention=record.proposed_retention,
            confidence=record.confidence,
            created_by=record.created_by,
            promotion_policy_id=record.promotion_policy_id,
            state="active",
        )
        self._records[key] = promoted
        return promoted

    def revoke(self, tenant_id: str, candidate_id: str, *, reason: str) -> MemoryRecord:
        key = (tenant_id, candidate_id)
        record = self._records[key]
        revoked = MemoryRecord(
            candidate_id=record.candidate_id,
            tenant_id=record.tenant_id,
            source_parcel_id=record.source_parcel_id,
            extracted_claims_ref=record.extracted_claims_ref,
            trust_level=record.trust_level,
            taint_labels=record.taint_labels,
            owner_visible_summary=record.owner_visible_summary,
            proposed_retention=record.proposed_retention,
            confidence=record.confidence,
            created_by=record.created_by,
            promotion_policy_id=record.promotion_policy_id,
            state="superseded",
            revoke_reason=reason,
        )
        self._records[key] = revoked
        return revoked

    def retrieve(
        self,
        *,
        tenant_id: str,
        min_trust_level: str = "model",
    ) -> tuple[MemoryRecord, ...]:
        min_rank = _trust_rank(min_trust_level)
        rows = [
            record
            for (record_tenant, _candidate_id), record in self._records.items()
            if record_tenant == tenant_id
            and record.state == "active"
            and _trust_rank(record.trust_level) >= min_rank
        ]
        return tuple(sorted(rows, key=lambda item: item.candidate_id))


def _trust_rank(trust_level: str) -> int:
    ranks = {
        "model": 10,
        "third_party": 20,
        "tool": 30,
        "user": 40,
        "system": 50,
    }
    return ranks.get(trust_level, 0)
