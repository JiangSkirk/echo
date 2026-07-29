"""Layered memory store: Entity/Claim dual-write beside legacy semantic tables."""

from __future__ import annotations

import json
import sqlite3
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from js.memory.layered.conflict import decide_claim_conflict
from js.memory.layered.schema import ensure_layered_schema
from js.utils.db import db_connection
from js.utils.log import get_logger

logger = get_logger("js.memory.layered")

_OWNER_SENTINEL = "__legacy_local__"


def _owner(owner_key_hash: str | None) -> str:
    return owner_key_hash if owner_key_hash else _OWNER_SENTINEL


@dataclass(frozen=True, slots=True)
class ClaimRecord:
    id: str
    owner_key_hash: str
    subject_id: str
    predicate: str
    typed_value: str
    status: str
    confidence: float
    evidence: str


class LayeredMemoryStore:
    """Side-car store sharing ``memory_enhanced.db`` with EnhancedMemoryStore."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self._ensured = False

    def ensure(self) -> None:
        if self._ensured:
            return
        with db_connection(self.db_path) as conn:
            ensure_layered_schema(conn)
        self._ensured = True

    def upsert_entity(
        self,
        *,
        owner_key_hash: str | None,
        canonical_name: str,
        entity_type: str = "concept",
        aliases: list[str] | None = None,
    ) -> str:
        """Return entity id for (owner, canonical_name), creating if needed."""
        self.ensure()
        owner = _owner(owner_key_hash)
        name = canonical_name.strip() or "unknown"
        now = time.time()
        with db_connection(self.db_path) as conn:
            row = conn.execute(
                """
                SELECT id FROM mem_entities
                WHERE owner_key_hash = ? AND canonical_name = ?
                  AND lifecycle_state = 'active'
                """,
                (owner, name),
            ).fetchone()
            if row:
                return str(row[0])
            entity_id = str(uuid.uuid4())
            conn.execute(
                """
                INSERT INTO mem_entities(
                    id, owner_key_hash, type, canonical_name, aliases,
                    revision, lifecycle_state, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, 1, 'active', ?, ?)
                """,
                (
                    entity_id,
                    owner,
                    entity_type or "concept",
                    name,
                    json.dumps(aliases or [], ensure_ascii=False),
                    now,
                    now,
                ),
            )
            conn.commit()
            return entity_id

    def upsert_claim_from_semantic(
        self,
        *,
        owner_key_hash: str | None,
        key: str,
        value: str,
        category: str = "fact",
        confidence: float = 0.5,
        entity_type: str | None = None,
        entity_name: str | None = None,
        source_semantic_id: int | None = None,
        evidence: str = "",
        explicit_correction: bool = False,
        source_authority: str = "inferred",
    ) -> dict[str, Any]:
        """Map a legacy semantic write into Entity+Claim with conflict rules."""
        self.ensure()
        owner = _owner(owner_key_hash)
        subject_name = (entity_name or key).strip() or key
        predicate = key if entity_name else (category or "fact")
        subject_id = self.upsert_entity(
            owner_key_hash=owner_key_hash,
            canonical_name=subject_name,
            entity_type=entity_type or "concept",
        )
        now = time.time()
        with db_connection(self.db_path) as conn:
            existing = conn.execute(
                """
                SELECT id, typed_value, status FROM mem_claims
                WHERE owner_key_hash = ? AND subject_id = ? AND predicate = ?
                  AND status IN ('active', 'disputed', 'candidate')
                ORDER BY
                  CASE status WHEN 'active' THEN 0 WHEN 'disputed' THEN 1 ELSE 2 END,
                  updated_at DESC
                LIMIT 1
                """,
                (owner, subject_id, predicate),
            ).fetchone()
            existing_value = str(existing[1]) if existing else None
            decision = decide_claim_conflict(
                existing_value=existing_value,
                incoming_value=value,
                explicit_correction=explicit_correction,
            )
            if existing and decision.new_status == "candidate" and existing_value == value.strip():
                return {
                    "claim_id": str(existing[0]),
                    "status": str(existing[2]),
                    "subject_id": subject_id,
                    "skipped_duplicate": True,
                }

            claim_id = str(uuid.uuid4())
            supersedes: list[str] = []
            if existing and decision.retire_existing_as is not None:
                conn.execute(
                    """
                    UPDATE mem_claims
                    SET status = ?, retired_at = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (decision.retire_existing_as, now, now, existing[0]),
                )
                if decision.retire_existing_as == "superseded":
                    supersedes.append(str(existing[0]))
                    self._tombstone(
                        conn,
                        owner=owner,
                        object_type="claim",
                        object_id=str(existing[0]),
                        reason="superseded",
                        now=now,
                    )
                elif decision.retire_existing_as == "disputed":
                    # Mark prior active as disputed as well
                    pass

            conn.execute(
                """
                INSERT INTO mem_claims(
                    id, owner_key_hash, subject_id, predicate, typed_value,
                    valid_from, valid_to, observed_at, retired_at, status,
                    confidence, source_episode_ids, source_semantic_id,
                    source_authority, supersedes_claim_ids, evidence,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, NULL, ?, NULL, ?, ?, '[]', ?, ?, ?, ?, ?, ?)
                """,
                (
                    claim_id,
                    owner,
                    subject_id,
                    predicate,
                    value,
                    now,
                    now,
                    decision.new_status,
                    confidence,
                    source_semantic_id,
                    source_authority,
                    json.dumps(supersedes),
                    evidence or "",
                    now,
                    now,
                ),
            )
            conn.commit()
            return {
                "claim_id": claim_id,
                "status": decision.new_status,
                "subject_id": subject_id,
                "superseded": supersedes,
                "skipped_duplicate": False,
            }

    def list_active_claims(
        self,
        *,
        owner_key_hash: str | None,
        limit: int = 20,
        query: str = "",
    ) -> list[ClaimRecord]:
        self.ensure()
        owner = _owner(owner_key_hash)
        with db_connection(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            if query.strip():
                like = f"%{query.strip()}%"
                rows = conn.execute(
                    """
                    SELECT id, owner_key_hash, subject_id, predicate, typed_value,
                           status, confidence, evidence
                    FROM mem_claims
                    WHERE owner_key_hash = ? AND status = 'active'
                      AND (predicate LIKE ? OR typed_value LIKE ?)
                    ORDER BY updated_at DESC
                    LIMIT ?
                    """,
                    (owner, like, like, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT id, owner_key_hash, subject_id, predicate, typed_value,
                           status, confidence, evidence
                    FROM mem_claims
                    WHERE owner_key_hash = ? AND status = 'active'
                    ORDER BY updated_at DESC
                    LIMIT ?
                    """,
                    (owner, limit),
                ).fetchall()
        return [
            ClaimRecord(
                id=str(r["id"]),
                owner_key_hash=str(r["owner_key_hash"]),
                subject_id=str(r["subject_id"]),
                predicate=str(r["predicate"]),
                typed_value=str(r["typed_value"]),
                status=str(r["status"]),
                confidence=float(r["confidence"] or 0.5),
                evidence=str(r["evidence"] or ""),
            )
            for r in rows
        ]

    def format_claims_context(
        self,
        *,
        owner_key_hash: str | None,
        query: str = "",
        max_chars: int = 800,
    ) -> str:
        claims = self.list_active_claims(owner_key_hash=owner_key_hash, limit=12, query=query)
        if not claims:
            return ""
        lines = [f"- [{c.predicate}] {c.typed_value[:200]}" for c in claims]
        block = "## Layered Claims\n" + "\n".join(lines) + "\n\n"
        return block if len(block) <= max_chars else block[: max_chars - 1] + "…\n\n"

    def retire_claim(
        self,
        claim_id: str,
        *,
        owner_key_hash: str | None,
        reason: str = "retracted",
    ) -> bool:
        """Soft-retire a claim (tombstone); never physical DELETE."""
        self.ensure()
        owner = _owner(owner_key_hash)
        now = time.time()
        with db_connection(self.db_path) as conn:
            cur = conn.execute(
                """
                UPDATE mem_claims
                SET status = 'retracted', retired_at = ?, updated_at = ?
                WHERE id = ? AND owner_key_hash = ?
                """,
                (now, now, claim_id, owner),
            )
            if cur.rowcount <= 0:
                return False
            self._tombstone(
                conn,
                owner=owner,
                object_type="claim",
                object_id=claim_id,
                reason=reason,
                now=now,
            )
            conn.commit()
            return True

    @staticmethod
    def _tombstone(
        conn: sqlite3.Connection,
        *,
        owner: str,
        object_type: str,
        object_id: str,
        reason: str,
        now: float,
    ) -> None:
        conn.execute(
            """
            INSERT INTO mem_tombstones(
                id, owner_key_hash, object_type, object_id, reason, retired_at, content_hash
            ) VALUES (?, ?, ?, ?, ?, ?, '')
            """,
            (str(uuid.uuid4()), owner, object_type, object_id, reason, now),
        )

    def dual_write_semantic(
        self,
        *,
        owner_key_hash: str | None,
        key: str,
        value: str,
        category: str,
        confidence: float,
        entity_type: str | None,
        entity_name: str | None,
        source_semantic_id: int | None,
        evidence: str,
        source: str,
    ) -> dict[str, Any] | None:
        """Best-effort dual-write; never raises to callers."""
        try:
            explicit = source in {"user", "manual"}
            authority = "user" if explicit else "inferred"
            return self.upsert_claim_from_semantic(
                owner_key_hash=owner_key_hash,
                key=key,
                value=value,
                category=category,
                confidence=confidence,
                entity_type=entity_type,
                entity_name=entity_name,
                source_semantic_id=source_semantic_id,
                evidence=evidence,
                explicit_correction=explicit,
                source_authority=authority,
            )
        except Exception:
            logger.warning("layered dual-write failed; legacy semantic kept", exc_info=True)
            return None
