"""R6 layered reversible memory tests - GREEN phase.

Tests use the new v2 API with MemoryCompressionAuthorityV1 and MemorySourceRefV1.
Uses real mem_* tables as sources.
"""

from __future__ import annotations

import hashlib
import sqlite3
import time
from pathlib import Path

import pytest

from js.memory.compression import CompressionPipeline
from js.memory.compression_schema import ensure_compression_schema
from js.memory.layered.schema import ensure_layered_schema
from js.memory.layers import (
    CompressionScopeV1,
    MemoryCompressionAuthorityV1,
    MemoryLayer,
    MemoryRecord,
    MemoryRecordKind,
    MemorySourceRefV1,
    compute_content_hash,
)

_OWNER = "a" * 64
_OWNER_B = "b" * 64
_WORKSPACE = "ws-test-1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"


def _sha_id(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:32]


def _make_authority(
    *,
    owner: str = _OWNER,
    mode: str = "personal",
    workspace: str | None = None,
    role: str = "admin",
    session: str = "sess-test-001",
    run: str = "run-test-001",
) -> MemoryCompressionAuthorityV1:
    task_ref_hash = "sha256:" + "a" * 64
    return MemoryCompressionAuthorityV1(
        task_ref_hash=task_ref_hash,
        owner=owner,
        mode=mode,
        workspace=workspace,
        role=role,
        session=session,
        run=run,
    )


def _insert_entity(
    conn: sqlite3.Connection,
    *,
    entity_id: str,
    owner: str = _OWNER,
    name: str = "test entity",
    lifecycle_state: str = "active",
) -> None:
    now = time.time()
    conn.execute(
        """
        INSERT INTO mem_entities(
            id, owner_key_hash, type, canonical_name, aliases,
            revision, lifecycle_state, created_at, updated_at
        ) VALUES (?, ?, 'concept', ?, '[]', 1, ?, ?, ?)
        """,
        (entity_id, owner, name, lifecycle_state, now, now),
    )


def _insert_claim(
    conn: sqlite3.Connection,
    *,
    claim_id: str,
    owner: str = _OWNER,
    subject_id: str = "ent-1",
    predicate: str = "test_pred",
    value: str = "test_value",
    status: str = "active",
    confidence: float = 0.8,
    evidence: str = "test evidence",
    source_authority: str = "inferred",
) -> None:
    now = time.time()
    conn.execute(
        """
        INSERT INTO mem_claims(
            id, owner_key_hash, subject_id, predicate, typed_value,
            valid_from, valid_to, observed_at, retired_at, status,
            confidence, source_episode_ids, source_semantic_id,
            source_authority, supersedes_claim_ids, evidence,
            created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, NULL, ?, NULL, ?, ?, '[]', NULL, ?, '[]', ?, ?, ?)
        """,
        (claim_id, owner, subject_id, predicate, value, now, now, status, confidence,
         source_authority, evidence, now, now),
    )


def _setup_db(db_path: Path, *, owner: str = _OWNER) -> None:
    """Set up layered schema + compression schema + a test entity and claim."""
    with sqlite3.connect(str(db_path)) as conn:
        ensure_layered_schema(conn)
        ensure_compression_schema(db_path)
        _insert_entity(conn, entity_id="ent-1", owner=owner, name="测试实体")
        _insert_claim(
            conn,
            claim_id="clm-1",
            owner=owner,
            subject_id="ent-1",
            predicate="名称",
            value="测试值",
            status="active",
            evidence="测试证据",
        )
        conn.commit()


def _make_source_refs() -> tuple[MemorySourceRefV1, ...]:
    return (
        MemorySourceRefV1(kind=MemoryRecordKind.CLAIM, record_id="clm-1"),
    )


class TestMemoryRecord:
    """MemoryRecord contract validation."""

    def test_valid_personal_record(self) -> None:
        r = MemoryRecord(
            record_id="rec-1", kind=MemoryRecordKind.CLAIM, owner=_OWNER,
            mode="personal", workspace=None, layer=MemoryLayer.WORKING,
            content_hash=compute_content_hash("test"), sensitivity="internal",
            retention="medium", created_at=time.time(),
        )
        assert r.mode == "personal"
        assert r.workspace is None
        assert r.content_hash.startswith("sha256:")

    def test_valid_work_record(self) -> None:
        r = MemoryRecord(
            record_id="rec-1", kind=MemoryRecordKind.CLAIM, owner=_OWNER,
            mode="work", workspace=_WORKSPACE, layer=MemoryLayer.WORKING,
            content_hash=compute_content_hash("test"), sensitivity="internal",
            retention="medium", created_at=time.time(),
        )
        assert r.mode == "work"
        assert r.workspace == _WORKSPACE

    def test_personal_rejects_workspace(self) -> None:
        with pytest.raises(ValueError, match="workspace"):
            MemoryRecord(
                record_id="rec-1", kind=MemoryRecordKind.CLAIM, owner=_OWNER,
                mode="personal", workspace="bad", layer=MemoryLayer.WORKING,
                content_hash=compute_content_hash("test"), sensitivity="internal",
                retention="medium", created_at=time.time(),
            )

    def test_record_cannot_be_subclassed(self) -> None:
        with pytest.raises(TypeError):
            class Sub(MemoryRecord):
                pass

    def test_record_id_does_not_use_python_hash(self) -> None:
        r1 = MemoryRecord(
            record_id="rec-sha", kind=MemoryRecordKind.CLAIM, owner=_OWNER,
            mode="personal", workspace=None, layer=MemoryLayer.WORKING,
            content_hash=compute_content_hash("hello"), sensitivity="internal",
            retention="medium", created_at=time.time(),
        )
        assert r1.record_id == "rec-sha"


# ===== Counterexample fixes (now GREEN) =====


class TestR6CounterexampleFixes:
    """6 个反例已修复：应 GREEN。"""

    def test_fix_1_different_summary_different_id(self, tmp_path: Path) -> None:
        """不同 summary 必须产生不同 proposal id。"""
        db = tmp_path / "memory.db"
        _setup_db(db)
        pipeline = CompressionPipeline(db)
        auth = _make_authority()
        refs = _make_source_refs()
        p1 = pipeline.create_proposal(
            authority=auth, source_refs=refs, proposed_summary="摘要A",
        )
        p2 = pipeline.create_proposal(
            authority=auth, source_refs=refs, proposed_summary="摘要B",
        )
        assert p1.proposal_id != p2.proposal_id

    def test_fix_2_cross_owner_approve_blocked(self, tmp_path: Path) -> None:
        """owner B 不能批准 owner A 的 proposal。"""
        db = tmp_path / "memory.db"
        _setup_db(db)
        pipeline = CompressionPipeline(db)
        auth_a = _make_authority(owner=_OWNER)
        refs = _make_source_refs()
        proposal = pipeline.create_proposal(
            authority=auth_a, source_refs=refs, proposed_summary="摘要",
        )
        auth_b = _make_authority(owner=_OWNER_B)
        result = pipeline.approve_proposal(proposal.proposal_id, authority=auth_b)
        assert not result.success
        assert result.error_code in ("not_found", "insufficient_role")

    def test_fix_3_approved_not_reset_by_recreate(self, tmp_path: Path) -> None:
        """已批准 proposal 不被 INSERT OR REPLACE 重置。"""
        db = tmp_path / "memory.db"
        _setup_db(db)
        pipeline = CompressionPipeline(db)
        auth = _make_authority()
        refs = _make_source_refs()
        proposal = pipeline.create_proposal(
            authority=auth, source_refs=refs, proposed_summary="摘要",
        )
        pipeline.approve_proposal(proposal.proposal_id, authority=auth)
        pipeline.create_proposal(
            authority=auth, source_refs=refs, proposed_summary="摘要",
        )
        scope = CompressionScopeV1(owner=_OWNER, mode="personal", workspace=None)
        proposals = pipeline.list_proposals(scope=scope, status="approved")
        assert any(p.proposal_id == proposal.proposal_id for p in proposals)

    def test_fix_4_chinese_no_spaces_real_token_count(self, tmp_path: Path) -> None:
        """无空格中文使用真实 BPE token count。"""
        db = tmp_path / "memory.db"
        _setup_db(db)
        pipeline = CompressionPipeline(db)
        auth = _make_authority()
        refs = _make_source_refs()
        summary = "这是一段没有空格的中文摘要用于测试真实分词器"
        proposal = pipeline.create_proposal(
            authority=auth, source_refs=refs, proposed_summary=summary,
        )
        assert proposal.summary_token_count > 1, "无空格中文 BPE token count 应 > 1"

    def test_fix_5_approval_rereads_real_sources(self, tmp_path: Path) -> None:
        """approval 重读真实来源，检测篡改。"""
        db = tmp_path / "memory.db"
        _setup_db(db)
        pipeline = CompressionPipeline(db)
        auth = _make_authority()
        refs = _make_source_refs()
        proposal = pipeline.create_proposal(
            authority=auth, source_refs=refs, proposed_summary="摘要",
        )
        with sqlite3.connect(str(db)) as conn:
            conn.execute(
                "UPDATE compression_proposal_sources SET source_hash = ? "
                "WHERE proposal_id = ?",
                ("sha256:fakehash", proposal.proposal_id),
            )
            conn.commit()
        result = pipeline.approve_proposal(proposal.proposal_id, authority=auth)
        assert not result.success

    def test_fix_6_rehydrate_returns_summary_and_payload(self, tmp_path: Path) -> None:
        """rehydrate 返回 summary 文本和来源 payload。"""
        db = tmp_path / "memory.db"
        _setup_db(db)
        pipeline = CompressionPipeline(db)
        auth = _make_authority()
        refs = _make_source_refs()
        proposal = pipeline.create_proposal(
            authority=auth, source_refs=refs, proposed_summary="这是完整摘要文本",
        )
        result = pipeline.approve_proposal(proposal.proposal_id, authority=auth)
        assert result.success
        assert result.capsule is not None
        rehydrated = pipeline.rehydrate_capsule(
            result.capsule.capsule_id, authority=auth,
        )
        assert rehydrated is not None
        assert rehydrated.proposed_summary == "这是完整摘要文本"
        assert len(rehydrated.sources) == 1
        assert rehydrated.sources[0].ref.record_id == "clm-1"


class TestCompressionPipeline:
    """Compression pipeline basic operations."""

    def test_create_proposal(self, tmp_path: Path) -> None:
        db = tmp_path / "memory.db"
        _setup_db(db)
        pipeline = CompressionPipeline(db)
        auth = _make_authority()
        proposal = pipeline.create_proposal(
            authority=auth, source_refs=_make_source_refs(),
            proposed_summary="test summary",
        )
        assert proposal.status == "pending"
        assert len(proposal.source_refs) == 1
        assert proposal.coverage_numerator > 0

    def test_approve_proposal_creates_capsule(self, tmp_path: Path) -> None:
        db = tmp_path / "memory.db"
        _setup_db(db)
        pipeline = CompressionPipeline(db)
        auth = _make_authority()
        proposal = pipeline.create_proposal(
            authority=auth, source_refs=_make_source_refs(),
            proposed_summary="summary",
        )
        result = pipeline.approve_proposal(proposal.proposal_id, authority=auth)
        assert result.success
        assert result.capsule is not None
        assert result.capsule.source_record_ids == ("clm-1",)

    def test_reject_proposal(self, tmp_path: Path) -> None:
        db = tmp_path / "memory.db"
        _setup_db(db)
        pipeline = CompressionPipeline(db)
        auth = _make_authority()
        proposal = pipeline.create_proposal(
            authority=auth, source_refs=_make_source_refs(),
            proposed_summary="summary",
        )
        rejected = pipeline.reject_proposal(proposal.proposal_id, authority=auth)
        assert rejected is not None
        assert rejected.status == "rejected"

    def test_user_cannot_approve(self, tmp_path: Path) -> None:
        db = tmp_path / "memory.db"
        _setup_db(db)
        pipeline = CompressionPipeline(db)
        auth_admin = _make_authority(role="admin")
        proposal = pipeline.create_proposal(
            authority=auth_admin, source_refs=_make_source_refs(),
            proposed_summary="summary",
        )
        auth_user = _make_authority(role="user")
        result = pipeline.approve_proposal(proposal.proposal_id, authority=auth_user)
        assert not result.success
        assert result.error_code == "insufficient_role"

    def test_rehydrate_wrong_owner_returns_none(self, tmp_path: Path) -> None:
        db = tmp_path / "memory.db"
        _setup_db(db)
        pipeline = CompressionPipeline(db)
        auth = _make_authority()
        proposal = pipeline.create_proposal(
            authority=auth, source_refs=_make_source_refs(),
            proposed_summary="summary",
        )
        result = pipeline.approve_proposal(proposal.proposal_id, authority=auth)
        auth_b = _make_authority(owner=_OWNER_B)
        rehydrated = pipeline.rehydrate_capsule(
            result.capsule.capsule_id, authority=auth_b,
        )
        assert rehydrated is None

    def test_idempotent_create_same_proposal(self, tmp_path: Path) -> None:
        db = tmp_path / "memory.db"
        _setup_db(db)
        pipeline = CompressionPipeline(db)
        auth = _make_authority()
        refs = _make_source_refs()
        p1 = pipeline.create_proposal(
            authority=auth, source_refs=refs, proposed_summary="same summary",
        )
        p2 = pipeline.create_proposal(
            authority=auth, source_refs=refs, proposed_summary="same summary",
        )
        assert p1.proposal_id == p2.proposal_id

    def test_idempotent_approve_same_capsule(self, tmp_path: Path) -> None:
        db = tmp_path / "memory.db"
        _setup_db(db)
        pipeline = CompressionPipeline(db)
        auth = _make_authority()
        proposal = pipeline.create_proposal(
            authority=auth, source_refs=_make_source_refs(),
            proposed_summary="summary",
        )
        r1 = pipeline.approve_proposal(proposal.proposal_id, authority=auth)
        r2 = pipeline.approve_proposal(proposal.proposal_id, authority=auth)
        assert r1.success and r2.success
        assert r1.capsule is not None and r2.capsule is not None
        assert r1.capsule.capsule_id == r2.capsule.capsule_id


class TestChineseMemory:
    """Chinese memory record basic coverage."""

    @pytest.mark.parametrize("i", range(50))
    def test_chinese_memory_record(self, i: int) -> None:
        content = f"这是第{i}条中文长期记忆测试记录，内容包含一些中文文本。"
        r = MemoryRecord(
            record_id=f"rec-{_sha_id(content)}", kind=MemoryRecordKind.CLAIM,
            owner=_OWNER, mode="personal", workspace=None,
            layer=MemoryLayer.WORKING, content_hash=compute_content_hash(content),
            sensitivity="internal", retention="medium", created_at=time.time(),
        )
        assert r.content_hash.startswith("sha256:")
        assert r.content_hash != compute_content_hash("different")
