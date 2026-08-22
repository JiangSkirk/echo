"""R6 memory authority tests - GREEN phase."""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path

import pytest

from js.memory.compression import CompressionPipeline
from js.memory.compression_schema import ensure_compression_schema
from js.memory.layered.schema import ensure_layered_schema
from js.memory.layers import (
    MemoryCompressionAuthorityV1,
    MemoryRecordKind,
    MemorySourceRefV1,
)

_OWNER_A = "a" * 64
_OWNER_B = "b" * 64
_WORKSPACE_X = "ws-aaaabbbbccccdddd"
_WORKSPACE_Y = "ws-eeeeffffgggghhhh"


def _make_authority(
    *,
    owner: str = _OWNER_A,
    mode: str = "personal",
    workspace: str | None = None,
    role: str = "admin",
) -> MemoryCompressionAuthorityV1:
    return MemoryCompressionAuthorityV1(
        task_ref_hash="sha256:" + "a" * 64,
        owner=owner, mode=mode, workspace=workspace, role=role,
        session="sess-test", run="run-test",
    )


def _setup_db(db_path: Path, *, owner: str = _OWNER_A) -> None:
    with sqlite3.connect(str(db_path)) as conn:
        ensure_layered_schema(conn)
        now = time.time()
        conn.execute(
            "INSERT INTO mem_entities(id, owner_key_hash, type, canonical_name, aliases, "
            "revision, lifecycle_state, created_at, updated_at) "
            "VALUES ('ent-1', ?, 'concept', 'test', '[]', 1, 'active', ?, ?)",
            (owner, now, now),
        )
        conn.execute(
            "INSERT INTO mem_claims(id, owner_key_hash, subject_id, predicate, typed_value, "
            "valid_from, valid_to, observed_at, retired_at, status, confidence, "
            "source_episode_ids, source_semantic_id, source_authority, supersedes_claim_ids, "
            "evidence, created_at, updated_at) "
            "VALUES ('clm-1', ?, 'ent-1', 'pred', 'val', ?, NULL, ?, NULL, 'active', 0.8, "
            "'[]', NULL, 'inferred', '[]', 'ev', ?, ?)",
            (owner, now, now, now, now),
        )
        conn.commit()
    ensure_compression_schema(db_path)


class TestAuthority:
    """权限测试：应 GREEN。"""

    def test_cross_owner_approve_blocked(self, tmp_path: Path) -> None:
        db = tmp_path / "memory.db"
        _setup_db(db, owner=_OWNER_A)
        pipeline = CompressionPipeline(db)
        auth_a = _make_authority(owner=_OWNER_A)
        proposal = pipeline.create_proposal(
            authority=auth_a,
            source_refs=(MemorySourceRefV1(kind=MemoryRecordKind.CLAIM, record_id="clm-1"),),
            proposed_summary="摘要",
        )
        auth_b = _make_authority(owner=_OWNER_B)
        result = pipeline.approve_proposal(proposal.proposal_id, authority=auth_b)
        assert not result.success

    def test_cross_mode_approve_blocked(self, tmp_path: Path) -> None:
        db = tmp_path / "memory.db"
        _setup_db(db, owner=_OWNER_A)
        pipeline = CompressionPipeline(db)
        auth_p = _make_authority(owner=_OWNER_A, mode="personal")
        proposal = pipeline.create_proposal(
            authority=auth_p,
            source_refs=(MemorySourceRefV1(kind=MemoryRecordKind.CLAIM, record_id="clm-1"),),
            proposed_summary="摘要",
        )
        auth_w = _make_authority(owner=_OWNER_A, mode="work", workspace=_WORKSPACE_X)
        result = pipeline.approve_proposal(proposal.proposal_id, authority=auth_w)
        assert not result.success

    def test_cross_workspace_approve_blocked(self, tmp_path: Path) -> None:
        db = tmp_path / "memory.db"
        _setup_db(db, owner=_OWNER_A)
        pipeline = CompressionPipeline(db)
        auth_x = _make_authority(owner=_OWNER_A, mode="work", workspace=_WORKSPACE_X)
        proposal = pipeline.create_proposal(
            authority=auth_x,
            source_refs=(MemorySourceRefV1(kind=MemoryRecordKind.CLAIM, record_id="clm-1"),),
            proposed_summary="摘要",
        )
        auth_y = _make_authority(owner=_OWNER_A, mode="work", workspace=_WORKSPACE_Y)
        result = pipeline.approve_proposal(proposal.proposal_id, authority=auth_y)
        assert not result.success

    def test_user_role_cannot_approve(self, tmp_path: Path) -> None:
        db = tmp_path / "memory.db"
        _setup_db(db)
        pipeline = CompressionPipeline(db)
        auth_admin = _make_authority(role="admin")
        proposal = pipeline.create_proposal(
            authority=auth_admin,
            source_refs=(MemorySourceRefV1(kind=MemoryRecordKind.CLAIM, record_id="clm-1"),),
            proposed_summary="摘要",
        )
        auth_user = _make_authority(role="user")
        result = pipeline.approve_proposal(proposal.proposal_id, authority=auth_user)
        assert not result.success
        assert result.error_code == "insufficient_role"

    def test_rehydrate_wrong_scope_returns_none(self, tmp_path: Path) -> None:
        db = tmp_path / "memory.db"
        _setup_db(db, owner=_OWNER_A)
        pipeline = CompressionPipeline(db)
        auth = _make_authority(owner=_OWNER_A)
        proposal = pipeline.create_proposal(
            authority=auth,
            source_refs=(MemorySourceRefV1(kind=MemoryRecordKind.CLAIM, record_id="clm-1"),),
            proposed_summary="摘要",
        )
        result = pipeline.approve_proposal(proposal.proposal_id, authority=auth)
        auth_b = _make_authority(owner=_OWNER_B)
        rehydrated = pipeline.rehydrate_capsule(result.capsule.capsule_id, authority=auth_b)
        assert rehydrated is None

    def test_no_edits_parameter(self, tmp_path: Path) -> None:
        """approve_proposal 不接受 edits 参数。"""
        db = tmp_path / "memory.db"
        _setup_db(db)
        pipeline = CompressionPipeline(db)
        auth = _make_authority()
        proposal = pipeline.create_proposal(
            authority=auth,
            source_refs=(MemorySourceRefV1(kind=MemoryRecordKind.CLAIM, record_id="clm-1"),),
            proposed_summary="原始摘要",
        )
        with pytest.raises(TypeError):
            pipeline.approve_proposal(
                proposal.proposal_id, authority=auth, edits="篡改",  # type: ignore[call-arg]
            )
