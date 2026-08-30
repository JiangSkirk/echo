"""Inbox projection: authority, attention sources, and artifact visibility."""

from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any

import pytest

from js.appshell.inbox import (
    ProjectionAuthorityV1,
    ProjectionEnvelopeV1,
    ProjectionIssueV1,
    list_artifact_refs,
    list_inbox_items,
)
from js.echo.ledger.service import (
    EchoUnavailableError,
    ManualReviewRow,
    VerifiedArtifactProjectionV1,
)
from js.echo.mode_contract import AppMode, ArtifactRefV1, ModeContractError
from js.orin import taint as orin_taint

OWNER = "aabbccddeeff00112233445566778899"
DIGEST = "sha256:" + "ab" * 32
WORKSPACE = "ws-handle"


@dataclass
class _ApprovalRequest:
    id: str
    owner_key_hash: str
    session_id: str | None
    run_id: str | None
    timestamp: float
    timeout_seconds: float


class _Approvals:
    def __init__(self, pending: list[_ApprovalRequest], *, args: str = DIGEST) -> None:
        self._pending = pending
        self._args = args

    def get_pending(self, owner_key_hash: str) -> list[_ApprovalRequest]:
        del owner_key_hash
        return list(self._pending)

    def pending_arguments_hash(self, request_id: str, owner_key_hash: str) -> str:
        del request_id, owner_key_hash
        return self._args


class _Memory:
    def __init__(
        self,
        proposals: list[Any] | BaseException | None = None,
        compression: list[Any] | BaseException | None = None,
    ) -> None:
        self._proposals = [] if proposals is None else proposals
        self._compression = [] if compression is None else compression

    def list_proposals(self, status: str, owner: str, limit: int) -> list[Any]:
        del status, owner, limit
        if isinstance(self._proposals, BaseException):
            raise self._proposals
        return list(self._proposals)

    def list_compression_proposals(self, *, scope: Any, status: str, limit: int) -> list[Any]:
        del scope, status, limit
        if isinstance(self._compression, BaseException):
            raise self._compression
        return list(self._compression)


class _Agent:
    def __init__(
        self,
        approvals: Any | None = None,
        memory: Any | None = None,
    ) -> None:
        self.approvals = approvals or _Approvals([])
        self.memory = memory or _Memory()


class _Echo:
    def __init__(
        self,
        reviews: tuple[ManualReviewRow, ...] | BaseException = (),
        projection: VerifiedArtifactProjectionV1 | BaseException | None = None,
    ) -> None:
        self._reviews = reviews
        self._projection = projection or VerifiedArtifactProjectionV1(
            receipts=(),
            refs=(),
            retired_history_complete=True,
        )

    def list_manual_reviews(
        self, *, tenant_id: str, product_id: str | None = None
    ) -> tuple[ManualReviewRow, ...]:
        del tenant_id, product_id
        if isinstance(self._reviews, BaseException):
            raise self._reviews
        return self._reviews

    def project_verified_artifacts(self, **kwargs: Any) -> VerifiedArtifactProjectionV1:
        del kwargs
        if isinstance(self._projection, BaseException):
            raise self._projection
        return self._projection


def _authority(
    *,
    mode: AppMode = AppMode.PERSONAL,
    workspace: str | None = None,
    role: str = "user",
    owner: str = OWNER,
    parent_session: str = "parent-session",
    agent: Any | None = None,
    echo: Any | None = None,
) -> ProjectionAuthorityV1:
    return ProjectionAuthorityV1(
        mode=mode,
        owner=owner,
        workspace=workspace,
        parent_session=parent_session,
        role=role,
        agent=agent or _Agent(),
        echo_safety_service=echo or _Echo(),
    )


def _approval(
    *,
    request_id: str = "req-1",
    session: str = "s-1",
    run: str = "r-1",
    owner: str = OWNER,
) -> _ApprovalRequest:
    return _ApprovalRequest(
        id=request_id,
        owner_key_hash=owner,
        session_id=session,
        run_id=run,
        timestamp=1_700_000_000.0,
        timeout_seconds=3_600.0,
    )


def _artifact(
    *,
    session: str = "s-1",
    run: str = "r-1",
    acl: str = "owner",
    uri: str = "echo://doc/report",
    mode: AppMode = AppMode.PERSONAL,
    workspace: str | None = None,
    owner: str = OWNER,
) -> ArtifactRefV1:
    return ArtifactRefV1(
        mode=mode,
        owner=owner,
        session=session,
        workspace=workspace,
        kind="document",
        uri=uri,
        digest=DIGEST,
        acl=acl,
        created_by_run=run,
    )


def test_authority_rejects_incomplete_or_mismatched_identity() -> None:
    with pytest.raises(TypeError, match="AppMode"):
        list_inbox_items(
            ProjectionAuthorityV1(
                mode="personal",  # type: ignore[arg-type]
                owner=OWNER,
                workspace=None,
                parent_session="parent-session",
                role="user",
                agent=_Agent(),
                echo_safety_service=_Echo(),
            )
        )
    with pytest.raises(ValueError, match="incomplete"):
        list_inbox_items(_authority(owner=""))
    with pytest.raises(ValueError, match="incomplete"):
        list_inbox_items(_authority(parent_session=""))
    with pytest.raises(ValueError, match="role is invalid"):
        list_inbox_items(_authority(role="guest"))
    with pytest.raises(ValueError, match="must not carry workspace"):
        list_inbox_items(_authority(mode=AppMode.PERSONAL, workspace=WORKSPACE))
    with pytest.raises(ValueError, match="requires workspace"):
        list_inbox_items(_authority(mode=AppMode.WORK, workspace=None, role="admin"))


@pytest.mark.parametrize(
    ("session", "run", "limit"),
    [
        ("", None, 50),
        ("   ", None, 50),
        (None, "", 50),
        (None, "   ", 50),
        (None, None, 0),
        (None, None, 101),
        (None, None, True),
    ],
)
def test_filters_are_validated(session: str | None, run: str | None, limit: int) -> None:
    with pytest.raises(ValueError, match="projection"):
        list_inbox_items(_authority(), session=session, run=run, limit=limit)
    with pytest.raises(ValueError, match="projection"):
        list_artifact_refs(_authority(), session=session, run=run, limit=limit)


def test_user_role_only_projects_approvals() -> None:
    agent = _Agent(
        approvals=_Approvals([_approval()]),
        memory=_Memory(
            proposals=[
                {"id": 1, "status": "pending", "owner_key_hash": OWNER, "session_id": "s-9"}
            ],
            compression=[
                SimpleNamespace(proposal_id="p1", proposal_digest="d1", creator_session="s-9")
            ],
        ),
    )
    echo = _Echo(
        reviews=(
            ManualReviewRow(
                effect_id="e1",
                outbox_id="o1",
                tenant_id=OWNER,
                action_kind="tool",
                status="manual_review",
                session_id="s-9",
                run_id="r-9",
                product_id="js-agent",
                effect_digest=DIGEST,
                args_digest=DIGEST,
            ),
        )
    )
    envelope = list_inbox_items(_authority(agent=agent, echo=echo, role="user"))
    assert envelope.status == "ok"
    assert len(envelope.items) == 1
    assert envelope.items[0].kind == "approval"
    assert envelope.items[0].session == "s-1"
    public = envelope.to_dict()
    assert public["schema"] == "ProjectionEnvelopeV1"
    assert public["count"] == 1
    assert "owner" not in public["items"][0]
    assert "eligible_approver" not in public["items"][0]
    assert public["items"][0]["orin_taint"] == orin_taint.INBOX_CONTENT
    assert envelope.source_watermark["mode"] == "personal"
    assert envelope.source_watermark["verified_source_count"] == "1"


def test_admin_projects_all_attention_sources() -> None:
    reviews = (
        ManualReviewRow(
            effect_id="e1",
            outbox_id="o1",
            tenant_id=OWNER,
            action_kind="tool",
            status="manual_review",
            session_id="s-2",
            run_id="r-2",
            product_id="js-agent",
            effect_digest=DIGEST,
            args_digest=DIGEST,
        ),
    )
    agent = _Agent(
        approvals=_Approvals([_approval()]),
        memory=_Memory(
            proposals=[
                {
                    "id": 7,
                    "status": "pending",
                    "owner_key_hash": OWNER,
                    "session_id": "s-3",
                }
            ],
            compression=[
                SimpleNamespace(
                    proposal_id="comp-1",
                    proposal_digest=DIGEST,
                    creator_session="s-4",
                )
            ],
        ),
    )
    envelope = list_inbox_items(_authority(role="admin", agent=agent, echo=_Echo(reviews=reviews)))
    assert envelope.status == "ok"
    kinds = {item.kind for item in envelope.items}
    assert kinds == {"approval", "manual_review", "memory_proposal"}
    sessions = {item.session for item in envelope.items}
    assert sessions == {"s-1", "s-2", "s-3", "s-4"}
    assert envelope.source_watermark["verified_source_count"] == "4"


def test_session_and_run_filters_apply_to_inbox() -> None:
    agent = _Agent(
        approvals=_Approvals(
            [
                _approval(request_id="a", session="s-1", run="r-1"),
                _approval(request_id="b", session="s-2", run="r-2"),
            ]
        )
    )
    all_items = list_inbox_items(_authority(agent=agent))
    assert {item.session for item in all_items.items} == {"s-1", "s-2"}
    filtered = list_inbox_items(_authority(agent=agent), session="s-1")
    assert [item.session for item in filtered.items] == ["s-1"]
    by_run = list_inbox_items(_authority(agent=agent), run="r-2")
    assert [item.run for item in by_run.items] == ["r-2"]


def test_inbox_limit_truncates_sorted_items() -> None:
    pending = [
        _approval(request_id=f"req-{index}", session=f"s-{index}", run=f"r-{index}")
        for index in range(1, 6)
    ]
    envelope = list_inbox_items(_authority(agent=_Agent(approvals=_Approvals(pending))), limit=2)
    assert len(envelope.items) == 2
    assert [item.session for item in envelope.items] == ["s-1", "s-2"]


def test_approval_owner_mismatch_marks_source_corrupt() -> None:
    agent = _Agent(approvals=_Approvals([_approval(owner="other-owner")]))
    envelope = list_inbox_items(_authority(agent=agent))
    assert envelope.status == "blocked"
    assert envelope.items == ()
    assert envelope.access_issues[0].code == "source_corrupt"
    assert envelope.access_issues[0].safe_detail == "projection source unavailable"


def test_unbound_approval_session_is_isolated() -> None:
    agent = _Agent(approvals=_Approvals([_approval(session="")]))
    envelope = list_inbox_items(_authority(agent=agent))
    assert envelope.access_issues[0].code == "unbound_record"


def test_unbound_approval_run_is_isolated() -> None:
    agent = _Agent(approvals=_Approvals([_approval(run="")]))
    envelope = list_inbox_items(_authority(agent=agent))
    assert envelope.access_issues[0].code == "unbound_record"


def test_admin_partial_when_one_source_fails() -> None:
    agent = _Agent(
        approvals=_Approvals([_approval()]),
        memory=_Memory(proposals=ValueError("memory down")),
    )
    envelope = list_inbox_items(_authority(role="admin", agent=agent))
    assert envelope.status == "partial"
    assert any(item.kind == "approval" for item in envelope.items)
    codes = {issue.code for issue in envelope.access_issues}
    assert "source_corrupt" in codes


def test_manual_review_product_mismatch_is_unbound() -> None:
    reviews = (
        ManualReviewRow(
            effect_id="e1",
            outbox_id="o1",
            tenant_id=OWNER,
            action_kind="tool",
            status="manual_review",
            session_id="s-1",
            run_id="r-1",
            product_id="js-work",
            effect_digest=DIGEST,
            args_digest=DIGEST,
        ),
    )
    envelope = list_inbox_items(
        _authority(role="admin", echo=_Echo(reviews=reviews), agent=_Agent())
    )
    assert any(issue.code == "unbound_record" for issue in envelope.access_issues)


def test_manual_review_owner_mismatch_is_corrupt() -> None:
    reviews = (
        ManualReviewRow(
            effect_id="e1",
            outbox_id="o1",
            tenant_id="other-owner",
            action_kind="tool",
            status="manual_review",
            session_id="s-1",
            run_id="r-1",
            product_id="js-agent",
            effect_digest=DIGEST,
            args_digest=DIGEST,
        ),
    )
    envelope = list_inbox_items(
        _authority(role="admin", echo=_Echo(reviews=reviews), agent=_Agent())
    )
    assert any(issue.code == "source_corrupt" for issue in envelope.access_issues)


def test_memory_proposal_invalid_rows_fail_the_batch() -> None:
    bad_rows: list[Any] = [
        [{"id": True, "status": "pending", "owner_key_hash": OWNER, "session_id": "s-1"}],
        [{"id": 1, "status": "accepted", "owner_key_hash": OWNER, "session_id": "s-1"}],
        [{"id": 1, "status": "pending", "owner_key_hash": "other", "session_id": "s-1"}],
        [{"id": 1, "status": "pending", "owner_key_hash": OWNER, "session_id": ""}],
        ["not-a-dict"],
    ]
    for proposals in bad_rows:
        envelope = list_inbox_items(
            _authority(role="admin", agent=_Agent(memory=_Memory(proposals=proposals)))
        )
        assert envelope.access_issues
        assert envelope.access_issues[0].source == "memory_proposals"


def test_compression_invalid_id_fails_batch() -> None:
    memory = _Memory(
        compression=[SimpleNamespace(proposal_id="", proposal_digest=DIGEST, creator_session="s-1")]
    )
    envelope = list_inbox_items(_authority(role="admin", agent=_Agent(memory=memory)))
    assert any(issue.source == "compression_proposals" for issue in envelope.access_issues)


def test_work_mode_requires_matching_product_on_reviews() -> None:
    reviews = (
        ManualReviewRow(
            effect_id="e1",
            outbox_id="o1",
            tenant_id=OWNER,
            action_kind="tool",
            status="manual_review",
            session_id="s-1",
            run_id="r-1",
            product_id="js-work",
            effect_digest=DIGEST,
            args_digest=DIGEST,
        ),
    )
    envelope = list_inbox_items(
        _authority(
            mode=AppMode.WORK,
            workspace=WORKSPACE,
            role="admin",
            echo=_Echo(reviews=reviews),
        )
    )
    assert any(item.kind == "manual_review" for item in envelope.items)


def test_echo_unavailable_marks_source_unavailable() -> None:
    envelope = list_inbox_items(
        _authority(role="admin", echo=_Echo(reviews=EchoUnavailableError("down")))
    )
    assert any(issue.code == "source_unavailable" for issue in envelope.access_issues)


def test_mode_contract_error_is_invalid_projection_record() -> None:
    envelope = list_inbox_items(
        _authority(
            role="admin",
            echo=_Echo(
                reviews=ModeContractError(code="bad", field="x", detail="nope"),
            ),
        )
    )
    assert any(issue.code == "invalid_projection_record" for issue in envelope.access_issues)


def test_list_artifact_refs_ok_and_strips_owner() -> None:
    ref = _artifact()
    echo = _Echo(
        projection=VerifiedArtifactProjectionV1(
            receipts=(),
            refs=(ref,),
            retired_history_complete=True,
        )
    )
    envelope = list_artifact_refs(_authority(echo=echo))
    assert envelope.status == "ok"
    assert envelope.items == (ref,)
    public = envelope.to_dict()
    assert "owner" not in public["items"][0]
    assert public["items"][0]["orin_taint"] == orin_taint.INBOX_CONTENT
    assert public["items"][0]["uri"] == "echo://doc/report"


def test_private_artifact_requires_session_and_run() -> None:
    ref = _artifact(acl="private")
    echo = _Echo(
        projection=VerifiedArtifactProjectionV1(
            receipts=(), refs=(ref,), retired_history_complete=True
        )
    )
    hidden = list_artifact_refs(_authority(echo=echo))
    assert hidden.items == ()
    visible = list_artifact_refs(_authority(echo=echo), session="s-1", run="r-1")
    assert visible.items == (ref,)


def test_session_acl_requires_session_filter() -> None:
    ref = _artifact(acl="session")
    echo = _Echo(
        projection=VerifiedArtifactProjectionV1(
            receipts=(), refs=(ref,), retired_history_complete=True
        )
    )
    assert list_artifact_refs(_authority(echo=echo)).items == ()
    assert list_artifact_refs(_authority(echo=echo), session="s-1").items == (ref,)
    assert list_artifact_refs(_authority(echo=echo), session="other").items == ()


def test_retired_history_incomplete_is_partial() -> None:
    echo = _Echo(
        projection=VerifiedArtifactProjectionV1(
            receipts=(),
            refs=(_artifact(),),
            retired_history_complete=False,
        )
    )
    envelope = list_artifact_refs(_authority(echo=echo))
    assert envelope.status == "partial"
    assert envelope.items
    assert envelope.access_issues[0].code == "retired_artifacts_not_available"


def test_artifact_source_failure_blocks() -> None:
    envelope = list_artifact_refs(_authority(echo=_Echo(projection=OSError("ledger down"))))
    assert envelope.status == "blocked"
    assert envelope.items == ()
    assert envelope.access_issues[0].code == "source_unavailable"


def test_artifact_authority_mismatch_is_corrupt() -> None:
    foreign = _artifact(owner="other-owner-hash")
    echo = _Echo(
        projection=VerifiedArtifactProjectionV1(
            receipts=(), refs=(foreign,), retired_history_complete=True
        )
    )
    envelope = list_artifact_refs(_authority(echo=echo))
    assert envelope.status == "blocked"
    assert envelope.access_issues[0].code == "source_corrupt"


def test_invalid_artifact_type_is_corrupt() -> None:
    echo = _Echo(
        projection=VerifiedArtifactProjectionV1(
            receipts=(),
            refs=("nope",),
            retired_history_complete=True,  # type: ignore[arg-type]
        )
    )
    envelope = list_artifact_refs(_authority(echo=echo))
    assert envelope.access_issues[0].code == "source_corrupt"


def test_work_artifacts_keep_workspace_acl() -> None:
    ref = _artifact(
        mode=AppMode.WORK,
        workspace=WORKSPACE,
        acl="workspace",
        uri="echo://work/report",
    )
    echo = _Echo(
        projection=VerifiedArtifactProjectionV1(
            receipts=(), refs=(ref,), retired_history_complete=True
        )
    )
    envelope = list_artifact_refs(_authority(mode=AppMode.WORK, workspace=WORKSPACE, echo=echo))
    assert envelope.items == (ref,)


def test_envelope_issue_dict_is_closed() -> None:
    issue = ProjectionIssueV1(
        source="echo_ledger",
        code="source_unavailable",
        safe_detail="projection source unavailable",
    )
    assert issue.to_dict() == {
        "source": "echo_ledger",
        "code": "source_unavailable",
        "safe_detail": "projection source unavailable",
    }
    empty = ProjectionEnvelopeV1(status="ok", items=())
    assert empty.to_dict()["count"] == 0
