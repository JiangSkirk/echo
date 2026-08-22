"""Read-only AppShell projections over real Echo-owned authority sources."""

from __future__ import annotations

import logging
import math
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Literal

from js.echo.ledger._hashing import stable_hash
from js.echo.ledger.service import (
    ArtifactVisibilityQueryV1,
    EchoSafetyService,
    EchoUnavailableError,
    artifact_ref_visible,
)
from js.echo.mode_contract import (
    AppMode,
    ArtifactRefV1,
    AttentionItemV1,
    ModeContractError,
)

ProjectionStatusV1 = Literal["ok", "partial", "blocked"]
ProjectionItemV1 = AttentionItemV1 | ArtifactRefV1
ProjectionIssueCodeV1 = Literal[
    "source_unavailable",
    "source_corrupt",
    "unbound_record",
    "invalid_projection_record",
    "retired_artifacts_not_available",
]

_LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class ProjectionAuthorityV1:
    """One trusted Personal or Work authority selected by the parent AppShell."""

    mode: AppMode
    owner: str
    workspace: str | None
    parent_session: str
    role: str
    agent: Any
    echo_safety_service: EchoSafetyService


@dataclass(frozen=True, slots=True)
class ProjectionIssueV1:
    source: str
    code: ProjectionIssueCodeV1
    safe_detail: str

    def to_dict(self) -> dict[str, str]:
        return {
            "source": self.source,
            "code": self.code,
            "safe_detail": self.safe_detail,
        }


@dataclass(frozen=True, slots=True)
class ProjectionEnvelopeV1:
    status: ProjectionStatusV1
    items: tuple[ProjectionItemV1, ...]
    access_issues: tuple[ProjectionIssueV1, ...] = field(default_factory=tuple)
    source_watermark: Mapping[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": "ProjectionEnvelopeV1",
            "status": self.status,
            "items": [_public_item(item) for item in self.items],
            "access_issues": [issue.to_dict() for issue in self.access_issues],
            "source_watermark": dict(self.source_watermark),
            "count": len(self.items),
        }


@dataclass(frozen=True, slots=True)
class _SourceBatch:
    source: str
    succeeded: bool
    items: tuple[ProjectionItemV1, ...] = ()
    issue: ProjectionIssueV1 | None = None


class _UnboundProjectionRecordError(ValueError):
    pass


def _public_item(item: ProjectionItemV1) -> dict[str, object]:
    payload = item.to_dict()
    # Physical owner hashes remain server-side.  The authority intersection is
    # already complete before this serializer runs.
    payload.pop("owner", None)
    if type(item) is AttentionItemV1:
        payload.pop("eligible_approver", None)
    return payload


def _issue(
    source: str,
    exc: BaseException,
) -> ProjectionIssueV1:
    if isinstance(exc, _UnboundProjectionRecordError):
        code: ProjectionIssueCodeV1 = "unbound_record"
    elif isinstance(exc, ModeContractError):
        code = "invalid_projection_record"
    elif isinstance(exc, (EchoUnavailableError, OSError, KeyError)):
        code = "source_unavailable"
    elif isinstance(exc, (ValueError, TypeError)):
        code = "source_corrupt"
    else:
        code = "source_unavailable"
    _LOGGER.exception("AppShell projection source %s failed", source, exc_info=exc)
    return ProjectionIssueV1(
        source=source,
        code=code,
        safe_detail="projection source unavailable",
    )


def _expected_product(mode: AppMode) -> str:
    return "js-work" if mode is AppMode.WORK else "js-agent"


def _validate_authority(authority: ProjectionAuthorityV1) -> None:
    if type(authority.mode) is not AppMode:
        raise TypeError("projection authority mode must be AppMode")
    if not authority.owner or not authority.parent_session:
        raise ValueError("projection authority identity is incomplete")
    if authority.role not in {"user", "admin"}:
        raise ValueError("projection authority role is invalid")
    if authority.mode is AppMode.PERSONAL and authority.workspace is not None:
        raise ValueError("Personal projection authority must not carry workspace")
    if authority.mode is AppMode.WORK and not isinstance(authority.workspace, str):
        raise ValueError("Work projection authority requires workspace")


def _validate_attention_authority(
    item: AttentionItemV1,
    authority: ProjectionAuthorityV1,
) -> None:
    if (
        item.owner != authority.owner
        or item.mode is not authority.mode
        or item.workspace != authority.workspace
        or not item.session
        or not item.run
    ):
        raise ValueError("attention item does not match trusted authority")
    if AttentionItemV1.from_dict(item.to_dict()) != item:
        raise ValueError("attention item does not survive strict R1 round-trip")


def _validate_artifact_authority(
    ref: ArtifactRefV1,
    authority: ProjectionAuthorityV1,
) -> None:
    if (
        ref.owner != authority.owner
        or ref.mode is not authority.mode
        or ref.workspace != authority.workspace
        or not ref.session
        or not ref.created_by_run
    ):
        raise ValueError("artifact ref does not match trusted authority")
    if ArtifactRefV1.from_dict(ref.to_dict()) != ref:
        raise ValueError("artifact ref does not survive strict R1 round-trip")


def _approval_batch(authority: ProjectionAuthorityV1) -> _SourceBatch:
    source = "tool_approvals"
    try:
        pending = authority.agent.approvals.get_pending(
            owner_key_hash=authority.owner,
        )
        local: list[AttentionItemV1] = []
        now = time.time()
        for request in pending:
            if request.owner_key_hash != authority.owner:
                raise ValueError("approval owner binding mismatch")
            if not isinstance(request.session_id, str) or not request.session_id:
                raise _UnboundProjectionRecordError(
                    "approval session binding is unavailable"
                )
            if not isinstance(request.run_id, str) or not request.run_id:
                raise _UnboundProjectionRecordError("approval run binding is unavailable")
            args_digest = authority.agent.approvals.pending_arguments_hash(
                request.id,
                owner_key_hash=authority.owner,
            )
            effect_digest = stable_hash(
                {
                    "domain": "js-agent:appshell-approval:v1",
                    "request_id": request.id,
                    "owner": authority.owner,
                    "mode": authority.mode.value,
                    "workspace": authority.workspace,
                    "session": request.session_id,
                    "run": request.run_id,
                    "args_digest": args_digest,
                }
            )
            remaining = math.ceil(
                request.timestamp + request.timeout_seconds - now
            )
            ttl_seconds = max(1, min(86400, remaining))
            item = AttentionItemV1(
                kind="approval",
                mode=authority.mode,
                owner=authority.owner,
                session=request.session_id,
                run=request.run_id,
                workspace=authority.workspace,
                effect_digest=effect_digest,
                args_digest=args_digest,
                eligible_approver=authority.owner,
                ttl_seconds=ttl_seconds,
            )
            _validate_attention_authority(item, authority)
            local.append(item)
        return _SourceBatch(source=source, succeeded=True, items=tuple(local))
    except Exception as exc:  # noqa: BLE001 - source batch must fail atomically
        return _SourceBatch(source=source, succeeded=False, issue=_issue(source, exc))


def _manual_review_batch(authority: ProjectionAuthorityV1) -> _SourceBatch:
    source = "manual_reviews"
    try:
        reviews = authority.echo_safety_service.list_manual_reviews(
            tenant_id=authority.owner,
            product_id=_expected_product(authority.mode),
        )
        local: list[AttentionItemV1] = []
        for row in reviews:
            if row.tenant_id != authority.owner:
                raise ValueError("manual review owner binding mismatch")
            if row.product_id != _expected_product(authority.mode):
                raise _UnboundProjectionRecordError(
                    "manual review product binding is unavailable"
                )
            if not isinstance(row.session_id, str) or not row.session_id:
                raise _UnboundProjectionRecordError(
                    "manual review session binding is unavailable"
                )
            if not isinstance(row.run_id, str) or not row.run_id:
                raise _UnboundProjectionRecordError(
                    "manual review run binding is unavailable"
                )
            if not isinstance(row.effect_digest, str):
                raise _UnboundProjectionRecordError(
                    "manual review effect digest is unavailable"
                )
            if not isinstance(row.args_digest, str):
                raise _UnboundProjectionRecordError(
                    "manual review args digest is unavailable"
                )
            item = AttentionItemV1(
                kind="manual_review",
                mode=authority.mode,
                owner=authority.owner,
                session=row.session_id,
                run=row.run_id,
                workspace=authority.workspace,
                effect_digest=row.effect_digest,
                args_digest=row.args_digest,
                eligible_approver=authority.owner,
                ttl_seconds=86400,
            )
            _validate_attention_authority(item, authority)
            local.append(item)
        return _SourceBatch(source=source, succeeded=True, items=tuple(local))
    except Exception as exc:  # noqa: BLE001 - source batch must fail atomically
        return _SourceBatch(source=source, succeeded=False, issue=_issue(source, exc))


def _memory_proposal_batch(authority: ProjectionAuthorityV1) -> _SourceBatch:
    source = "memory_proposals"
    try:
        proposals = authority.agent.memory.list_proposals(
            "pending",
            authority.owner,
            50,
        )
        local: list[AttentionItemV1] = []
        for row in proposals:
            if type(row) is not dict:
                raise ValueError("memory proposal row is invalid")
            proposal_id = row.get("id")
            session_id = row.get("session_id")
            if not isinstance(proposal_id, int) or isinstance(proposal_id, bool):
                raise ValueError("memory proposal id is invalid")
            if row.get("status") != "pending":
                raise ValueError("memory proposal status is invalid")
            if row.get("owner_key_hash") != authority.owner:
                raise ValueError("memory proposal owner binding mismatch")
            if not isinstance(session_id, str) or not session_id:
                raise _UnboundProjectionRecordError(
                    "memory proposal session binding is unavailable"
                )
            safe_identity = {
                "owner": authority.owner,
                "mode": authority.mode.value,
                "workspace": authority.workspace,
                "proposal_id": proposal_id,
                "status": "pending",
            }
            item = AttentionItemV1(
                kind="memory_proposal",
                mode=authority.mode,
                owner=authority.owner,
                session=session_id,
                run=f"memory-proposal:{proposal_id}",
                workspace=authority.workspace,
                effect_digest=stable_hash(
                    {"domain": "js-agent:memory-proposal-effect:v1", **safe_identity}
                ),
                args_digest=stable_hash(
                    {"domain": "js-agent:memory-proposal-args:v1", **safe_identity}
                ),
                eligible_approver=authority.owner,
                ttl_seconds=86400,
            )
            _validate_attention_authority(item, authority)
            local.append(item)
        return _SourceBatch(source=source, succeeded=True, items=tuple(local))
    except Exception as exc:  # noqa: BLE001 - source batch must fail atomically
        return _SourceBatch(source=source, succeeded=False, issue=_issue(source, exc))


def _compression_proposal_batch(authority: ProjectionAuthorityV1) -> _SourceBatch:
    """Project R6 compression proposals (SHA-256 proposal IDs)."""
    source = "compression_proposals"
    try:
        from js.memory.layers import CompressionScopeV1

        scope = CompressionScopeV1(
            owner=authority.owner,
            mode=authority.mode.value,
            workspace=authority.workspace,
        )
        proposals = authority.agent.memory.list_compression_proposals(
            scope=scope, status="pending", limit=50,
        )
        local: list[AttentionItemV1] = []
        for proposal in proposals:
            if not isinstance(proposal.proposal_id, str) or not proposal.proposal_id:
                raise ValueError("compression proposal id is invalid")
            safe_identity = {
                "owner": authority.owner,
                "mode": authority.mode.value,
                "workspace": authority.workspace,
                "proposal_id": proposal.proposal_id,
                "status": "pending",
                "proposal_digest": proposal.proposal_digest,
            }
            item = AttentionItemV1(
                kind="memory_proposal",
                mode=authority.mode,
                owner=authority.owner,
                session=proposal.creator_session or "unknown",
                run=f"compression-proposal:{proposal.proposal_id}",
                workspace=authority.workspace,
                effect_digest=stable_hash(
                    {"domain": "js-agent:compression-proposal-effect:v1", **safe_identity}
                ),
                args_digest=stable_hash(
                    {"domain": "js-agent:compression-proposal-args:v1", **safe_identity}
                ),
                eligible_approver=authority.owner,
                ttl_seconds=86400,
            )
            _validate_attention_authority(item, authority)
            local.append(item)
        return _SourceBatch(source=source, succeeded=True, items=tuple(local))
    except Exception as exc:  # noqa: BLE001 - source batch must fail atomically
        return _SourceBatch(source=source, succeeded=False, issue=_issue(source, exc))


def _status_for_batches(batches: tuple[_SourceBatch, ...]) -> ProjectionStatusV1:
    succeeded = sum(batch.succeeded for batch in batches)
    if succeeded == 0:
        return "blocked"
    if succeeded != len(batches):
        return "partial"
    return "ok"


def _validate_filters(*, session: str | None, run: str | None, limit: int) -> None:
    if session is not None and (not isinstance(session, str) or not session.strip()):
        raise ValueError("projection session filter is invalid")
    if run is not None and (not isinstance(run, str) or not run.strip()):
        raise ValueError("projection run filter is invalid")
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
        raise ValueError("projection limit must be between 1 and 100")


def _watermark(
    *,
    mode: AppMode,
    batches: tuple[_SourceBatch, ...],
    items: tuple[ProjectionItemV1, ...],
) -> dict[str, str]:
    hashes = [item.canonical_hash() for item in items]
    return {
        "mode": mode.value,
        "verified_source_count": str(sum(batch.succeeded for batch in batches)),
        "item_set": stable_hash(
            {
                "domain": "js-agent:appshell-projection-watermark:v1",
                "mode": mode.value,
                "item_hashes": hashes,
            }
        ),
    }


def list_inbox_items(
    authority: ProjectionAuthorityV1,
    *,
    session: str | None = None,
    run: str | None = None,
    limit: int = 50,
) -> ProjectionEnvelopeV1:
    """Project eligible attention sources from one exact trusted mode authority."""
    _validate_authority(authority)
    _validate_filters(session=session, run=run, limit=limit)
    batches: list[_SourceBatch] = [_approval_batch(authority)]
    if authority.role == "admin":
        batches.extend(
            (
                _manual_review_batch(authority),
                _memory_proposal_batch(authority),
                _compression_proposal_batch(authority),
            )
        )
    batch_tuple = tuple(batches)
    items = tuple(
        sorted(
            (
                item
                for batch in batch_tuple
                if batch.succeeded
                for item in batch.items
                if type(item) is AttentionItemV1
                and (session is None or item.session == session)
                and (run is None or item.run == run)
            ),
            key=lambda item: (
                item.mode.value,
                item.kind,
                item.session,
                item.run,
                item.effect_digest,
                item.args_digest,
            ),
        )[:limit]
    )
    issues = tuple(batch.issue for batch in batch_tuple if batch.issue is not None)
    return ProjectionEnvelopeV1(
        status=_status_for_batches(batch_tuple),
        items=items,
        access_issues=issues,
        source_watermark=_watermark(
            mode=authority.mode,
            batches=batch_tuple,
            items=items,
        ),
    )


def _artifact_visible(
    ref: ArtifactRefV1,
    *,
    session: str | None,
    run: str | None,
) -> bool:
    return artifact_ref_visible(
        ref,
        ArtifactVisibilityQueryV1(session=session, run=run),
    )


def list_artifact_refs(
    authority: ProjectionAuthorityV1,
    *,
    session: str | None = None,
    run: str | None = None,
    limit: int = 50,
) -> ProjectionEnvelopeV1:
    """Project only refs returned by EchoSafetyService verified replay."""
    _validate_authority(authority)
    _validate_filters(session=session, run=run, limit=limit)
    source = "echo_ledger"
    batches: tuple[_SourceBatch, ...]
    try:
        projection = authority.echo_safety_service.project_verified_artifacts(
            tenant_id=authority.owner,
            mode=authority.mode,
            workspace=authority.workspace,
            limit=limit,
            visibility=ArtifactVisibilityQueryV1(session=session, run=run),
        )
        local: list[ArtifactRefV1] = []
        for ref in projection.refs:
            if type(ref) is not ArtifactRefV1:
                raise ValueError("artifact source returned an invalid R1 value")
            _validate_artifact_authority(ref, authority)
            if _artifact_visible(ref, session=session, run=run):
                local.append(ref)
        items: tuple[ProjectionItemV1, ...] = tuple(
            sorted(
                local,
                key=lambda ref: (
                    ref.mode.value,
                    ref.session,
                    ref.created_by_run,
                    ref.digest,
                    ref.uri,
                ),
            )[:limit]
        )
        batch = _SourceBatch(source=source, succeeded=True, items=items)
        if projection.retired_history_complete:
            batches = (batch,)
        else:
            batches = (
                batch,
                _SourceBatch(
                    source=source,
                    succeeded=False,
                    issue=ProjectionIssueV1(
                        source=source,
                        code="retired_artifacts_not_available",
                        safe_detail="retired artifact history is unavailable",
                    ),
                ),
            )
    except Exception as exc:  # noqa: BLE001 - sole authority must fail closed
        batch = _SourceBatch(source=source, succeeded=False, issue=_issue(source, exc))
        items = ()
        batches = (batch,)
    return ProjectionEnvelopeV1(
        status=_status_for_batches(batches),
        items=items,
        access_issues=tuple(
            current.issue for current in batches if current.issue is not None
        ),
        source_watermark=_watermark(
            mode=authority.mode,
            batches=batches,
            items=items,
        ),
    )


__all__ = [
    "ProjectionAuthorityV1",
    "ProjectionEnvelopeV1",
    "ProjectionIssueV1",
    "ProjectionItemV1",
    "ProjectionStatusV1",
    "list_artifact_refs",
    "list_inbox_items",
]
