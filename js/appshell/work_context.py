"""Work-mode context projection — closed-set DTOs bound to session/run.

This is a SEPARATE projection from the Inbox (``js/appshell/inbox.py``).
It never reuses ``ProjectionEnvelopeV1`` to carry arbitrary payloads: every
field has a strict closed DTO with fail-closed unknown-field handling and a
canonical round-trip.

Data sources (all pre-existing authority surfaces):
  - attention items: tool approvals (owner-scoped, session/run bound)
  - artifacts: EchoSafetyService verified receipts only (no directory scans)
  - files: the owner's session-scoped upload partition (root-relative only)
  - current task: Echo-owned session lifecycle bound to owner/session/run
  - directory grants: only an authoritative grant store may feed this; when
    none exists the projection reports ``unavailable`` plus an access issue
    instead of inventing a count.
"""

from __future__ import annotations

import logging
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Literal, cast

from js.appshell.inbox import (
    ProjectionAuthorityV1,
    ProjectionIssueV1,
    ProjectionStatusV1,
    _approval_batch,
    _issue,
    _validate_artifact_authority,
    _validate_attention_authority,
    _validate_authority,
)
from js.echo.ledger._hashing import stable_hash
from js.echo.ledger.service import ArtifactVisibilityQueryV1, artifact_ref_visible
from js.echo.mode_contract import AppMode, ArtifactRefV1, AttentionItemV1

_LOGGER = logging.getLogger(__name__)

GrantsStateV1 = Literal["bound", "none", "unavailable"]
WritePolicyV1 = Literal["requires_approval", "unknown"]
WorkTaskStatusNameV1 = Literal[
    "pending", "running", "paused", "completed", "failed", "cancelled"
]

_ROOT_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
_DRIVE_RE = re.compile(r"^[A-Za-z]:")
_TASK_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SESSION_RE = re.compile(r"^[^\s]{1,128}$")
_TASK_STATUSES = frozenset(
    {"pending", "running", "paused", "completed", "failed", "cancelled"}
)


class WorkContextError(ValueError):
    """Strict-contract violation in a Work Context value or projection."""

    def __init__(self, code: str, field: str, detail: str) -> None:
        super().__init__(f"{code}: {field}: {detail}")
        self.code = code
        self.field = field
        self.detail = detail


def _err(condition: bool, code: str, field: str, detail: str) -> None:
    if condition:
        raise WorkContextError(code, field, detail)


def _validate_relative_path(path: object, field: str = "path") -> str:
    _err(type(path) is not str, "invalid_type", field, "path must be str")
    value = cast("str", path)
    _err(not value, "invalid_value", field, "path must be non-empty")
    _err(len(value) > 512, "invalid_value", field, "path exceeds 512 chars")
    _err("\x00" in value, "invalid_value", field, "path contains NUL")
    _err(
        value.startswith("/") or value.startswith("\\") or _DRIVE_RE.match(value) is not None,
        "absolute_path_rejected",
        field,
        "absolute paths are never projected",
    )
    _err("\\" in value, "invalid_value", field, "path must be POSIX relative")
    segments = value.split("/")
    _err(any(not seg for seg in segments), "invalid_value", field, "empty path segment")
    _err(
        any(seg == ".." for seg in segments),
        "path_escape_rejected",
        field,
        "parent traversal is never projected",
    )
    return value


def _validate_root(root: object) -> str:
    _err(type(root) is not str, "invalid_type", "root", "root must be str")
    value = cast("str", root)
    _err(
        _ROOT_RE.fullmatch(value) is None,
        "invalid_value",
        "root",
        "root must be an opaque root label",
    )
    return value


def _validate_optional_runtime_id(value: object, field: str) -> str | None:
    if value is None:
        return None
    _err(type(value) is not str, "invalid_type", field, f"{field} must be str or null")
    text = cast("str", value)
    _err(
        _SESSION_RE.fullmatch(text) is None,
        "invalid_value",
        field,
        f"{field} must be a non-empty runtime id",
    )
    return text


def _strict_keys(data: object, allowed: frozenset[str], schema: str) -> dict[str, Any]:
    _err(type(data) is not dict, "invalid_type", schema, "payload must be an object")
    mapping = cast("dict[str, Any]", data)
    unknown = sorted(set(mapping) - allowed)
    _err(
        bool(unknown),
        "unknown_field",
        schema,
        f"unknown fields fail closed: {','.join(unknown)}",
    )
    missing = sorted(allowed - set(mapping))
    _err(
        bool(missing),
        "missing_field",
        schema,
        f"missing fields: {','.join(missing)}",
    )
    return mapping


def _validate_schema_version(value: object) -> None:
    _err(type(value) is not int, "invalid_type", "schema_version", "must be int 1")
    _err(value != 1, "invalid_value", "schema_version", "must be 1")


@dataclass(frozen=True, slots=True, init=False)
class WorkFileRefV1:
    """One root-relative file reference. Absolute paths are unrepresentable."""

    root: str
    path: str

    def __init_subclass__(cls, **kwargs: object) -> None:
        raise TypeError("WorkFileRefV1 cannot be subclassed")

    def __init__(self, *, root: str, path: str) -> None:
        object.__setattr__(self, "root", _validate_root(root))
        object.__setattr__(self, "path", _validate_relative_path(path))

    @property
    def schema_version(self) -> int:
        return 1

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "root": self.root,
            "path": self.path,
        }

    @classmethod
    def from_dict(cls, payload: object) -> WorkFileRefV1:
        data = _strict_keys(
            payload, frozenset({"schema_version", "root", "path"}), "WorkFileRefV1"
        )
        _validate_schema_version(data["schema_version"])
        return cls(root=cast("str", data["root"]), path=cast("str", data["path"]))

    def canonical_hash(self) -> str:
        return stable_hash({"domain": "js-agent:work-file-ref:v1", **self.to_dict()})


@dataclass(frozen=True, slots=True, init=False)
class WorkTaskStatusV1:
    """Current task/step projection bound to the requesting session."""

    task_id: str
    title: str
    status: WorkTaskStatusNameV1
    session: str | None
    run: str | None
    progress: float

    def __init_subclass__(cls, **kwargs: object) -> None:
        raise TypeError("WorkTaskStatusV1 cannot be subclassed")

    def __init__(
        self,
        *,
        task_id: str,
        title: str,
        status: str,
        session: str | None,
        run: str | None,
        progress: float,
    ) -> None:
        _err(type(task_id) is not str, "invalid_type", "task_id", "task_id must be str")
        _err(
            _TASK_ID_RE.fullmatch(task_id) is None,
            "invalid_value",
            "task_id",
            "task_id must be an opaque runtime id",
        )
        _err(type(title) is not str, "invalid_type", "title", "title must be str")
        _err(len(title) > 200, "invalid_value", "title", "title too long")
        _err(
            status not in _TASK_STATUSES,
            "invalid_value",
            "status",
            "status must be a known task state",
        )
        _err(
            isinstance(progress, bool)
            or not isinstance(progress, (int, float))
            or not math.isfinite(progress)
            or not 0.0 <= progress <= 1.0,
            "invalid_value",
            "progress",
            "progress must be within [0, 1]",
        )
        object.__setattr__(self, "task_id", task_id)
        object.__setattr__(self, "title", title)
        object.__setattr__(self, "status", cast("WorkTaskStatusNameV1", status))
        object.__setattr__(self, "session", _validate_optional_runtime_id(session, "session"))
        object.__setattr__(self, "run", _validate_optional_runtime_id(run, "run"))
        object.__setattr__(self, "progress", float(progress))

    @property
    def schema_version(self) -> int:
        return 1

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "task_id": self.task_id,
            "title": self.title,
            "status": self.status,
            "session": self.session,
            "run": self.run,
            "progress": self.progress,
        }

    @classmethod
    def from_dict(cls, payload: object) -> WorkTaskStatusV1:
        data = _strict_keys(
            payload,
            frozenset(
                {"schema_version", "task_id", "title", "status", "session", "run", "progress"}
            ),
            "WorkTaskStatusV1",
        )
        _validate_schema_version(data["schema_version"])
        return cls(
            task_id=cast("str", data["task_id"]),
            title=cast("str", data["title"]),
            status=cast("str", data["status"]),
            session=cast("str | None", data["session"]),
            run=cast("str | None", data["run"]),
            progress=cast("float", data["progress"]),
        )

    def canonical_hash(self) -> str:
        return stable_hash({"domain": "js-agent:work-task-status:v1", **self.to_dict()})


@dataclass(frozen=True, slots=True, init=False)
class WorkContextSummaryV1:
    """Workspace summary. Grant counts exist only when authoritatively bound."""

    workspace: str
    grants_state: GrantsStateV1
    grants_count: int | None
    write_policy: WritePolicyV1

    def __init_subclass__(cls, **kwargs: object) -> None:
        raise TypeError("WorkContextSummaryV1 cannot be subclassed")

    def __init__(
        self,
        *,
        workspace: str,
        grants_state: str,
        grants_count: int | None,
        write_policy: str,
    ) -> None:
        _err(type(workspace) is not str, "invalid_type", "workspace", "workspace must be str")
        _err(not workspace, "invalid_value", "workspace", "workspace must be non-empty")
        _err(
            grants_state not in {"bound", "none", "unavailable"},
            "invalid_value",
            "grants_state",
            "grants_state must be bound/none/unavailable",
        )
        if grants_state == "bound":
            _err(
                isinstance(grants_count, bool)
                or not isinstance(grants_count, int)
                or grants_count < 0,
                "invalid_value",
                "grants_count",
                "bound grants require a non-negative count",
            )
        else:
            _err(
                grants_count is not None,
                "invalid_value",
                "grants_count",
                "grants_count is forbidden without an authoritative binding",
            )
        _err(
            write_policy not in {"requires_approval", "unknown"},
            "invalid_value",
            "write_policy",
            "write_policy must be requires_approval/unknown",
        )
        object.__setattr__(self, "workspace", workspace)
        object.__setattr__(self, "grants_state", cast("GrantsStateV1", grants_state))
        object.__setattr__(self, "grants_count", grants_count)
        object.__setattr__(self, "write_policy", cast("WritePolicyV1", write_policy))

    @property
    def schema_version(self) -> int:
        return 1

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "workspace": self.workspace,
            "grants_state": self.grants_state,
            "grants_count": self.grants_count,
            "write_policy": self.write_policy,
        }

    @classmethod
    def from_dict(cls, payload: object) -> WorkContextSummaryV1:
        data = _strict_keys(
            payload,
            frozenset(
                {"schema_version", "workspace", "grants_state", "grants_count", "write_policy"}
            ),
            "WorkContextSummaryV1",
        )
        _validate_schema_version(data["schema_version"])
        return cls(
            workspace=cast("str", data["workspace"]),
            grants_state=cast("str", data["grants_state"]),
            grants_count=cast("int | None", data["grants_count"]),
            write_policy=cast("str", data["write_policy"]),
        )

    def canonical_hash(self) -> str:
        return stable_hash({"domain": "js-agent:work-context-summary:v1", **self.to_dict()})


def _issue_from_dict(payload: object) -> ProjectionIssueV1:
    data = _strict_keys(
        payload, frozenset({"source", "code", "safe_detail"}), "ProjectionIssueV1"
    )
    source = data["source"]
    code = data["code"]
    detail = data["safe_detail"]
    _err(type(source) is not str, "invalid_type", "source", "source must be str")
    _err(type(detail) is not str, "invalid_type", "safe_detail", "safe_detail must be str")
    _err(
        code
        not in {
            "source_unavailable",
            "source_corrupt",
            "unbound_record",
            "invalid_projection_record",
            "retired_artifacts_not_available",
        },
        "invalid_value",
        "code",
        "unknown issue code",
    )
    return ProjectionIssueV1(
        source=cast("str", source),
        code=cast("Any", code),
        safe_detail=cast("str", detail),
    )


@dataclass(frozen=True, slots=True)
class WorkContextEnvelopeV1:
    """Closed Work Context envelope. Unknown fields fail closed on parse."""

    status: ProjectionStatusV1
    workspace_summary: WorkContextSummaryV1 | None
    files: tuple[WorkFileRefV1, ...]
    artifacts: tuple[ArtifactRefV1, ...]
    attention_items: tuple[AttentionItemV1, ...]
    current_task: WorkTaskStatusV1 | None
    access_issues: tuple[ProjectionIssueV1, ...] = field(default_factory=tuple)
    source_watermark: Mapping[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": "WorkContextEnvelopeV1",
            "status": self.status,
            "workspace_summary": (
                self.workspace_summary.to_dict() if self.workspace_summary else None
            ),
            "files": [ref.to_dict() for ref in self.files],
            "artifacts": [_public_artifact(ref) for ref in self.artifacts],
            "attention_items": [_public_attention(item) for item in self.attention_items],
            "current_task": self.current_task.to_dict() if self.current_task else None,
            "access_issues": [issue.to_dict() for issue in self.access_issues],
            "source_watermark": dict(self.source_watermark),
        }

    @classmethod
    def from_dict(cls, payload: object) -> WorkContextEnvelopeV1:
        data = _strict_keys(
            payload,
            frozenset(
                {
                    "schema",
                    "status",
                    "workspace_summary",
                    "files",
                    "artifacts",
                    "attention_items",
                    "current_task",
                    "access_issues",
                    "source_watermark",
                }
            ),
            "WorkContextEnvelopeV1",
        )
        _err(
            data["schema"] != "WorkContextEnvelopeV1",
            "invalid_value",
            "schema",
            "schema marker mismatch",
        )
        _err(
            data["status"] not in {"ok", "partial", "blocked"},
            "invalid_value",
            "status",
            "status must be ok/partial/blocked",
        )
        summary_raw = data["workspace_summary"]
        task_raw = data["current_task"]
        files_raw = data["files"]
        artifacts_raw = data["artifacts"]
        attention_raw = data["attention_items"]
        issues_raw = data["access_issues"]
        watermark_raw = data["source_watermark"]
        _err(type(files_raw) is not list, "invalid_type", "files", "files must be a list")
        _err(
            type(artifacts_raw) is not list,
            "invalid_type",
            "artifacts",
            "artifacts must be a list",
        )
        _err(
            type(attention_raw) is not list,
            "invalid_type",
            "attention_items",
            "attention_items must be a list",
        )
        _err(
            type(issues_raw) is not list,
            "invalid_type",
            "access_issues",
            "access_issues must be a list",
        )
        _err(
            type(watermark_raw) is not dict,
            "invalid_type",
            "source_watermark",
            "source_watermark must be an object",
        )
        return cls(
            status=cast("ProjectionStatusV1", data["status"]),
            workspace_summary=(
                WorkContextSummaryV1.from_dict(summary_raw)
                if summary_raw is not None
                else None
            ),
            files=tuple(
                WorkFileRefV1.from_dict(item) for item in cast("list[Any]", files_raw)
            ),
            artifacts=tuple(
                ArtifactRefV1.from_dict(item) for item in cast("list[Any]", artifacts_raw)
            ),
            attention_items=tuple(
                AttentionItemV1.from_dict(item) for item in cast("list[Any]", attention_raw)
            ),
            current_task=(
                WorkTaskStatusV1.from_dict(task_raw) if task_raw is not None else None
            ),
            access_issues=tuple(
                _issue_from_dict(item) for item in cast("list[Any]", issues_raw)
            ),
            source_watermark=cast("dict[str, str]", watermark_raw),
        )


def _public_artifact(ref: ArtifactRefV1) -> dict[str, object]:
    payload = ref.to_dict()
    payload.pop("owner", None)
    return payload


def _public_attention(item: AttentionItemV1) -> dict[str, object]:
    payload = item.to_dict()
    payload.pop("owner", None)
    payload.pop("eligible_approver", None)
    return payload


@dataclass(frozen=True, slots=True)
class _WorkBatch:
    source: str
    succeeded: bool
    issue: ProjectionIssueV1 | None = None


def _validate_session(session: object) -> str:
    _err(type(session) is not str, "invalid_type", "session_id", "session_id must be str")
    value = cast("str", session)
    _err(
        _SESSION_RE.fullmatch(value) is None,
        "invalid_value",
        "session_id",
        "session_id must be a non-empty runtime id",
    )
    return value


def _known_runs_for_session(authority: ProjectionAuthorityV1, session: str) -> frozenset[str]:
    """Trusted run registry: pending approvals + verified artifacts only."""
    runs: set[str] = set()
    try:
        pending = authority.agent.approvals.get_pending(owner_key_hash=authority.owner)
        for request in pending:
            if request.session_id == session and isinstance(request.run_id, str):
                runs.add(request.run_id)
    except Exception:  # noqa: BLE001 - registry unavailable contributes nothing
        _LOGGER.debug("approval run registry unavailable", exc_info=True)
    try:
        projection = authority.echo_safety_service.project_verified_artifacts(
            tenant_id=authority.owner,
            mode=authority.mode,
            workspace=authority.workspace,
            limit=100,
            visibility=ArtifactVisibilityQueryV1(session=session, run=None),
        )
        for ref in projection.refs:
            if ref.session == session and ref.created_by_run:
                runs.add(ref.created_by_run)
    except Exception:  # noqa: BLE001 - registry unavailable contributes nothing
        _LOGGER.debug("artifact run registry unavailable", exc_info=True)
    return frozenset(runs)


def _attention_batch(
    authority: ProjectionAuthorityV1, *, session: str, run: str | None
) -> tuple[_WorkBatch, tuple[AttentionItemV1, ...]]:
    source = "tool_approvals"
    try:
        batch = _approval_batch(authority)
        if not batch.succeeded:
            return _WorkBatch(source=source, succeeded=False, issue=batch.issue), ()
        items: list[AttentionItemV1] = []
        for item in batch.items:
            if type(item) is not AttentionItemV1:
                raise ValueError("approval source returned an invalid R1 value")
            if item.session != session:
                continue
            if run is not None and item.run != run:
                continue
            _validate_attention_authority(item, authority)
            items.append(item)
        return _WorkBatch(source=source, succeeded=True), tuple(items)
    except Exception as exc:  # noqa: BLE001 - source batch must fail atomically
        return _WorkBatch(source=source, succeeded=False, issue=_issue(source, exc)), ()


def _artifact_batch(
    authority: ProjectionAuthorityV1,
    *,
    session: str,
    run: str | None,
    limit: int,
) -> tuple[_WorkBatch, tuple[ArtifactRefV1, ...]]:
    source = "echo_ledger"
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
            if artifact_ref_visible(
                ref, ArtifactVisibilityQueryV1(session=session, run=run)
            ):
                local.append(ref)
        items = tuple(
            sorted(
                local,
                key=lambda ref: (ref.session, ref.created_by_run, ref.digest, ref.uri),
            )[:limit]
        )
        return _WorkBatch(source=source, succeeded=True), items
    except Exception as exc:  # noqa: BLE001 - sole artifact authority fails closed
        return _WorkBatch(source=source, succeeded=False, issue=_issue(source, exc)), ()


def _file_batch(
    authority: ProjectionAuthorityV1, *, session: str, limit: int
) -> tuple[_WorkBatch, tuple[WorkFileRefV1, ...]]:
    """Session-bound upload partition listing; root-relative or nothing."""
    source = "session_uploads"
    try:
        from js.echo.attachment_gate import list_owned_upload_entries

        workspace = getattr(getattr(authority.agent, "settings", None), "workspace", None)
        if workspace is None:
            raise KeyError("agent workspace is unavailable")
        entries = list_owned_upload_entries(workspace, authority.owner, session)
        local: list[WorkFileRefV1] = []
        for entry in entries:
            relative = getattr(entry, "relative_path", None)
            # WorkFileRefV1 hard-rejects absolute/escaping paths: one bad
            # record fails the whole batch instead of leaking into the UI.
            local.append(WorkFileRefV1(root="uploads", path=cast("str", relative)))
        items = tuple(sorted(local, key=lambda ref: (ref.root, ref.path))[:limit])
        return _WorkBatch(source=source, succeeded=True), items
    except Exception as exc:  # noqa: BLE001 - source batch must fail atomically
        return _WorkBatch(source=source, succeeded=False, issue=_issue(source, exc)), ()


def _task_batch(
    authority: ProjectionAuthorityV1, *, session: str
) -> tuple[_WorkBatch, WorkTaskStatusV1 | None]:
    source = "session_lifecycle"
    try:
        lifecycle = getattr(authority.agent, "lifecycle_store", None)
        if lifecycle is None:
            raise KeyError("session lifecycle store is unavailable")
        row = lifecycle.get(session, authority.owner)
        if row is None:
            return _WorkBatch(source=source, succeeded=True), None
        if type(row) is not dict:
            raise ValueError("session lifecycle row is invalid")
        if row.get("session_id") != session or row.get("owner_key_hash") != authority.owner:
            raise ValueError("session lifecycle row is not bound to this authority")
        status = row.get("status")
        if status in {"completed", "cancelled", "error", "aborted"}:
            return _WorkBatch(source=source, succeeded=True), None
        if status != "running":
            raise ValueError("session lifecycle row has an unknown status")
        run = _validate_optional_runtime_id(row.get("run_id"), "run_id")
        if run is None:
            raise ValueError("running session lifecycle row is missing run identity")
        return (
            _WorkBatch(source=source, succeeded=True),
            WorkTaskStatusV1(
                task_id=run,
                title="当前工作任务",
                status="running",
                session=session,
                run=run,
                progress=0.0,
            ),
        )
    except Exception as exc:  # noqa: BLE001 - source batch must fail atomically
        return _WorkBatch(source=source, succeeded=False, issue=_issue(source, exc)), None


def _grants_batch(authority: ProjectionAuthorityV1) -> tuple[_WorkBatch, GrantsStateV1, int | None]:
    """Directory grants: only an authoritative store may answer.

    The current architecture has no queryable persistent DirectoryGrant
    store (``DirectoryGrantV1`` is a pure value object passed across the
    connector boundary). The projection therefore reports ``unavailable``
    with an access issue — it never infers a count from workspace config,
    file listings, or default roots.
    """
    del authority
    return (
        _WorkBatch(
            source="directory_grants",
            succeeded=False,
            issue=ProjectionIssueV1(
                source="directory_grants",
                code="source_unavailable",
                safe_detail="no authoritative directory-grant store",
            ),
        ),
        "unavailable",
        None,
    )


def _status_for(batches: tuple[_WorkBatch, ...]) -> ProjectionStatusV1:
    succeeded = sum(batch.succeeded for batch in batches)
    if succeeded == 0:
        return "blocked"
    if succeeded != len(batches):
        return "partial"
    return "ok"


def list_work_context(
    authority: ProjectionAuthorityV1,
    *,
    session: str,
    run: str | None = None,
    limit: int = 25,
) -> WorkContextEnvelopeV1:
    """Project the Work context for exactly one session (and optional run).

    Fail-closed rules:
      - authority must be Work mode with a workspace binding
      - ``session`` is mandatory; ``run`` must exist in a trusted registry
      - any item failing authority re-validation fails its whole batch
      - zero successful sources → ``blocked`` (never an empty fake-ok)
    """
    _validate_authority(authority)
    if authority.mode is not AppMode.WORK:
        raise WorkContextError(
            "work_mode_required", "mode", "work context requires an active work authority"
        )
    clean_session = _validate_session(session)
    if run is not None:
        clean_run = _validate_optional_runtime_id(run, "run_id")
        known = _known_runs_for_session(authority, clean_session)
        if clean_run not in known:
            raise WorkContextError(
                "run_binding_unknown",
                "run_id",
                "run is not bound to this session in any trusted registry",
            )
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
        raise WorkContextError(
            "invalid_value", "limit", "limit must be an int between 1 and 100"
        )

    attention_batch, attention = _attention_batch(authority, session=clean_session, run=run)
    artifact_batch, artifacts = _artifact_batch(
        authority, session=clean_session, run=run, limit=limit
    )
    file_batch, files = _file_batch(authority, session=clean_session, limit=limit)
    task_batch, current_task = _task_batch(authority, session=clean_session)
    grants_batch, grants_state, grants_count = _grants_batch(authority)

    batches = (attention_batch, artifact_batch, file_batch, task_batch, grants_batch)
    summary = WorkContextSummaryV1(
        workspace=cast("str", authority.workspace),
        grants_state=grants_state,
        grants_count=grants_count,
        write_policy="unknown",
    )
    item_hashes = [ref.canonical_hash() for ref in files]
    item_hashes += [ref.canonical_hash() for ref in artifacts]
    item_hashes += [item.canonical_hash() for item in attention]
    if current_task is not None:
        item_hashes.append(current_task.canonical_hash())
    watermark = {
        "mode": authority.mode.value,
        "workspace": cast("str", authority.workspace),
        "session_digest": stable_hash(
            {"domain": "js-agent:work-context-session:v1", "session": clean_session}
        ),
        "verified_source_count": str(sum(batch.succeeded for batch in batches)),
        "item_set": stable_hash(
            {
                "domain": "js-agent:work-context-watermark:v1",
                "item_hashes": item_hashes,
            }
        ),
    }
    return WorkContextEnvelopeV1(
        status=_status_for(batches),
        workspace_summary=summary,
        files=files,
        artifacts=artifacts,
        attention_items=attention,
        current_task=current_task,
        access_issues=tuple(batch.issue for batch in batches if batch.issue is not None),
        source_watermark=watermark,
    )


__all__ = [
    "GrantsStateV1",
    "WorkContextEnvelopeV1",
    "WorkContextError",
    "WorkContextSummaryV1",
    "WorkFileRefV1",
    "WorkTaskStatusV1",
    "WritePolicyV1",
    "list_work_context",
]
