"""Parent-owned AppShell session, mode switch, and unified chrome APIs."""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator

from js.agent import OwnedCancelResult
from js.appshell.inbox import (
    ProjectionAuthorityV1,
    ProjectionEnvelopeV1,
    list_artifact_refs,
    list_inbox_items,
)
from js.appshell.principal import (
    APPSHELL_SESSION_COOKIE,
    APPSHELL_SESSION_TTL_SECONDS,
    AppShellOperationLimitError,
    AppShellPrincipalV1,
    AppShellSessionConflictError,
    AppShellSessionError,
    appshell_principal_from_scope,
)
from js.appshell.routing import (
    AppShellEpochClosedError,
    AppShellEpochDrainTimeoutError,
    AppShellModeGate,
)
from js.echo.capability import LeaseDenied
from js.echo.ledger.service import EchoSafetyService
from js.echo.mode_contract import AppMode
from js.utils.log import get_logger
from js.web.auth import (
    AuthManager,
    check_origin,
    request_is_direct_loopback,
    require_admin,
    require_auth_dep,
)
from js.web.bootstrap import consume_bootstrap_admin_key_file

logger = get_logger("js.appshell")

router = APIRouter(prefix="/api/appshell", tags=["appshell"])


class AppShellSessionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    api_key: str | None = None


class AppShellSwitchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_from_mode: Literal["personal", "work"]
    to_mode: Literal["personal", "work"]
    session_id: str | None = Field(...)
    workspace_handle: str | None = Field(...)

    @field_validator("session_id")
    @classmethod
    def _validate_session_id(cls, value: str | None) -> str | None:
        if value is not None and not value.strip():
            raise ValueError("session_id must be null or a non-empty string")
        return value


async def _await_work_runtime(request: Request) -> None:
    """Fail-closed start of Work before any Work-mode parent API."""
    if getattr(request.app.state, "work_runtime_ready", False):
        return
    ensure = getattr(request.app.state, "ensure_work_runtime", None)
    if not callable(ensure):
        raise HTTPException(
            503,
            {"code": "work_runtime_starting", "message": "正在启动 Work"},
        )
    try:
        await ensure()
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            503,
            {"code": "work_runtime_starting", "message": "正在启动 Work"},
        ) from exc


def _trusted_principal(request: Request) -> AppShellPrincipalV1:
    managed, principal = appshell_principal_from_scope(request.scope)
    if not managed or principal is None:
        raise HTTPException(
            401,
            "AppShell session is required",
            headers={"Cache-Control": "no-store"},
        )
    return principal


def _projection_authority(
    request: Request,
    principal: AppShellPrincipalV1,
    *,
    requested_mode: Literal["personal", "work"] | None,
) -> ProjectionAuthorityV1:
    """Select exactly one child runtime from trusted parent-owned state."""
    if requested_mode is not None and requested_mode != principal.active_mode:
        raise HTTPException(
            403,
            {"code": "projection_mode_not_active"},
            headers={"Cache-Control": "no-store"},
        )
    role = principal.mode_roles.get(principal.active_mode)
    if not isinstance(role, str) or not role:
        raise HTTPException(
            403,
            {"code": "projection_mode_role_required"},
            headers={"Cache-Control": "no-store"},
        )
    if principal.active_mode == "work":
        mode = AppMode.WORK
        workspace = request.app.state.work_workspace_handle
        if principal.workspace != workspace:
            raise HTTPException(
                409,
                {"code": "projection_workspace_binding_mismatch"},
                headers={"Cache-Control": "no-store"},
            )
        child_app = request.app.state.work_app
    else:
        mode = AppMode.PERSONAL
        workspace = None
        if principal.workspace is not None:
            raise HTTPException(
                409,
                {"code": "projection_workspace_binding_mismatch"},
                headers={"Cache-Control": "no-store"},
            )
        child_app = request.app.state.personal_app
    runtime = getattr(child_app.state, "web_runtime", None)
    if runtime is None:
        raise HTTPException(
            503,
            {"code": "projection_runtime_unavailable"},
            headers={"Cache-Control": "no-store"},
        )
    agent = runtime.agent
    service = getattr(agent, "echo_safety_service", None)
    if not isinstance(service, EchoSafetyService):
        raise HTTPException(
            503,
            {"code": "projection_ledger_unavailable"},
            headers={"Cache-Control": "no-store"},
        )
    return ProjectionAuthorityV1(
        mode=mode,
        owner=principal.owner,
        workspace=workspace,
        parent_session=principal.session,
        role=role,
        agent=agent,
        echo_safety_service=service,
    )


def _validate_projection_query(request: Request) -> None:
    allowed = {"mode", "session", "run", "limit"}
    unexpected = sorted(set(request.query_params) - allowed)
    if unexpected:
        raise HTTPException(
            400,
            {"code": "unsupported_projection_parameter"},
            headers={"Cache-Control": "no-store"},
        )


def _projection_response(envelope: ProjectionEnvelopeV1) -> JSONResponse:
    return JSONResponse(
        envelope.to_dict(),
        status_code=503 if envelope.status == "blocked" else 200,
        headers={"Cache-Control": "no-store"},
    )


def _session_token(request: Request) -> str:
    token = request.cookies.get(APPSHELL_SESSION_COOKIE)
    if not isinstance(token, str) or not token:
        raise HTTPException(401, "AppShell session is required")
    return token


def _trusted_resource_session_ids(agent: Any, owner: str) -> tuple[str, ...]:
    """Derive departing resource sessions only from trusted runtime registries."""
    try:
        active_cancel_sessions = agent.owned_active_session_ids(
            owner_key_hash=owner,
        )
        authority = agent._get_echo_tool_lease_authority()
        active_lease_sessions = authority.active_session_ids_for_owner(
            owner_key_hash=owner,
        )
        pending = agent.approvals.get_pending(owner_key_hash=owner)
    except Exception as exc:
        raise HTTPException(
            503,
            {"code": "departing_resource_discovery_unavailable"},
        ) from exc

    sessions = set(active_cancel_sessions) | set(active_lease_sessions)
    for approval in pending:
        session_id = getattr(approval, "session_id", None)
        if not isinstance(session_id, str) or not session_id.strip():
            raise HTTPException(
                503,
                {"code": "unbound_departing_approval"},
            )
        sessions.add(session_id)
    return tuple(sorted(sessions))


async def _exchange_session(
    request: Request,
    body: AppShellSessionRequest | None,
) -> JSONResponse:
    check_origin(request)
    api_key = request.headers.get("x-api-key")
    if not api_key and body is not None:
        api_key = body.api_key
    if not isinstance(api_key, str) or not api_key:
        raise HTTPException(401, "X-API-Key header is required")

    personal_settings = request.app.state.personal_app.state.runtime_settings
    work_settings = request.app.state.work_app.state.runtime_settings
    try:
        personal_identity = AuthManager(personal_settings.state_dir).verify(api_key)
    except Exception as exc:
        from js.exceptions import AuthRequiredError

        if isinstance(exc, AuthRequiredError):
            raise HTTPException(401, str(exc)) from exc
        raise

    roles = {"personal": str(personal_identity["role"])}
    work_auth = AuthManager(work_settings.state_dir)
    try:
        work_identity = work_auth.verify(api_key)
    except Exception as exc:
        from js.exceptions import AuthRequiredError

        if not isinstance(exc, AuthRequiredError):
            raise
        # Docker recreate wipes the ephemeral Work store while Personal
        # survives on the mounted volume. Restore the first-boot binding
        # only when Work has no admin left — never widen an existing store.
        if personal_identity.get("role") == "admin" and not work_auth.has_admin():
            work_identity = work_auth.provision_existing_key(
                api_key,
                name=str(personal_identity.get("name") or "appshell-admin"),
                role="admin",
            )
            roles["work"] = str(work_identity["role"])
            logger.warning(
                "Restored missing Work admin from Personal key after empty Work store",
                work_state_dir=str(work_settings.state_dir),
            )
    else:
        # The same plaintext credential produces the same physical owner hash.
        # Refuse any future verifier that claims otherwise.
        if work_identity.get("key_hash") != personal_identity.get("key_hash"):
            raise HTTPException(409, "Personal and Work identity binding mismatch")
        roles["work"] = str(work_identity["role"])

    token, principal = request.app.state.appshell_session_store.create(
        owner=str(personal_identity["key_hash"]),
        mode_roles=roles,
    )
    response = JSONResponse({"success": True, "principal": principal.public_dict()})
    response.set_cookie(
        APPSHELL_SESSION_COOKIE,
        token,
        max_age=APPSHELL_SESSION_TTL_SECONDS,
        httponly=True,
        samesite="strict",
        secure=request.url.scheme == "https",
        path="/",
    )
    # Remove child/legacy cookies. AppShell children will not consume them, but
    # deleting them makes the one-login boundary visible and deterministic.
    for name in ("js_session", "js_session_js-agent", "js_session_js-work"):
        response.delete_cookie(name, path="/")
    return response


@router.post("/session")
async def create_appshell_session(
    request: Request,
    body: AppShellSessionRequest | None = None,
) -> JSONResponse:
    """Exchange one shared credential for the sole parent browser session."""
    response = await _exchange_session(request, body)
    personal_settings = request.app.state.personal_app.state.runtime_settings

    consume_bootstrap_admin_key_file(personal_settings.state_dir)
    return response


@router.post("/logout")
async def logout_appshell_session(request: Request) -> JSONResponse:
    """Revoke the sole parent browser session and expire its HttpOnly cookie."""
    check_origin(request)
    request.app.state.appshell_session_store.revoke(request.cookies.get(APPSHELL_SESSION_COOKIE))
    response = JSONResponse({"success": True})
    response.delete_cookie(APPSHELL_SESSION_COOKIE, path="/")
    return response


@router.post("/bootstrap")
async def bootstrap_appshell_session(
    request: Request,
    body: AppShellSessionRequest | None = None,
) -> JSONResponse:
    """Create or join the one shared Personal/Work recovery identity."""
    if not request_is_direct_loopback(request):
        raise HTTPException(403, "AppShell bootstrap is restricted to direct loopback")
    check_origin(request)

    managed, current = appshell_principal_from_scope(request.scope)
    if managed and current is not None:
        return JSONResponse({"success": True, "principal": current.public_dict()})

    api_key = request.headers.get("x-api-key")
    if not api_key and body is not None:
        api_key = body.api_key
    personal_settings = request.app.state.personal_app.state.runtime_settings
    work_settings = request.app.state.work_app.state.runtime_settings
    personal_auth = AuthManager(personal_settings.state_dir)
    work_auth = AuthManager(work_settings.state_dir)

    if not api_key:
        if personal_auth.has_admin():
            raise HTTPException(401, "Existing Personal admin login is required")
        from js.appshell.bootstrap_key import provision_shared_bootstrap_key

        api_key = provision_shared_bootstrap_key(personal_settings, work_settings)
        if api_key is None:
            raise HTTPException(401, "Existing Personal admin login is required")
    else:
        try:
            personal_identity = personal_auth.verify(api_key)
        except Exception as exc:
            from js.exceptions import AuthRequiredError

            if isinstance(exc, AuthRequiredError):
                raise HTTPException(401, str(exc)) from exc
            raise
        try:
            work_auth.verify(api_key)
        except Exception as exc:
            from js.exceptions import AuthRequiredError

            if not isinstance(exc, AuthRequiredError):
                raise
            if personal_identity.get("role") != "admin":
                raise HTTPException(403, "Personal admin role is required to grant Work") from exc
            work_auth.provision_existing_key(
                api_key,
                name=str(personal_identity.get("name") or "appshell-admin"),
                role="admin",
            )

    assert api_key is not None
    return await _exchange_session(request, AppShellSessionRequest(api_key=api_key))


@router.get("/capabilities")
async def appshell_capabilities(
    request: Request,
    principal: AppShellPrincipalV1 = Depends(_trusted_principal),
) -> dict[str, Any]:
    return {
        "schema": "AppShellCapabilitiesV1",
        "active_mode": principal.active_mode,
        "available_modes": list(principal.mode_roles),
        "mode_roles": dict(principal.mode_roles),
        "workspace": principal.workspace,
        "workspace_handles": {
            "personal": None,
            "work": request.app.state.work_workspace_handle,
        },
        "session": principal.session,
        "expires_at": principal.expires_at,
    }


class IntentIssueRequest(BaseModel):
    """Owner-witness intent issuance (WP5): user confirms a task boundary."""

    model_config = ConfigDict(extra="forbid")

    raw_request: str = Field(min_length=1, max_length=20_000)
    template: Literal["personal", "work", "factory"] = "personal"
    task_id: str | None = Field(default=None, max_length=256)
    ttl_ms: int | None = Field(default=None, ge=1_000, le=24 * 60 * 60 * 1000)
    sink_handles: list[str] = Field(default_factory=list, max_length=32)
    resource_handles: list[str] = Field(default_factory=list, max_length=32)


class ExportPassRequest(BaseModel):
    """Approve one exact egress: payload hash + destinations (K§7.9)."""

    task_id: str = Field(min_length=1, max_length=256)
    payload_hash: str = Field(min_length=71, max_length=71)
    destination_handles: list[str] = Field(min_length=1, max_length=32)
    witness_id: str = Field(default="", max_length=256)
    ttl_ms: int = Field(default=600_000, ge=1_000, le=3_600_000)


class FileCommitApproveRequest(BaseModel):
    """Confirm the exact machine preview for the current Personal task."""

    model_config = ConfigDict(extra="forbid")

    approved: StrictBool
    witness_id: str = Field(min_length=7, max_length=256)
    diff_hash: str = Field(min_length=71, max_length=71)
    ttl_ms: int = Field(default=60_000, ge=1_000, le=60_000)

    @field_validator("approved")
    @classmethod
    def _require_approval(cls, value: bool) -> bool:
        if value is not True:
            raise ValueError("approved must be true")
        return value


def _safe_file_commit_previews(raw: Any) -> list[dict[str, Any]]:
    """Fail closed while stripping all authority-bearing adapter fields."""

    from js.orin.draft import file_commit_preview_from_dict
    from js.orin.protocol import ProtocolError

    if not isinstance(raw, list) or len(raw) > 128:
        raise HTTPException(502, {"code": "orind_invalid_projection"})
    safe: list[dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            raise HTTPException(502, {"code": "orind_invalid_projection"})
        witness_id = item.get("witness_id")
        if (
            not isinstance(witness_id, str)
            or not witness_id.startswith("state:")
            or len(witness_id) > 256
        ):
            raise HTTPException(502, {"code": "orind_invalid_projection"})
        try:
            preview = file_commit_preview_from_dict(
                {
                    "schema": "FileCommitPreviewV1",
                    "file_count": item.get("file_count"),
                    "bytes": item.get("bytes"),
                    "overwrites": item.get("overwrites"),
                    "diff_hash": item.get("diff_hash"),
                }
            )
        except (ProtocolError, TypeError, ValueError) as exc:
            raise HTTPException(502, {"code": "orind_invalid_projection"}) from exc
        safe.append(
            {
                "file_count": preview.file_count,
                "bytes": preview.bytes,
                "overwrites": list(preview.overwrites),
                "diff_hash": preview.diff_hash,
                "witness_id": witness_id,
            }
        )
    return safe


class AdminUnfreezeRequest(BaseModel):
    session_id: str = Field(min_length=1, max_length=128)
    raw_request: str = Field(default="admin unfreeze", max_length=2_000)


def _mode_runtime(request: Request, principal: AppShellPrincipalV1) -> Any:
    app = (
        request.app.state.work_app
        if principal.active_mode == "work"
        else (request.app.state.personal_app)
    )
    return getattr(app.state, "web_runtime", None)


def _stage_b_adapter(runtime: Any) -> tuple[Any | None, str | None]:
    """Fetch the agent-owned Orin adapter when stage B is actually enabled.

    Reusing the agent's single connection matters: orind publishes one
    ``session-<pid>.key`` per peer pid, so a second concurrent connection
    from this process would race the key file exchange.
    """

    agent = getattr(runtime, "agent", None)
    getter = getattr(agent, "_get_echo_tool_lease_authority", None)
    if not callable(getter):
        return None, "no_lease_authority"
    try:
        authority = getter()
    except Exception:  # noqa: BLE001 - surfaced as 503, never crash the route
        return None, "lease_authority_unavailable"
    if not bool(getattr(authority, "_stage_b", False)):
        return None, "orin_stage_b_disabled"
    return authority, None


def _installation_owner_hash(settings: Any) -> str:
    import hashlib

    material = f"js-agent:{getattr(settings, 'state_dir', '.')}"
    return "sha256:" + hashlib.sha256(material.encode("utf-8")).hexdigest()


@router.post("/intent")
async def issue_owner_intent(
    request: Request,
    body: IntentIssueRequest,
    principal: AppShellPrincipalV1 = Depends(_trusted_principal),
) -> dict[str, Any]:
    """Sign an IntentEnvelope as the owner witness and register it with Orin."""
    check_origin(request)
    gate: AppShellModeGate | None = getattr(
        request.app.state,
        "appshell_mode_gate",
        None,
    )
    if gate is None:
        raise HTTPException(503, {"code": "appshell_mode_gate_unavailable"})
    try:
        admission = await gate.admit(
            principal,
            operation_kind="appshell_orin_intent",
        )
    except AppShellEpochClosedError as exc:
        raise HTTPException(409, {"code": "appshell_epoch_closed"}) from exc
    except AppShellOperationLimitError as exc:
        raise HTTPException(429, {"code": "appshell_operation_limit"}) from exc

    try:
        state = request.app.state
        if principal.active_mode == "work":
            if principal.workspace != getattr(state, "work_workspace_handle", None):
                raise HTTPException(409, {"code": "appshell_workspace_binding_mismatch"})
        elif principal.workspace is not None:
            raise HTTPException(409, {"code": "appshell_workspace_binding_mismatch"})

        runtime = _mode_runtime(request, principal)
        if runtime is None:
            raise HTTPException(503, {"code": "runtime_unavailable"})
        adapter, reason = _stage_b_adapter(runtime)
        if adapter is None:
            raise HTTPException(503, {"code": reason})
        from js.orin.handles import (
            canonical_workspace_root,
            derive_appshell_directory_handle_id,
        )
        from js.orin.witness import build_intent_from_template, ensure_witness_keypair

        if any(handle.startswith("dirh:") for handle in body.resource_handles):
            raise HTTPException(400, {"code": "directory_handle_is_server_derived"})

        settings = runtime.settings
        state_dir = Path(settings.state_dir)
        private_key, _pub = ensure_witness_keypair(state_dir)
        installation_owner = _installation_owner_hash(settings)
        directory_handle_id: str | None = None

        if body.template in {"personal", "work"}:
            if body.template != principal.active_mode:
                raise HTTPException(403, {"code": "intent_profile_not_active"})
            if body.task_id is not None:
                raise HTTPException(400, {"code": "orin_task_id_is_server_derived"})
            task_id = f"task:{uuid4().hex}"
            product_id = str(getattr(settings, "product_id", "js-agent"))
            workspace_root = canonical_workspace_root(settings.workspace)
            directory_handle_id = derive_appshell_directory_handle_id(
                installation_owner_hash=installation_owner,
                product_id=product_id,
                task_id=task_id,
                profile=body.template,
                principal_owner=principal.owner,
                principal_session=principal.session,
                principal_epoch=principal.epoch,
                workspace_root=workspace_root,
            )
            envelope = build_intent_from_template(
                template=body.template,
                task_id=task_id,
                raw_request=body.raw_request,
                owner_key_hash=installation_owner,
                product_id=product_id,
                ttl_ms=body.ttl_ms or 60 * 60 * 1000,
                sink_handles=tuple(body.sink_handles),
                resource_handles=(*body.resource_handles, directory_handle_id),
            )
            signed = envelope.sign_with(private_key)
            try:
                ack = adapter.register_file_binding(
                    signed.to_dict(),
                    appshell_owner=principal.owner,
                    appshell_session=principal.session,
                    appshell_epoch=principal.epoch,
                    workspace_root=workspace_root,
                )
            except LeaseDenied as exc:
                raise HTTPException(
                    502,
                    {"code": "orind_rejected", "reason": str(exc)},
                ) from exc
        else:
            task_id = body.task_id or f"task:{uuid4().hex}"
            envelope = build_intent_from_template(
                template=body.template,
                task_id=task_id,
                raw_request=body.raw_request,
                owner_key_hash=installation_owner,
                ttl_ms=body.ttl_ms or 60 * 60 * 1000,
                sink_handles=tuple(body.sink_handles),
                resource_handles=tuple(body.resource_handles),
            )
            signed = envelope.sign_with(private_key)
            try:
                ack = adapter.register_intent(signed.to_dict())
            except LeaseDenied as exc:
                raise HTTPException(
                    502,
                    {"code": "orind_rejected", "reason": str(exc)},
                ) from exc

        response: dict[str, Any] = {
            "schema": "AppShellIntentAckV1",
            "ok": bool(ack.get("ok")),
            "task_id": task_id,
            "intent_id": envelope.intent_id,
            "expires_at_ms": envelope.expires_at_ms,
            "approval_policy": envelope.approval_policy,
            "allowed_effect_classes": list(envelope.allowed_effect_classes),
        }
        if directory_handle_id is not None:
            response["directory_handle_id"] = directory_handle_id
        return response
    finally:
        await gate.release(admission)


@router.get("/intent/active")
async def get_active_intent(
    request: Request,
    task_id: str,
    principal: AppShellPrincipalV1 = Depends(_trusted_principal),
) -> dict[str, Any]:
    check_origin(request)
    runtime = _mode_runtime(request, principal)
    if runtime is None:
        raise HTTPException(503, {"code": "runtime_unavailable"})
    adapter, reason = _stage_b_adapter(runtime)
    if adapter is None:
        raise HTTPException(503, {"code": reason})
    active = adapter.active_intent(task_id)
    return {"schema": "AppShellActiveIntentV1", "task_id": task_id, "intent": active}


@router.get("/file-commit/pending")
async def get_pending_file_commits(
    request: Request,
    principal: AppShellPrincipalV1 = Depends(_trusted_principal),
) -> JSONResponse:
    """Project the current Personal task's machine-generated file preview."""

    check_origin(request)
    gate: AppShellModeGate | None = getattr(request.app.state, "appshell_mode_gate", None)
    if gate is None:
        raise HTTPException(503, {"code": "appshell_mode_gate_unavailable"})
    try:
        admission = await gate.admit(
            principal,
            operation_kind="appshell_orin_file_commit_pending",
        )
    except AppShellEpochClosedError as exc:
        raise HTTPException(409, {"code": "appshell_epoch_closed"}) from exc
    except AppShellOperationLimitError as exc:
        raise HTTPException(429, {"code": "appshell_operation_limit"}) from exc
    try:
        if principal.active_mode != "personal":
            raise HTTPException(403, {"code": "exact_file_approval_personal_only"})
        if principal.workspace is not None:
            raise HTTPException(409, {"code": "appshell_workspace_binding_mismatch"})
        runtime = _mode_runtime(request, principal)
        if runtime is None:
            raise HTTPException(503, {"code": "runtime_unavailable"})
        adapter, reason = _stage_b_adapter(runtime)
        if adapter is None:
            raise HTTPException(503, {"code": reason})
        settings = runtime.settings
        try:
            pending = adapter.pending_file_approvals(
                appshell_owner=principal.owner,
                appshell_session=principal.session,
                appshell_epoch=principal.epoch,
                active_mode=principal.active_mode,
                product_id=str(getattr(settings, "product_id", "js-agent")),
                workspace_root=settings.workspace,
            )
        except LeaseDenied as exc:
            raise HTTPException(502, {"code": "orind_rejected"}) from exc
        return JSONResponse(
            {
                "schema": "AppShellFileCommitPendingV1",
                "pending": _safe_file_commit_previews(pending),
            },
            headers={"Cache-Control": "no-store"},
        )
    finally:
        await gate.release(admission)


@router.post("/file-commit/approve")
async def approve_pending_file_commit(
    request: Request,
    body: FileCommitApproveRequest,
    principal: AppShellPrincipalV1 = Depends(_trusted_principal),
) -> JSONResponse:
    """Owner-sign and consume one exact Personal File Cell proposal."""

    check_origin(request)
    gate: AppShellModeGate | None = getattr(request.app.state, "appshell_mode_gate", None)
    if gate is None:
        raise HTTPException(503, {"code": "appshell_mode_gate_unavailable"})
    try:
        admission = await gate.admit(
            principal,
            operation_kind="appshell_orin_file_commit_approve",
        )
    except AppShellEpochClosedError as exc:
        raise HTTPException(409, {"code": "appshell_epoch_closed"}) from exc
    except AppShellOperationLimitError as exc:
        raise HTTPException(429, {"code": "appshell_operation_limit"}) from exc
    try:
        if principal.active_mode != "personal":
            raise HTTPException(403, {"code": "exact_file_approval_personal_only"})
        if principal.workspace is not None:
            raise HTTPException(409, {"code": "appshell_workspace_binding_mismatch"})
        runtime = _mode_runtime(request, principal)
        if runtime is None:
            raise HTTPException(503, {"code": "runtime_unavailable"})
        adapter, reason = _stage_b_adapter(runtime)
        if adapter is None:
            raise HTTPException(503, {"code": reason})
        from js.orin.witness import ensure_witness_keypair

        settings = runtime.settings
        private_key, _public_key = ensure_witness_keypair(Path(settings.state_dir))
        try:
            result = adapter.approve_pending_file_change(
                witness_id=body.witness_id,
                diff_hash=body.diff_hash,
                ttl_ms=body.ttl_ms,
                private_key=private_key,
                appshell_owner=principal.owner,
                appshell_session=principal.session,
                appshell_epoch=principal.epoch,
                active_mode=principal.active_mode,
                product_id=str(getattr(settings, "product_id", "js-agent")),
                workspace_root=settings.workspace,
            )
        except LeaseDenied as exc:
            raise HTTPException(502, {"code": "orind_rejected"}) from exc
        if not isinstance(result, dict) or result.get("status") != "COMMITTED":
            raise HTTPException(502, {"code": "orind_invalid_projection"})
        return JSONResponse(
            {
                "schema": "AppShellFileCommitApprovalAckV1",
                "ok": True,
                "status": "COMMITTED",
            },
            headers={"Cache-Control": "no-store"},
        )
    finally:
        await gate.release(admission)


@router.post("/export-pass")
async def grant_export_pass(
    request: Request,
    body: ExportPassRequest,
    principal: AppShellPrincipalV1 = Depends(_trusted_principal),
) -> dict[str, Any]:
    """Owner approves exact bytes (by hash) to named destination handles.

    The pass is signed by the owner witness — Echo cannot mint one — and
    the Connector Cell re-verifies the payload hash at send time.
    """
    check_origin(request)
    runtime = _mode_runtime(request, principal)
    if runtime is None:
        raise HTTPException(503, {"code": "runtime_unavailable"})
    adapter, reason = _stage_b_adapter(runtime)
    if adapter is None:
        raise HTTPException(503, {"code": reason})
    from uuid import uuid4

    from js.orin.draft import ExportPass
    from js.orin.witness import ensure_witness_keypair

    settings = runtime.settings
    private_key, _pub = ensure_witness_keypair(Path(settings.state_dir))
    ts = int(time.time() * 1000)
    export_pass = ExportPass(
        pass_id=f"export:{uuid4().hex}",
        task_id=body.task_id,
        payload_hash=body.payload_hash,
        destination_handles=tuple(body.destination_handles),
        witness_id=body.witness_id,
        created_at_ms=ts - 1000,
        expires_at_ms=ts + body.ttl_ms,
    ).sign_with(private_key)
    try:
        ack = adapter.grant_export(export_pass.to_dict(), task_id=body.task_id)
    except LeaseDenied as exc:
        raise HTTPException(502, {"code": "orind_rejected", "reason": str(exc)}) from exc
    return {
        "schema": "AppShellExportPassAckV1",
        "ok": bool(ack.get("ok")),
        "pass_id": export_pass.pass_id,
        "expires_at_ms": export_pass.expires_at_ms,
    }


@router.post("/admin/unfreeze")
async def admin_unfreeze_session(
    request: Request,
    body: AdminUnfreezeRequest,
    auth: dict[str, Any] = Depends(require_admin),
    principal: AppShellPrincipalV1 = Depends(_trusted_principal),
) -> dict[str, Any]:
    """R3 de-escalation: requires the admin API key plus a dual-control
    admin.unfreeze IntentEnvelope signed by the owner witness. Echo has no
    path here — the ladder can only be unwound by the human operator."""
    check_origin(request)
    if principal.active_mode == "work":
        await _await_work_runtime(request)
    runtime = _mode_runtime(request, principal)
    if runtime is None:
        raise HTTPException(503, {"code": "runtime_unavailable"})
    adapter, reason = _stage_b_adapter(runtime)
    if adapter is None:
        raise HTTPException(503, {"code": reason})
    from js.orin.intent import APPROVAL_POLICIES, EFFECT_CLASSES
    from js.orin.witness import ensure_witness_keypair

    _ = EFFECT_CLASSES, APPROVAL_POLICIES
    settings = runtime.settings
    state_dir = Path(settings.state_dir)
    private_key, _pub = ensure_witness_keypair(state_dir)
    ts = int(time.time() * 1000)
    from js.orin.intent import Budgets, IntentEnvelope, request_hash_of

    admin_intent = IntentEnvelope(
        intent_id=f"intent:{ts:x}-admin",
        owner_key_hash=_installation_owner_hash(settings),
        product_id="js-agent",
        profile="admin",
        task_id=f"task:admin-{ts}",
        raw_request_hash=request_hash_of(body.raw_request),
        allowed_effect_classes=("admin.unfreeze",),
        allowed_resource_handles=(),
        allowed_sink_handles=(),
        budgets=Budgets(),
        approval_policy="dual_control",
        issued_by="appshell:admin-witness",
        issued_at_ms=ts - 1000,
        expires_at_ms=ts + 60_000,
    )
    admin_intent = admin_intent.sign_with(private_key)
    try:
        ack = adapter.admin_unfreeze(admin_intent.to_dict(), session_id=body.session_id)
    except LeaseDenied as exc:
        raise HTTPException(502, {"code": "orind_rejected", "reason": str(exc)}) from exc
    return {
        "schema": "AppShellAdminUnfreezeAckV1",
        "ok": bool(ack.get("ok")),
        "unfrozen": list(ack.get("unfrozen") or []),
        "operator": str(auth.get("sub") or auth.get("key_id") or "admin"),
    }


@router.post("/prewarm")
async def prewarm_work_runtime(
    request: Request,
    principal: AppShellPrincipalV1 = Depends(_trusted_principal),
) -> dict[str, str]:
    """Start Work runtime in the background without changing the active mode."""
    check_origin(request)
    if "work" not in principal.mode_roles:
        raise HTTPException(403, {"code": "work_role_required"})
    if getattr(request.app.state, "work_runtime_ready", False):
        return {"status": "ready"}
    ensure = getattr(request.app.state, "ensure_work_runtime", None)
    if not callable(ensure):
        raise HTTPException(
            503,
            {"code": "work_runtime_starting", "message": "正在启动 Work"},
        )

    async def _run() -> None:
        try:
            await ensure()
        except Exception:
            logger.warning("Work runtime prewarm failed", exc_info=True)

    task = getattr(request.app.state, "work_prewarm_task", None)
    if task is None or task.done():
        request.app.state.work_prewarm_task = asyncio.create_task(_run())
    return {"status": "warming"}


@router.post("/switch")
async def switch_appshell_mode(
    request: Request,
    body: AppShellSwitchRequest,
    principal: AppShellPrincipalV1 = Depends(_trusted_principal),
) -> dict[str, Any]:
    """Cancel and revoke the departing mode before atomically changing routing."""
    check_origin(request)
    if body.expected_from_mode != principal.active_mode:
        raise HTTPException(
            409,
            {
                "code": "active_mode_conflict",
                "expected": body.expected_from_mode,
                "actual": principal.active_mode,
            },
        )
    if body.to_mode == principal.active_mode:
        raise HTTPException(409, {"code": "mode_already_active"})
    if body.to_mode == "work":
        if "work" not in principal.mode_roles:
            raise HTTPException(403, {"code": "work_role_required"})
        if body.workspace_handle != request.app.state.work_workspace_handle:
            raise HTTPException(400, {"code": "invalid_work_workspace_handle"})
        target_workspace = request.app.state.work_workspace_handle
        await _await_work_runtime(request)
    else:
        if body.workspace_handle is not None:
            raise HTTPException(400, {"code": "personal_workspace_must_be_null"})
        target_workspace = None

    gate: AppShellModeGate = request.app.state.appshell_mode_gate
    try:
        binding = await gate.begin_switch(_session_token(request), principal)
    except AppShellSessionConflictError as exc:
        raise HTTPException(409, {"code": "active_mode_conflict"}) from exc
    except AppShellSessionError as exc:
        raise HTTPException(401, str(exc)) from exc

    try:
        departing_app = (
            request.app.state.work_app
            if principal.active_mode == "work"
            else request.app.state.personal_app
        )
        runtime = getattr(departing_app.state, "web_runtime", None)
        if runtime is None:
            raise HTTPException(503, "Departing runtime is unavailable")
        agent = runtime.agent
        resource_session_ids = _trusted_resource_session_ids(agent, principal.owner)
        if (
            body.session_id is not None
            and resource_session_ids
            and body.session_id not in resource_session_ids
        ):
            raise HTTPException(
                409,
                {
                    "code": "session_binding_mismatch",
                    "resource_session_ids": list(resource_session_ids),
                },
            )

        cancelled_sessions: list[str] = []
        cancel_results: dict[str, str] = {}
        revoked_lease_ids: list[str] = []
        revoked_approval_ids: list[str] = []
        completed_steps: list[str] = []

        # 1. Cancel every trusted departing owner session, never only the client hint.
        for session_id in resource_session_ids:
            result = agent.request_owned_cancel(session_id, owner_key_hash=principal.owner)
            cancel_results[session_id] = str(result)
            if result == OwnedCancelResult.DENIED:
                raise HTTPException(409, {"code": "session_owner_mismatch"})
            if result == OwnedCancelResult.CANCELLED:
                cancelled_sessions.append(session_id)
        if cancelled_sessions:
            completed_steps.append("cancel_old_runs")

        # 2. Revoke every owner/session lease and pending approval.
        if resource_session_ids:
            authority = agent._get_echo_tool_lease_authority()
            revoke_approvals = getattr(agent.approvals, "revoke_for_session", None)
            if not callable(revoke_approvals):
                raise HTTPException(503, "Approval revocation is unavailable")
            for session_id in resource_session_ids:
                revoked_lease_ids.extend(
                    authority.revoke_for_session(
                        owner_key_hash=principal.owner,
                        session_id=session_id,
                    )
                )
                revoked_approval_ids.extend(
                    revoke_approvals(
                        owner_key_hash=principal.owner,
                        session_id=session_id,
                        reason="appshell_mode_switch",
                    )
                )
            if revoked_lease_ids or revoked_approval_ids:
                completed_steps.append("revoke_leases_and_approvals")

        # 3. Revoke and close old sockets before the authoritative mode CAS.
        websocket_close = await request.app.state.appshell_ws_registry.close_for_session(
            principal.session,
            principal.active_mode,
        )
        if websocket_close["revoked"]:
            completed_steps.append("revoke_old_websockets")
        if websocket_close.get("timed_out"):
            raise HTTPException(503, {"code": "old_websocket_close_timeout"})
        if websocket_close["errors"]:
            raise HTTPException(503, {"code": "old_websocket_close_failed"})
        if websocket_close["revoked"] and websocket_close["closed"] == websocket_close["revoked"]:
            completed_steps.append("close_old_websockets")

        # 4. A cancellation signal is not drain. Wait for authoritative HTTP,
        # WebSocket, model, tool, receipt, and merge operation releases.
        try:
            await gate.wait_for_drain(binding)
        except AppShellEpochDrainTimeoutError as exc:
            raise HTTPException(503, {"code": "old_epoch_drain_timeout"}) from exc

        remaining_sessions = _trusted_resource_session_ids(agent, principal.owner)
        if remaining_sessions:
            raise HTTPException(
                503,
                {
                    "code": "departing_resources_not_cleared",
                    "resource_session_ids": list(remaining_sessions),
                },
            )
        completed_steps.append("verify_departing_resources_cleared")

        # 5. The browser clears stream and attachment references before reconnect.
        clear_keys = [
            "messages",
            "stream_buffers",
            "attachments",
            "leases",
            "approvals",
            f"mode:{principal.active_mode}",
        ]

        # 6. CAS only after every authoritative old-epoch operation ended.
        try:
            updated = await gate.commit_switch(
                _session_token(request),
                binding,
                to_mode=body.to_mode,
                workspace=target_workspace,
            )
        except AppShellSessionConflictError as exc:
            raise HTTPException(409, {"code": "active_mode_conflict"}) from exc
        except AppShellSessionError as exc:
            raise HTTPException(401, str(exc)) from exc
        completed_steps.append("update_principal")

        return {
            "ok": True,
            "from_mode": principal.active_mode,
            "to_mode": updated.active_mode,
            "workspace": updated.workspace,
            "completed_steps": completed_steps,
            "resource_session_ids": list(resource_session_ids),
            "cancelled_sessions": cancelled_sessions,
            "cancel_results": cancel_results,
            "revoked_lease_ids": revoked_lease_ids,
            "revoked_approval_ids": revoked_approval_ids,
            "closed_websockets": websocket_close["closed"],
            "websocket_close": websocket_close,
            "client_required_steps": [
                "clear_stream_and_attachments",
                "reconnect_at_target_path",
            ],
            "clear_ui_cache_keys": clear_keys,
            "target_path": "/",
            "must_reconnect": True,
        }
    finally:
        await gate.abort_switch(binding)


@router.get("/inbox")
async def get_inbox(
    request: Request,
    mode: Literal["personal", "work"] | None = None,
    session: str | None = None,
    run: str | None = None,
    limit: int = 50,
    principal: AppShellPrincipalV1 = Depends(_trusted_principal),
) -> Any:
    """Unified Inbox: aggregate tool approvals, manual reviews, memory proposals.

    Returns ``ProjectionEnvelopeV1`` with status ``ok``/``partial``/``blocked``.
    When all sources fail, returns 503 with ``blocked`` status.
    """
    _validate_projection_query(request)
    gate: AppShellModeGate = request.app.state.appshell_mode_gate
    try:
        admission = await gate.admit(
            principal,
            operation_kind="appshell_inbox_projection",
        )
    except AppShellEpochClosedError as exc:
        raise HTTPException(
            409,
            {"code": "appshell_epoch_closed"},
            headers={"Cache-Control": "no-store"},
        ) from exc
    except AppShellOperationLimitError as exc:
        raise HTTPException(
            429,
            {"code": "appshell_operation_limit"},
            headers={"Cache-Control": "no-store"},
        ) from exc
    try:
        if principal.active_mode == "work":
            await _await_work_runtime(request)
        authority = _projection_authority(
            request,
            principal,
            requested_mode=mode,
        )
        envelope = await asyncio.to_thread(
            list_inbox_items,
            authority,
            session=session,
            run=run,
            limit=limit,
        )
        response = _projection_response(envelope)
    finally:
        await gate.release(admission)
    return response


@router.get("/artifacts")
async def list_artifacts(
    request: Request,
    mode: Literal["personal", "work"] | None = None,
    session: str | None = None,
    run: str | None = None,
    limit: int = 50,
    principal: AppShellPrincipalV1 = Depends(_trusted_principal),
) -> Any:
    """Artifact center: project artifact references from verified EchoLedger receipts.

    Does NOT scan directories. Only returns artifacts from receipts that
    have been verified by the EchoLedger.
    """
    _validate_projection_query(request)
    gate: AppShellModeGate = request.app.state.appshell_mode_gate
    try:
        admission = await gate.admit(
            principal,
            operation_kind="appshell_artifact_projection",
        )
    except AppShellEpochClosedError as exc:
        raise HTTPException(
            409,
            {"code": "appshell_epoch_closed"},
            headers={"Cache-Control": "no-store"},
        ) from exc
    except AppShellOperationLimitError as exc:
        raise HTTPException(
            429,
            {"code": "appshell_operation_limit"},
            headers={"Cache-Control": "no-store"},
        ) from exc
    try:
        if principal.active_mode == "work":
            await _await_work_runtime(request)
        authority = _projection_authority(
            request,
            principal,
            requested_mode=mode,
        )
        envelope = await asyncio.to_thread(
            list_artifact_refs,
            authority,
            session=session,
            run=run,
            limit=limit,
        )
        response = _projection_response(envelope)
    finally:
        await gate.release(admission)
    return response


@router.get("/work-context")
async def get_work_context(
    request: Request,
    mode: Literal["personal", "work"] | None = None,
    session_id: str | None = None,
    run_id: str | None = None,
    limit: int = 25,
    principal: AppShellPrincipalV1 = Depends(_trusted_principal),
) -> Any:
    """Work-context projection for exactly one session (optional run).

    Separate closed projection from /inbox and /artifacts. Personal mode is
    rejected; unknown query params (including forged owner/product/workspace
    fields) fail closed with 400.
    """
    from js.appshell.work_context import WorkContextError, list_work_context

    allowed = {"mode", "session_id", "run_id", "limit"}
    unexpected = sorted(set(request.query_params) - allowed)
    if unexpected:
        raise HTTPException(
            400,
            {"code": "unsupported_projection_parameter"},
            headers={"Cache-Control": "no-store"},
        )
    if principal.active_mode != "work":
        raise HTTPException(
            403,
            {"code": "work_context_requires_work_mode"},
            headers={"Cache-Control": "no-store"},
        )
    if session_id is None:
        raise HTTPException(
            400,
            {"code": "session_id_required"},
            headers={"Cache-Control": "no-store"},
        )
    gate: AppShellModeGate = request.app.state.appshell_mode_gate
    try:
        admission = await gate.admit(
            principal,
            operation_kind="appshell_work_context_projection",
        )
    except AppShellEpochClosedError as exc:
        raise HTTPException(
            409,
            {"code": "appshell_epoch_closed"},
            headers={"Cache-Control": "no-store"},
        ) from exc
    except AppShellOperationLimitError as exc:
        raise HTTPException(
            429,
            {"code": "appshell_operation_limit"},
            headers={"Cache-Control": "no-store"},
        ) from exc
    try:
        await _await_work_runtime(request)
        authority = _projection_authority(
            request,
            principal,
            requested_mode=mode,
        )
        try:
            envelope = await asyncio.to_thread(
                list_work_context,
                authority,
                session=session_id,
                run=run_id,
                limit=limit,
            )
        except WorkContextError as exc:
            status = 409 if exc.code == "run_binding_unknown" else 400
            raise HTTPException(
                status,
                {"code": exc.code},
                headers={"Cache-Control": "no-store"},
            ) from exc
        response = JSONResponse(
            envelope.to_dict(),
            status_code=503 if envelope.status == "blocked" else 200,
            headers={"Cache-Control": "no-store"},
        )
    finally:
        await gate.release(admission)
    return response


@router.get("/settings")
async def get_settings_summary(
    auth: dict[str, Any] = Depends(require_auth_dep),
) -> dict[str, Any]:
    """Unified settings summary: global prefs + Personal + Work config overview."""
    from js.appshell.global_prefs import load_global_prefs

    prefs = load_global_prefs()
    return {
        "global": {
            "language": prefs.language,
            "timezone": prefs.timezone,
            "theme": prefs.theme,
        },
        "sections": ["global", "personal", "work"],
    }


@router.get("/devices")
async def list_devices(
    auth: dict[str, Any] = Depends(require_auth_dep),
) -> dict[str, Any]:
    """Reject the deferred Mobile surface without implying it is available."""
    del auth
    raise HTTPException(
        status_code=404,
        detail={"code": "feature_not_enabled", "feature": "devices"},
    )


@router.get("/friends")
async def list_friends(
    auth: dict[str, Any] = Depends(require_auth_dep),
) -> dict[str, Any]:
    """Reject the deferred Friends surface without falling back to a generic 404."""
    del auth
    raise HTTPException(
        status_code=404,
        detail={"code": "feature_not_enabled", "feature": "friends"},
    )
