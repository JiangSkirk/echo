"""Parent-owned AppShell session, mode switch, and unified chrome APIs."""

from __future__ import annotations

import asyncio
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator

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
from js.echo.ledger.service import EchoSafetyService
from js.echo.mode_contract import AppMode
from js.web.auth import (
    AuthManager,
    check_origin,
    request_is_direct_loopback,
    require_auth_dep,
)

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
    try:
        work_identity = AuthManager(work_settings.state_dir).verify(api_key)
    except Exception as exc:
        from js.exceptions import AuthRequiredError

        if not isinstance(exc, AuthRequiredError):
            raise
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
    return await _exchange_session(request, body)


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
        from js.web.auth import _generate_key
        from js.web.server import _persist_bootstrap_admin_key

        api_key = _generate_key()
        personal_identity = personal_auth.provision_existing_key(
            api_key,
            name="appshell-bootstrap",
            role="admin",
        )
        try:
            work_auth.provision_existing_key(
                api_key,
                name="appshell-bootstrap",
                role="admin",
            )
            _persist_bootstrap_admin_key(
                personal_settings.state_dir / "bootstrap_admin_key.txt",
                api_key,
            )
        except Exception:
            personal_auth.revoke_key(str(personal_identity["key_hash"]))
            try:
                work_auth.revoke_key(str(personal_identity["key_hash"]))
            except Exception:
                pass
            raise
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
