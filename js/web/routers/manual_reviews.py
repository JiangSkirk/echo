"""Admin operator endpoints for durable Echo manual-review effects."""

from __future__ import annotations

import asyncio
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from js.web.auth import memory_owner, require_admin, require_admin_write
from js.web.deps import get_echo_safety_service
from js.web.runtime_context import current_web_runtime

router = APIRouter(prefix="/api/echo/manual-reviews", tags=["echo-manual-reviews"])

_LOCAL_TENANT = "local-user"
_MAX_REASON_LENGTH = 1_000
_MAX_TENANT_ID_LENGTH = 256
_ALLOWED_ACTIONS = frozenset({"cancel", "override", "resolved"})


def _default_tenant(auth: dict[str, Any]) -> str:
    return memory_owner(auth) or _LOCAL_TENANT


def _operator(auth: dict[str, Any]) -> str:
    name = str(auth.get("name") or _LOCAL_TENANT)
    key_hash = memory_owner(auth)
    return f"{name}:{key_hash}" if key_hash else name


def _selected_tenant(auth: dict[str, Any], tenant_id: str | None) -> str:
    default_tenant = _default_tenant(auth)
    selected = tenant_id.strip() if tenant_id is not None else default_tenant
    if not selected or len(selected) > _MAX_TENANT_ID_LENGTH:
        raise HTTPException(
            400,
            f"tenant_id must be 1 to {_MAX_TENANT_ID_LENGTH} characters",
        )
    runtime = current_web_runtime()
    if (
        runtime is not None
        and str(getattr(runtime.settings, "product_id", "")) == "js-work"
        and selected != default_tenant
    ):
        raise HTTPException(403, "JS Agent Work manual reviews are owner-bound")
    return selected


@router.get("")
async def list_manual_reviews(
    tenant_id: str | None = None,
    auth: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    """List current manual-review effects for an admin-selected tenant."""
    selected_tenant = _selected_tenant(auth, tenant_id)
    try:
        rows = await asyncio.to_thread(
            get_echo_safety_service().list_manual_reviews,
            tenant_id=selected_tenant,
        )
    except (OSError, RuntimeError, ValueError) as exc:
        raise HTTPException(503, "Echo ledger validation failed") from exc
    return {
        "manual_reviews": [
            {
                "effect_id": row.effect_id,
                "outbox_id": row.outbox_id,
                "tenant_id": row.tenant_id,
                "action_kind": row.action_kind,
                "status": row.status,
            }
            for row in rows
        ]
    }


@router.post("/{effect_id}/resolve")
async def resolve_manual_review(
    effect_id: str,
    payload: dict[str, Any],
    tenant_id: str | None = None,
    auth: dict[str, Any] = Depends(require_admin_write),
) -> dict[str, Any]:
    """Durably resolve an effect in the admin-selected tenant."""
    selected_tenant = _selected_tenant(auth, tenant_id)
    action = payload.get("action")
    if action not in _ALLOWED_ACTIONS:
        raise HTTPException(400, "action must be cancel, override, or resolved")
    reason = payload.get("reason")
    if not isinstance(reason, str):
        raise HTTPException(400, "reason is required")
    reason = reason.strip()
    if not reason or len(reason) > _MAX_REASON_LENGTH:
        raise HTTPException(400, f"reason must be 1 to {_MAX_REASON_LENGTH} characters")

    try:
        result = await asyncio.to_thread(
            get_echo_safety_service().resolve_manual_review,
            tenant_id=selected_tenant,
            effect_id=effect_id,
            action=action,
            operator=_operator(auth),
            reason=reason,
        )
    except KeyError as exc:
        raise HTTPException(404, "manual review effect not found") from exc
    except PermissionError as exc:
        raise HTTPException(409, "manual review effect is already resolved") from exc
    except (OSError, RuntimeError, ValueError) as exc:
        raise HTTPException(503, "Echo ledger validation failed") from exc

    return {
        "ok": result.ok,
        "mode": result.mode,
        "record_types": list(result.record_types),
    }
