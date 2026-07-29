"""HTTP surface for AppShell workspace switching."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from js.appshell.global_prefs import load_global_prefs
from js.appshell.switch import WorkspaceProduct, run_workspace_switch
from js.web.auth import require_auth_dep
from js.web.deps import get_agent

router = APIRouter(tags=["appshell"])


class WorkspaceSwitchRequest(BaseModel):
    to_product: str = Field(..., description="Target product id: js-agent or js-work")
    session_id: str | None = None


def _target_base_url(to_product: str) -> str:
    prefs = load_global_prefs()
    if to_product == WorkspaceProduct.WORK:
        return prefs.work_base_url
    return prefs.personal_base_url


@router.post("/api/workspace/switch")
async def workspace_switch(
    body: WorkspaceSwitchRequest,
    auth: dict[str, Any] = Depends(require_auth_dep),
) -> dict[str, Any]:
    """Run the Personal/Work switch protocol on the current process.

    v1 keeps separate backends/state dirs. This endpoint cancels local streams,
    revokes session-bound Echo tool leases, and returns UI cache-clear keys so
    the client can rebind to the target product endpoint.
    """
    agent = get_agent()
    from_product = str(getattr(agent.settings, "product_id", "js-agent") or "js-agent")
    to_product = body.to_product
    if to_product not in {WorkspaceProduct.PERSONAL, WorkspaceProduct.WORK}:
        raise HTTPException(400, f"unsupported to_product: {to_product}")

    cancelled: list[str] = []
    owner_key_hash = auth.get("owner_key_hash")
    if not isinstance(owner_key_hash, str):
        owner_key_hash = None

    async def _cancel() -> None:
        session_id = body.session_id
        request_cancel = getattr(agent, "request_cancel", None)
        if callable(request_cancel) and session_id:
            try:
                cancelled_ok = request_cancel(session_id, owner_key_hash)
                cancelled.append(session_id if cancelled_ok else f"{session_id}:idle")
            except PermissionError as exc:
                raise RuntimeError(f"cancel denied: {exc}") from exc
        # Also cancel any other active runs owned by this caller on this product.
        tokens = getattr(agent, "_cancel_tokens", {})
        if isinstance(tokens, dict):
            for partition_key, entry in list(tokens.items()):
                if not isinstance(entry, tuple) or len(entry) < 3:
                    continue
                _event, _run_id, session_owner = entry
                expected = owner_key_hash or "local-user"
                if (session_owner or "local-user") != expected:
                    continue
                # partition_key format embeds session; request_cancel is session-scoped.
                parts = str(partition_key).split(":")
                sid = parts[-1] if parts else ""
                if sid and sid != session_id and callable(request_cancel):
                    try:
                        if request_cancel(sid, owner_key_hash):
                            cancelled.append(sid)
                    except PermissionError:
                        continue

    async def _invalidate() -> dict[str, Any]:
        getter = getattr(agent, "_get_echo_tool_lease_authority", None)
        if not callable(getter):
            return {"revoked_lease_ids": []}
        authority = getter()
        revoke_fn = getattr(authority, "revoke_for_session", None)
        if not callable(revoke_fn) or not body.session_id:
            return {"revoked_lease_ids": []}
        revoked = revoke_fn(body.session_id)
        return {"revoked_lease_ids": list(revoked)}

    async def _rebind() -> dict[str, Any]:
        from js.web.capability_manifest import build_capability_manifest

        target_url = _target_base_url(to_product)
        # Manifest for *current* process is still from_product; client must
        # fetch capabilities from target_url after navigation.
        current_manifest = build_capability_manifest(agent.settings)
        return {
            "target_product": to_product,
            "target_base_url": target_url,
            "departing_product_id": current_manifest.get("product_id"),
            "must_reconnect": True,
        }

    result = await run_workspace_switch(
        from_product=from_product,
        to_product=to_product,
        cancel_streams=_cancel,
        invalidate_leases=_invalidate,
        rebind_context=_rebind,
    )
    payload = result.as_dict()
    payload["cancelled_sessions"] = cancelled
    payload["note"] = (
        "v1 keeps separate Personal/Work backends; client must reconnect to the "
        "target product host after clearing UI cache keys."
    )
    if not result.ok:
        raise HTTPException(409, payload)
    return payload
