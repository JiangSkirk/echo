"""Owner-scoped Echo tool approval endpoints."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException

from js.security.approvals import ApprovalDecisionType
from js.web.auth import memory_owner, require_auth_dep, require_user_write
from js.web.deps import get_agent

router = APIRouter(prefix="/api/echo/approvals", tags=["echo-approvals"])

_LOCAL_OWNER = "local-user"
_ALLOWED_ACTIONS = frozenset({"approve", "edit", "reject", "respond"})


def _owner(auth: dict[str, Any]) -> str:
    return memory_owner(auth) or _LOCAL_OWNER


def _redact_arguments(value: Any, secrets: Any) -> Any:
    """Recursively redact string leaves before approval arguments leave the server."""
    if isinstance(value, str):
        return secrets.detect_and_redact(value, "approval_arguments")
    if isinstance(value, Mapping):
        return {key: _redact_arguments(item, secrets) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [_redact_arguments(item, secrets) for item in value]
    return value


def _request_payload(request: Any, secrets: Any) -> dict[str, Any]:
    return {
        "id": request.id,
        "tool_name": request.tool_name,
        "arguments": _redact_arguments(request.arguments, secrets),
        "timestamp": request.timestamp,
        "context": request.context,
        "session_id": request.session_id,
        "run_id": request.run_id,
    }


def _parse_decision_payload(payload: Any) -> tuple[ApprovalDecisionType, dict[str, Any]]:
    if not isinstance(payload, dict):
        raise HTTPException(400, "approval decision payload must be an object")

    action_value = payload.get("action")
    if not isinstance(action_value, str) or action_value not in _ALLOWED_ACTIONS:
        raise HTTPException(400, "action must be approve, edit, reject, or respond")

    action = ApprovalDecisionType(action_value)
    allowed_fields = {"action", "reason"}
    kwargs: dict[str, Any] = {"reason": ""}
    if "reason" in payload:
        reason = payload["reason"]
        if not isinstance(reason, str):
            raise HTTPException(400, "reason must be a string")
        kwargs["reason"] = reason

    if action is ApprovalDecisionType.EDIT:
        allowed_fields.add("edited_arguments")
        edited_arguments = payload.get("edited_arguments")
        if not isinstance(edited_arguments, dict):
            raise HTTPException(400, "edited_arguments must be an object for edit")
        kwargs["edited_arguments"] = edited_arguments
    elif action is ApprovalDecisionType.RESPOND:
        allowed_fields.add("response")
        response = payload.get("response")
        if not isinstance(response, str) or not response.strip():
            raise HTTPException(400, "response must be a non-empty string for respond")
        kwargs["response"] = response

    if set(payload) - allowed_fields:
        raise HTTPException(400, "payload contains fields not valid for this action")
    return action, kwargs


@router.get("")
async def list_approvals(
    auth: dict[str, Any] = Depends(require_auth_dep),
) -> dict[str, Any]:
    """List unresolved tool approvals belonging to the authenticated owner."""
    agent = get_agent()
    owner_key_hash = _owner(auth)
    requests = await asyncio.to_thread(
        agent.approvals.get_pending,
        owner_key_hash=owner_key_hash,
    )
    return {
        "approvals": [
            _request_payload(request, agent.secrets)
            for request in requests
            if not request.resolved and request.owner_key_hash == owner_key_hash
        ]
    }


@router.post("/{request_id}/decision")
async def decide_approval(
    request_id: str,
    payload: Any = Body(default=None),
    auth: dict[str, Any] = Depends(require_user_write),
) -> dict[str, Any]:
    """Resolve one owner-scoped tool approval without exposing foreign requests."""
    action, kwargs = _parse_decision_payload(payload)
    agent = get_agent()
    owner_key_hash = _owner(auth)
    request = await asyncio.to_thread(
        agent.approvals.get_pending_request,
        request_id,
        owner_key_hash=owner_key_hash,
    )
    if request is None:
        raise HTTPException(404, "approval request not found")

    decision = await asyncio.to_thread(
        agent.approvals.decide,
        request_id,
        action,
        owner_key_hash=owner_key_hash,
        **kwargs,
    )
    if decision.action is ApprovalDecisionType.PENDING:
        raise HTTPException(404, "approval request not found")
    return {
        "ok": True,
        "action": decision.action.value,
        "request_id": decision.request_id,
    }
