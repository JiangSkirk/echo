"""FastAPI routes for JS Agent Work routines."""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from js.echo.effect_interpreter import ToolEffect
from js.security.approvals import ApprovalDecision, ApprovalDecisionType
from js.web.auth import memory_owner, require_admin, require_auth_dep, require_user_write
from js.web.deps import get_agent, get_settings
from js_work.routines.store import DEFAULT_WORK_OWNER_KEY_HASH, WorkRoutineStore

router = APIRouter(prefix="/api/work/routines", tags=["work-routines"])

_WEB_ROUTINE_CHANNEL = "js_work_routine_web"


def _owner_from_auth(auth: dict[str, Any] | None) -> str:
    return memory_owner(auth) or DEFAULT_WORK_OWNER_KEY_HASH


def _store(auth: dict[str, Any] | None, session_id: str | None = None) -> WorkRoutineStore:
    return WorkRoutineStore(
        get_settings().state_dir,
        owner_key_hash=_owner_from_auth(auth),
        session_id=session_id or "web",
    )


def _map_tool_error(error: str) -> HTTPException:
    message = error or "routine execution failed"
    lowered = message.lower()
    if "not found" in lowered:
        return HTTPException(404, "routine not found")
    if "must be approved" in lowered or "permission" in lowered:
        return HTTPException(403, "routine is not approved for execution")
    if "path escapes workspace" in lowered or "outside work workspace" in lowered:
        return HTTPException(403, "path outside work workspace is not allowed")
    if "invalid routine_id" in lowered or "path traversal" in lowered:
        return HTTPException(400, "invalid routine_id")
    return HTTPException(400, "routine request is invalid")


async def _execute_routine_control_effect(
    *,
    tool_name: str,
    arguments: dict[str, Any],
    auth: dict[str, Any],
) -> Any:
    agent = get_agent()
    context = agent.echo_runtime.build_context(
        channel=f"{_WEB_ROUTINE_CHANNEL}_control",
        owner_key_hash=_owner_from_auth(auth),
        session_id="web",
        role=str(auth.get("role") or "user"),
        capabilities=(tool_name,),
    )
    _message, result = await agent.echo_runtime.execute_tool_effect(
        ToolEffect.from_arguments(
            tool_name,
            arguments,
            allowed_tools=(tool_name,),
            user_input=f"administrator-approved Work routine control: {tool_name}",
        ),
        context,
    )
    return result


def _routine_control_payload(result: Any) -> dict[str, Any]:
    if not result.success:
        status_code = result.metadata.get("status_code", 500)
        if not isinstance(status_code, int) or status_code not in {400, 403, 404, 500, 503}:
            status_code = 500
        raise HTTPException(status_code, result.error or "Work routine control failed")
    routine = result.metadata.get("routine")
    if not isinstance(routine, dict):
        raise HTTPException(500, "Work routine control returned invalid data")
    return routine


@router.get("")
async def list_routines(auth: dict[str, Any] = Depends(require_auth_dep)) -> dict[str, Any]:
    return {"routines": [routine.to_dict() for routine in _store(auth).list_routines()]}


@router.post("/draft")
async def create_draft(
    payload: dict[str, Any],
    auth: dict[str, Any] = Depends(require_auth_dep),
) -> dict[str, Any]:
    result = await _execute_routine_control_effect(
        tool_name="control_work_routine_draft",
        arguments={
            "name": payload.get("name"),
            "trigger_phrases": payload.get("trigger_phrases"),
            "routine_type": payload.get("routine_type", "spreadsheet_template"),
            "field_mapping": payload.get("field_mapping", {}),
            "row_filters": payload.get("row_filters", []),
            "header_aliases": payload.get("header_aliases", {}),
            "aggregation_rules": payload.get("aggregation_rules", {}),
            "validation_rules": payload.get("validation_rules", {}),
            "source_sheet": payload.get("source_sheet", ""),
            "review_policy": payload.get("review_policy", {}),
            "template_path": payload.get("template_path", ""),
        },
        auth=auth,
    )
    return _routine_control_payload(result)


@router.get("/{routine_id}")
async def inspect_routine(
    routine_id: str,
    auth: dict[str, Any] = Depends(require_auth_dep),
) -> dict[str, Any]:
    try:
        return _store(auth).get(routine_id).to_dict()
    except KeyError as e:
        raise HTTPException(404, "routine not found") from e
    except ValueError as e:
        raise HTTPException(400, "invalid routine_id") from e


@router.post("/{routine_id}/approve")
async def approve_routine(
    routine_id: str,
    auth: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    result = await _execute_routine_control_effect(
        tool_name="control_work_routine_approve",
        arguments={"routine_id": routine_id},
        auth=auth,
    )
    return _routine_control_payload(result)


@router.post("/run")
async def run_routine(
    payload: dict[str, Any],
    auth: dict[str, Any] = Depends(require_user_write),
) -> dict[str, Any]:
    routine_id = str(payload.get("routine_id") or "")
    if not routine_id:
        raise HTTPException(400, "routine_id is required")
    session_id = str(payload.get("session_id") or "").strip()
    if not session_id or len(session_id) > 256:
        raise HTTPException(400, "session_id is required")
    output_path = str(payload.get("output_path") or "")
    dry_run = bool(payload.get("dry_run") or False)
    if not dry_run and not output_path:
        raise HTTPException(400, "output_path is required")

    tool_name = "work_routine_preview" if dry_run else "work_routine_run"
    arguments: dict[str, Any] = {
        "routine_id": routine_id,
        "source_path": str(payload.get("source_path") or ""),
        "template_path": str(payload.get("template_path") or ""),
    }
    if not dry_run:
        arguments["output_path"] = output_path

    owner = _owner_from_auth(auth)
    agent = get_agent()
    runtime = agent.echo_runtime
    context = runtime.build_context(
        channel=_WEB_ROUTINE_CHANNEL,
        owner_key_hash=owner,
        session_id=session_id,
        role=str(auth.get("role") or "user"),
        capabilities=(tool_name,),
    )
    if not dry_run:
        agent.approvals.set_callback(
            session_id,
            lambda _request: ApprovalDecision(
                ApprovalDecisionType.APPROVE,
                reason="explicit_authenticated_work_routine_request",
            ),
            owner_key_hash=owner,
            run_id=context.run_id,
            tool_name=tool_name,
            arguments=arguments,
        )
    try:
        try:
            _message, result = await runtime.execute_tool_effect(
                ToolEffect.from_arguments(
                    tool_name,
                    arguments,
                    allowed_tools=(tool_name,),
                    user_input=f"work routine {tool_name}",
                ),
                context,
            )
        except PermissionError as e:
            raise HTTPException(403, "routine execution is not permitted") from e
        except ValueError as e:
            raise HTTPException(400, "routine request is invalid") from e
        except Exception as e:
            raise HTTPException(400, "routine execution failed") from e

        if not result.success:
            raise _map_tool_error(result.error)

        try:
            payload_out = json.loads(result.output or "{}")
        except json.JSONDecodeError as e:
            raise HTTPException(500, "routine tool returned invalid payload") from e
        if not isinstance(payload_out, dict):
            raise HTTPException(500, "routine tool returned invalid payload")
        return payload_out
    finally:
        if not dry_run:
            agent.approvals.remove_callback(session_id)
