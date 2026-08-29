"""Fleet API — collaboration, history, and model assignment."""

from __future__ import annotations

import inspect
from typing import Any, cast

from fastapi import APIRouter, Depends, HTTPException

from js.echo.effect_interpreter import ToolEffect
from js.orchestration.fleet import AgentFleet
from js.utils.log import get_logger
from js.web.auth import memory_owner, require_admin, require_auth_dep
from js.web.deps import (
    get_agent,
    get_runtime_agent_config,
    get_settings,
    require_path_session_id,
)
from js.web.runtime_context import current_web_runtime, web_channel
from js.web.schemas import FleetCollaborateRequest, FleetContinueRequest

logger = get_logger("js.web")

router = APIRouter(prefix="/api/fleet", tags=["fleet"])

# Compatibility hook for callers that reset the former singleton. The router
# no longer reads or populates this module-level value.
_fleet: AgentFleet | None = None


def _owner(auth: dict[str, Any]) -> str:
    owner = memory_owner(auth)
    if owner:
        return owner
    if auth.get("name") in {"anonymous", "bootstrap"}:
        return "local-user"
    raise HTTPException(403, "Fleet owner identity is required")


def _owner_status(fleet: Any, owner_key_hash: str) -> dict[str, Any]:
    get_status = fleet.get_status
    parameters = inspect.signature(get_status).parameters
    if "owner_key_hash" in parameters or any(
        parameter.kind is inspect.Parameter.VAR_KEYWORD for parameter in parameters.values()
    ):
        return cast("dict[str, Any]", get_status(owner_key_hash=owner_key_hash))
    # Embedded product test doubles predating owner-scoped status.
    return cast("dict[str, Any]", get_status())


def _create_fleet(settings: Any, parent_agent: Any) -> AgentFleet:
    parent_skills = getattr(parent_agent, "skills", None) if parent_agent else None
    features = getattr(settings, "features", None)
    inherit_skills = bool(
        parent_skills is not None
        and getattr(features, "skills_enabled", True)
        and getattr(features, "skill_tools_enabled", True)
    )
    return AgentFleet(
        settings,
        agent_config=dict(get_runtime_agent_config()),
        skills=parent_skills if inherit_skills else None,
        inherit_skills=inherit_skills,
    )


def get_fleet() -> AgentFleet:
    """Return the Fleet owned by the active web runtime, if there is one."""
    try:
        runtime = current_web_runtime()
        if runtime is not None:
            runtime_fleet = runtime.get_or_create_fleet()
            if runtime_fleet is None:
                runtime_fleet = _create_fleet(runtime.settings, runtime.agent)
                runtime.fleet = runtime_fleet
            return runtime_fleet
        return _create_fleet(get_settings(), get_agent())
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Fleet initialization failed", exc_info=True)
        raise HTTPException(500, "Failed to initialize Fleet") from exc


async def _execute_fleet_effect(
    *,
    tool_name: str,
    arguments: dict[str, Any],
    auth: dict[str, Any],
    channel: str,
    user_input: str,
) -> Any:
    agent = get_agent()
    context = agent.echo_runtime.build_context(
        channel=web_channel(agent.settings, channel),
        owner_key_hash=_owner(auth),
        role=str(auth.get("role") or "admin"),
        capabilities=(tool_name,),
    )
    _message, result = await agent.echo_runtime.execute_tool_effect(
        ToolEffect.from_arguments(
            tool_name,
            arguments,
            user_input=user_input,
            allowed_tools=(tool_name,),
        ),
        context,
    )
    return result


def _raise_fleet_effect_error(result: Any, *, default: str) -> None:
    if result.success:
        return
    status_code = result.metadata.get("status_code", 500)
    if not isinstance(status_code, int) or status_code not in {
        400,
        403,
        404,
        429,
        500,
        503,
    }:
        status_code = 500
    raise HTTPException(status_code, result.error or default)


@router.post("/collaborate")
async def fleet_collaborate(
    payload: FleetCollaborateRequest,
    auth: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    """Execute a task with an auto-formed agent team.

    Example payload:
        {
            "task": "写一个完整的 Web 应用（前端 + 后端 + 测试）",
            "subtasks": ["写前端代码", "写后端 API", "写测试"]  // optional
        }
    """
    try:
        (
            task,
            subtasks,
            session_id,
            role_mapping,
            mode,
        ) = AgentFleet._validate_collaboration_request(
            payload.task,
            payload.subtasks,
            payload.session_id,
            cast("dict[int | str, str] | None", payload.role_mapping),
            payload.mode,
        )
    except (TypeError, ValueError) as exc:
        raise HTTPException(400, "Invalid Fleet collaboration request") from exc

    try:
        arguments = {
            "task": task,
            "subtasks": subtasks,
            "session_id": session_id,
            "role_mapping": role_mapping,
            "mode": mode,
        }
        tool_result = await _execute_fleet_effect(
            tool_name="fleet_collaborate",
            arguments=arguments,
            auth=auth,
            channel="fleet_collaborate",
            user_input="Run an administrator-approved Fleet collaboration",
        )
        _raise_fleet_effect_error(tool_result, default="Fleet collaboration failed")
        return {
            "success": True,
            "final": tool_result.output,
            **tool_result.metadata,
        }
    except PermissionError as exc:
        raise HTTPException(403, "Fleet collaboration is unavailable in this profile") from exc
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Fleet collaborate failed", exc_info=True)
        raise HTTPException(500, "Fleet collaboration failed") from exc


@router.get("/status")
async def fleet_status(
    auth: dict[str, Any] = Depends(require_auth_dep),
) -> dict[str, Any]:
    """Show active agents and their current status."""
    try:
        fleet = get_fleet()
        return _owner_status(fleet, _owner(auth))
    except Exception:
        raise


@router.get("/history")
async def fleet_history(
    limit: int = 50,
    auth: dict[str, Any] = Depends(require_auth_dep),
) -> dict[str, Any]:
    """List recent collaboration sessions."""
    try:
        fleet = get_fleet()
        return {
            "success": True,
            "history": fleet.list_history(limit=limit, owner_key_hash=_owner(auth)),
        }
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Fleet history failed", exc_info=True)
        raise HTTPException(500, "Fleet history failed") from exc


@router.get("/sessions/{session_id}")
async def fleet_session_detail(
    session_id: str = Depends(require_path_session_id),
    auth: dict[str, Any] = Depends(require_auth_dep),
) -> dict[str, Any]:
    """Get full details of a collaboration session."""
    try:
        fleet = get_fleet()
        session = fleet.get_session(session_id, owner_key_hash=_owner(auth))
        if session is None:
            raise HTTPException(404, "Session not found")
        return {"success": True, "session": session}
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Fleet session detail failed", exc_info=True)
        raise HTTPException(500, "Fleet session detail failed") from exc


@router.delete("/sessions/{session_id}")
async def fleet_session_delete(
    session_id: str = Depends(require_path_session_id),
    auth: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    """Delete a collaboration session."""
    try:
        result = await _execute_fleet_effect(
            tool_name="control_fleet_session_delete",
            arguments={"session_id": session_id},
            auth=auth,
            channel="fleet_session_delete",
            user_input="Delete an administrator-approved Fleet session",
        )
        _raise_fleet_effect_error(result, default="Fleet session deletion failed")
        return {"success": True}
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Fleet delete failed", exc_info=True)
        raise HTTPException(500, "Fleet session deletion failed") from exc


@router.post("/sessions/{session_id}/continue")
async def fleet_session_continue(
    payload: FleetContinueRequest,
    session_id: str = Depends(require_path_session_id),
    auth: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    """Continue a previous collaboration session with a follow-up task."""
    follow_up = payload.follow_up.strip()
    if not follow_up:
        raise HTTPException(400, "follow_up is required")

    try:
        result = await _execute_fleet_effect(
            tool_name="control_fleet_continue",
            arguments={"session_id": session_id, "follow_up": follow_up},
            auth=auth,
            channel="fleet_session_continue",
            user_input="Continue an administrator-approved Fleet session",
        )
        _raise_fleet_effect_error(result, default="Fleet continuation failed")
        return {
            "success": True,
            "final": result.output,
            **result.metadata,
        }
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Fleet continue failed", exc_info=True)
        raise HTTPException(500, "Fleet continuation failed") from exc
