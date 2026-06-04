"""Fleet API — collaboration, history, and model assignment."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from js.orchestration.fleet import AgentFleet
from js.utils.log import get_logger
from js.web.auth import require_admin, require_auth_dep
from js.web.deps import _agent_config, get_settings

logger = get_logger("js.web")

router = APIRouter(prefix="/api/fleet", tags=["fleet"])

_fleet: AgentFleet | None = None


def get_fleet() -> AgentFleet:
    global _fleet
    if _fleet is None:
        settings = get_settings()
        try:
            from js.web.deps import get_agent
            parent_agent = get_agent()
            _fleet = AgentFleet(
                settings,
                agent_config=_agent_config,
                skills=parent_agent.skills if parent_agent else None,
            )
        except Exception as e:
            raise HTTPException(500, f"Failed to initialize fleet: {e}") from e
    return _fleet


@router.post("/collaborate")
async def fleet_collaborate(
    payload: dict[str, Any],
    auth: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    """Execute a task with an auto-formed agent team.

    Example payload:
        {
            "task": "写一个完整的 Web 应用（前端 + 后端 + 测试）",
            "subtasks": ["写前端代码", "写后端 API", "写测试"]  // optional
        }
    """
    task = payload.get("task", "").strip()
    if not task:
        raise HTTPException(400, "task is required")

    try:
        fleet = get_fleet()
        result = await fleet.collaborate(
            main_task=task,
            subtasks=payload.get("subtasks"),
            role_mapping=payload.get("role_mapping"),
            mode=payload.get("mode", "auto"),
        )
        return {"success": True, **result}
    except Exception as e:
        logger.error(f"Fleet collaborate failed: {e}", exc_info=True)
        raise HTTPException(500, f"Collaboration failed: {e}") from e


@router.get("/status")
async def fleet_status(
    auth: dict[str, Any] = Depends(require_auth_dep),
) -> dict[str, Any]:
    """Show active agents and their current status."""
    try:
        fleet = get_fleet()
        return fleet.get_status()
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
        return {"success": True, "history": fleet.list_history(limit=limit)}
    except Exception as e:
        logger.error(f"Fleet history failed: {e}", exc_info=True)
        raise HTTPException(500, f"History failed: {e}") from e


@router.get("/sessions/{session_id}")
async def fleet_session_detail(
    session_id: str,
    auth: dict[str, Any] = Depends(require_auth_dep),
) -> dict[str, Any]:
    """Get full details of a collaboration session."""
    try:
        fleet = get_fleet()
        session = fleet.get_session(session_id)
        if session is None:
            raise HTTPException(404, "Session not found")
        return {"success": True, "session": session}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Fleet session detail failed: {e}", exc_info=True)
        raise HTTPException(500, f"Session detail failed: {e}") from e


@router.delete("/sessions/{session_id}")
async def fleet_session_delete(
    session_id: str,
    auth: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    """Delete a collaboration session."""
    try:
        fleet = get_fleet()
        ok = fleet.delete_session(session_id)
        if not ok:
            raise HTTPException(404, "Session not found")
        return {"success": True}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Fleet delete failed: {e}", exc_info=True)
        raise HTTPException(500, f"Delete failed: {e}") from e


@router.post("/sessions/{session_id}/continue")
async def fleet_session_continue(
    session_id: str,
    payload: dict[str, Any],
    auth: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    """Continue a previous collaboration session with a follow-up task."""
    follow_up = payload.get("follow_up", "").strip()
    if not follow_up:
        raise HTTPException(400, "follow_up is required")

    try:
        fleet = get_fleet()
        result = await fleet.continue_session(session_id, follow_up)
        return {"success": True, **result}
    except ValueError as e:
        raise HTTPException(404, str(e)) from e
    except Exception as e:
        logger.error(f"Fleet continue failed: {e}", exc_info=True)
        raise HTTPException(500, f"Continue failed: {e}") from e
