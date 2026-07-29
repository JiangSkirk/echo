"""Task management API router — list, control, and monitor long-running tasks."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from js.agent.tool_executor import CONTROL_TASK_MUTATE_TOOL
from js.echo.effect_interpreter import ToolEffect
from js.tools.registry import ToolResult
from js.utils.log import get_logger
from js.web.auth import require_admin, require_auth_dep, runtime_owner
from js.web.deps import get_agent
from js.web.runtime_context import web_channel

logger = get_logger("js.web.tasks")
router = APIRouter(tags=["tasks"])


async def _mutate_task(
    action: str,
    task_id: str,
    auth: dict[str, Any],
) -> ToolResult:
    agent = get_agent()
    runtime = agent.echo_runtime
    context = runtime.build_context(
        channel=web_channel(agent.settings, f"task_{action}"),
        owner_key_hash=runtime_owner(auth),
        role=str(auth.get("role") or "admin"),
        capabilities=(CONTROL_TASK_MUTATE_TOOL,),
    )
    _message, result = await runtime.execute_tool_effect(
        ToolEffect.from_arguments(
            CONTROL_TASK_MUTATE_TOOL,
            {"action": action, "task_id": task_id},
            user_input=f"Apply owner-bound task action: {action}",
            allowed_tools=(CONTROL_TASK_MUTATE_TOOL,),
        ),
        context,
    )
    if not result.success:
        status_code = result.metadata.get("status_code", 500)
        if not isinstance(status_code, int) or not 400 <= status_code <= 599:
            status_code = 500
        raise HTTPException(status_code, result.error or "Task update failed")
    return result


@router.get("/api/tasks")
async def list_tasks(
    status: str | None = None,
    type: str | None = None,
    limit: int = 100,
    auth: dict[str, Any] = Depends(require_auth_dep),
) -> dict[str, Any]:
    """List all tracked tasks."""
    agent = get_agent()
    tm = getattr(agent, "task_manager", None)
    if not tm:
        return {"tasks": []}
    tasks = tm.list(
        status=status,
        type=type,
        limit=limit,
        owner_key_hash=runtime_owner(auth),
    )
    return {"tasks": tasks}


@router.get("/api/tasks/{task_id}")
async def get_task(
    task_id: str,
    auth: dict[str, Any] = Depends(require_auth_dep),
) -> dict[str, Any]:
    """Get a single task by ID."""
    agent = get_agent()
    tm = getattr(agent, "task_manager", None)
    if not tm:
        raise HTTPException(503, "Task manager not initialized")
    task = tm.get(task_id, owner_key_hash=runtime_owner(auth))
    if not task:
        raise HTTPException(404, "Task not found")
    return task  # type: ignore[no-any-return]


@router.post("/api/tasks/{task_id}/pause")
async def pause_task(
    task_id: str,
    auth: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    """Pause a running task. Requires admin role."""
    await _mutate_task("pause", task_id, auth)
    return {"success": True, "status": "paused"}


@router.post("/api/tasks/{task_id}/resume")
async def resume_task(
    task_id: str,
    auth: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    """Resume a paused task. Requires admin role."""
    await _mutate_task("resume", task_id, auth)
    return {"success": True, "status": "running"}


@router.delete("/api/tasks/{task_id}")
async def delete_task(
    task_id: str,
    auth: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    """Delete a task. Requires admin role."""
    await _mutate_task("delete", task_id, auth)
    return {"success": True}
