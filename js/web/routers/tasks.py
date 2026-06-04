"""Task management API router — list, control, and monitor long-running tasks."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from js.utils.log import get_logger
from js.web.auth import require_admin, require_auth_dep
from js.web.deps import get_agent

logger = get_logger("js.web.tasks")
router = APIRouter(tags=["tasks"])


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
    tasks = tm.list(status=status, type=type, limit=limit, owner_key_hash=auth.get("key_hash"))
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
    task = tm.get(task_id, owner_key_hash=auth.get("key_hash"))
    if not task:
        raise HTTPException(404, "Task not found")
    return task  # type: ignore[no-any-return]


@router.post("/api/tasks/{task_id}/pause")
async def pause_task(
    task_id: str,
    auth: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    """Pause a running task. Requires admin role."""
    agent = get_agent()
    tm = getattr(agent, "task_manager", None)
    if not tm:
        raise HTTPException(503, "Task manager not initialized")
    ok = tm.pause(task_id)
    if not ok:
        raise HTTPException(404, "Task not found")
    return {"success": True, "status": "paused"}


@router.post("/api/tasks/{task_id}/resume")
async def resume_task(
    task_id: str,
    auth: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    """Resume a paused task. Requires admin role."""
    agent = get_agent()
    tm = getattr(agent, "task_manager", None)
    if not tm:
        raise HTTPException(503, "Task manager not initialized")
    ok = tm.resume(task_id)
    if not ok:
        raise HTTPException(404, "Task not found")
    return {"success": True, "status": "running"}


@router.delete("/api/tasks/{task_id}")
async def delete_task(
    task_id: str,
    auth: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    """Delete a task. Requires admin role."""
    agent = get_agent()
    tm = getattr(agent, "task_manager", None)
    if not tm:
        raise HTTPException(503, "Task manager not initialized")
    ok = tm.delete(task_id)
    if not ok:
        raise HTTPException(404, "Task not found")
    return {"success": True}
