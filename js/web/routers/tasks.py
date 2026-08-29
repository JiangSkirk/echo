"""Tasks page is a read-only projection of owner-scoped bots goal runs."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from js.bots.models import GoalRun
from js.bots.service import bot_store_for
from js.web.auth import require_admin, require_auth_dep, runtime_owner
from js.web.deps import get_agent

router = APIRouter(tags=["tasks"])

_PHASE_STATUS = {
    "clarify": "pending",
    "confirmed": "pending",
    "executing": "running",
    "verifying": "running",
    "done": "completed",
    "blocked": "paused",
}


def goal_to_task_view(goal: GoalRun) -> dict[str, Any]:
    used = goal.budget.echo_turns_used
    cap = max(goal.budget.max_echo_turns, 1)
    return {
        "id": goal.id,
        "name": goal.contract.objective or goal.id,
        "type": "bots_goal",
        "status": _PHASE_STATUS.get(goal.phase, "pending"),
        "phase": goal.phase,
        "progress": min(1.0, used / cap),
        "room_id": goal.room_id,
        "updated_at": goal.updated_at,
        "result_preview": goal.pause_reason or goal.contract.objective,
        "error": goal.pause_reason if goal.phase == "blocked" else "",
    }


def _store(agent: Any) -> Any:
    store = getattr(agent, "_bot_store", None)
    if store is None:
        store = bot_store_for(agent.settings.state_dir)
        agent._bot_store = store
    return store


@router.get("/api/tasks")
async def list_tasks(
    status: str | None = None,
    type: str | None = None,
    limit: int = 100,
    auth: dict[str, Any] = Depends(require_auth_dep),
) -> dict[str, Any]:
    """List the caller's bots goals as a task-shaped read model."""
    agent = get_agent()
    goals = _store(agent).list_goal_runs(
        owner_key_hash=runtime_owner(auth),
        limit=limit,
    )
    tasks = [goal_to_task_view(goal) for goal in goals]
    if type:
        tasks = [item for item in tasks if item["type"] == type]
    if status:
        tasks = [item for item in tasks if item["status"] == status]
    return {"tasks": tasks}


@router.get("/api/tasks/{task_id}")
async def get_task(
    task_id: str,
    auth: dict[str, Any] = Depends(require_auth_dep),
) -> dict[str, Any]:
    agent = get_agent()
    goal = _store(agent).get_goal_run(task_id, owner_key_hash=runtime_owner(auth))
    if goal is None:
        raise HTTPException(404, "Goal not found")
    return goal_to_task_view(goal)


@router.post("/api/tasks/{task_id}/pause")
async def pause_task(
    task_id: str,
    auth: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    raise HTTPException(503, "Tasks page is a read-only bots goals view")


@router.post("/api/tasks/{task_id}/resume")
async def resume_task(
    task_id: str,
    auth: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    raise HTTPException(503, "Tasks page is a read-only bots goals view")


@router.delete("/api/tasks/{task_id}")
async def delete_task(
    task_id: str,
    auth: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    raise HTTPException(503, "Tasks page is a read-only bots goals view")
