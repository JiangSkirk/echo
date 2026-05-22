"""Fleet API router."""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from js.orchestration.fleet import AgentFleet
from js.utils.log import get_logger
from js.web.auth import require_auth_dep
from js.web.deps import get_agent, get_settings

logger = get_logger("js.web")

router = APIRouter(prefix="/api/fleet", tags=["fleet"])

_fleet: AgentFleet | None = None


def get_fleet() -> AgentFleet:
    global _fleet
    if _fleet is None:
        settings = get_settings()
        try:
            _fleet = AgentFleet(settings, agent_config={})
        except Exception as e:
            raise HTTPException(500, f"Failed to initialize fleet: {e}") from e
    return _fleet


@router.get("/status")
async def fleet_status(auth: dict[str, Any] = Depends(require_auth_dep)) -> dict[str, Any]:
    try:
        fleet = get_fleet()
        return fleet.get_status()
    except Exception:
        raise


@router.get("/models")
async def fleet_models(auth: dict[str, Any] = Depends(require_auth_dep)) -> dict[str, Any]:
    """List all models available for fleet agents."""
    agent = get_agent()
    models: list[dict[str, Any]] = []
    for p in agent.settings.providers:
        for m in p.models:
            models.append({
                "id": f"{p.name}/{m.id}",
                "provider": p.name,
                "model_id": m.id,
                "name": m.name or m.id,
                "context_window": m.context_window,
                "supports_vision": m.supports_vision,
            })
    return {"models": models}


@router.post("/spawn")
async def fleet_spawn(
    payload: dict[str, Any],
    auth: dict[str, Any] = Depends(require_auth_dep),
) -> dict[str, Any]:
    from js.orchestration.fleet import AgentRole

    try:
        fleet = get_fleet()
        role = AgentRole(payload.get("role", "generalist"))
        model = payload.get("model")

        # Validate model against available providers
        if model:
            agent = get_agent()
            valid_models = {
                f"{p.name}/{m.id}"
                for p in agent.settings.providers
                for m in p.models
            }
            if model not in valid_models:
                raise HTTPException(
                    400,
                    f"Invalid model '{model}'. Use /api/fleet/models to see available models."
                )

        instance = fleet.spawn(
            name=payload.get("name", f"agent-{role.value}"),
            role=role,
            model=model,
        )
        return {
            "success": True,
            "agent_id": instance.id,
            "role": role.value,
            "model": model,
        }
    except ValueError as e:
        raise HTTPException(400, str(e)) from e
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Fleet spawn failed: {e}", exc_info=True)
        raise HTTPException(500, f"Fleet spawn failed: {e}") from e


@router.post("/dispatch")
async def fleet_dispatch(
    payload: dict[str, Any],
    auth: dict[str, Any] = Depends(require_auth_dep),
) -> dict[str, Any]:
    from js.orchestration.fleet import AgentRole, Task

    try:
        fleet = get_fleet()
        task = Task(
            id=str(uuid.uuid4()),
            description=payload.get("description", ""),
            role_hint=AgentRole(payload.get("role", "generalist")),
            priority=payload.get("priority", 5),
        )
        task_id = await fleet.dispatch(task)
        return {"success": True, "task_id": task_id}
    except ValueError as e:
        raise HTTPException(400, str(e)) from e
    except Exception as e:
        logger.error(f"Fleet dispatch failed: {e}", exc_info=True)
        raise HTTPException(500, f"Fleet dispatch failed: {e}") from e


@router.post("/collaborate")
async def fleet_collaborate(
    payload: dict[str, Any],
    auth: dict[str, Any] = Depends(require_auth_dep),
) -> dict[str, Any]:
    from js.orchestration.fleet import AgentRole

    try:
        fleet = get_fleet()
        subtasks_raw = payload.get("subtasks", [])
        subtasks: list[tuple[str, AgentRole]] = []
        for st in subtasks_raw:
            subtasks.append((st.get("description", ""), AgentRole(st.get("role", "generalist"))))
        result = await fleet.collaborate(
            main_task=payload.get("task", ""),
            subtasks=subtasks,
        )
        return {"success": True, "result": result}
    except ValueError as e:
        raise HTTPException(400, str(e)) from e
    except Exception as e:
        logger.error(f"Fleet collaborate failed: {e}", exc_info=True)
        raise HTTPException(500, f"Fleet collaborate failed: {e}") from e


@router.post("/broadcast")
async def fleet_broadcast(
    payload: dict[str, Any],
    auth: dict[str, Any] = Depends(require_auth_dep),
) -> dict[str, Any]:
    try:
        fleet = get_fleet()
        await fleet.broadcast(payload.get("message", ""))
        return {"success": True}
    except Exception as e:
        logger.error(f"Fleet broadcast failed: {e}", exc_info=True)
        raise HTTPException(500, f"Fleet broadcast failed: {e}") from e
