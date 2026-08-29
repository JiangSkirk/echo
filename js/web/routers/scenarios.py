"""Scenario template API router — list and launch pre-configured multi-agent setups."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from js.scenarios.instantiate import instantiate_scenario
from js.scenarios.loader import load_builtin_scenarios
from js.scenarios.registry import ScenarioRegistry
from js.utils.log import get_logger
from js.web.auth import require_auth_dep, require_user_write, runtime_owner
from js.web.deps import get_agent

logger = get_logger("js.web.scenarios")
router = APIRouter(tags=["scenarios"])

# Initialize registry once at module load
_registry = ScenarioRegistry(load_builtin_scenarios())


@router.get("/api/scenarios")
async def list_scenarios(auth: dict[str, Any] = Depends(require_auth_dep)) -> dict[str, Any]:
    """List all available scenario templates."""
    return {"scenarios": _registry.to_dict_list()}


@router.get("/api/scenarios/{scenario_id}")
async def get_scenario(
    scenario_id: str, auth: dict[str, Any] = Depends(require_auth_dep)
) -> dict[str, Any]:
    """Get a specific scenario template."""
    scenario = _registry.get(scenario_id)
    if not scenario:
        raise HTTPException(404, f"Scenario '{scenario_id}' not found")
    return scenario.to_dict()


@router.post("/api/scenarios/{scenario_id}/start")
async def start_scenario(
    scenario_id: str, auth: dict[str, Any] = Depends(require_user_write)
) -> dict[str, Any]:
    """Start a scenario as a prefabricated bots goal + personas."""
    scenario = _registry.get(scenario_id)
    if not scenario:
        raise HTTPException(404, f"Scenario '{scenario_id}' not found")

    agent = get_agent()
    created = instantiate_scenario(
        scenario,
        owner_key_hash=runtime_owner(auth),
        state_dir=agent.settings.state_dir,
    )

    fleet_config: dict[str, str] = {role.role: "" for role in scenario.roles}
    skills_manager = getattr(agent, "skills", None)
    skills_status: list[dict[str, Any]] = []
    for skill_id in scenario.suggested_skills:
        lookup = None
        if skills_manager is not None:
            lookup = getattr(skills_manager, "get_skill", None) or getattr(
                skills_manager, "get", None
            )
        skill = lookup(skill_id) if callable(lookup) else None
        skills_status.append(
            {
                "id": skill_id,
                "available": skill is not None,
                "active": getattr(skill, "enabled", False) if skill else False,
            }
        )

    return {
        "success": True,
        "scenario_id": scenario.id,
        "scenario_name": scenario.name,
        "fleet_config": fleet_config,
        "default_mode": scenario.default_mode,
        "skills_status": skills_status,
        "example_prompts": scenario.example_prompts,
        "bot_ids": created["bot_ids"],
        "room_id": created["room_id"],
        "goal_id": created["goal_id"],
        "goal": created["goal"],
    }
