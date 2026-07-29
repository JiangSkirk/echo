"""Scenario template API router — list and launch pre-configured multi-agent setups."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from js.scenarios.loader import load_builtin_scenarios
from js.scenarios.registry import ScenarioRegistry
from js.utils.log import get_logger
from js.web.auth import require_auth_dep
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
async def get_scenario(scenario_id: str, auth: dict[str, Any] = Depends(require_auth_dep)) -> dict[str, Any]:
    """Get a specific scenario template."""
    scenario = _registry.get(scenario_id)
    if not scenario:
        raise HTTPException(404, f"Scenario '{scenario_id}' not found")
    return scenario.to_dict()


@router.post("/api/scenarios/{scenario_id}/start")
async def start_scenario(scenario_id: str, auth: dict[str, Any] = Depends(require_auth_dep)) -> dict[str, Any]:
    """Start a scenario: configure fleet roles and suggested skills."""
    scenario = _registry.get(scenario_id)
    if not scenario:
        raise HTTPException(404, f"Scenario '{scenario_id}' not found")

    agent = get_agent()

    # Build fleet config from scenario roles
    fleet_config: dict[str, str] = {}
    for role in scenario.roles:
        # Use default model if available, otherwise leave empty (user can set later)
        fleet_config[role.role] = ""

    # Check and suggest skills
    skills_manager = getattr(agent, "skills", None)
    skills_status: list[dict[str, Any]] = []
    for skill_id in scenario.suggested_skills:
        skill = skills_manager.get(skill_id) if skills_manager is not None else None
        skills_status.append({
            "id": skill_id,
            "available": skill is not None,
            "active": getattr(skill, "enabled", False) if skill else False,
        })

    return {
        "success": True,
        "scenario_id": scenario.id,
        "scenario_name": scenario.name,
        "fleet_config": fleet_config,
        "default_mode": scenario.default_mode,
        "skills_status": skills_status,
        "example_prompts": scenario.example_prompts,
    }
