"""Load scenario definitions from YAML files."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from js.scenarios.schemas import Scenario, ScenarioRole
from js.utils.log import get_logger

logger = get_logger("js.scenarios")
BUILTIN_DIR = Path(__file__).parent / "builtin"


def _load_yaml(path: Path) -> dict[str, Any] | None:
    try:
        with open(path, encoding="utf-8") as f:
            return yaml.safe_load(f)  # type: ignore[no-any-return]
    except Exception as e:
        logger.warning(f"Failed to load scenario {path}: {e}")
        return None


def _dict_to_scenario(data: dict[str, Any]) -> Scenario:
    roles = [
        ScenarioRole(role=r["role"], name=r["name"], description=r["description"])
        for r in data.get("roles", [])
    ]
    return Scenario(
        id=data["id"],
        name=data["name"],
        description=data["description"],
        icon=data.get("icon", "fa-robot"),
        roles=roles,
        default_mode=data.get("default_mode", "auto"),
        suggested_skills=data.get("suggested_skills", []),
        system_prompt_addon=data.get("system_prompt_addon", ""),
        example_prompts=data.get("example_prompts", []),
    )


def load_builtin_scenarios() -> list[Scenario]:
    """Load all built-in scenario YAML files."""
    scenarios: list[Scenario] = []
    if not BUILTIN_DIR.exists():
        return scenarios
    for path in sorted(BUILTIN_DIR.glob("*.yaml")):
        data = _load_yaml(path)
        if data:
            try:
                scenarios.append(_dict_to_scenario(data))
            except Exception as e:
                logger.warning(f"Invalid scenario schema in {path}: {e}")
    return scenarios
