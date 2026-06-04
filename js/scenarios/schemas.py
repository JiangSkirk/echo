"""Scenario template dataclasses."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ScenarioRole:
    role: str
    name: str
    description: str


@dataclass
class Scenario:
    id: str
    name: str
    description: str
    icon: str
    roles: list[ScenarioRole]
    default_mode: str
    suggested_skills: list[str]
    system_prompt_addon: str = ""
    example_prompts: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "icon": self.icon,
            "roles": [{"role": r.role, "name": r.name, "description": r.description} for r in self.roles],
            "default_mode": self.default_mode,
            "suggested_skills": self.suggested_skills,
            "system_prompt_addon": self.system_prompt_addon,
            "example_prompts": self.example_prompts,
        }
