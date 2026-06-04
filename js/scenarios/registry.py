"""Scenario registry — holds loaded scenarios in memory."""

from __future__ import annotations

from typing import Any

from js.scenarios.schemas import Scenario


class ScenarioRegistry:
    """In-memory registry of available scenarios."""

    def __init__(self, scenarios: list[Scenario] | None = None) -> None:
        self._scenarios: dict[str, Scenario] = {}
        if scenarios:
            for s in scenarios:
                self._scenarios[s.id] = s

    def register(self, scenario: Scenario) -> None:
        self._scenarios[scenario.id] = scenario

    def get(self, scenario_id: str) -> Scenario | None:
        return self._scenarios.get(scenario_id)

    def list_all(self) -> list[Scenario]:
        return list(self._scenarios.values())

    def to_dict_list(self) -> list[dict[str, Any]]:
        return [s.to_dict() for s in self._scenarios.values()]
