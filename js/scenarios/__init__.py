"""Scenario templates for one-click multi-agent collaboration setups."""

from js.scenarios.loader import load_builtin_scenarios
from js.scenarios.registry import ScenarioRegistry
from js.scenarios.schemas import Scenario, ScenarioRole

__all__ = ["Scenario", "ScenarioRole", "load_builtin_scenarios", "ScenarioRegistry"]
