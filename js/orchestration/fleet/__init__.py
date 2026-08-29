"""Simplified multi-agent fleet — one call, auto-team, no manual management."""

from __future__ import annotations

from js.orchestration.fleet.agent_fleet import AgentFleet
from js.orchestration.fleet.identity import (
    bind_fleet_event_identity,
    validate_fleet_event_identity,
)
from js.orchestration.fleet.models import (
    AgentInstance,
    AgentRole,
    FleetCapacityError,
    FleetEventSubscription,
    Task,
)

__all__ = [
    "AgentFleet",
    "AgentInstance",
    "AgentRole",
    "FleetCapacityError",
    "FleetEventSubscription",
    "Task",
    "bind_fleet_event_identity",
    "validate_fleet_event_identity",
]
