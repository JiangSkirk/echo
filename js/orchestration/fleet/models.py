"""Fleet data models."""

from __future__ import annotations

import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from js.agent import JSAgent
from js.orchestration.fleet.identity import _LOCAL_FLEET_OWNER, _SAFE_FLEET_ROLE_RE


class FleetCapacityError(RuntimeError):
    """Raised when no owner-safe Fleet worker can be allocated."""


class AgentRole(StrEnum):
    """Dynamic role enum — supports arbitrary role names via AgentRole('name')."""

    WORKER = "worker"
    REVIEWER = "reviewer"

    @classmethod
    def from_value(cls, value: str) -> AgentRole:
        """Create or return a role by string value."""
        if not isinstance(value, str) or not _SAFE_FLEET_ROLE_RE.fullmatch(value):
            raise ValueError("invalid fleet role")
        try:
            return cls(value)
        except ValueError:
            # Dynamically create a new enum member
            obj = str.__new__(cls, value)
            obj._value_ = value
            obj._name_ = value
            return obj  # type: ignore[return-value]


@dataclass
class AgentInstance:
    id: str
    name: str
    role: AgentRole
    agent: JSAgent
    product_id: str = "js-agent"
    owner_key_hash: str = _LOCAL_FLEET_OWNER
    model: str | None = None
    status: str = "idle"  # idle, busy, error
    current_task: str | None = None
    task_description: str = ""
    capabilities: list[str] = field(default_factory=list)
    last_active_at: float = field(default_factory=time.time)


@dataclass
class Task:
    id: str
    description: str
    role_hint: AgentRole
    priority: int = 5
    deps: list[str] = field(default_factory=list)
    result: str | None = None
    status: str = "pending"  # pending, running, done, failed, cancelled
    assigned_to: str | None = None
    group_id: str | None = None
    conversation_log: list[dict[str, Any]] = field(default_factory=list)


@dataclass(frozen=True)
class FleetEventSubscription:
    callback: Callable[[dict[str, Any]], Awaitable[None]]
    product_id: str
    owner_key_hash: str

