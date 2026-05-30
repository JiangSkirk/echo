"""DEPRECATED — auto-decomposition is now built into AgentFleet.

TaskRouter is kept as a thin shim for any existing callers.
"""

from __future__ import annotations

from dataclasses import dataclass

from js.orchestration.fleet import AgentFleet, AgentRole


@dataclass
class RoutingScore:
    role: AgentRole
    score: float
    reason: str


class TaskRouter:
    """Thin shim — delegates to AgentFleet._auto_decompose()."""

    def route(self, task_description: str) -> RoutingScore:
        return RoutingScore(
            role=AgentRole.WORKER,
            score=1.0,
            reason="All tasks go to workers",
        )

    def decompose(self, task_description: str) -> list[tuple[str, AgentRole]]:
        descs = AgentFleet._auto_decompose(task_description)
        return [(d, AgentRole.WORKER) for d in descs]
