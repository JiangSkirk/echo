"""DEPRECATED — fleet strategies have been merged into AgentFleet.collaborate().

This module remains for backward compatibility of any imports.
The CollaborationStrategy ABC and all subclasses are no-ops.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from js.orchestration.fleet import AgentFleet


class CollaborationStrategy:
    """No-op base class for backward compatibility."""

    async def execute(
        self,
        fleet: AgentFleet,
        main_task: str,
        subtasks: list[tuple[str, Any]],
        options: dict[str, Any],
    ) -> dict[str, Any]:
        raise RuntimeError(
            "CollaborationStrategy is deprecated. Use AgentFleet.collaborate() directly."
        )


class ManagerWorkerStrategy(CollaborationStrategy):
    pass


class PeerToPeerStrategy(CollaborationStrategy):
    pass


class DebateStrategy(CollaborationStrategy):
    pass
