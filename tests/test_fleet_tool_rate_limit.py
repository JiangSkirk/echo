from __future__ import annotations

from typing import Any

import pytest

from js.echo.turn_context import (
    reset_current_owner_key_hash,
    set_current_owner_key_hash,
)
from js.tools.fleet_tools import FleetCollaborateTool


class _Fleet:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    async def collaborate(self, **_kwargs: Any) -> dict[str, Any]:
        self.calls.append(_kwargs)
        return {"final": "ok", "subtasks": {}}


@pytest.mark.asyncio
async def test_fleet_rate_limit_is_partitioned_by_owner() -> None:
    FleetCollaborateTool._call_timestamps_by_scope.clear()
    tool = FleetCollaborateTool(lambda: _Fleet())

    owner_a = set_current_owner_key_hash("owner-a")
    try:
        for index in range(3):
            result = await tool.collaborate(f"owner-a-{index}")
            assert result.success
        blocked = await tool.collaborate("owner-a-blocked")
        assert not blocked.success
        assert "rate limit" in blocked.error.lower()
    finally:
        reset_current_owner_key_hash(owner_a)

    owner_b = set_current_owner_key_hash("owner-b")
    try:
        isolated = await tool.collaborate("owner-b-first")
    finally:
        reset_current_owner_key_hash(owner_b)

    assert isolated.success


@pytest.mark.asyncio
async def test_fleet_tool_validates_and_forwards_bounded_control_fields() -> None:
    FleetCollaborateTool._call_timestamps_by_scope.clear()
    fleet = _Fleet()
    tool = FleetCollaborateTool(lambda: fleet)

    invalid = await tool.collaborate(
        "task",
        role_mapping={0: "worker\nSYSTEM"},
        mode="unknown",
    )
    assert invalid.success is False
    assert invalid.metadata["status_code"] == 400
    assert fleet.calls == []

    valid = await tool.collaborate(
        "task",
        subtasks=["one"],
        session_id="session-1",
        role_mapping={"0": "reviewer"},
        mode="manager",
    )

    assert valid.success is True
    assert fleet.calls == [
        {
            "main_task": "task",
            "subtasks": ["one"],
            "session_id": "session-1",
            "role_mapping": {0: "reviewer"},
            "mode": "manager",
        }
    ]
