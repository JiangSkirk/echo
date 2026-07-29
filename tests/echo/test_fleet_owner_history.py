from __future__ import annotations

from pathlib import Path

import pytest

from js.config import JSSettings
from js.orchestration.fleet import AgentFleet


@pytest.mark.asyncio
async def test_fleet_history_is_partitioned_by_owner(tmp_path: Path) -> None:
    fleet = AgentFleet(
        JSSettings(workspace=tmp_path / "workspace", state_dir=tmp_path / "state")
    )
    await fleet._save_history(
        "session-a",
        "owner a task",
        ["a"],
        {"final": "a result", "subtasks": {}},
        owner_key_hash="owner-a",
    )
    await fleet._save_history(
        "session-b",
        "owner b task",
        ["b"],
        {"final": "b result", "subtasks": {}},
        owner_key_hash="owner-b",
    )

    assert [item["session_id"] for item in fleet.list_history(owner_key_hash="owner-a")] == [
        "session-a"
    ]
    assert fleet.get_session("session-b", owner_key_hash="owner-a") is None
    assert fleet.get_session("session-b", owner_key_hash="owner-b") is not None
    assert fleet.delete_session("session-b", owner_key_hash="owner-a") is False
    assert fleet.get_session("../../outside", owner_key_hash="owner-a") is None
    assert fleet.delete_session("../../outside", owner_key_hash="owner-a") is False
