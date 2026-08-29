"""Fleet workers and observability stay inside one product/owner boundary."""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import pytest

from js.config import JSSettings
from js.echo.turn_context import (
    RuntimeContext,
    reset_current_owner_key_hash,
    reset_runtime_context,
    set_current_owner_key_hash,
    set_runtime_context,
)
from js.orchestration.fleet import (
    AgentFleet,
    FleetCapacityError,
    bind_fleet_event_identity,
)


class _FakeAgent:
    def __init__(self, settings: JSSettings) -> None:
        self.settings = settings
        self.SYSTEM_PROMPT = ""
        self._current_allowed_tools: set[str] = set()
        self.closed = False
        self.close_error = False
        self.close_wait: asyncio.Event | None = None

    async def close(self) -> None:
        if self.close_wait is not None:
            await self.close_wait.wait()
        if self.close_error:
            raise RuntimeError("close failed")
        self.closed = True


def _fleet(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, max_workers: int = 2) -> AgentFleet:
    monkeypatch.setattr("js.orchestration.fleet.agent_fleet.JSAgent", _FakeAgent)
    settings = JSSettings(
        state_dir=tmp_path / "state",
        workspace=tmp_path / "workspace",
    )
    object.__setattr__(settings, "product_id", "js-agent")
    return AgentFleet(settings, max_workers=max_workers, inherit_skills=False)


def _context(
    tmp_path: Path,
    owner: str,
    product: str = "js-agent",
    *,
    role: str = "local-user",
    profile: str = "default",
    capabilities: tuple[str, ...] = (),
    deadline_ms: int | None = None,
    cancel_token: asyncio.Event | None = None,
) -> RuntimeContext:
    return RuntimeContext(
        product_id=product,
        channel="fleet-test",
        owner_key_hash=owner,
        session_id=f"session-{owner}",
        run_id=f"run-{owner}",
        role=role,
        profile=profile,
        capabilities=capabilities,
        workspace=tmp_path / "workspace",
        state_dir=tmp_path / "state",
        fs_roots=(tmp_path / "workspace",),
        network_allowlist=("allowed.example",),
        deadline_ms=deadline_ms or int(time.monotonic() * 1000) + 60_000,
        cancel_token=cancel_token or asyncio.Event(),
    )


async def _acquire_as(
    fleet: AgentFleet,
    tmp_path: Path,
    owner: str,
    *,
    product: str = "js-agent",
) -> Any:
    token = set_runtime_context(_context(tmp_path, owner, product))
    try:
        return await fleet._acquire_agent("worker", f"group-{owner}")
    finally:
        reset_runtime_context(token)


@pytest.mark.asyncio
async def test_tool_owner_context_is_preserved_without_full_runtime_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fleet = _fleet(tmp_path, monkeypatch)
    token = set_current_owner_key_hash("tool-owner")
    try:
        worker = await fleet._acquire_agent("worker", "tool-group")
    finally:
        reset_current_owner_key_hash(token)

    assert worker.owner_key_hash == "tool-owner"


@pytest.mark.asyncio
async def test_internal_acquire_without_owner_context_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fleet = _fleet(tmp_path, monkeypatch)

    with pytest.raises(RuntimeError, match="owner context is required"):
        await fleet._acquire_agent("worker", "missing-owner")


@pytest.mark.asyncio
async def test_parent_runtime_owner_cannot_be_overridden_by_fleet_argument(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fleet = _fleet(tmp_path, monkeypatch)
    collaborate_scoped = AsyncMock(return_value={"final": "unexpected"})
    monkeypatch.setattr(fleet, "_collaborate_scoped", collaborate_scoped)
    token = set_runtime_context(_context(tmp_path, "owner-a"))
    try:
        with pytest.raises(PermissionError, match="owner"):
            await fleet.collaborate("task", owner_key_hash="owner-b")
    finally:
        reset_runtime_context(token)

    collaborate_scoped.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "kwargs",
    [
        {"mode": "unknown"},
        {"subtasks": "not-a-list"},
        {"subtasks": ["ok", 3]},
        {"role_mapping": {0: "worker\nSYSTEM"}},
        {"role_mapping": {"not-an-index": "worker"}},
        {"session_id": "../escape"},
    ],
)
async def test_fleet_rejects_invalid_mode_role_and_shape_before_dispatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    kwargs: dict[str, Any],
) -> None:
    fleet = _fleet(tmp_path, monkeypatch)
    collaborate_scoped = AsyncMock(return_value={"final": "unexpected"})
    monkeypatch.setattr(fleet, "_collaborate_scoped", collaborate_scoped)

    with pytest.raises((TypeError, ValueError)):
        await fleet.collaborate("task", owner_key_hash="owner-a", **kwargs)

    collaborate_scoped.assert_not_awaited()


@pytest.mark.asyncio
async def test_fleet_normalizes_safe_json_role_mapping_keys(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fleet = _fleet(tmp_path, monkeypatch)
    collaborate_scoped = AsyncMock(return_value={"final": "ok"})
    monkeypatch.setattr(fleet, "_collaborate_scoped", collaborate_scoped)

    result = await fleet.collaborate(
        "task",
        subtasks=["one"],
        role_mapping={"0": "reviewer"},  # type: ignore[dict-item]
        mode="manager",
        owner_key_hash="owner-a",
    )

    assert result == {"final": "ok"}
    assert collaborate_scoped.await_args.kwargs["role_mapping"] == {0: "reviewer"}


@pytest.mark.asyncio
async def test_worker_inherits_non_expanding_parent_runtime_envelope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fleet = _fleet(tmp_path, monkeypatch)
    cancel_token = asyncio.Event()
    deadline_ms = int(time.monotonic() * 1000) + 45_000
    parent = _context(
        tmp_path,
        "owner-a",
        role="user",
        profile="restricted",
        capabilities=("file_read", "file_write", "fleet_collaborate"),
        deadline_ms=deadline_ms,
        cancel_token=cancel_token,
    )
    token = set_runtime_context(parent)
    try:
        worker = await fleet._acquire_agent("admin", "group-a")
    finally:
        reset_runtime_context(token)

    assert worker.agent._role == "user"
    assert worker.agent._work_profile == "restricted"
    assert worker.agent._echo_capability_ceiling == frozenset({"file_read", "file_write"})
    assert worker.agent._echo_network_allowlist_ceiling == frozenset({"allowed.example"})
    assert worker.agent._echo_deadline_ceiling_ms == deadline_ms
    assert worker.agent._echo_cancel_token is cancel_token
    assert worker.capabilities == ["file_read", "file_write"]


@pytest.mark.asyncio
async def test_reused_worker_is_renarrowed_for_each_parent_turn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fleet = _fleet(tmp_path, monkeypatch)
    broad_token = set_runtime_context(
        _context(
            tmp_path,
            "owner-a",
            capabilities=("file_read", "file_write"),
        )
    )
    try:
        worker = await fleet._acquire_agent("worker", "group-a")
    finally:
        reset_runtime_context(broad_token)
    worker.status = "idle"

    narrow_token = set_runtime_context(_context(tmp_path, "owner-a", capabilities=("file_read",)))
    try:
        reused = await fleet._acquire_agent("worker", "group-b")
    finally:
        reset_runtime_context(narrow_token)

    assert reused is worker
    assert reused.agent._echo_capability_ceiling == frozenset({"file_read"})
    assert reused.capabilities == ["file_read"]


@pytest.mark.asyncio
async def test_event_subscriptions_deliver_only_to_matching_product_and_owner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fleet = _fleet(tmp_path, monkeypatch)
    received_a: list[dict[str, Any]] = []
    received_b: list[dict[str, Any]] = []

    async def collect_a(event: dict[str, Any]) -> None:
        received_a.append(event)

    async def collect_b(event: dict[str, Any]) -> None:
        received_b.append(event)

    fleet.on_event(collect_a, product_id="js-agent", owner_key_hash="owner-a")
    fleet.on_event(collect_b, product_id="js-agent", owner_key_hash="owner-b")

    sensitive_events = [
        {"type": "agent_start", "task_id": "task-a"},
        {"type": "collaborate_result", "session_id": "session-a", "final": "result-a"},
        {"type": "agent_thinking", "task_id": "task-a", "content": "thinking-a"},
        {"type": "agent_tool_call", "task_id": "task-a", "tool_name": "search"},
    ]
    with bind_fleet_event_identity("request-a", "turn-a", "session-a"):
        for event in sensitive_events:
            await fleet._emit(event, product_id="js-agent", owner_key_hash="owner-a")

    assert received_a == [
        {**event, "request_id": "request-a", "turn_id": "turn-a", "session_id": "session-a"}
        for event in sensitive_events
    ]
    assert received_b == []
    assert all("owner" not in event and "owner_key_hash" not in event for event in received_a)


@pytest.mark.asyncio
async def test_event_subscription_token_removes_only_the_registered_scope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fleet = _fleet(tmp_path, monkeypatch)
    received: list[str] = []

    async def collect(event: dict[str, Any]) -> None:
        received.append(str(event["type"]))

    subscription_a = fleet.on_event(
        collect,
        product_id="js-agent",
        owner_key_hash="owner-a",
    )
    fleet.on_event(
        collect,
        product_id="js-agent",
        owner_key_hash="owner-b",
    )

    fleet.off_event(subscription_a)
    with bind_fleet_event_identity("request-a", "turn-a", "session-a"):
        await fleet._emit(
            {"type": "owner-a-event"},
            product_id="js-agent",
            owner_key_hash="owner-a",
        )
        await fleet._emit(
            {"type": "owner-b-event"},
            product_id="js-agent",
            owner_key_hash="owner-b",
        )

    assert received == ["owner-b-event"]


@pytest.mark.asyncio
async def test_event_payload_strips_internal_owner_identity_fields(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fleet = _fleet(tmp_path, monkeypatch)
    received: list[dict[str, Any]] = []

    async def collect(event: dict[str, Any]) -> None:
        received.append(event)

    fleet.on_event(collect, product_id="js-agent", owner_key_hash="owner-a")
    with bind_fleet_event_identity("request-real", "turn-real", "session-real"):
        await fleet._emit(
            {
                "type": "agent_thinking",
                "content": "safe content",
                "owner": "owner-a",
                "owner_key_hash": "owner-a",
                "request_id": "spoofed-request",
                "turn_id": "spoofed-turn",
                "session_id": "spoofed-session",
            },
            product_id="js-agent",
            owner_key_hash="owner-a",
        )

    assert received == [
        {
            "type": "agent_thinking",
            "content": "safe content",
            "request_id": "request-real",
            "turn_id": "turn-real",
            "session_id": "session-real",
        }
    ]


@pytest.mark.asyncio
async def test_event_emission_without_complete_identity_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fleet = _fleet(tmp_path, monkeypatch)

    with pytest.raises(RuntimeError, match="identity context is required"):
        await fleet._emit(
            {"type": "agent_start"},
            product_id="js-agent",
            owner_key_hash="owner-a",
        )


@pytest.mark.asyncio
async def test_internal_collaboration_generates_one_stable_complete_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fleet = _fleet(tmp_path, monkeypatch)
    received: list[dict[str, Any]] = []

    async def collect(event: dict[str, Any]) -> None:
        received.append(event)

    async def collaborate_scoped(*_args: Any, **kwargs: Any) -> dict[str, Any]:
        await fleet._emit({"type": "agent_start"})
        await fleet._emit({"type": "agent_done"})
        return {"session_id": kwargs["session_id"], "final": "ok", "subtasks": {}}

    fleet.on_event(collect, product_id="js-agent", owner_key_hash="owner-a")
    monkeypatch.setattr(fleet, "_collaborate_scoped", collaborate_scoped)

    result = await fleet.collaborate("task", owner_key_hash="owner-a")

    identities = [
        (event["request_id"], event["turn_id"], event["session_id"]) for event in received
    ]
    assert len(identities) == 2
    assert identities[0] == identities[1]
    assert all(isinstance(part, str) and part for part in identities[0])
    assert result["session_id"] == identities[0][2]


@pytest.mark.asyncio
async def test_same_role_workers_are_isolated_by_product_and_owner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fleet = _fleet(tmp_path, monkeypatch)

    owner_a, owner_b = await asyncio.gather(
        _acquire_as(fleet, tmp_path, "owner-a"),
        _acquire_as(fleet, tmp_path, "owner-b"),
    )

    assert owner_a is not owner_b
    assert owner_a.agent is not owner_b.agent
    assert owner_a.id != owner_b.id
    assert (owner_a.product_id, owner_a.owner_key_hash) == ("js-agent", "owner-a")
    assert (owner_b.product_id, owner_b.owner_key_hash) == ("js-agent", "owner-b")


@pytest.mark.asyncio
async def test_same_owner_workers_are_isolated_by_product(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fleet = _fleet(tmp_path, monkeypatch)

    main_worker = await _acquire_as(fleet, tmp_path, "owner-a", product="js-agent")
    work_worker = await _acquire_as(fleet, tmp_path, "owner-a", product="js-work")

    assert main_worker.id != work_worker.id
    assert main_worker.product_id == "js-agent"
    assert work_worker.product_id == "js-work"
    assert main_worker.agent.settings.product_id == "js-agent"
    assert work_worker.agent.settings.product_id == "js-work"


@pytest.mark.asyncio
async def test_worker_directories_use_irreversible_owner_partition_slugs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fleet = _fleet(tmp_path, monkeypatch)
    worker = await _acquire_as(fleet, tmp_path, "owner/raw value")

    state_dir = worker.agent.settings.state_dir
    workspace = worker.agent.settings.workspace
    assert state_dir.is_relative_to(tmp_path / "state" / "fleet")
    assert workspace.is_relative_to(tmp_path / "workspace" / "fleet")
    assert "owner/raw value" not in str(state_dir)
    assert "owner/raw value" not in str(workspace)
    assert len(state_dir.relative_to(tmp_path / "state" / "fleet").parts) == 3
    assert len(workspace.relative_to(tmp_path / "workspace" / "fleet").parts) == 3


@pytest.mark.asyncio
async def test_full_pool_replaces_another_owners_idle_worker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fleet = _fleet(tmp_path, monkeypatch, max_workers=1)
    owner_a = await _acquire_as(fleet, tmp_path, "owner-a")
    owner_a.status = "idle"

    owner_b = await _acquire_as(fleet, tmp_path, "owner-b")

    assert owner_b.owner_key_hash == "owner-b"
    assert owner_b.id != owner_a.id
    assert owner_a.agent.closed is True
    assert list(fleet.agents.values()) == [owner_b]


@pytest.mark.asyncio
async def test_full_pool_does_not_replace_when_idle_worker_cannot_close(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fleet = _fleet(tmp_path, monkeypatch, max_workers=1)
    owner_a = await _acquire_as(fleet, tmp_path, "owner-a")
    owner_a.status = "idle"
    owner_a.agent.close_error = True

    with pytest.raises(FleetCapacityError, match="could not be closed"):
        await _acquire_as(fleet, tmp_path, "owner-b")

    assert list(fleet.agents.values()) == [owner_a]
    assert owner_a.status == "error"


@pytest.mark.asyncio
async def test_full_pool_times_out_instead_of_waiting_on_idle_worker_close(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fleet = _fleet(tmp_path, monkeypatch, max_workers=1)
    fleet._worker_close_timeout = 0.01
    owner_a = await _acquire_as(fleet, tmp_path, "owner-a")
    owner_a.status = "idle"
    owner_a.agent.close_wait = asyncio.Event()

    with pytest.raises(FleetCapacityError, match="could not be closed"):
        await asyncio.wait_for(
            _acquire_as(fleet, tmp_path, "owner-b"),
            timeout=0.1,
        )

    assert list(fleet.agents.values()) == [owner_a]
    assert owner_a.status == "error"


@pytest.mark.asyncio
async def test_full_pool_with_other_owner_busy_fails_without_waiting_or_reuse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fleet = _fleet(tmp_path, monkeypatch, max_workers=1)
    owner_a = await _acquire_as(fleet, tmp_path, "owner-a")

    with pytest.raises(RuntimeError, match="capacity exhausted"):
        await asyncio.wait_for(
            _acquire_as(fleet, tmp_path, "owner-b"),
            timeout=0.2,
        )

    assert owner_a.owner_key_hash == "owner-a"
    assert owner_a.status == "busy"
    assert list(fleet.agents.values()) == [owner_a]


@pytest.mark.asyncio
async def test_capacity_error_during_team_formation_releases_partial_team(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fleet = _fleet(tmp_path, monkeypatch, max_workers=1)

    with pytest.raises(RuntimeError, match="capacity exhausted"):
        await fleet.collaborate(
            "compare two views",
            subtasks=["view A", "view B"],
            mode="debate",
            owner_key_hash="owner-a",
        )

    assert len(fleet.agents) == 1
    assert next(iter(fleet.agents.values())).status == "idle"


@pytest.mark.asyncio
async def test_status_filters_owner_and_omits_task_text(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fleet = _fleet(tmp_path, monkeypatch)
    owner_a = await _acquire_as(fleet, tmp_path, "owner-a")
    owner_b = await _acquire_as(fleet, tmp_path, "owner-b")
    owner_a.current_task = "task-a"
    owner_a.task_description = "owner A secret task body"
    owner_b.current_task = "task-b"
    owner_b.task_description = "owner B secret task body"

    status = fleet.get_status(owner_key_hash="owner-a")

    assert status == {
        "agents": [
            {
                "id": owner_a.id,
                "name": "worker",
                "role": "worker",
                "status": "busy",
                "task_id": "task-a",
            }
        ]
    }
    assert "secret" not in str(status)


@pytest.mark.asyncio
async def test_same_session_id_history_and_continue_remain_owner_scoped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fleet = _fleet(tmp_path, monkeypatch)
    await fleet._save_history(
        "shared-session",
        "owner A task",
        ["A"],
        {"final": "A result", "subtasks": {}, "review": None},
        owner_key_hash="owner-a",
    )
    await fleet._save_history(
        "shared-session",
        "owner B task",
        ["B"],
        {"final": "B result", "subtasks": {}, "review": None},
        owner_key_hash="owner-b",
    )

    assert fleet.get_session("shared-session", owner_key_hash="owner-a")["main_task"] == (
        "owner A task"
    )
    assert fleet.get_session("shared-session", owner_key_hash="owner-b")["main_task"] == (
        "owner B task"
    )

    calls: list[dict[str, Any]] = []

    async def capture_collaborate(**kwargs: Any) -> dict[str, Any]:
        calls.append(kwargs)
        return {"session_id": "shared-session", "final": "continued", "subtasks": {}}

    monkeypatch.setattr(fleet, "collaborate", capture_collaborate)
    await fleet.continue_session(
        "shared-session",
        "A follow-up",
        owner_key_hash="owner-a",
    )

    assert calls[0]["owner_key_hash"] == "owner-a"
    assert "owner A task" in calls[0]["main_task"]
    assert "owner B task" not in calls[0]["main_task"]


@pytest.mark.asyncio
async def test_fleet_history_rejects_symlinked_session_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fleet = _fleet(tmp_path, monkeypatch)
    await fleet._save_history(
        "session-a",
        "owned task",
        ["owned"],
        {"final": "owned", "subtasks": {}, "review": None},
        owner_key_hash="owner-a",
    )
    product_id = str(fleet.settings.product_id)
    session_path = fleet._history_path(
        "session-a",
        product_id=product_id,
        owner_key_hash="owner-a",
    )
    outside = tmp_path / "outside.json"
    outside.write_text(
        json.dumps(
            {
                "session_id": "session-a",
                "main_task": "outside secret",
                "subtasks": [],
                "final": "outside",
                "product_id": product_id,
                "owner_key_hash": "owner-a",
            }
        ),
        encoding="utf-8",
    )
    session_path.unlink()
    session_path.symlink_to(outside)

    assert fleet.get_session("session-a", owner_key_hash="owner-a") is None
    assert fleet.delete_session("session-a", owner_key_hash="owner-a") is False
    assert outside.exists()
    assert "outside secret" in outside.read_text(encoding="utf-8")


@pytest.mark.asyncio
async def test_fleet_history_rejects_symlinked_owner_partition_on_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fleet = _fleet(tmp_path, monkeypatch)
    product_id = str(fleet.settings.product_id)
    owner_dir = fleet._history_scope_dir(product_id, "owner-a")
    owner_dir.parent.mkdir(parents=True, exist_ok=True)
    outside = tmp_path / "outside-history"
    outside.mkdir()
    owner_dir.symlink_to(outside, target_is_directory=True)

    with pytest.raises(OSError):
        await fleet._save_history(
            "session-a",
            "must stay inside",
            ["owned"],
            {"final": "owned", "subtasks": {}, "review": None},
            owner_key_hash="owner-a",
        )

    assert list(outside.iterdir()) == []
