"""ResourceGovernor integration tests for daily event-file retention."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from js.events.store import EventStore
from js.runtime.governor import ResourceGovernor


def _agent(event_store: object, *, audit: object | None = None) -> SimpleNamespace:
    return SimpleNamespace(
        _state_store=None,
        event_store=event_store,
        audit=audit,
        memory=None,
        lifecycle_store=None,
        review_store=None,
    )


@pytest.mark.asyncio
async def test_governor_prunes_primary_low_traffic_daily_event_files_without_fleet(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = EventStore(tmp_path / "events", retention_days=1)
    today = datetime.now(UTC).date()
    old_path = store.base_dir / f"events_{today - timedelta(days=2)}.jsonl"
    active_path = store.base_dir / f"events_{today}.jsonl"
    old_path.write_text("{}\n", encoding="utf-8")
    active_path.write_text("{}\n", encoding="utf-8")
    governor = ResourceGovernor(_agent(store))
    monkeypatch.setattr(governor, "_collect_snapshot", lambda: None)

    await governor._run_cycle()

    assert not old_path.exists()
    assert active_path.exists()


@pytest.mark.asyncio
async def test_governor_prunes_agent_and_fleet_stores_for_same_path_only_once(
    tmp_path: Path,
) -> None:
    primary_store = MagicMock()
    primary_store.base_dir = tmp_path / "events"
    primary_store.prune.return_value = 1
    fleet_store = MagicMock()
    fleet_store.base_dir = tmp_path / "events"
    fleet = SimpleNamespace(_agent_store=None, _event_store=fleet_store)
    governor = ResourceGovernor(_agent(primary_store), fleet_getter=lambda: fleet)

    await governor._prune_databases()

    primary_store.prune.assert_called_once_with()
    fleet_store.prune.assert_not_called()


@pytest.mark.asyncio
async def test_governor_continues_to_fleet_event_store_when_primary_prune_fails() -> None:
    primary_store = MagicMock()
    primary_store.prune.side_effect = RuntimeError("primary event store unavailable")
    fleet_store = MagicMock()
    fleet_store.prune.return_value = 1
    fleet = SimpleNamespace(_agent_store=None, _event_store=fleet_store)
    governor = ResourceGovernor(_agent(primary_store), fleet_getter=lambda: fleet)

    await governor._prune_databases()

    primary_store.prune.assert_called_once_with()
    fleet_store.prune.assert_called_once_with()


@pytest.mark.asyncio
async def test_governor_continues_after_compatible_fleet_event_store_prune_fails() -> None:
    primary_store = MagicMock()
    primary_store.prune.return_value = 1
    fleet_store = MagicMock()
    fleet_store.prune.side_effect = RuntimeError("fleet event store unavailable")
    audit = MagicMock()
    audit.prune.return_value = 1
    fleet = SimpleNamespace(_agent_store=None, _event_store=fleet_store)
    governor = ResourceGovernor(_agent(primary_store, audit=audit), fleet_getter=lambda: fleet)

    await governor._prune_databases()

    primary_store.prune.assert_called_once_with()
    fleet_store.prune.assert_called_once_with()
    audit.prune.assert_called_once_with()
