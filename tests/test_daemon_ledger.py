"""P1-5: daemon lifecycle/health must be authoritative in EchoLedger.

Previously the daemon only wrote ``daemon_heartbeat.json`` while a docstring
claimed lifecycle transitions were recorded in EchoLedger — no such records
existed anywhere.  These tests require:

- daemon_started / daemon_heartbeat / daemon_stopped events in EchoLedger;
- the JSON file remains only a derived snapshot;
- a failing ledger write degrades the daemon (fail-closed signal), never
  silently healthy.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from js.config import JSSettings
from js.daemon.core import JSDaemon
from js.echo.ledger.journal import FileEchoLedger


class _StubAgent:
    def __init__(self, settings: JSSettings, service: Any) -> None:
        self.settings = settings
        self.echo_safety_service = service

    def start_background_tasks(self) -> None:
        return None

    def stop_background_tasks(self) -> None:
        return None

    async def close(self) -> None:
        return None


def _settings(tmp_path: Path) -> JSSettings:
    return JSSettings(
        workspace=tmp_path / "workspace",
        state_dir=tmp_path / "state",
        providers=[],
    )


def _daemon(tmp_path: Path) -> JSDaemon:
    from js.echo.ledger.service import EchoSafetyService

    settings = _settings(tmp_path)
    service = EchoSafetyService(state_dir=settings.state_dir)
    return JSDaemon(settings, agent=_StubAgent(settings, service))


def _daemon_journal_records(daemon: JSDaemon) -> list[Any]:
    service = daemon.agent.echo_safety_service
    product_id = str(getattr(daemon.settings, "product_id", "js-agent"))
    journal_path = service.journal_path_for_scope(
        "daemon", product_id=product_id, session_id="daemon"
    )
    if not journal_path.exists():
        return []
    return list(
        FileEchoLedger(
            journal_path,
            mac_key=service.journal_key_for_scope(
                "daemon", product_id=product_id, session_id="daemon"
            ),
        ).records
    )


def test_daemon_heartbeat_writes_echo_ledger_event(tmp_path: Path) -> None:
    daemon = _daemon(tmp_path)
    daemon._write_heartbeat()
    records = _daemon_journal_records(daemon)
    heartbeats = [
        record for record in records
        if record.record_type == "daemon" and record.payload.get("event_type") == "daemon_heartbeat"
    ]
    assert heartbeats, "no daemon_heartbeat event in EchoLedger"
    assert heartbeats[0].payload["instance_id"] == daemon._instance_id


def test_daemon_lifecycle_start_stop_events(tmp_path: Path) -> None:
    daemon = _daemon(tmp_path)
    daemon._record_daemon_lifecycle("daemon_started")
    daemon._record_daemon_lifecycle("daemon_stopped")
    records = _daemon_journal_records(daemon)
    event_types = [
        record.payload.get("event_type") for record in records if record.record_type == "daemon"
    ]
    assert "daemon_started" in event_types
    assert "daemon_stopped" in event_types


def test_heartbeat_json_is_derived_snapshot_only(tmp_path: Path) -> None:
    daemon = _daemon(tmp_path)
    daemon._write_heartbeat()
    data = json.loads (daemon._heartbeat_path.read_text(encoding="utf-8"))
    assert data.get("authoritative") is False


def test_ledger_failure_marks_daemon_degraded(tmp_path: Path) -> None:
    daemon = _daemon(tmp_path)
    service = daemon.agent.echo_safety_service

    def broken_append(*_args: Any, **_kwargs: Any) -> None:
        raise OSError("journal unavailable")

    service.record_daemon_event = broken_append  # type: ignore[method-assign]
    with pytest.raises(OSError, match="journal unavailable"):
        daemon._record_daemon_lifecycle("daemon_started")
    assert daemon.ledger_degraded is True
