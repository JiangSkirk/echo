"""Responder ladder levels and L3 freeze hook."""

from __future__ import annotations

from pathlib import Path

from js.orind.responder import (
    LEVEL_FREEZE,
    LEVEL_KILL,
    LEVEL_NARROW,
    LEVEL_OBSERVE,
    LEVEL_QUARANTINE,
    Responder,
)
from js.orind.store import OrinStore


def test_monotonic_escalate_and_lock_l0(tmp_path: Path) -> None:
    store = OrinStore(tmp_path / "s.db")
    frozen: list[str] = []
    responder = Responder(store, freeze_fn=lambda sid: frozen.append(sid) or ())
    assert responder.escalate(session_id="s", level=LEVEL_NARROW, now_ms=1, evidence="a") == 1
    assert responder.escalate(session_id="s", level=LEVEL_OBSERVE, now_ms=2, evidence="b") == 1
    assert responder.escalate(session_id="s", level=LEVEL_FREEZE, now_ms=3, evidence="c") == 3
    assert frozen == ["s"]
    locked = Responder(store, lock_l0=True, freeze_fn=lambda sid: frozen.append(sid) or ())
    assert locked.escalate(session_id="t", level=LEVEL_QUARANTINE, now_ms=4, evidence="d") == 0


def test_l4_l5_are_recorded_without_process_kill(tmp_path: Path) -> None:
    store = OrinStore(tmp_path / "s.db")
    responder = Responder(store)
    assert responder.escalate(session_id="s", level=LEVEL_KILL, now_ms=1, evidence="k") == 4
    assert responder.escalate(session_id="s", level=LEVEL_QUARANTINE, now_ms=2, evidence="q") == 5
    assert responder.level_of("s") == 5
