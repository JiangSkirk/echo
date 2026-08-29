"""Pulse kernel remains admission-only; ADR 0005 records the shadow plan."""

from __future__ import annotations

from pathlib import Path

from js.echo.core import pulse
from js.echo.testing import new_fake_amber, new_fake_tide, new_fake_wheel


def test_adr_0005_is_shadow_first() -> None:
    text = Path("docs/adr/0005-echo-pulse-kernel-unification.md").read_text(encoding="utf-8")
    assert "shadow mode" in text.lower() or "Shadow mode" in text
    assert "does not change the production authority path" in text


def test_adr_0006_does_not_merge_engines() -> None:
    text = Path("docs/adr/0006-parser-fs-rejection-convergence.md").read_text(encoding="utf-8")
    assert "Do **not** merge" in text or "not merge" in text.lower()


def test_pulse_does_not_emit_exec_frames() -> None:
    amber = new_fake_amber()
    # pulse() against an empty inbound list must not invent Exec actions.
    successor, actions = pulse(0, [], amber, new_fake_wheel(), new_fake_tide())
    del successor
    kinds = {type(action).__name__ for action in actions}
    assert "Exec" not in kinds
    assert "CommitFrame" not in kinds
