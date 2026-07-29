"""Crash-safe bounded text state persistence regressions."""

from __future__ import annotations

from pathlib import Path

import pytest

from js.utils import atomic_state


def test_atomic_text_publish_failure_preserves_previous_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "active_model.txt"
    atomic_state.write_text_state(target, "provider/model-a", max_bytes=512)

    def fail_publish(_temp_path: Path, _target: Path) -> None:
        raise OSError("simulated publish failure")

    monkeypatch.setattr(atomic_state, "_publish_temp", fail_publish)

    with pytest.raises(atomic_state.AtomicStateError):
        atomic_state.write_text_state(target, "provider/model-b", max_bytes=512)

    assert atomic_state.read_text_state(target, max_bytes=512) == "provider/model-a"


def test_atomic_text_state_rejects_symbolic_link(tmp_path: Path) -> None:
    outside = tmp_path / "outside.txt"
    outside.write_text("outside", encoding="utf-8")
    target = tmp_path / "active_model.txt"
    target.symlink_to(outside)

    with pytest.raises(atomic_state.AtomicStateError):
        atomic_state.read_text_state(target, max_bytes=512)
    with pytest.raises(atomic_state.AtomicStateError):
        atomic_state.write_text_state(target, "provider/model", max_bytes=512)

    assert outside.read_text(encoding="utf-8") == "outside"
