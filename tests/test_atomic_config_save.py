from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from js.config import JSSettings
from js.utils.atomic_config import AtomicConfigError


def _settings(tmp_path: Path) -> JSSettings:
    return JSSettings(
        workspace=tmp_path / "workspace",
        state_dir=tmp_path / "state",
        providers=[],
    )


def test_settings_save_preserves_previous_file_when_atomic_publish_fails(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    target = tmp_path / "config.yaml"
    settings = _settings(tmp_path)
    settings.max_turns = 17
    settings.save(target)
    before = target.read_bytes()

    def fail_publish(_temp_path: Path, _target: Path) -> None:
        raise OSError("simulated publish failure")

    monkeypatch.setattr("js.utils.atomic_config._publish_temp", fail_publish)
    settings.max_turns = 23

    with pytest.raises(AtomicConfigError):
        settings.save(target)

    assert target.read_bytes() == before


def test_field_merge_preserves_unrelated_configuration(tmp_path: Path) -> None:
    target = tmp_path / "config.yaml"
    target.write_text("unknown_user_field: keep\nmax_turns: 3\n", encoding="utf-8")
    settings = _settings(tmp_path)
    settings.max_turns = 9

    settings.save(target, fields=["max_turns"])

    saved = yaml.safe_load(target.read_text(encoding="utf-8"))
    assert saved == {"unknown_user_field": "keep", "max_turns": 9}


def test_settings_save_rejects_symbolic_link_target(tmp_path: Path) -> None:
    outside = tmp_path / "outside.yaml"
    outside.write_text("sentinel: unchanged\n", encoding="utf-8")
    target = tmp_path / "config.yaml"
    target.symlink_to(outside)

    with pytest.raises(AtomicConfigError):
        _settings(tmp_path).save(target)

    assert outside.read_text(encoding="utf-8") == "sentinel: unchanged\n"
