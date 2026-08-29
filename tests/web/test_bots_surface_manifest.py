"""Bots tab is on Personal and hidden on Work."""

from __future__ import annotations

from pathlib import Path

from js.config import JSSettings
from js.web.capability_manifest import build_capability_manifest


def test_personal_manifest_enables_bots(tmp_path: Path) -> None:
    settings = JSSettings(
        workspace=tmp_path / "personal" / "workspace",
        state_dir=tmp_path / "personal" / "state",
        providers=[],
    )
    manifest = build_capability_manifest(settings)
    assert manifest["product_id"] == "js-agent"
    assert manifest["tabs"]["bots"]["enabled"] is True
    assert "bots" in manifest["enabled_tabs"]


def test_work_manifest_hides_bots(tmp_path: Path) -> None:
    from js_work.config import WorkSettings, work_feature_config

    home = tmp_path / "work-home-bots"
    settings = WorkSettings(
        workspace=home / "workspace",
        state_dir=home / "state",
        work_home=home,
        providers=[],
    )
    settings.features = work_feature_config()
    manifest = build_capability_manifest(settings)
    assert manifest["product_id"] == "js-work"
    assert manifest["tabs"]["bots"]["enabled"] is False
    assert "bots" not in manifest["enabled_tabs"]
