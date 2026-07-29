"""Fail-closed boundaries for legacy Python plugins."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from js.plugins.manager import PluginManager


def _external_plugin(root: Path) -> None:
    root.mkdir(parents=True)
    (root / "plugin.json").write_text(
        '{"id":"external-demo","name":"External Demo",'
        '"entry_point":"plugin:Plugin","categories":["demo"]}',
        encoding="utf-8",
    )
    (root / "plugin.py").write_text(
        "class Plugin:\n    pass\n",
        encoding="utf-8",
    )


def test_discovery_does_not_ingest_user_python_plugins(tmp_path: Path) -> None:
    manager = PluginManager(
        MagicMock(),
        SimpleNamespace(state_dir=tmp_path / "state"),
    )
    manager._user_plugin_dir = tmp_path / "user-plugins"
    _external_plugin(manager._user_plugin_dir / "external-demo")

    discovered = manager.discover()

    assert "external-demo" not in {record.manifest.id for record in discovered}


def test_remote_plugin_install_never_opens_network(tmp_path: Path) -> None:
    manager = PluginManager(
        MagicMock(),
        SimpleNamespace(state_dir=tmp_path / "state"),
    )

    with patch("urllib.request.urlretrieve") as retrieve:
        result = manager.install_from_url(
            "https://example.com/plugin.zip",
            expected_hash="0" * 64,
        )

    assert result["success"] is False
    assert "disabled" in result["message"].lower()
    retrieve.assert_not_called()


def test_external_plugin_record_cannot_be_loaded_or_enabled(tmp_path: Path) -> None:
    manager = PluginManager(
        MagicMock(),
        SimpleNamespace(state_dir=tmp_path / "state"),
    )
    external_dir = tmp_path / "external-demo"
    _external_plugin(external_dir)
    record = manager._discover_from_dir(external_dir)
    assert record is not None
    manager._plugins[record.manifest.id] = record

    with patch("importlib.util.spec_from_file_location") as import_spec:
        assert manager.load(record.manifest.id) is False
    import_spec.assert_not_called()

    with patch.object(manager, "load") as load:
        enabled = manager.enable(record.manifest.id)

    assert enabled is False
    load.assert_not_called()
