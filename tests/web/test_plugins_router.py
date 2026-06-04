"""Tests for the plugins web router."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from js.config import JSSettings, SecurityConfig
from js.web.routers.plugins import router as plugins_router


def _make_client() -> TestClient:
    """Create a TestClient with an admin API key for plugin endpoints."""
    app = FastAPI()
    app.include_router(plugins_router)
    _settings = JSSettings(
        workspace=Path("/tmp/js_test"),
        state_dir=Path("/tmp/js_test"),
        security=SecurityConfig(api_key_required=False),
    )
    patch("js.web.server._settings", _settings).start()

    from js.web.auth import AuthManager
    auth_mgr = AuthManager(_settings.state_dir)
    admin_key = auth_mgr.create_key("test-admin", role="admin")

    return TestClient(app, headers={"X-API-Key": admin_key})


def _make_plugin_manager() -> MagicMock:
    pm = MagicMock()
    record = MagicMock()
    record.to_dict.return_value = {
        "id": "example-dashboard",
        "name": "Example Dashboard",
        "enabled": True,
    }
    pm.list_plugins.return_value = [record]
    pm.enable.return_value = True
    pm.disable.return_value = True
    return pm


def test_list_plugins_success() -> None:
    agent = MagicMock()
    agent.plugins = _make_plugin_manager()

    client = _make_client()
    with patch("js.web.routers.plugins.get_agent", return_value=agent):
        resp = client.get("/api/plugins/")

    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 1
    assert data["plugins"][0]["id"] == "example-dashboard"


def test_list_plugins_not_initialized() -> None:
    agent = MagicMock()
    agent.plugins = None

    client = _make_client()
    with patch("js.web.routers.plugins.get_agent", return_value=agent):
        resp = client.get("/api/plugins/")

    assert resp.status_code == 200
    assert resp.json()["plugins"] == []
    assert resp.json()["total"] == 0


def test_enable_plugin_success() -> None:
    agent = MagicMock()
    agent.plugins = _make_plugin_manager()

    client = _make_client()
    with patch("js.web.routers.plugins.get_agent", return_value=agent):
        resp = client.post("/api/plugins/example-dashboard/enable")

    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    assert data["status"] == "enabled"
    agent.plugins.enable.assert_called_once_with("example-dashboard")


def test_enable_plugin_failure() -> None:
    agent = MagicMock()
    pm = _make_plugin_manager()
    pm.enable.return_value = False
    agent.plugins = pm

    client = _make_client()
    with patch("js.web.routers.plugins.get_agent", return_value=agent):
        resp = client.post("/api/plugins/example-dashboard/enable")

    assert resp.status_code == 400


def test_enable_plugin_no_pm() -> None:
    agent = MagicMock()
    agent.plugins = None

    client = _make_client()
    with patch("js.web.routers.plugins.get_agent", return_value=agent):
        resp = client.post("/api/plugins/example-dashboard/enable")

    assert resp.status_code == 503


def test_disable_plugin_success() -> None:
    agent = MagicMock()
    agent.plugins = _make_plugin_manager()

    client = _make_client()
    with patch("js.web.routers.plugins.get_agent", return_value=agent):
        resp = client.post("/api/plugins/example-dashboard/disable")

    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    assert data["status"] == "disabled"
    agent.plugins.disable.assert_called_once_with("example-dashboard")


def test_disable_plugin_failure() -> None:
    agent = MagicMock()
    pm = _make_plugin_manager()
    pm.disable.return_value = False
    agent.plugins = pm

    client = _make_client()
    with patch("js.web.routers.plugins.get_agent", return_value=agent):
        resp = client.post("/api/plugins/example-dashboard/disable")

    assert resp.status_code == 400


def test_disable_plugin_no_pm() -> None:
    agent = MagicMock()
    agent.plugins = None

    client = _make_client()
    with patch("js.web.routers.plugins.get_agent", return_value=agent):
        resp = client.post("/api/plugins/example-dashboard/disable")

    assert resp.status_code == 503
