"""Tests for the simplified fleet web router."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from js.config import JSSettings, SecurityConfig
from js.web.routers.fleet import router as fleet_router


def _make_client() -> TestClient:
    """Create a TestClient with an admin API key for fleet endpoints."""
    app = FastAPI()
    app.include_router(fleet_router)
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


def _make_fleet() -> MagicMock:
    fleet = MagicMock()
    fleet.get_status.return_value = {"agents": []}
    fleet.collaborate = AsyncMock(return_value={"final": "done", "subtasks": {}, "review": None})
    return fleet


def test_fleet_status() -> None:
    fleet = _make_fleet()

    client = _make_client()
    with patch("js.web.routers.fleet.get_fleet", return_value=fleet):
        resp = client.get("/api/fleet/status")

    assert resp.status_code == 200
    fleet.get_status.assert_called_once()


def test_fleet_collaborate_success() -> None:
    fleet = _make_fleet()

    client = _make_client()
    with patch("js.web.routers.fleet.get_fleet", return_value=fleet):
        resp = client.post(
            "/api/fleet/collaborate",
            json={
                "task": "Build app",
                "subtasks": ["Write code", "Review code"],
            },
        )

    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    assert data["final"] == "done"
    fleet.collaborate.assert_called_once_with(
        main_task="Build app",
        subtasks=["Write code", "Review code"],
        role_mapping=None,
        mode="auto",
    )


def test_fleet_collaborate_no_subtasks() -> None:
    fleet = _make_fleet()

    client = _make_client()
    with patch("js.web.routers.fleet.get_fleet", return_value=fleet):
        resp = client.post(
            "/api/fleet/collaborate",
            json={"task": "Build app"},
        )

    assert resp.status_code == 200
    fleet.collaborate.assert_called_once_with(
        main_task="Build app",
        subtasks=None,
        role_mapping=None,
        mode="auto",
    )


def test_fleet_collaborate_failure() -> None:
    fleet = _make_fleet()
    fleet.collaborate = AsyncMock(side_effect=RuntimeError("collaboration error"))

    client = _make_client()
    with patch("js.web.routers.fleet.get_fleet", return_value=fleet):
        resp = client.post("/api/fleet/collaborate", json={"task": "x"})

    assert resp.status_code == 500


def test_fleet_collaborate_missing_task() -> None:
    fleet = _make_fleet()

    client = _make_client()
    with patch("js.web.routers.fleet.get_fleet", return_value=fleet):
        resp = client.post("/api/fleet/collaborate", json={})

    assert resp.status_code == 400
