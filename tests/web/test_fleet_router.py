"""Tests for the simplified fleet web router."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from js.web.routers.fleet import router as fleet_router


def _make_app() -> FastAPI:
    app = FastAPI()
    app.include_router(fleet_router)
    patch("js.web.server._settings", None).start()
    return app


def _make_fleet() -> MagicMock:
    fleet = MagicMock()
    fleet.get_status.return_value = {"agents": []}
    fleet.collaborate = AsyncMock(return_value={"final": "done", "subtasks": {}, "review": None})
    return fleet


def test_fleet_status() -> None:
    fleet = _make_fleet()

    app = _make_app()
    client = TestClient(app)
    with patch("js.web.routers.fleet.get_fleet", return_value=fleet):
        resp = client.get("/api/fleet/status")

    assert resp.status_code == 200
    fleet.get_status.assert_called_once()


def test_fleet_collaborate_success() -> None:
    fleet = _make_fleet()

    app = _make_app()
    client = TestClient(app)
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

    app = _make_app()
    client = TestClient(app)
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

    app = _make_app()
    client = TestClient(app)
    with patch("js.web.routers.fleet.get_fleet", return_value=fleet):
        resp = client.post("/api/fleet/collaborate", json={"task": "x"})

    assert resp.status_code == 500


def test_fleet_collaborate_missing_task() -> None:
    fleet = _make_fleet()

    app = _make_app()
    client = TestClient(app)
    with patch("js.web.routers.fleet.get_fleet", return_value=fleet):
        resp = client.post("/api/fleet/collaborate", json={})

    assert resp.status_code == 400
