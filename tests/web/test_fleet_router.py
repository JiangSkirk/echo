"""Tests for the fleet web router."""

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


def _make_agent() -> MagicMock:
    provider = MagicMock()
    provider.name = "mock"
    model = MagicMock()
    model.id = "gpt"
    model.name = "GPT"
    model.context_window = 8192
    model.supports_vision = False
    provider.models = [model]

    agent = MagicMock()
    agent.settings.providers = [provider]
    return agent


def _make_fleet() -> MagicMock:
    fleet = MagicMock()
    fleet.get_status.return_value = {"agents": [], "tasks": []}

    instance = MagicMock()
    instance.id = "agent-123"
    instance.role = "coder"
    instance.model = "mock/gpt"
    fleet.spawn.return_value = instance

    fleet.dispatch = AsyncMock(return_value="task-456")
    fleet.collaborate = AsyncMock(return_value={"final": "done", "subtasks": []})
    fleet.broadcast = AsyncMock()
    return fleet


def test_fleet_status() -> None:
    agent = _make_agent()
    fleet = _make_fleet()

    app = _make_app()
    client = TestClient(app)
    with patch("js.web.routers.fleet.get_agent", return_value=agent), \
         patch("js.web.routers.fleet.get_fleet", return_value=fleet):
        resp = client.get("/api/fleet/status")

    assert resp.status_code == 200
    fleet.get_status.assert_called_once()


def test_fleet_models() -> None:
    agent = _make_agent()
    fleet = _make_fleet()

    app = _make_app()
    client = TestClient(app)
    with patch("js.web.routers.fleet.get_agent", return_value=agent), \
         patch("js.web.routers.fleet.get_fleet", return_value=fleet):
        resp = client.get("/api/fleet/models")

    assert resp.status_code == 200
    data = resp.json()
    assert len(data["models"]) == 1
    assert data["models"][0]["id"] == "mock/gpt"


def test_fleet_spawn_success() -> None:
    agent = _make_agent()
    fleet = _make_fleet()

    app = _make_app()
    client = TestClient(app)
    with patch("js.web.routers.fleet.get_agent", return_value=agent), \
         patch("js.web.routers.fleet.get_fleet", return_value=fleet):
        resp = client.post(
            "/api/fleet/spawn",
            json={"name": "Coder-1", "role": "coder", "model": "mock/gpt"},
        )

    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    assert data["agent_id"] == "agent-123"
    assert data["role"] == "coder"


def test_fleet_spawn_invalid_model() -> None:
    agent = _make_agent()
    fleet = _make_fleet()

    app = _make_app()
    client = TestClient(app)
    with patch("js.web.routers.fleet.get_agent", return_value=agent), \
         patch("js.web.routers.fleet.get_fleet", return_value=fleet):
        resp = client.post(
            "/api/fleet/spawn",
            json={"name": "Coder-1", "role": "coder", "model": "bad/model"},
        )

    assert resp.status_code == 400


def test_fleet_spawn_invalid_role() -> None:
    agent = _make_agent()
    fleet = _make_fleet()
    fleet.spawn.side_effect = ValueError("Invalid role")

    app = _make_app()
    client = TestClient(app)
    with patch("js.web.routers.fleet.get_agent", return_value=agent), \
         patch("js.web.routers.fleet.get_fleet", return_value=fleet):
        resp = client.post("/api/fleet/spawn", json={"role": "not_a_role"})

    assert resp.status_code == 400


def test_fleet_dispatch_success() -> None:
    agent = _make_agent()
    fleet = _make_fleet()

    app = _make_app()
    client = TestClient(app)
    with patch("js.web.routers.fleet.get_agent", return_value=agent), \
         patch("js.web.routers.fleet.get_fleet", return_value=fleet):
        resp = client.post(
            "/api/fleet/dispatch",
            json={"description": "Do something", "role": "coder", "priority": 3},
        )

    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    assert data["task_id"] == "task-456"


def test_fleet_dispatch_invalid_role() -> None:
    agent = _make_agent()
    fleet = _make_fleet()
    fleet.dispatch = AsyncMock(side_effect=ValueError("bad role"))

    app = _make_app()
    client = TestClient(app)
    with patch("js.web.routers.fleet.get_agent", return_value=agent), \
         patch("js.web.routers.fleet.get_fleet", return_value=fleet):
        resp = client.post("/api/fleet/dispatch", json={"role": "xyz"})

    assert resp.status_code == 400


def test_fleet_collaborate_success() -> None:
    agent = _make_agent()
    fleet = _make_fleet()

    app = _make_app()
    client = TestClient(app)
    with patch("js.web.routers.fleet.get_agent", return_value=agent), \
         patch("js.web.routers.fleet.get_fleet", return_value=fleet):
        resp = client.post(
            "/api/fleet/collaborate",
            json={
                "task": "Build app",
                "subtasks": [
                    {"description": "Write code", "role": "coder"},
                    {"description": "Review code", "role": "reviewer"},
                ],
            },
        )

    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    assert data["result"]["final"] == "done"


def test_fleet_collaborate_invalid_role() -> None:
    agent = _make_agent()
    fleet = _make_fleet()
    fleet.collaborate = AsyncMock(side_effect=ValueError("bad role"))

    app = _make_app()
    client = TestClient(app)
    with patch("js.web.routers.fleet.get_agent", return_value=agent), \
         patch("js.web.routers.fleet.get_fleet", return_value=fleet):
        resp = client.post(
            "/api/fleet/collaborate",
            json={"task": "x", "subtasks": [{"description": "y", "role": "bad"}]},
        )

    assert resp.status_code == 400


def test_fleet_broadcast_success() -> None:
    agent = _make_agent()
    fleet = _make_fleet()

    app = _make_app()
    client = TestClient(app)
    with patch("js.web.routers.fleet.get_agent", return_value=agent), \
         patch("js.web.routers.fleet.get_fleet", return_value=fleet):
        resp = client.post("/api/fleet/broadcast", json={"message": "Hello agents"})

    assert resp.status_code == 200
    assert resp.json()["success"] is True
    fleet.broadcast.assert_called_once_with("Hello agents")


def test_fleet_broadcast_failure() -> None:
    agent = _make_agent()
    fleet = _make_fleet()
    fleet.broadcast = AsyncMock(side_effect=RuntimeError("network down"))

    app = _make_app()
    client = TestClient(app)
    with patch("js.web.routers.fleet.get_agent", return_value=agent), \
         patch("js.web.routers.fleet.get_fleet", return_value=fleet):
        resp = client.post("/api/fleet/broadcast", json={"message": "Hello"})

    assert resp.status_code == 500
