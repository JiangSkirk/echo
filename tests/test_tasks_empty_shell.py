"""Tasks page is a read-only bots goals view."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from js.config import JSSettings
from js.web.auth import AuthManager
from js.web.server import create_app


def _app(tmp_path: Path) -> tuple[object, Path]:
    settings = JSSettings(
        workspace=tmp_path / "workspace",
        state_dir=tmp_path / "state",
        first_run_completed=True,
        providers=[],
        models=[],
    )
    return create_app(runtime_settings=settings), settings.state_dir


def test_tasks_list_is_empty_until_a_goal_exists(tmp_path: Path) -> None:
    app, state_dir = _app(tmp_path)
    key = AuthManager(state_dir).create_key("tasks-admin", role="admin")
    headers = {"Host": "localhost", "Origin": "http://localhost", "X-API-Key": key}
    with TestClient(app, headers=headers) as client:
        listed = client.get("/api/tasks")
        assert listed.status_code == 200, listed.text
        assert listed.json() == {"tasks": []}

        missing = client.get("/api/tasks/task-empty")
        assert missing.status_code == 404, missing.text

        for method, path in (
            ("post", "/api/tasks/task-empty/pause"),
            ("post", "/api/tasks/task-empty/resume"),
            ("delete", "/api/tasks/task-empty"),
        ):
            response = getattr(client, method)(path)
            assert response.status_code == 503, f"{method} {path}: {response.text}"


def test_tasks_list_projects_scenario_goal(tmp_path: Path) -> None:
    app, state_dir = _app(tmp_path)
    auth = AuthManager(state_dir)
    owner_key = auth.create_key("tasks-owner", role="user")
    other_key = auth.create_key("tasks-other", role="user")
    headers = {"Host": "localhost", "Origin": "http://localhost", "X-API-Key": owner_key}
    with TestClient(app, headers=headers) as client:
        started = client.post("/api/scenarios/code-review/start")
        assert started.status_code == 200, started.text
        payload = started.json()
        goal_id = payload["goal_id"]
        assert payload["room_id"]
        assert payload["bot_ids"]

        listed = client.get("/api/tasks")
        assert listed.status_code == 200, listed.text
        tasks = listed.json()["tasks"]
        assert [item["id"] for item in tasks] == [goal_id]
        assert tasks[0]["type"] == "bots_goal"
        assert tasks[0]["status"] == "pending"

        detail = client.get(f"/api/tasks/{goal_id}")
        assert detail.status_code == 200, detail.text
        assert detail.json()["id"] == goal_id

        other = TestClient(
            app,
            headers={"Host": "localhost", "Origin": "http://localhost", "X-API-Key": other_key},
        )
        assert other.get("/api/tasks").json() == {"tasks": []}
        assert other.get(f"/api/tasks/{goal_id}").status_code == 404
