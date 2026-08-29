"""Host tasks page is an empty shell: list is empty, mutate is 503."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from js.config import JSSettings
from js.web.auth import AuthManager
from js.web.server import create_app


def test_tasks_list_is_empty_and_mutate_is_unavailable(tmp_path: Path) -> None:
    settings = JSSettings(
        workspace=tmp_path / "workspace",
        state_dir=tmp_path / "state",
        first_run_completed=True,
        providers=[],
        models=[],
    )
    key = AuthManager(settings.state_dir).create_key("tasks-admin", role="admin")
    app = create_app(runtime_settings=settings)
    headers = {"Host": "localhost", "Origin": "http://localhost", "X-API-Key": key}
    with TestClient(app, headers=headers) as client:
        listed = client.get("/api/tasks")
        assert listed.status_code == 200, listed.text
        assert listed.json() == {"tasks": []}

        missing = client.get("/api/tasks/task-empty")
        assert missing.status_code == 503, missing.text

        for method, path in (
            ("post", "/api/tasks/task-empty/pause"),
            ("post", "/api/tasks/task-empty/resume"),
            ("delete", "/api/tasks/task-empty"),
        ):
            response = getattr(client, method)(path)
            assert response.status_code == 503, f"{method} {path}: {response.text}"
