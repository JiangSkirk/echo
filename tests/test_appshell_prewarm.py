"""AppShell Work prewarm is role-gated, idempotent, and does not switch mode."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import pytest
import yaml
from fastapi.testclient import TestClient


@pytest.fixture()
def appshell_app(tmp_path: Path) -> Any:
    from js.appshell.server import create_appshell_app
    from js_work.tools import WorkToolProfile

    personal = tmp_path / "personal.yaml"
    personal.write_text(
        yaml.safe_dump(
            {
                "workspace": str(tmp_path / "personal-workspace"),
                "state_dir": str(tmp_path / "personal-state"),
                "first_run_completed": True,
                "security": {"api_key_required": True},
                "providers": [],
            }
        ),
        encoding="utf-8",
    )
    work = tmp_path / "work.yaml"
    work.write_text(
        yaml.safe_dump(
            {
                "first_run_completed": True,
                "security": {"api_key_required": True},
                "providers": [],
            }
        ),
        encoding="utf-8",
    )
    return create_appshell_app(
        personal_config=str(personal),
        work_config=str(work),
        work_home=tmp_path / "work-home",
        work_profile=WorkToolProfile.SAFE,
        host="127.0.0.1",
        port=8000,
    )


def _client(appshell_app: Any) -> TestClient:
    return TestClient(
        appshell_app,
        base_url="http://localhost",
        headers={"Origin": "http://localhost"},
        client=("127.0.0.1", 50123),
    )


def test_prewarm_requires_session(appshell_app: Any) -> None:
    with _client(appshell_app) as client:
        response = client.post("/api/appshell/prewarm")
        assert response.status_code == 401
        assert appshell_app.state.work_runtime_ready is False


def test_prewarm_rejects_missing_work_role(appshell_app: Any) -> None:
    from js.web.auth import AuthManager

    key = "js_user-prewarm-key"
    personal_state = appshell_app.state.personal_app.state.runtime_settings.state_dir
    AuthManager(personal_state).provision_existing_key(key, name="user", role="user")

    with _client(appshell_app) as client:
        login = client.post("/api/appshell/session", headers={"X-API-Key": key})
        assert login.status_code == 200, login.text
        response = client.post("/api/appshell/prewarm")
        assert response.status_code == 403, response.text
        detail = response.json().get("detail")
        code = detail.get("code") if isinstance(detail, dict) else None
        assert code == "work_role_required"
        assert appshell_app.state.work_runtime_ready is False
        assert getattr(appshell_app.state.work_app.state, "web_runtime", None) is None


def test_prewarm_is_idempotent_and_does_not_switch_mode(appshell_app: Any) -> None:
    with _client(appshell_app) as client:
        boot = client.post("/api/appshell/bootstrap")
        assert boot.status_code == 200, boot.text
        assert appshell_app.state.work_runtime_ready is False

        first = client.post("/api/appshell/prewarm")
        assert first.status_code == 200, first.text
        assert first.json()["status"] in {"warming", "ready"}

        deadline = time.time() + 30
        while time.time() < deadline and not appshell_app.state.work_runtime_ready:
            time.sleep(0.05)
        assert appshell_app.state.work_runtime_ready is True
        assert appshell_app.state.work_app.state.web_runtime.agent is not None

        second = client.post("/api/appshell/prewarm")
        assert second.status_code == 200, second.text
        assert second.json()["status"] == "ready"

        caps = client.get("/api/appshell/capabilities")
        assert caps.status_code == 200, caps.text
        assert caps.json()["active_mode"] == "personal"
        status = client.get("/api/status")
        assert status.status_code == 200, status.text
        assert status.json()["product_id"] == "js-agent"
