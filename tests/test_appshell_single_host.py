"""B1 single-host surface: one root, hidden children, isolated runtimes."""

from __future__ import annotations

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


def test_root_is_the_only_browser_surface(appshell_app: Any) -> None:
    with TestClient(appshell_app, base_url="http://localhost") as client:
        root = client.get("/")
        assert root.status_code == 200
        assert "text/html" in root.headers.get("content-type", "")
        assert client.get("/personal/").status_code == 404
        assert client.get("/work/").status_code == 404


def test_root_api_without_parent_session_fails_closed(appshell_app: Any) -> None:
    with TestClient(appshell_app, base_url="http://localhost") as client:
        response = client.get("/api/status")
        assert response.status_code == 401
        assert response.json()["detail"] == "AppShell session is required"


def test_child_login_and_legacy_switch_are_hidden(appshell_app: Any) -> None:
    with TestClient(
        appshell_app,
        base_url="http://localhost",
        headers={"Origin": "http://localhost"},
    ) as client:
        assert client.post("/api/auth/session", json={"api_key": "unused"}).status_code == 404
        legacy = client.post("/api/workspace/switch", json={"to_product": "js-work"})
        assert legacy.status_code == 410
        assert legacy.json()["detail"]["use"] == "/api/appshell/switch"


def test_personal_and_work_runtime_storage_remain_physically_isolated(
    appshell_app: Any,
) -> None:
    personal = appshell_app.state.personal_app.state.runtime_settings
    work = appshell_app.state.work_app.state.runtime_settings
    assert personal.product_id == "js-agent"
    assert work.product_id == "js-work"
    assert personal.state_dir != work.state_dir
    assert personal.workspace != work.workspace
    assert personal.bind_port == work.bind_port == 8000


def test_real_appshell_composition_has_separate_local_only_connector_managers(
    appshell_app: Any,
) -> None:
    with TestClient(appshell_app, base_url="http://localhost"):
        personal_runtime = (
            appshell_app.state.personal_app.state.web_runtime.agent.echo_runtime
        )
        work_runtime = appshell_app.state.work_app.state.web_runtime.agent.echo_runtime
        assert personal_runtime._connector_manager is not work_runtime._connector_manager
        for runtime in (personal_runtime, work_runtime):
            assert {
                item["connector_type"]
                for item in runtime._connector_manager.list_available()
            } == {"local_import", "local_publish"}
            assert not runtime._connector_manager.is_available("fake")


def test_health_never_advertises_a_second_port(appshell_app: Any) -> None:
    with TestClient(appshell_app, base_url="http://localhost") as client:
        response = client.get("/api/appshell/health")
        assert response.status_code == 200
        assert response.json()["modes"] == ["personal", "work"]
        assert "8765" not in response.text


def test_ordinary_cli_help_never_advertises_a_second_port() -> None:
    from click.testing import CliRunner

    from js.ui.cli import main as js_main
    from js_work.cli import main as work_main

    runner = CliRunner()
    outputs = [
        runner.invoke(js_main, ["--help"]),
        runner.invoke(js_main, ["appshell", "--help"]),
        runner.invoke(work_main, ["--help"]),
        runner.invoke(work_main, ["web", "--help"]),
    ]
    assert all(result.exit_code == 0 for result in outputs)
    assert all("8765" not in result.output for result in outputs)
