"""Same-process isolation for the main and Work web applications."""

from __future__ import annotations

import json
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock, MagicMock

import yaml
from fastapi.testclient import TestClient

from js.config import JSSettings, ModelConfig, ModelProviderConfig, SecurityConfig
from js.models.providers import ChatMessage
from js.tools.registry import ToolResult
from js.web.runtime_context import WebRuntime, bind_web_runtime, clear_web_runtime

if TYPE_CHECKING:
    import pytest


class _MainFleet:
    def __init__(self) -> None:
        self.agent_config = {"worker": "", "reviewer": ""}

    def update_agent_config(self, config: dict[str, str]) -> None:
        self.agent_config.update(config)

    def get_agent_config(self) -> dict[str, str]:
        return dict(self.agent_config)


def _write_work_config(path: Path) -> Path:
    config = path / "config.yaml"
    config.write_text(
        """
security:
  api_key_required: false
providers:
  - name: mock
    base_url: http://127.0.0.1:1/v1
    default_model: mock-model
    models:
      - id: mock-model
        name: Mock
        provider: mock
""".strip()
        + "\n",
        encoding="utf-8",
    )
    return config


def _create_main_app(path: Path) -> tuple[Any, _MainFleet]:
    from js.web.server import create_app

    provider = ModelProviderConfig(
        name="main",
        base_url="http://127.0.0.1:2/v1",
        default_model="main-model",
        models=[ModelConfig(id="main-model", name="Main", provider="main")],
    )
    settings = JSSettings(
        workspace=path / "workspace",
        state_dir=path / "state",
        providers=[provider],
        security=SecurityConfig(api_key_required=False),
    )
    settings.workspace.mkdir(parents=True, exist_ok=True)
    settings.state_dir.mkdir(parents=True, exist_ok=True)

    # Admin endpoints reject anonymous guests; mint a main-app admin key.
    from js.web.auth import AuthManager

    admin_key = AuthManager(settings.state_dir).create_key("main-admin", role="admin")

    agent = MagicMock()
    agent.settings = settings
    agent.router._providers = {"main": MagicMock(health_check=AsyncMock(return_value=True))}
    agent.provider_manager.get_all.return_value = []
    fleet = _MainFleet()
    agent.echo_runtime.build_context.return_value = MagicMock()

    async def execute_control_effect(effect: Any, _context: Any) -> tuple[Any, ToolResult]:
        if effect.tool_name == "control_fleet_configure":
            arguments = json.loads(effect.arguments_json)
            fleet.update_agent_config(arguments["config"])
        return (
            ChatMessage(role="tool", content="ok", name=effect.tool_name),
            ToolResult(success=True, output="ok", metadata={}),
        )

    agent.echo_runtime.execute_tool_effect = AsyncMock(side_effect=execute_control_effect)

    @asynccontextmanager
    async def lifespan(app: Any) -> AsyncIterator[None]:
        runtime = WebRuntime(agent=agent, settings=settings, fleet=fleet)
        bind_web_runtime(app, runtime)
        try:
            yield
        finally:
            clear_web_runtime(app, runtime)

    app = create_app(
        lifespan_context=lifespan,
        title="Main Isolation Test App",
        runtime_settings=settings,
    )
    app.state.test_admin_key = admin_key
    return app, fleet


def test_work_agent_config_and_provider_delete_do_not_change_main_fleet(
    tmp_path: Path,
) -> None:
    from js_work.web import create_work_web_app

    main_home = tmp_path / "main"
    work_home = tmp_path / "work"
    work_home.mkdir()
    main_app, main_fleet = _create_main_app(main_home)
    work_app = create_work_web_app(
        config=str(_write_work_config(work_home)),
        home=work_home,
    )
    headers = {"Origin": "http://localhost"}

    with (
        TestClient(main_app, base_url="http://localhost", headers=headers) as main_client,
        TestClient(work_app, base_url="http://localhost", headers=headers) as work_client,
    ):
        # Admin endpoints reject anonymous guests; authenticate both apps.
        from js.web.auth import AuthManager

        main_client.headers["X-API-Key"] = main_app.state.test_admin_key
        work_state_dir = work_app.state.web_runtime.settings.state_dir
        work_client.headers["X-API-Key"] = AuthManager(work_state_dir).create_key(
            "work-admin", role="admin"
        )
        main_update = main_client.post(
            "/api/agents/config",
            json={"config": {"worker": "main/main-model"}},
        )
        assert main_update.status_code == 200
        assert main_fleet.get_agent_config()["worker"] == "main/main-model"

        work_update = work_client.post(
            "/api/agents/config",
            json={"config": {"worker": "mock/mock-model"}},
        )
        assert work_update.status_code == 200
        assert work_update.json()["config"]["worker"] == "mock/mock-model"
        assert work_app.state.web_runtime.fleet.get_agent_config()["worker"] == (
            "mock/mock-model"
        )
        assert main_client.get("/api/agents/config").json()["config"]["worker"] == (
            "main/main-model"
        )
        assert main_fleet.get_agent_config()["worker"] == "main/main-model"

        rejected = work_client.post(
            "/api/agents/config",
            json={"config": {"../other-owner": "mock/mock-model"}},
        )
        assert rejected.status_code == 400
        assert work_client.get("/api/agents/config").json()["config"]["worker"] == (
            "mock/mock-model"
        )
        assert work_app.state.web_runtime.fleet.get_agent_config()["worker"] == (
            "mock/mock-model"
        )

        deleted = work_client.delete("/api/providers/mock")
        assert deleted.status_code == 200
        assert work_client.get("/api/agents/config").json()["config"]["worker"] == ""
        assert work_app.state.web_runtime.fleet.get_agent_config()["worker"] == ""
        assert main_client.get("/api/agents/config").json()["config"]["worker"] == (
            "main/main-model"
        )
        assert main_fleet.get_agent_config()["worker"] == "main/main-model"
        saved_work_config = yaml.safe_load(
            (work_home / "config.yaml").read_text(encoding="utf-8")
        )
        assert saved_work_config["providers"] == []


def test_model_listing_in_each_product_schedules_no_background_discovery(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from js_work.web import create_work_web_app

    main_home = tmp_path / "main"
    work_home = tmp_path / "work"
    work_home.mkdir()
    main_app, _ = _create_main_app(main_home)
    work_app = create_work_web_app(
        config=str(_write_work_config(work_home)),
        home=work_home,
    )
    discover = AsyncMock(return_value={"models": []})
    monkeypatch.setattr(
        "js.models.provider_manager.ProviderManager.discover_models",
        discover,
    )

    with (
        TestClient(main_app, base_url="http://localhost") as main_client,
        TestClient(work_app, base_url="http://localhost") as work_client,
    ):
        work_provider = work_app.state.web_runtime.agent.router._providers["mock"]
        work_provider.health_check = AsyncMock(return_value=True)

        assert work_client.get("/api/models").status_code == 200
        work_refresh = work_app.state.model_refresh_state
        main_refresh = main_app.state.model_refresh_state
        assert work_refresh.last_local_refresh == 0.0
        assert work_refresh.last_cloud_refresh == 0.0
        assert main_refresh.last_local_refresh == 0.0
        assert main_refresh.last_cloud_refresh == 0.0

        assert main_client.get("/api/models").status_code == 200
        assert main_refresh.last_local_refresh == 0.0
        assert main_refresh.last_cloud_refresh == 0.0

    discover.assert_not_awaited()


def test_creating_second_app_keeps_fail_closed_model_refresh_state(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from js_work.web import create_work_web_app

    main_app, _ = _create_main_app(tmp_path / "main")
    discover = AsyncMock(return_value={"models": []})
    monkeypatch.setattr(
        "js.models.provider_manager.ProviderManager.discover_models",
        discover,
    )

    with TestClient(main_app, base_url="http://localhost") as main_client:
        assert main_client.get("/api/models").status_code == 200
        main_refresh = main_app.state.model_refresh_state
        assert main_refresh.last_local_refresh == 0.0
        assert main_refresh.last_cloud_refresh == 0.0

        work_home = tmp_path / "work"
        work_home.mkdir()
        create_work_web_app(
            config=str(_write_work_config(work_home)),
            home=work_home,
        )
        assert main_refresh.last_local_refresh == 0.0
        assert main_refresh.last_cloud_refresh == 0.0

        assert main_client.get("/api/models").status_code == 200
        time.sleep(0.05)
        assert main_refresh.last_local_refresh == 0.0
        assert main_refresh.last_cloud_refresh == 0.0

    discover.assert_not_awaited()


def test_work_app_restores_its_own_persisted_active_model(tmp_path: Path) -> None:
    from js_work.web import create_work_web_app

    work_home = tmp_path / "work"
    work_home.mkdir()
    app = create_work_web_app(
        config=str(_write_work_config(work_home)),
        home=work_home,
    )
    state_dir = app.state.runtime_settings.state_dir
    state_dir.mkdir(parents=True, exist_ok=True)
    (state_dir / "active_model.txt").write_text("mock-model", encoding="utf-8")

    with TestClient(app, base_url="http://localhost"):
        runtime = app.state.web_runtime
        assert runtime.active_model == "mock-model"
        assert runtime.agent.router.preferred_model == "mock-model"
