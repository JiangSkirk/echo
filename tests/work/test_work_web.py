from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from click.testing import CliRunner
from fastapi import FastAPI
from fastapi.testclient import TestClient

from js_work.cli import main as work_main
from js_work.tools import WorkToolProfile


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


def test_create_work_web_app_bootstraps_work_agent_without_skills(tmp_path: Path) -> None:
    from js_work.web import create_work_web_app

    config = _write_work_config(tmp_path)
    app = create_work_web_app(config=str(config), home=tmp_path, profile=WorkToolProfile.SAFE)

    with TestClient(
        app, base_url="http://localhost", headers={"Origin": "http://localhost"}
    ) as client:
        resp = client.get("/api/status")
        assert resp.status_code == 200
        data = resp.json()

        assert data["state_dir"] == str(tmp_path / ".js-work" / "state")
        assert data["workspace"] == str(tmp_path / ".js-work" / "workspace")
        assert data["product_id"] == "js-work"
        assert data["profile"] == "safe"
        assert data["echo"]["mode"] == "on"
        assert data["echo_ledger"]["mode"] == "on"

        from js.web import server as web_server

        runtime = app.state.web_runtime
        agent = runtime.agent
        assert agent is not None
        assert web_server._agent is not agent
        assert agent.skills is None
        assert agent.promotion_store is None
        assert agent.settings.echo_engine == "on"
        tool_names = {tool.name for tool in agent.registry.list_tools()}
        assert "file_write" not in tool_names
        assert "shell" not in tool_names
        assert not any(name.startswith("skill_") for name in tool_names)
        assert not (tmp_path / ".js-work" / "state" / "skills.db").exists()
        assert not (tmp_path / ".js-work" / "state" / "skill_promotions.db").exists()

        page = client.get("/")
        assert page.status_code == 200
        assert "<title>JS Agent Work</title>" in page.text
        assert 'class="rail-brand"' in page.text


@pytest.mark.parametrize("fleet_timeout", [False, True], ids=["success", "timeout"])
@pytest.mark.asyncio
async def test_work_lifespan_closes_fleet_and_releases_agent_on_timeout(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    fleet_timeout: bool,
) -> None:
    from js.web import server as web_server
    from js_work.config import load_work_settings
    from js_work.web import create_work_lifespan

    settings = load_work_settings(home=tmp_path)
    events: list[str] = []
    agent = MagicMock()
    agent.settings = settings
    agent.memory.cleanup_empty_sessions.return_value = 0

    async def close_agent() -> None:
        events.append("agent")

    async def close_fleet() -> None:
        events.append("fleet")
        if fleet_timeout:
            raise TimeoutError("fleet close timed out")

    agent.close = AsyncMock(side_effect=close_agent)
    fleet = MagicMock()
    fleet.close_all = AsyncMock(side_effect=close_fleet)
    telemetry_logger = MagicMock()

    monkeypatch.setattr("js_work.web.create_work_agent", lambda **_kwargs: agent)
    monkeypatch.setattr("js_work.web.create_work_fleet", lambda **_kwargs: fleet)
    monkeypatch.setattr(web_server, "logger", telemetry_logger)

    app = FastAPI()
    lifespan = create_work_lifespan(settings=settings, profile=WorkToolProfile.EXECUTE)
    async with lifespan(app):
        runtime = app.state.web_runtime
        assert runtime.fleet is None
        assert runtime.fleet_factory is not None
        assert runtime.get_or_create_fleet() is fleet

    assert events == ["fleet", "agent"]
    fleet.close_all.assert_awaited_once()
    agent.close.assert_awaited_once()
    assert app.state.web_runtime is None
    if fleet_timeout:
        assert any(
            "fleet shutdown degraded" in call.args[0].lower()
            for call in telemetry_logger.warning.call_args_list
        )


def test_work_web_diag_and_skill_endpoints_are_skill_free(tmp_path: Path) -> None:
    from js_work.web import create_work_web_app

    config = _write_work_config(tmp_path)
    app = create_work_web_app(config=str(config), home=tmp_path)

    with TestClient(
        app, base_url="http://localhost", headers={"Origin": "http://localhost"}
    ) as client:
        from js.web.auth import AuthManager

        key = AuthManager(app.state.web_runtime.settings.state_dir).create_key(
            "work-diag", role="user"
        )
        diag = client.get("/api/diag", headers={"X-API-Key": key})
        assert diag.status_code == 200
        diag_data = diag.json()
        assert diag_data["hermes_bridge"] == {
            "enabled": False,
            "opt_in": False,
            "skills_loaded": 0,
        }
        assert diag_data["subsystems"]["evolver"] is False

        skills = client.get("/api/skills")
        assert skills.status_code == 200
        assert skills.json()["skills"] == []
        assert skills.json()["disabled"] is True


def test_authenticated_work_file_api_is_owner_scoped(tmp_path: Path) -> None:
    from js.echo.attachment_gate import owner_slug, session_slug
    from js.web.auth import AuthManager
    from js_work.web import create_work_web_app

    config = tmp_path / "config-auth.yaml"
    config.write_text("security:\n  api_key_required: true\nproviders: []\n", encoding="utf-8")
    app = create_work_web_app(config=str(config), home=tmp_path, profile=WorkToolProfile.OFFICE)

    with TestClient(app, base_url="http://localhost") as client:
        state_dir = app.state.web_runtime.settings.state_dir
        auth = AuthManager(state_dir)
        key_a = auth.create_key("owner-a", role="user")
        key_b = auth.create_key("owner-b", role="user")
        owner_a = auth.verify(key_a)["key_hash"]
        owner_b = auth.verify(key_b)["key_hash"]
        workspace = app.state.web_runtime.settings.workspace
        session_id = "session-a"
        root_a = workspace / "owners" / owner_slug(owner_a) / session_slug(session_id)
        root_b = workspace / "owners" / owner_slug(owner_b) / session_slug(session_id)
        root_a.mkdir(parents=True)
        root_b.mkdir(parents=True)
        (root_a / "a-only.txt").write_text("owner a", encoding="utf-8")
        (root_b / "b-secret.txt").write_text("owner b", encoding="utf-8")

        missing_session = client.get("/api/files", headers={"X-API-Key": key_a})
        listed = client.get(
            "/api/files",
            params={"session_id": session_id},
            headers={"X-API-Key": key_a},
        )
        own_preview = client.get(
            "/api/file-preview",
            params={"path": "a-only.txt", "session_id": session_id},
            headers={"X-API-Key": key_a},
        )
        cross_preview = client.get(
            "/api/file-preview",
            params={
                "path": (f"owners/{owner_slug(owner_b)}/{session_slug(session_id)}/b-secret.txt"),
                "session_id": session_id,
            },
            headers={"X-API-Key": key_a},
        )
        cross_list = client.get(
            "/api/files",
            params={
                "path": f"owners/{owner_slug(owner_b)}/{session_slug(session_id)}",
                "session_id": session_id,
            },
            headers={"X-API-Key": key_a},
        )

    assert missing_session.status_code == 400
    assert listed.status_code == 200
    assert "a-only.txt" in listed.json()["output"]
    assert "b-secret.txt" not in listed.json()["output"]
    assert own_preview.status_code == 200
    assert own_preview.json()["content"] == "owner a"
    assert cross_preview.status_code == 403
    assert cross_list.status_code == 403


def test_authenticated_work_web_removes_host_code_tools(tmp_path: Path) -> None:
    from js_work.web import create_work_web_app

    config = tmp_path / "config-auth-execute.yaml"
    config.write_text("security:\n  api_key_required: true\nproviders: []\n", encoding="utf-8")
    app = create_work_web_app(
        config=str(config),
        home=tmp_path,
        profile=WorkToolProfile.EXECUTE,
    )

    with TestClient(app, base_url="http://localhost"):
        tool_names = {tool.name for tool in app.state.web_runtime.agent.registry.list_tools()}

    assert "shell" not in tool_names
    assert "python" not in tool_names


def test_no_auth_work_web_still_removes_host_code_tools(tmp_path: Path) -> None:
    from js_work.web import create_work_web_app

    app = create_work_web_app(
        config=str(_write_work_config(tmp_path)),
        home=tmp_path,
        profile=WorkToolProfile.EXECUTE,
    )

    with TestClient(
        app,
        base_url="http://localhost",
        headers={"Origin": "http://localhost"},
    ):
        tool_names = {tool.name for tool in app.state.web_runtime.agent.registry.list_tools()}

    assert "shell" not in tool_names
    assert "python" not in tool_names


def test_bootstrap_admin_key_has_a_private_work_owner_scope(tmp_path: Path) -> None:
    from js.echo.attachment_gate import owner_slug, session_slug
    from js.web.auth import AuthManager
    from js_work.web import create_work_web_app

    config = tmp_path / "config-bootstrap-owner.yaml"
    config.write_text("security:\n  api_key_required: true\nproviders: []\n", encoding="utf-8")
    app = create_work_web_app(config=str(config), home=tmp_path, profile=WorkToolProfile.OFFICE)

    with TestClient(app, base_url="http://localhost") as client:
        runtime = app.state.web_runtime
        key = (
            (runtime.settings.state_dir / "bootstrap_admin_key.txt")
            .read_text(encoding="utf-8")
            .strip()
        )
        owner = AuthManager(runtime.settings.state_dir).verify(key)["key_hash"]
        workspace = runtime.settings.workspace
        session_id = "bootstrap-session"
        private_root = workspace / "owners" / owner_slug(owner) / session_slug(session_id)
        private_root.mkdir(parents=True)
        (private_root / "bootstrap-private.txt").write_text("private", encoding="utf-8")
        (workspace / "global-secret.txt").write_text("global", encoding="utf-8")

        response = client.get(
            "/api/files",
            params={"session_id": session_id},
            headers={"X-API-Key": key},
        )

    assert response.status_code == 200
    assert "bootstrap-private.txt" in response.json()["output"]
    assert "global-secret.txt" not in response.json()["output"]


def test_local_work_upload_api_requires_and_isolates_session(tmp_path: Path) -> None:
    from js.echo.attachment_gate import owner_slug, session_slug
    from js_work.web import create_work_web_app

    app = create_work_web_app(
        config=str(_write_work_config(tmp_path)),
        home=tmp_path,
        profile=WorkToolProfile.OFFICE,
    )
    with TestClient(app, base_url="http://localhost") as client:
        # Anonymous guests are read-only; authenticate as a work user.
        from js.web.auth import AuthManager

        state_dir = app.state.web_runtime.settings.state_dir
        user_key = AuthManager(state_dir).create_key("work-user", role="user")
        headers = {"Origin": "http://localhost", "X-API-Key": user_key}
        owner = AuthManager(state_dir).verify(user_key)["key_hash"]
        missing = client.post(
            "/api/upload",
            files={"file": ("missing.txt", b"missing", "text/plain")},
            headers=headers,
        )
        first = client.post(
            "/api/upload",
            data={"session_id": "session-a"},
            files={"file": ("first.txt", b"first", "text/plain")},
            headers=headers,
        )
        second = client.post(
            "/api/upload",
            data={"session_id": "session-b"},
            files={"file": ("second.txt", b"second", "text/plain")},
            headers=headers,
        )
        missing_list = client.get("/api/uploads", headers=headers)
        list_a = client.get("/api/uploads", params={"session_id": "session-a"}, headers=headers)
        list_b = client.get("/api/uploads", params={"session_id": "session-b"}, headers=headers)
        cross_preview = client.get(
            "/api/file-preview",
            params={"path": second.json()["path"], "session_id": "session-a"},
            headers=headers,
        )

        workspace = app.state.web_runtime.settings.workspace

    assert missing.status_code == 400
    assert first.status_code == 200
    assert second.status_code == 200
    assert missing_list.status_code == 400
    assert [item["name"] for item in list_a.json()["files"]] == ["first.txt"]
    assert [item["name"] for item in list_b.json()["files"]] == ["second.txt"]
    assert cross_preview.status_code == 403
    assert (
        workspace / "uploads" / owner_slug(owner) / session_slug("session-a") / "first.txt"
    ).read_bytes() == b"first"


@pytest.mark.parametrize("profile", list(WorkToolProfile))
def test_work_web_all_desktop_endpoints_are_forbidden_before_host_probes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    profile: WorkToolProfile,
) -> None:
    from js.tools.desktop import wizard as desktop_wizard_module
    from js.tools.desktop.permissions import PermissionChecker
    from js_work.web import create_work_web_app

    host_probe_calls: list[str] = []

    def fail_permission_probe() -> bool:
        host_probe_calls.append("PermissionChecker")
        raise AssertionError("Work desktop endpoint probed host permissions")

    def fail_wizard_probe() -> Any:
        host_probe_calls.append("run_wizard")
        raise AssertionError("Work desktop endpoint ran the desktop wizard")

    monkeypatch.setattr(PermissionChecker, "is_macos", fail_permission_probe)
    monkeypatch.setattr(desktop_wizard_module, "run_wizard", fail_wizard_probe)

    home = tmp_path / profile.value
    home.mkdir()
    app = create_work_web_app(
        config=str(_write_work_config(home)),
        home=home,
        profile=profile,
    )

    with TestClient(
        app,
        base_url="http://localhost",
        headers={"Origin": "http://localhost"},
    ) as client:
        runtime = app.state.web_runtime
        before = {tool.name for tool in runtime.agent.registry.list_tools()}
        responses = [
            client.get("/api/desktop/status"),
            client.post("/api/desktop/toggle"),
            client.get("/api/desktop/wizard"),
            client.post(
                "/api/desktop/wizard/action",
                json={"action_type": "install"},
            ),
            client.post("/api/desktop/wizard/enable"),
            client.post("/api/desktop/wizard/enable-writes"),
            client.get("/api/desktop/wizard/status"),
        ]

        assert [response.status_code for response in responses] == [403] * 7
        assert host_probe_calls == []
        assert {tool.name for tool in runtime.agent.registry.list_tools()} == before
        assert runtime.agent.settings.desktop_control_enabled is False


def test_main_and_work_diag_routes_stay_bound_to_the_request_app(tmp_path: Path) -> None:
    from collections.abc import AsyncIterator
    from contextlib import asynccontextmanager

    from js.agent import JSAgent
    from js.config import JSSettings
    from js.echo.ledger.service import EchoSafetyService
    from js.web import server as web_server
    from js.web.auth import AuthManager
    from js.web.runtime_context import WebRuntime, bind_web_runtime, clear_web_runtime
    from js.web.stats_store import TokenStatsStore
    from js_work.web import create_work_web_app

    main_home = tmp_path / "main"
    work_home = tmp_path / "work"
    main_settings = JSSettings(
        workspace=main_home / "workspace",
        state_dir=main_home / "state",
        providers=[],
        security={"api_key_required": False},
    )

    @asynccontextmanager
    async def main_lifespan(app: Any) -> AsyncIterator[None]:
        agent = JSAgent(main_settings)
        runtime = WebRuntime(
            agent=agent,
            settings=main_settings,
            stats_store=TokenStatsStore(main_settings.state_dir),
            echo_safety_service=EchoSafetyService.from_settings(main_settings),
        )
        bind_web_runtime(app, runtime)
        try:
            yield
        finally:
            await agent.close()
            clear_web_runtime(app, runtime)

    main_app = web_server.create_app(
        lifespan_context=main_lifespan,
        title="Main Test App",
        runtime_settings=main_settings,
    )

    @main_app.get("/_main-only")
    async def main_only() -> dict[str, bool]:
        return {"main": True}

    work_home.mkdir()
    work_app = create_work_web_app(
        config=str(_write_work_config(work_home)),
        home=work_home,
    )

    with TestClient(main_app) as main_client, TestClient(work_app) as work_client:
        main_runtime = main_app.state.web_runtime
        work_runtime = work_app.state.web_runtime
        main_runtime.agent.router.health_check = AsyncMock(return_value={})
        work_runtime.agent.router.health_check = AsyncMock(return_value={})
        main_runtime.stats_store.record(
            model="main-model",
            provider="main",
            prompt_tokens=11,
            completion_tokens=1,
        )
        for _ in range(2):
            work_runtime.stats_store.record(
                model="work-model",
                provider="work",
                prompt_tokens=22,
                completion_tokens=2,
            )

        main_routes = {
            route["path"]
            for route in main_client.get(
                "/api/diag",
                headers={
                    "X-API-Key": AuthManager(main_runtime.settings.state_dir).create_key(
                        "main-diag", role="user"
                    )
                },
            ).json()["routes"]
        }
        work_routes = {
            route["path"]
            for route in work_client.get(
                "/api/diag",
                headers={
                    "X-API-Key": AuthManager(work_runtime.settings.state_dir).create_key(
                        "work-diag", role="user"
                    )
                },
            ).json()["routes"]
        }
        main_calls = main_client.get("/api/dashboard").json()["token_stats"]["total"]["calls"]
        work_calls = work_client.get("/api/dashboard").json()["token_stats"]["total"]["calls"]

    assert "/_main-only" in main_routes
    assert "/api/work/routines" not in main_routes
    assert "/_main-only" not in work_routes
    assert "/api/work/routines" in work_routes
    assert main_calls == 1
    assert work_calls == 2


def test_work_web_chat_uses_echo_runtime_with_work_channel(
    monkeypatch: Any, tmp_path: Path
) -> None:
    from js_work.web import create_work_web_app

    config = _write_work_config(tmp_path)
    captured: dict[str, Any] = {}

    class FakeMessage:
        role = "assistant"
        content = "Work web response"

    class FakeState:
        session_id = "work-web-session"
        turn_count = 1
        total_tokens = {"input": 1, "output": 1}
        cost_estimate = 0.0
        status = "completed"
        model = "mock-model"
        error_message = None
        messages = [FakeMessage()]

    async def fake_run_echo_turn(agent: Any, message: str, **kwargs: Any) -> FakeState:
        captured["agent"] = agent
        captured["message"] = message
        captured.update(kwargs)
        return FakeState()

    monkeypatch.setattr("js.web.routers.chat.run_echo_turn", fake_run_echo_turn)
    app = create_work_web_app(config=str(config), home=tmp_path)

    with TestClient(app, base_url="http://localhost") as client:
        # Anonymous guests are read-only; authenticate as a work user.
        from js.web.auth import AuthManager

        state_dir = app.state.web_runtime.settings.state_dir
        user_key = AuthManager(state_dir).create_key("work-user", role="user")
        resp = client.post(
            "/api/chat",
            json={"message": "搜索并整理资料"},
            headers={"Origin": "http://localhost", "X-API-Key": user_key},
        )
        expected_owner = AuthManager(state_dir).verify(user_key)["key_hash"]

    assert resp.status_code == 200
    assert resp.json()["response"] == "Work web response"
    assert captured["channel"] == "js_work_web_api_chat"
    assert captured["owner_key_hash"] == expected_owner
    assert captured["agent"].settings.state_dir == tmp_path / ".js-work" / "state"
    assert "优先使用搜索" in captured["message"]
    assert "不要调用 skill" in captured["message"]


def test_work_web_fleet_does_not_inherit_skills(monkeypatch: Any, tmp_path: Path) -> None:
    from js.web.deps import set_globals
    from js.web.routers import fleet as fleet_router
    from js_work.agent_factory import create_work_agent
    from js_work.config import load_work_settings

    settings = load_work_settings(home=tmp_path)
    agent = create_work_agent(settings=settings)
    set_globals(agent, settings)
    monkeypatch.setattr(fleet_router, "_fleet", None)

    fleet = fleet_router.get_fleet()

    assert fleet._inherit_skills is False
    assert fleet._skills_source is None


def test_work_web_apps_keep_runtime_isolated_when_peer_starts_and_stops(
    monkeypatch: Any, tmp_path: Path
) -> None:
    from js.web import server as web_server
    from js.web.deps import (
        get_active_model,
        get_agent,
        get_settings,
        get_stats_store,
        set_active_model,
    )
    from js_work.web import create_work_web_app

    class FakeMemory:
        def cleanup_empty_sessions(self) -> int:
            return 0

    class FakeAgent:
        def __init__(self, settings: Any) -> None:
            self.settings = settings
            self.memory = FakeMemory()
            self.echo_safety_service = MagicMock()
            self.registry = MagicMock()
            self.registry.get.return_value = None
            self.closed = False

        def set_fleet_getter(self, getter: Any) -> None:
            self.fleet_getter = getter

        def set_active_model_publisher(self, publisher: Any) -> None:
            self.active_model_publisher = publisher

        def register_fleet_tool(self, getter: Any) -> None:
            self.fleet_tool_getter = getter

        def start_background_tasks(self) -> None:
            return None

        async def close(self) -> None:
            self.closed = True

    def fake_create_work_agent(
        *,
        settings: Any,
        profile: WorkToolProfile,
        allow_host_code_tools: bool,
    ) -> FakeAgent:
        assert allow_host_code_tools is False
        return FakeAgent(settings)

    monkeypatch.setattr("js_work.web.create_work_agent", fake_create_work_agent)

    home_a = tmp_path / "app-a"
    home_b = tmp_path / "app-b"
    home_a.mkdir()
    home_b.mkdir()
    app_a = create_work_web_app(config=str(_write_work_config(home_a)), home=home_a)
    app_b = create_work_web_app(config=str(_write_work_config(home_b)), home=home_b)

    def add_runtime_probe(app: Any) -> None:
        @app.get("/_test/runtime")
        async def runtime_probe() -> dict[str, str]:
            stats_store = get_stats_store()
            assert stats_store is not None
            return {
                "deps_agent": str(get_agent().settings.state_dir),
                "deps_settings": str(get_settings().state_dir),
                "server_agent": str(web_server.get_agent().settings.state_dir),
                "stats_store": str(stats_store.db_path.parent),
            }

        @app.post("/_test/model/{model}")
        async def set_runtime_model(model: str) -> dict[str, str]:
            set_active_model(model)
            return {"model": get_active_model()}

        @app.get("/_test/model")
        async def get_runtime_model() -> dict[str, str]:
            return {"model": get_active_model()}

    add_runtime_probe(app_a)
    add_runtime_probe(app_b)
    expected_a = str(home_a / ".js-work" / "state")
    expected_b = str(home_b / ".js-work" / "state")

    with TestClient(app_a) as client_a:
        assert set(client_a.get("/_test/runtime").json().values()) == {expected_a}
        assert client_a.post("/_test/model/model-a").json() == {"model": "model-a"}
        with TestClient(app_b) as client_b:
            assert set(client_b.get("/_test/runtime").json().values()) == {expected_b}
            assert client_b.get("/_test/model").json() == {"model": ""}
            assert client_b.post("/_test/model/model-b").json() == {"model": "model-b"}
            assert set(client_a.get("/_test/runtime").json().values()) == {expected_a}
            assert client_a.get("/_test/model").json() == {"model": "model-a"}

        assert app_b.state.web_runtime is None
        assert app_a.state.web_runtime is not None
        assert set(client_a.get("/_test/runtime").json().values()) == {expected_a}
        assert client_a.get("/_test/model").json() == {"model": "model-a"}


def test_js_work_web_cli_builds_work_web_app(monkeypatch: Any, tmp_path: Path) -> None:
    captured: dict[str, Any] = {}
    fake_app = MagicMock()

    def fake_create_work_web_app(
        *,
        config: str | None,
        home: Path | None,
        personal_roots: Any,
        profile: WorkToolProfile,
        host: str,
        port: int,
        manage_orind: bool = False,
    ) -> MagicMock:
        captured["config"] = config or ""
        captured["home"] = str(home)
        captured["personal_roots"] = personal_roots
        captured["profile"] = profile.value
        captured["host"] = host
        captured["port"] = port
        captured["manage_orind"] = manage_orind
        return fake_app

    def fake_uvicorn_run(app: Any, *, host: str, port: int, reload: bool) -> None:
        captured["app"] = app
        captured["uvicorn_host"] = host
        captured["uvicorn_port"] = port
        captured["reload"] = reload

    monkeypatch.setattr("js_work.web.create_work_web_app", fake_create_work_web_app)
    monkeypatch.setattr("uvicorn.run", fake_uvicorn_run)

    result = CliRunner().invoke(
        work_main,
        [
            "--home",
            str(tmp_path),
            "--profile",
            "office",
            "web",
            "--host",
            "127.0.0.1",
            "--port",
            "8765",
        ],
    )

    assert result.exit_code == 0
    assert captured == {
        "config": "",
        "home": str(tmp_path),
        "personal_roots": None,
        "profile": "office",
        "host": "127.0.0.1",
        "port": 8765,
        "manage_orind": True,
        "app": fake_app,
        "uvicorn_host": "127.0.0.1",
        "uvicorn_port": 8765,
        "reload": False,
    }
