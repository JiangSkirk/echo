from __future__ import annotations

import warnings
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.routing import APIRoute, iter_route_contexts
from fastapi.testclient import TestClient

from js.config import JSSettings, SecurityConfig
from js.echo.ledger.service import EchoSafetyService
from js.web.runtime_context import WebRuntime, bind_web_runtime, clear_web_runtime
from js.web.server import create_app

_SHARED_GET_PATHS = (
    "/api/status",
    "/api/diag",
    "/api/metrics/providers",
)
_HTTP_METHODS = {"get", "post", "put", "patch", "delete", "options", "head"}


def test_openapi_has_no_duplicate_operation_id_warnings() -> None:
    app = create_app()

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        app.openapi()

    duplicate_warnings = [
        str(warning.message)
        for warning in caught
        if "Duplicate Operation ID" in str(warning.message)
    ]
    assert duplicate_warnings == []


@pytest.mark.parametrize("path", _SHARED_GET_PATHS)
def test_shared_get_path_has_one_effective_operation(path: str) -> None:
    app = create_app()

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        schema = app.openapi()

    operations = {
        method: operation
        for method, operation in schema["paths"][path].items()
        if method in _HTTP_METHODS
    }
    route_operation_ids = [
        route.unique_id
        for context in iter_route_contexts(app.routes)
        if isinstance((route := context.route), APIRoute)
        and route.path == path
        and route.methods == {"GET"}
    ]

    assert list(operations) == ["get"]
    assert operations["get"]["operationId"]
    assert operations["get"]["security"] == [{"APIKeyHeader": []}]
    assert route_operation_ids == [operations["get"]["operationId"]]


@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json"])
def test_api_documentation_routes_are_not_served(path: str) -> None:
    """Swagger UI and the raw schema are unauthenticated reconnaissance value,
    so the HTTP routes stay disabled; app.openapi() remains for in-process use.
    """
    client = TestClient(create_app())

    assert client.get(path).status_code == 404


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


def _main_app(tmp_path: Path) -> Any:
    settings = JSSettings(
        workspace=tmp_path / "workspace",
        state_dir=tmp_path / "state",
        providers=[],
        security=SecurityConfig(api_key_required=False),
        desktop_control_enabled=True,
    )
    settings.workspace.mkdir(parents=True, exist_ok=True)
    settings.state_dir.mkdir(parents=True, exist_ok=True)

    agent = MagicMock()
    agent.settings = settings
    agent._check_degraded = AsyncMock()
    agent.degraded = False
    agent.degraded_reason = None
    agent.registry.get_stats.return_value = {}
    agent.secrets.get_stats.return_value = {}
    agent.event_store.health.return_value = {
        "ok": True,
        "write_failures": 0,
        "consecutive_write_failures": 0,
        "last_error": "",
    }
    agent.metacognition = MagicMock()
    agent.learner = MagicMock()
    agent.optimizer = MagicMock()
    agent.evolver = MagicMock()
    agent.compression_feedback = MagicMock()
    agent._dream_scheduler = MagicMock()
    agent.memory.embedder.health.return_value = SimpleNamespace(
        provider="none",
        active=False,
        fallback_provider=None,
        failure_count=0,
    )
    agent.skills.get_all.return_value = {}

    @asynccontextmanager
    async def lifespan(app: Any) -> AsyncIterator[None]:
        runtime = WebRuntime(
            agent=agent,
            settings=settings,
            echo_safety_service=EchoSafetyService.from_settings(settings),
        )
        bind_web_runtime(app, runtime)
        try:
            yield
        finally:
            clear_web_runtime(app, runtime)

    app = create_app(
        lifespan_context=lifespan,
        title="Main Route Test App",
        runtime_settings=settings,
    )

    @app.get("/_main-only")
    async def main_only() -> dict[str, bool]:
        return {"main": True}

    return app


def test_main_and_work_status_diag_contracts_are_runtime_isolated(tmp_path: Path) -> None:
    from js_work.tools import WorkToolProfile
    from js_work.web import create_work_web_app

    main_home = tmp_path / "main"
    work_home = tmp_path / "work"
    main_home.mkdir()
    work_home.mkdir()
    main_app = _main_app(main_home)
    work_app = create_work_web_app(
        config=str(_write_work_config(work_home)),
        home=work_home,
        profile=WorkToolProfile.SAFE,
    )

    with TestClient(main_app) as main_client, TestClient(work_app) as work_client:
        from js.web.auth import AuthManager

        main_key = AuthManager(main_app.state.web_runtime.settings.state_dir).create_key(
            "main-diag", role="user"
        )
        work_key = AuthManager(work_app.state.web_runtime.settings.state_dir).create_key(
            "work-diag", role="user"
        )
        main_headers = {"X-API-Key": main_key}
        work_headers = {"X-API-Key": work_key}
        main_status = main_client.get("/api/status").json()
        work_status = work_client.get("/api/status").json()
        main_diag = main_client.get("/api/diag", headers=main_headers).json()
        work_diag = work_client.get("/api/diag", headers=work_headers).json()

    assert set(main_status) == set(work_status)
    assert main_status["desktop_control_enabled"] is True
    assert work_status["desktop_control_enabled"] is False
    assert main_status["echo"]["mode"] == "on"
    assert work_status["echo"]["mode"] == "on"
    assert main_status["echo_ledger"]["mode"] == "on"
    assert work_status["echo_ledger"]["mode"] == "on"
    assert main_status["event_store"]["ok"] is True
    assert work_status["event_store"]["ok"] is True
    assert main_status["workspace"] == str(main_home / "workspace")
    assert work_status["workspace"] == str(work_home / ".js-work" / "workspace")

    assert set(main_diag) == set(work_diag)
    main_routes = {route["path"] for route in main_diag["routes"]}
    work_routes = {route["path"] for route in work_diag["routes"]}
    assert "/_main-only" in main_routes
    assert "/_main-only" not in work_routes
    assert "/api/work/routines" not in main_routes
    assert "/api/work/routines" in work_routes
