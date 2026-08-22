"""Web entry point for JS Agent Work."""

from __future__ import annotations

import asyncio
import threading
import time
import webbrowser
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from rich.console import Console

from js.product_storage import StorageRoots
from js.ui.cli import _bootstrap_browser_url
from js.web import model_refresh
from js.web import server as web_server
from js.web.deps import AgentConfigState, set_active_model
from js.web.runtime_context import (
    WebRuntime,
    bind_web_runtime,
    clear_web_runtime,
    install_web_runtime_context,
)
from js.web.stats_store import TokenStatsStore
from js_work.agent_factory import create_work_agent, create_work_fleet
from js_work.config import WorkSettings, load_work_settings
from js_work.tools import WorkToolProfile
from js_work.workflows import WorkIntentRouter

if TYPE_CHECKING:
    from fastapi import FastAPI

WORK_WEB_CHANNEL_PREFIX = "js_work_web"

console = Console()


def _tag_work_web_settings(
    settings: WorkSettings,
    *,
    profile: WorkToolProfile,
    host: str,
    port: int,
) -> None:
    object.__setattr__(settings, "bind_host", host)
    object.__setattr__(settings, "bind_port", port)
    object.__setattr__(settings, "product_id", "js-work")
    object.__setattr__(settings, "work_profile", profile.value)
    object.__setattr__(settings, "_web_channel_prefix", WORK_WEB_CHANNEL_PREFIX)
    object.__setattr__(settings, "_work_intent_router", WorkIntentRouter())


def create_work_lifespan(
    *,
    settings: WorkSettings,
    profile: WorkToolProfile,
) -> Any:
    """Create the FastAPI lifespan that boots the Work product line."""

    @asynccontextmanager
    async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
        if not hasattr(app.state, "agent_config_state"):
            app.state.agent_config_state = AgentConfigState()
        if not hasattr(app.state, "model_refresh_state"):
            app.state.model_refresh_state = model_refresh.ModelRefreshState()
        allow_host_code_tools = False
        agent = create_work_agent(
            settings=settings,
            profile=profile,
            allow_host_code_tools=allow_host_code_tools,
        )
        runtime_settings = agent.settings
        if not isinstance(runtime_settings, WorkSettings):
            raise TypeError("Work agent returned non-WorkSettings")
        object.__setattr__(agent, "_work_profile", profile.value)
        echo_safety_service = agent.echo_safety_service
        stats_store = TokenStatsStore(runtime_settings.state_dir)
        runtime = WebRuntime(
            agent=agent,
            settings=runtime_settings,
            fleet_factory=lambda: create_work_fleet(
                settings=runtime_settings,
                profile=profile,
                allow_host_code_tools=allow_host_code_tools,
            ),
            stats_store=stats_store,
            echo_safety_service=echo_safety_service,
        )
        cast("Any", runtime).agent_config_state = app.state.agent_config_state
        cast("Any", runtime).model_refresh_state = app.state.model_refresh_state
        agent.set_fleet_getter(runtime.get_or_create_fleet)
        agent.set_active_model_publisher(set_active_model)
        if agent.registry.get("fleet_collaborate") is not None:
            agent.register_fleet_tool(runtime.get_or_create_fleet)
        bind_web_runtime(app, runtime)

        runtime_settings.echo_engine = "on"
        runtime.bootstrap_admin_key = (
            None
            if bool(getattr(runtime_settings, "_appshell_managed", False))
            else web_server._provision_bootstrap_admin_key(runtime_settings)
        )
        persisted_model = web_server._load_active_model(runtime_settings.state_dir)
        if persisted_model and agent.router.get_model_config(persisted_model) is not None:
            runtime.active_model = persisted_model
            agent.router.preferred_model = persisted_model
        agent.start_background_tasks()

        try:
            agent.memory.cleanup_empty_sessions()
        except Exception:
            pass

        runtime.startup_time = asyncio.get_event_loop().time()
        try:
            yield
        finally:
            try:
                await web_server._close_runtime_fleet(runtime.fleet, runtime_name="JS Agent Work")
            finally:
                try:
                    await agent.close()
                finally:
                    clear_web_runtime(app, runtime)

    return _lifespan


def create_work_web_app(
    *,
    config: str | None = None,
    home: Path | None = None,
    personal_roots: StorageRoots | None = None,
    profile: WorkToolProfile = WorkToolProfile.EXECUTE,
    host: str = "127.0.0.1",
    port: int = 8000,
) -> FastAPI:
    """Build the Work Web app without loading the regular JS Agent state."""
    settings = load_work_settings(config, home=home, personal_roots=personal_roots)
    _tag_work_web_settings(settings, profile=profile, host=host, port=port)
    app = web_server.create_app(
        lifespan_context=create_work_lifespan(settings=settings, profile=profile),
        title="JS Agent Work Web",
        runtime_settings=settings,
    )
    install_web_runtime_context(app)
    from js_work.routines.web import router as routines_router

    app.include_router(routines_router)
    return app


def serve_work_web(
    *,
    config: str | None = None,
    home: Path | None = None,
    personal_roots: StorageRoots | None = None,
    profile: WorkToolProfile = WorkToolProfile.EXECUTE,
    host: str = "127.0.0.1",
    port: int = 8000,
    reload: bool = False,
    open_browser: bool = False,
) -> None:
    """Start the JS Agent Work Web server."""
    import uvicorn

    app = create_work_web_app(
        config=config,
        home=home,
        personal_roots=personal_roots,
        profile=profile,
        host=host,
        port=port,
    )
    url = f"http://{host}:{port}"
    console.print(f"[green]Starting JS Agent Work Web at {url}[/green]")
    console.print(f"[dim]Profile: {profile.value} | State: ~/.js-work[/dim]")

    if open_browser:

        def _open() -> None:
            time.sleep(1.5)
            runtime_settings = cast("WorkSettings", app.state.runtime_settings)
            webbrowser.open(_bootstrap_browser_url(url, runtime_settings.state_dir))

        threading.Thread(target=_open, daemon=True).start()

    uvicorn.run(app, host=host, port=port, reload=reload)
