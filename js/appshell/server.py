"""Single-host AppShell server with parent-controlled root routing."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import AsyncExitStack, asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException

from js.appshell.bootstrap_key import (
    appshell_provision_key_enabled,
    provision_shared_bootstrap_key,
)
from js.appshell.principal import AppShellSessionStore
from js.appshell.routing import (
    AppShellModeGate,
    AppShellRoutingMiddleware,
    AppShellWebSocketRegistry,
)
from js.config import JSSettings
from js.echo.turn_runtime import _workspace_handle
from js.product_storage import StorageRoots
from js.web import server as web_server
from js.web.auth import AuthManager
from js_work.tools import WorkToolProfile
from js_work.web import create_work_web_app


def ensure_work_runtime_blocking(app: FastAPI, *, timeout: float = 60.0) -> None:
    """Start the Work child on the AppShell loop and wait (tests / sync helpers)."""
    if getattr(app.state, "work_runtime_ready", False):
        return
    ensure = getattr(app.state, "ensure_work_runtime", None)
    if not callable(ensure):
        raise RuntimeError("Work bootstrap is unavailable")
    loop = getattr(app.state, "appshell_loop", None)
    if loop is None:
        raise RuntimeError("AppShell event loop is unavailable")
    future = asyncio.run_coroutine_threadsafe(ensure(), loop)
    future.result(timeout=timeout)


def create_appshell_app(
    *,
    personal_config: str | None = None,
    work_config: str | None = None,
    work_home: Path | None = None,
    work_profile: WorkToolProfile = WorkToolProfile.EXECUTE,
    host: str = "127.0.0.1",
    port: int = 8000,
    manage_orind: bool = False,
) -> FastAPI:
    """Build one parent host with isolated Personal and Work child runtimes.

    Children are never selected by URL/product input. Root ``/api/*`` and
    ``/ws`` are dispatched solely from the parent ``AppShellPrincipalV1``.
    """
    personal_settings: JSSettings
    if personal_config is not None:
        personal_settings = JSSettings.from_file(personal_config)
    else:
        personal_settings = JSSettings.from_file()
    object.__setattr__(personal_settings, "bind_host", host)
    object.__setattr__(personal_settings, "bind_port", port)
    object.__setattr__(personal_settings, "product_id", "js-agent")
    object.__setattr__(personal_settings, "_appshell_managed", True)
    if manage_orind:
        from js.orin.supervisor import prepare_product_orin

        prepare_product_orin(personal_settings)

    personal_app = web_server.create_app(
        runtime_settings=personal_settings,
        title="JS Agent",
        manage_orind=manage_orind,
    )

    personal_roots = StorageRoots(
        config_path=personal_settings.config_source_path,
        workspace=personal_settings.workspace.expanduser().resolve(strict=False),
        state_dir=personal_settings.state_dir.expanduser().resolve(strict=False),
    )

    work_app = create_work_web_app(
        config=work_config,
        home=work_home,
        personal_roots=personal_roots,
        profile=work_profile,
        host=host,
        port=port,
        manage_orind=manage_orind,
    )
    work_settings = work_app.state.runtime_settings
    object.__setattr__(work_settings, "_appshell_managed", True)
    # Pre-lifespan peer link (may be replaced after children boot if agents
    # bind a different live settings object).
    object.__setattr__(personal_settings, "_appshell_peer_settings", work_settings)
    object.__setattr__(work_settings, "_appshell_peer_settings", personal_settings)
    session_store = AppShellSessionStore(personal_settings.state_dir / "appshell_sessions.db")

    def _wire_appshell_onboarding_peers(parent_app: FastAPI) -> None:
        """Link live Personal/Work settings so onboarding skip is product-wide.

        Work's lifespan may create a fresh agent/settings object; always wire
        the peer on ``web_runtime.settings`` (request-path authority), not only
        the pre-boot ``app.state.runtime_settings`` snapshot. Workspace paths,
        leases, and approvals are never mirrored.
        """
        personal_live = personal_app.state.web_runtime.settings
        work_live = work_app.state.web_runtime.settings
        for live in (personal_live, work_live):
            object.__setattr__(live, "_appshell_managed", True)
        object.__setattr__(personal_live, "_appshell_peer_settings", work_live)
        object.__setattr__(work_live, "_appshell_peer_settings", personal_live)
        personal_app.state.runtime_settings = personal_live
        work_app.state.runtime_settings = work_live
        parent_app.state.work_workspace_handle = _workspace_handle(work_live.workspace)

    def _bind_child_epoch(child_app: FastAPI) -> None:
        child_app.state.web_runtime.agent.__dict__["_appshell_epoch_validator"] = (
            session_store.require_epoch_current
        )
        child_app.state.web_runtime.agent.__dict__["_appshell_operation_store"] = session_store

    @asynccontextmanager
    async def appshell_lifespan(parent_app: FastAPI) -> AsyncIterator[None]:
        work_boot_lock = asyncio.Lock()
        parent_app.state.appshell_loop = asyncio.get_running_loop()
        parent_app.state.work_runtime_ready = False
        async with AsyncExitStack() as stack:

            async def ensure_work_runtime() -> None:
                async with work_boot_lock:
                    if getattr(parent_app.state, "work_runtime_ready", False):
                        return
                    if getattr(work_app.state, "web_runtime", None) is not None:
                        _wire_appshell_onboarding_peers(parent_app)
                        _bind_child_epoch(work_app)
                        parent_app.state.work_runtime_ready = True
                        return
                    await stack.enter_async_context(work_app.router.lifespan_context(work_app))
                    _wire_appshell_onboarding_peers(parent_app)
                    _bind_child_epoch(work_app)
                    parent_app.state.work_runtime_ready = True

            parent_app.state.ensure_work_runtime = ensure_work_runtime
            await stack.enter_async_context(personal_app.router.lifespan_context(personal_app))
            _bind_child_epoch(personal_app)
            if appshell_provision_key_enabled():
                personal_live = personal_app.state.web_runtime.settings
                work_live = work_app.state.runtime_settings
                provision_shared_bootstrap_key(personal_live, work_live)
            yield

    parent = FastAPI(title="JS Agent", lifespan=appshell_lifespan)
    parent.state.personal_app = personal_app
    parent.state.work_app = work_app
    parent.state.appshell_session_store = session_store
    parent.state.appshell_mode_gate = AppShellModeGate(session_store)
    parent.state.appshell_ws_registry = AppShellWebSocketRegistry()
    parent.state.work_workspace_handle = _workspace_handle(work_settings.workspace)

    def _principal_is_active(principal: Any) -> bool:
        settings_by_mode = {
            "personal": personal_settings,
            "work": work_settings,
        }
        try:
            for mode, expected_role in principal.mode_roles.items():
                identity = AuthManager(settings_by_mode[mode].state_dir).verify_key_hash(
                    principal.owner
                )
                if identity.get("role") != expected_role:
                    return False
        except Exception:
            return False
        return True

    parent.state.appshell_principal_is_active = _principal_is_active

    from js.appshell.routers import router as appshell_api_router

    parent.include_router(appshell_api_router)

    @parent.get("/api/appshell/health")
    async def _health() -> dict[str, Any]:
        return {"status": "ok", "app_id": "js-agent", "modes": ["personal", "work"]}

    @parent.post("/api/workspace/switch")
    async def _legacy_switch_hidden() -> None:
        raise HTTPException(
            410,
            {
                "code": "legacy_switch_hidden",
                "use": "/api/appshell/switch",
            },
        )

    parent.add_middleware(
        AppShellRoutingMiddleware,
        owner_app=parent,
        personal_app=personal_app,
        work_app=work_app,
    )

    return parent
