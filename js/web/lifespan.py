"""AppShell Host lifespan: start and stop the in-process agent runtime."""

from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI  # noqa: TC002

from js.config import JSSettings
from js.utils.log import get_logger
from js.web.deps import set_active_model, set_globals
from js.web.runtime_context import WebRuntime, bind_web_runtime, clear_web_runtime
from js.web.stats_store import TokenStatsStore

logger = get_logger("js.web")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    from js.web import server as web_server

    # Explicit create_app(runtime_settings=...) / CLI ``-c`` is the sole authority.
    # Never silently reload ~/.config/js when an explicit settings object was passed.
    runtime_settings = getattr(app.state, "runtime_settings", None)
    if isinstance(runtime_settings, JSSettings):
        web_server._settings = runtime_settings
    else:
        web_server._settings = JSSettings.from_file()
    if bool(getattr(app.state, "manage_orind", False)):
        from js.orin.supervisor import prepare_product_orin

        prepare_product_orin(web_server._settings)
    os.environ["JS_ECHO_ENGINE"] = web_server._settings.echo_engine
    # Allow tests/CI to override state_dir without editing config files, but only
    # when no explicit runtime_settings object was provided (env is a fallback).
    if not isinstance(runtime_settings, JSSettings) and (
        state_dir_env := os.getenv("JS_STATE_DIR")
    ):
        web_server._settings.state_dir = Path(state_dir_env)
        web_server._settings.state_dir.mkdir(parents=True, exist_ok=True)
    from js.agent import JSAgent

    web_server._agent = JSAgent(web_server._settings)
    web_server._echo_safety_service = web_server._agent.echo_safety_service
    # Register fleet collaboration tool so the agent can delegate to multi-agent team
    try:
        from js.web.routers.fleet import get_fleet

        web_server._agent.register_fleet_tool(get_fleet)
        web_server._agent.set_fleet_getter(get_fleet)
    except Exception:
        logger.warning("Fleet tool registration failed (fleet may be unavailable)", exc_info=True)
    web_server._agent.start_background_tasks()
    web_server._stats_store = TokenStatsStore(web_server._settings.state_dir)
    runtime = WebRuntime(
        agent=web_server._agent,
        settings=web_server._settings,
        stats_store=web_server._stats_store,
        echo_safety_service=web_server._echo_safety_service,
    )
    web_server._agent.set_active_model_publisher(set_active_model)
    bind_web_runtime(app, runtime)
    # Sync shared deps so routers can access agent and stats store
    set_globals(
        web_server._agent,
        web_server._settings,
        web_server._stats_store,
        web_server._echo_safety_service,
    )
    # Guarantee a usable admin key exists so a fresh install lands usable and
    # we never get stuck in a keyless, fully-401-locked state.
    web_server._bootstrap_admin_key = (
        None
        if bool(getattr(web_server._settings, "_appshell_managed", False))
        else web_server._provision_bootstrap_admin_key(web_server._settings)
    )
    runtime.bootstrap_admin_key = web_server._bootstrap_admin_key
    # Restore the persisted active model from the configured state dir, but
    # only adopt it if it still maps to a real configured provider/model.
    # This self-heals stale values (e.g. a leftover/test-polluted entry) that
    # would otherwise pin router.preferred_model to a non-existent model and
    # make every "default" run fall back to the wrong model.
    web_server._active_model = ""
    persisted_model = web_server._load_active_model(web_server._settings.state_dir)
    if persisted_model and web_server._agent and web_server._agent.router:
        if web_server._agent.router.get_model_config(persisted_model) is not None:
            web_server._active_model = persisted_model
            web_server._agent.router.preferred_model = persisted_model
        else:
            logger.warning(
                "Ignoring stale persisted active model %r (no matching configured "
                "provider/model); falling back to auto-select",
                persisted_model,
            )
            web_server._active_model = ""
    runtime.active_model = web_server._active_model
    ready_agent = web_server._agent
    ready_settings = web_server._settings
    if ready_agent is None or ready_settings is None:
        raise RuntimeError("host runtime missing after startup")

    async def _post_ready_maintenance() -> None:
        try:
            cleaned = await asyncio.to_thread(ready_agent.memory.cleanup_empty_sessions)
            logger.info("Sessions on startup: %s empty cleaned", cleaned)
        except Exception:
            logger.warning("Failed to clean up empty sessions", exc_info=True)
        try:
            recovered = await asyncio.to_thread(
                ready_agent.lifecycle_store.recover_all_aborted_sessions
            )
            if recovered:
                logger.info("Recovered %d aborted sessions after ready", len(recovered))
        except Exception:
            logger.warning("Session recovery failed", exc_info=True)
        try:
            skills = getattr(ready_agent, "skills", None)
            if skills is not None:
                await asyncio.to_thread(skills.ensure_loaded)
        except Exception:
            logger.debug("Deferred skill scan failed", exc_info=True)
        try:
            if getattr(getattr(ready_settings, "orin", None), "enabled", False) is True:
                from js.orin.supervisor import orind_socket_path, wait_orind_socket

                await asyncio.to_thread(wait_orind_socket, orind_socket_path(ready_settings))
        except Exception:
            logger.debug("orind warmup failed", exc_info=True)
        try:
            import shutil

            state_dir = ready_settings.state_dir
            _total, _used, free = shutil.disk_usage(str(state_dir))
            free_gb = free / (1024**3)
            if free_gb < 1.0:
                logger.warning("CRITICAL: state_dir has only %.1fGB free space remaining", free_gb)
            elif free_gb < 5.0:
                logger.warning("Disk low: state_dir has %.1fGB free space remaining", free_gb)
            event_dir = state_dir / "events"
            if event_dir.is_dir():
                total_size = sum(f.stat().st_size for f in event_dir.iterdir() if f.is_file())
                if total_size > 1024**3:
                    logger.warning(
                        "Event log directory > 1GB (%.1fMB), consider pruning",
                        total_size / (1024**2),
                    )
        except Exception:
            logger.debug("Startup self-diagnostics failed", exc_info=True)

    from js.utils.async_tasks import spawn_background_task

    spawn_background_task(_post_ready_maintenance(), name="host-post-ready")

    # Load Hermes skills asynchronously only when explicitly enabled.
    warm_start = os.getenv("JS_WARM_START")
    skills = getattr(web_server._agent, "skills", None)
    hermes_opt_in = bool(skills is not None and getattr(skills, "hermes_skills_enabled", False))
    if hermes_opt_in and skills is not None and warm_start:
        try:
            await asyncio.wait_for(skills.load_hermes_async(), timeout=60.0)
            logger.info("Warm start: Hermes skills loaded")
        except TimeoutError:
            logger.warning("Warm start: Hermes skill loading timed out after 60s")
        except Exception:
            logger.warning("Warm start: Hermes skill loading failed", exc_info=True)

    elif hermes_opt_in and skills is not None:
        try:
            from js.utils.async_tasks import spawn_background_task

            spawn_background_task(skills.load_hermes_async(), name="hermes-skill-load")
            logger.info("Hermes skill loading started in background")
        except Exception:
            logger.warning("Failed to start Hermes skill loading", exc_info=True)
    else:
        logger.info("Hermes skill bridge skipped (features.hermes_skills_enabled=false)")
    logger.info("AppShell Host agent initialized")
    web_server._startup_time = asyncio.get_event_loop().time()
    runtime.startup_time = web_server._startup_time

    try:
        yield
    finally:
        logger.info("Shutting down JS Agent Host")
        # Graceful: give in-flight requests a brief window to finish
        try:
            await asyncio.wait_for(web_server._drain_inflight(), timeout=5.0)
        except TimeoutError:
            logger.warning("Some in-flight requests did not finish within grace period")
        try:
            from js.utils.async_tasks import drain_background_tasks

            await drain_background_tasks(timeout=2.0)
        except Exception:
            logger.debug("Background task drain failed", exc_info=True)
        try:
            await web_server._close_runtime_fleet(runtime.fleet, runtime_name="JS Agent Host")
        finally:
            try:
                await runtime.agent.close()
            finally:
                web_server._agent = None
                clear_web_runtime(app, runtime)
        logger.info("Shutdown complete")
