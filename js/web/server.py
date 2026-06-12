"""FastAPI Web server with WebSocket streaming."""

from __future__ import annotations

import asyncio
import json
import os
import re
import signal
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from fastapi import (
    Depends,
    FastAPI,
    HTTPException,
    Request,
    UploadFile,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

try:
    from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
    from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
    from prometheus_client import make_asgi_app
    HTTPXClientInstrumentor().instrument()
    _MONITORING_AVAILABLE = True
except ImportError:
    _MONITORING_AVAILABLE = False
    FastAPIInstrumentor = None  # type: ignore[misc,assignment]
    make_asgi_app = None  # type: ignore[assignment]

from js import __version__
from js.agent import JSAgent
from js.config import JSSettings, ModelConfig, ModelProviderConfig
from js.models.provider_manager import ProviderManager
from js.models.providers import OpenAICompatibleProvider
from js.utils.log import get_logger
from js.web import model_refresh
from js.web.auth import require_admin, require_auth_dep
from js.web.deps import _agent_config, set_active_model, set_globals
from js.web.messages import humanize_error

# Imported routers (extracted from this file)
from js.web.routers import chat as chat_router
from js.web.routers import cron, desktop, fleet, metrics, setup, system
from js.web.routers import memory as memory_router
from js.web.routers import plugins as plugins_router
from js.web.routers import scenarios as scenarios_router
from js.web.routers import tasks as tasks_router
from js.web.stats_store import TokenStatsStore

logger = get_logger("js.web")

# Server version (bump when adding new API surfaces)
SERVER_VERSION = f"{__version__}+evolution"

# Global agent instance
_agent: JSAgent | None = None
_settings: JSSettings | None = None
_stats_store: TokenStatsStore | None = None
_active_model: str = ""
_startup_time: float = 0.0
# Plaintext of an admin key minted this session for first-run bootstrap.
# Set only when auth is required and no admin key existed at startup; used to
# auto-authenticate the local browser so the fresh install lands usable.
_bootstrap_admin_key: str | None = None


def _load_active_model(state_dir: Path) -> str:
    """Load the last selected model from the configured state dir."""
    path = state_dir / "active_model.txt"
    if path.exists():
        return path.read_text(encoding="utf-8").strip()
    return ""


def _save_active_model(state_dir: Path, model_id: str) -> None:
    """Persist the selected model so it survives server restarts.

    Keyed off ``settings.state_dir`` (not a hardcoded ``~/.js/state``) so that
    non-default installs work and tests can never pollute the real user file.
    """
    path = state_dir / "active_model.txt"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(model_id, encoding="utf-8")


# Loaded during lifespan startup once settings.state_dir is known (and only
# after the model has been validated against the configured providers).
_active_model = ""

# In-flight request tracking for graceful shutdown
_active_requests: int = 0
_active_lock = asyncio.Lock()


async def _drain_inflight(timeout: float = 5.0) -> None:
    """Wait for in-flight HTTP requests to complete."""
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        async with _active_lock:
            if _active_requests <= 0:
                return
        await asyncio.sleep(0.1)


def get_agent() -> JSAgent:
    if _agent is None:
        raise HTTPException(503, "Agent not initialized yet. Please wait for startup to complete.")
    return _agent


def _resolve_provider_from_state(state: Any) -> str:
    """Extract provider name from agent state via router model lookup."""
    agent = get_agent()
    model_id = getattr(state, "model", None) or ""
    if not model_id:
        return ""
    cfg = agent.router.get_model_config(model_id)
    if cfg:
        return cfg.provider or ""
    return ""


def _record_usage(state: Any, explicit_model: str | None = None) -> None:
    """Record token usage to stats store with provider resolution."""
    if _stats_store is None:
        return
    total_in = state.total_tokens.get("input", 0)
    total_out = state.total_tokens.get("output", 0)
    if total_in + total_out <= 0:
        return
    model_id = getattr(state, "model", None)
    if not isinstance(model_id, str):
        model_id = None
    model_id = model_id or explicit_model or "unknown"
    provider = _resolve_provider_from_state(state)
    cached_tokens = getattr(state, "cached_tokens", 0)
    if not isinstance(cached_tokens, int):
        cached_tokens = 0
    _stats_store.record(
        model=model_id,
        provider=provider,
        prompt_tokens=total_in,
        completion_tokens=total_out,
        cost=state.cost_estimate,
        cached_tokens=cached_tokens,
        session_id=getattr(state, "session_id", ""),
        run_id=getattr(state, "run_id", ""),
    )


def _provision_bootstrap_admin_key(settings: JSSettings) -> str | None:
    """Ensure an admin key exists when auth is required; return new plaintext.

    Prevents the "first_run_completed=true but no admin key → site-wide 401"
    lockdown by self-healing on every startup: if auth is required and no admin
    key exists, one is minted, written to a 0600 file, and logged so a headless
    operator can recover it.  Returns ``None`` when nothing was minted.
    """
    if not settings.security.api_key_required:
        return None
    from js.web.auth import AuthManager

    key = AuthManager(settings.state_dir).ensure_bootstrap_admin_key()
    if not key:
        return None
    key_file = settings.state_dir / "bootstrap_admin_key.txt"
    try:
        key_file.write_text(key + "\n", encoding="utf-8")
        os.chmod(key_file, 0o600)
    except OSError:
        logger.warning("Could not persist bootstrap admin key file", exc_info=True)
    logger.warning(
        "Bootstrap admin key created for first run: %s (saved to %s)", key, key_file
    )
    return key


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:  # noqa: ARG001
    global _agent, _settings, _stats_store, _bootstrap_admin_key, _active_model
    _settings = JSSettings.from_file()
    # Allow tests/CI to override state_dir without editing config files
    if state_dir_env := os.getenv("JS_STATE_DIR"):
        _settings.state_dir = Path(state_dir_env)
        _settings.state_dir.mkdir(parents=True, exist_ok=True)
    _agent = JSAgent(_settings)
    # Register fleet collaboration tool so the agent can delegate to multi-agent team
    try:
        from js.web.routers.fleet import get_fleet
        _agent.register_fleet_tool(get_fleet)
        _agent.set_fleet_getter(get_fleet)
    except Exception:
        logger.warning("Fleet tool registration failed (fleet may be unavailable)", exc_info=True)
    _agent.start_background_tasks()
    _stats_store = TokenStatsStore(_settings.state_dir)
    # Sync shared deps so routers can access agent and stats store
    set_globals(_agent, _settings, _stats_store)
    # Guarantee a usable admin key exists so a fresh install lands usable and
    # we never get stuck in a keyless, fully-401-locked state.
    _bootstrap_admin_key = _provision_bootstrap_admin_key(_settings)
    # Restore the persisted active model from the configured state dir, but
    # only adopt it if it still maps to a real configured provider/model.
    # This self-heals stale values (e.g. a leftover/test-polluted entry) that
    # would otherwise pin router.preferred_model to a non-existent model and
    # make every "default" run fall back to the wrong model.
    persisted_model = _load_active_model(_settings.state_dir)
    if persisted_model and _agent and _agent.router:
        if _agent.router.get_model_config(persisted_model) is not None:
            _active_model = persisted_model
            _agent.router.preferred_model = persisted_model
        else:
            logger.warning(
                "Ignoring stale persisted active model %r (no matching configured "
                "provider/model); falling back to auto-select",
                persisted_model,
            )
            _active_model = ""
    # Also sync system router globals for endpoints that reference them directly
    system._agent = _agent
    system._settings = _settings
    system._stats_store = _stats_store
    # Clean up empty sessions on startup (sessions with no messages are orphaned)
    try:
        before_cleanup = _agent.memory.enhanced.list_sessions(limit=1000)
        cleaned = _agent.memory.cleanup_empty_sessions()
        after_cleanup = _agent.memory.enhanced.list_sessions(limit=1000)
        logger.info(
            f"Sessions on startup: {len(before_cleanup)} total, "
            f"{cleaned} empty cleaned, {len(after_cleanup)} remaining"
        )
    except Exception:
        logger.warning("Failed to clean up empty sessions", exc_info=True)

    # Startup self-diagnostics
    try:
        import shutil
        state_dir = _settings.state_dir
        total, used, free = shutil.disk_usage(str(state_dir))
        free_gb = free / (1024**3)
        if free_gb < 1.0:
            logger.warning("CRITICAL: state_dir has only %.1fGB free space remaining", free_gb)
        elif free_gb < 5.0:
            logger.warning("Disk low: state_dir has %.1fGB free space remaining", free_gb)
        else:
            logger.info("Disk check: state_dir has %.1fGB free", free_gb)

        # Check WAL size
        import sqlite3
        for db_file in state_dir.rglob("*.db"):
            wal = db_file.with_suffix(".db-wal")
            if wal.exists() and wal.stat().st_size > 100 * 1024 * 1024:
                logger.warning("Large WAL file detected: %s (%.1fMB), checkpointing", wal, wal.stat().st_size / (1024**2))
                try:
                    with sqlite3.connect(str(db_file), timeout=5.0) as conn:
                        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                except Exception:
                    pass

        # Check event logs size
        event_dir = state_dir / "events"
        if event_dir.exists():
            total_size = sum(f.stat().st_size for f in event_dir.rglob("*") if f.is_file())
            if total_size > 1024**3:
                logger.warning("Event log directory > 1GB (%.1fMB), consider pruning", total_size / (1024**2))
    except Exception:
        logger.debug("Startup self-diagnostics failed", exc_info=True)

    # Load Hermes skills asynchronously so the web server starts immediately
    warm_start = os.getenv("JS_WARM_START")
    if warm_start:
        try:
            await asyncio.wait_for(_agent.skills.load_hermes_async(), timeout=60.0)
            logger.info("Warm start: Hermes skills loaded")
        except TimeoutError:
            logger.warning("Warm start: Hermes skill loading timed out after 60s")
        except Exception:
            logger.warning("Warm start: Hermes skill loading failed", exc_info=True)

        # Warm up provider connections
        for name, provider in _agent.router._providers.items():
            try:
                healthy = await provider.health_check()
                logger.info("Warm start: provider %s healthy=%s", name, healthy)
            except Exception:
                logger.warning("Warm start: provider %s health check failed", name)
    else:
        try:
            asyncio.create_task(_agent.skills.load_hermes_async())
            logger.info("Hermes skill loading started in background")
        except Exception:
            logger.warning("Failed to start Hermes skill loading", exc_info=True)
    logger.info("Web UI agent initialized")
    global _startup_time
    _startup_time = asyncio.get_event_loop().time()

    # SIGTERM handler for graceful shutdown
    _shutdown_event = asyncio.Event()

    def _handle_sigterm() -> None:
        logger.info("SIGTERM received, initiating graceful shutdown")
        _shutdown_event.set()

    try:
        loop = asyncio.get_running_loop()
        try:
            loop.add_signal_handler(signal.SIGTERM, _handle_sigterm)
        except (NotImplementedError, ValueError, RuntimeError):
            pass  # Windows, non-main thread, or already closed loop
    except RuntimeError:
        pass  # No running loop

    try:
        yield
    finally:
        logger.info("Shutting down JS Agent Web UI")
        try:
            loop = asyncio.get_running_loop()
            try:
                loop.remove_signal_handler(signal.SIGTERM)
            except (NotImplementedError, ValueError, RuntimeError):
                pass
        except RuntimeError:
            pass
        # Graceful: give in-flight requests a brief window to finish
        try:
            await asyncio.wait_for(_drain_inflight(), timeout=5.0)
        except TimeoutError:
            logger.warning("Some in-flight requests did not finish within grace period")
        if _agent:
            await _agent.close()
        _agent = None
        logger.info("Shutdown complete")


def create_app() -> FastAPI:
    app = FastAPI(title="JS Agent Web UI", lifespan=lifespan)

    # CORS: allow localhost origins so browser preflight (OPTIONS) works
    # when custom headers (e.g. X-API-Key) are sent with PATCH/DELETE.
    # Derive allowed origins from the configured bind host/port so the
    # server works on any port without hard-coding :8000.
    from fastapi.middleware.cors import CORSMiddleware
    _bind_host = getattr(_settings, "bind_host", "127.0.0.1") if _settings else "127.0.0.1"
    _bind_port = getattr(_settings, "bind_port", 8000) if _settings else 8000
    _cors_origins = [
        f"http://{_bind_host}:{_bind_port}",
        f"http://127.0.0.1:{_bind_port}",
        f"http://localhost:{_bind_port}",
    ]
    # Deduplicate and keep the bare loopback forms for convenience
    _cors_origins = list(dict.fromkeys(_cors_origins))
    if "http://127.0.0.1" not in _cors_origins:
        _cors_origins.insert(0, "http://127.0.0.1")
    if "http://localhost" not in _cors_origins:
        _cors_origins.insert(0, "http://localhost")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
        allow_headers=["Content-Type", "X-API-Key", "Authorization"],
    )

    # Global exception handler: AuthRequiredError must always map to 401,
    # never leak as a 500.
    from js.exceptions import AuthRequiredError

    @app.exception_handler(AuthRequiredError)
    async def _auth_required_handler(request: Request, exc: AuthRequiredError) -> JSONResponse:
        return JSONResponse(
            status_code=401,
            content={"detail": str(exc)},
            headers={"WWW-Authenticate": "Bearer"},
        )

    if _MONITORING_AVAILABLE:
        FastAPIInstrumentor.instrument_app(app)
        app.mount("/metrics", make_asgi_app())

    app.mount("/static", StaticFiles(directory=_STATIC_DIR), name="static")

    # Force-clear cache for static JS files (dev-mode: always load fresh)
    @app.middleware("http")
    async def no_cache_static(request: Request, call_next: Any) -> Any:
        response = await call_next(request)
        if request.url.path.startswith("/static") and request.url.path.endswith(".js"):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
        return response

    # Include extracted routers
    app.include_router(chat_router.router)
    app.include_router(cron.router)
    app.include_router(plugins_router.router)
    app.include_router(fleet.router)
    app.include_router(system.router)
    app.include_router(setup.router)
    app.include_router(memory_router.router)
    app.include_router(tasks_router.router)
    app.include_router(scenarios_router.router)
    app.include_router(desktop.router)
    app.include_router(metrics.router)
    # Fresh model-refresh throttle per app (matches the old per-create_app state).
    model_refresh.reset_throttle()

    # Wire up the diag endpoint's route list helper
    system._get_app_routes = lambda: [
        {"path": r.path, "methods": list(r.methods)}
        for r in app.routes
        if hasattr(r, "methods") and hasattr(r, "path")
    ]

    @app.get("/", response_class=HTMLResponse)
    async def root(request: Request) -> str:
        html = _load_index_html()
        # Inject the freshly-minted bootstrap admin key for the local browser so
        # the first run is usable without manual key entry.  Loopback-only so a
        # misconfigured 0.0.0.0 bind never leaks the key over the network.
        if _bootstrap_admin_key and _is_loopback(request):
            html = _inject_bootstrap_key(html, _bootstrap_admin_key)
        return html

    @app.get("/api/status")
    async def status(auth: dict[str, Any] = Depends(require_auth_dep)) -> dict[str, Any]:
        agent = get_agent()
        await agent._check_degraded()
        return {
            "workspace": str(agent.settings.workspace),
            "state_dir": str(agent.settings.state_dir),
            "max_turns": agent.settings.max_turns,
            "defense_mode": agent.settings.security.defense_mode.value,
            "degraded": agent.degraded,
            "degraded_reason": agent.degraded_reason,
            "tool_stats": agent.registry.get_stats(),
            "secret_stats": agent.secrets.get_stats(),
            "desktop_control_enabled": agent.settings.desktop_control_enabled,
        }

    @app.post("/api/cancel/{session_id}")
    async def cancel_session(session_id: str, auth: dict[str, Any] = Depends(require_auth_dep)) -> dict[str, Any]:
        """Request cancellation of an active agent run for *session_id*."""
        agent = get_agent()
        try:
            ok = agent.request_cancel(session_id, owner_key_hash=auth.get("key_hash"))
        except PermissionError as e:
            raise HTTPException(403, str(e)) from e
        if not ok:
            raise HTTPException(404, f"No active run for session {session_id}")
        return {"session_id": session_id, "cancelled": True}

    @app.get("/api/diag")
    async def diag(auth: dict[str, Any] = Depends(require_auth_dep)) -> dict[str, Any]:
        """Diagnostic endpoint to verify server version, routes and subsystem health."""
        agent = get_agent()
        routes = []
        for r in app.routes:
            if hasattr(r, "methods") and hasattr(r, "path"):
                routes.append({"path": r.path, "methods": list(r.methods)})
        subsystems = {
            "metacognition": agent.metacognition is not None,
            "learner": agent.learner is not None,
            "optimizer": agent.optimizer is not None,
            "evolver": agent.evolver is not None,
            "compression_feedback": agent.compression_feedback is not None,
            "dream_scheduler": agent._dream_scheduler is not None,
        }
        embedder_health = agent.memory.embedder.health()

        # Hermes bridge stats
        hermes_count: int = sum(
            1 for s in agent.skills.get_all().values()
            if s.id.startswith("hermes:")
        )

        return {
            "version": SERVER_VERSION,
            "routes": sorted(routes, key=lambda x: x["path"]),
            "subsystems": subsystems,
            "has_evolution_api": any(
                r["path"] == "/api/evolution/run" for r in routes
            ),
            "embedder": {
                "provider": embedder_health.provider,
                "active": embedder_health.active,
                "fallback": embedder_health.fallback_provider,
                "failures": embedder_health.failure_count,
            },
            "hermes_bridge": {
                "enabled": hermes_count > 0,
                "skills_loaded": hermes_count,
            },
        }

    # NOTE: /api/memory/* and /api/setup/* endpoints moved to dedicated routers

    @app.get("/api/audit")
    async def audit(limit: int = 50, auth: dict[str, Any] = Depends(require_auth_dep)) -> dict[str, Any]:
        agent = get_agent()
        events = agent.audit.query(limit=limit)
        return {
            "events": [
                {
                    "timestamp": e.timestamp,
                    "type": e.event_type.value,
                    "actor": e.actor,
                    "action": e.action,
                }
                for e in events
            ]
        }

    @app.get("/api/files")
    async def list_files(path: str = ".", auth: dict[str, Any] = Depends(require_auth_dep)) -> dict[str, Any]:
        agent = get_agent()
        # Validate path to prevent directory traversal
        try:
            resolved = (agent.settings.workspace / path).resolve()
            workspace_resolved = agent.settings.workspace.resolve()
            resolved.relative_to(workspace_resolved)
        except (ValueError, RuntimeError) as e:
            return {"success": False, "error": f"Invalid path: {e}"}

        handler = agent.registry.get_handler("file_list")
        if handler is None:
            return {"success": False, "error": "file_list tool not available"}
        result = await handler(path=path)
        return {"success": result.success, "output": result.output, "error": result.error}

    @app.get("/api/sessions")
    async def list_sessions(limit: int = 30, auth: dict[str, Any] = Depends(require_auth_dep)) -> dict[str, Any]:
        agent = get_agent()
        sessions = agent.memory.get_sessions(
            limit=limit, owner_key_hash=auth.get("key_hash")
        )
        return {"sessions": sessions}

    @app.get("/api/sessions/{session_id}/messages")
    async def session_messages(session_id: str, auth: dict[str, Any] = Depends(require_auth_dep)) -> dict[str, Any]:
        agent = get_agent()
        try:
            messages = agent.memory.get_session_messages(
                session_id, owner_key_hash=auth.get("key_hash")
            )
        except PermissionError as e:
            raise HTTPException(status_code=403, detail="Session access denied") from e
        return {"session_id": session_id, "messages": messages}

    @app.delete("/api/sessions/{session_id}")
    async def delete_session(session_id: str, auth: dict[str, Any] = Depends(require_auth_dep)) -> dict[str, Any]:
        agent = get_agent()
        try:
            agent.memory.delete_session(session_id, owner_key_hash=auth.get("key_hash"))
        except PermissionError as e:
            raise HTTPException(status_code=403, detail="Session deletion denied") from e
        return {"success": True, "session_id": session_id}

    @app.get("/api/models")
    async def models(auth: dict[str, Any] = Depends(require_auth_dep)) -> dict[str, Any]:
        agent = get_agent()
        # Trigger refreshes in the background so the list response is not
        # blocked by slow outbound HTTP calls to local/cloud providers.
        model_refresh.maybe_refresh_models_async(agent)

        # Health check all providers in parallel to avoid sequential latency
        health: dict[str, bool] = {}
        health_errors: dict[str, str] = {}

        async def _check_one(p: ModelProviderConfig) -> tuple[str, bool, str | None]:
            try:
                provider = agent.router._providers.get(p.name)
                if provider:
                    healthy = await provider.health_check()
                    return p.name, healthy, None
                else:
                    return p.name, False, "Provider not registered in router"
            except Exception as e:
                return p.name, False, str(e)

        results = await asyncio.gather(
            *[_check_one(p) for p in agent.settings.providers],
            return_exceptions=True,
        )
        for r in results:
            if isinstance(r, Exception):
                continue
            name, healthy, err = r  # type: ignore[misc]
            health[name] = healthy
            if err:
                health_errors[name] = err

        # Determine which providers are user-configured (from provider_manager)
        dyn_names = {p.name for p in agent.provider_manager.get_all()}

        # Build provider list with embedded health status
        providers_out: list[dict[str, Any]] = []
        for p in agent.settings.providers:
            has_key = bool(p.api_key)
            providers_out.append({
                "name": p.name,
                "base_url": p.base_url,
                "healthy": health.get(p.name, False),
                "health_error": health_errors.get(p.name),
                "has_key": has_key,
                "user_configured": p.name in dyn_names,
                "models": [
                    {
                        "id": m.id,
                        "name": m.name or m.id,
                        "context_window": m.context_window,
                        "max_tokens": m.max_tokens,
                        "cost_input": m.cost_input,
                        "cost_output": m.cost_output,
                    }
                    for m in p.models
                ],
            })

        # Hide providers that are empty, unhealthy, have no key, and were
        # not explicitly configured by the user (usually stale auto-detects).
        providers_out = [
            p for p in providers_out
            if not (len(p["models"]) == 0 and not p["healthy"] and not p["has_key"] and not p["user_configured"])
        ]

        # Include cloud presets that are NOT yet configured
        # so users can see what's available
        from js.models.cloud_providers import ALL_PRESETS
        configured_names = {p.name for p in agent.settings.providers}
        presets_out = []
        for preset in ALL_PRESETS:
            if preset.id not in configured_names:
                presets_out.append({
                    "id": preset.id,
                    "name": preset.name,
                    "description": preset.description,
                    "base_url": preset.base_url,
                    "api_key_env": preset.api_key_env,
                    "models": [
                        {
                            "id": m.id,
                            "name": m.name or m.id,
                            "context_window": m.context_window,
                        }
                        for m in preset.models
                    ],
                })

        return {
            "providers": providers_out,
            "presets": presets_out,
            "active_model": _active_model,
        }

    @app.post("/api/models/switch")
    async def models_switch(body: dict[str, Any], auth: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        global _active_model
        model_id = (body.get("model_id") or "").strip()
        if not model_id:
            raise HTTPException(400, "model_id is required")
        agent = get_agent()

        # Valid = configured providers + all cloud presets
        valid_models = {
            f"{p.name}/{m.id}"
            for p in agent.settings.providers
            for m in p.models
        }
        from js.models.cloud_providers import ALL_PRESETS
        for preset in ALL_PRESETS:
            for m in preset.models:
                valid_models.add(f"{preset.id}/{m.id}")

        # Also accept models that the router knows about (catches stale
        # mappings and dynamically-discovered models that may not yet be
        # reflected in settings.providers).
        if model_id not in valid_models and agent.router.get_model_config(model_id) is None:
            logger.warning(
                "Model switch rejected: model_id=%r not in valid_models (count=%d) "
                "and not in router._model_map",
                model_id,
                len(valid_models),
            )
            raise HTTPException(400, f"Invalid model '{model_id}'")

        _active_model = model_id
        _save_active_model(agent.settings.state_dir, model_id)
        set_active_model(model_id)
        agent = get_agent()
        if agent and agent.router:
            agent.router.preferred_model = model_id
            # Drop cached routing decisions so the new choice takes effect
            # immediately (consistent with register/unregister_provider).
            agent.router._routing_cache.clear()

        # Warn if the provider is not yet configured
        provider_name = model_id.split("/", 1)[0] if "/" in model_id else ""
        configured_providers = {p.name for p in agent.settings.providers}
        warning = None
        if provider_name and provider_name not in configured_providers:
            warning = f"Provider '{provider_name}' 尚未配置 API Key，调用时会报错。请先添加该云模型。"

        return {"success": True, "model_id": model_id, "warning": warning}

    def _validate_provider_name(name: str) -> None:
        if not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", name):
            raise HTTPException(
                400,
                "Provider name must be 1-64 chars, alphanumeric, hyphen, or underscore",
            )

    def _validate_url(url: str) -> None:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            raise HTTPException(400, "URL scheme must be http or https")
        if not parsed.netloc:
            raise HTTPException(400, "URL must have a host")

    @app.post("/api/providers/discover")
    async def discover_provider(
        payload: dict[str, Any],
        auth: dict[str, Any] = Depends(require_admin),
    ) -> dict[str, Any]:
        base_url = payload.get("base_url", "").strip()
        api_key = payload.get("api_key") or None
        if not base_url:
            raise HTTPException(400, "base_url is required")
        _validate_url(base_url)
        allow_private = get_agent().settings.security.allow_private_model_providers
        result = await ProviderManager.discover_models(base_url, api_key, allow_private=allow_private)
        if "error" in result:
            raise HTTPException(502, result["error"])
        return {"base_url": base_url, "models": result["models"]}

    @app.post("/api/providers/connect")
    async def connect_provider(payload: dict[str, Any], auth: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        name = payload.get("name", "").strip()
        base_url = payload.get("base_url", "").strip()
        api_key = payload.get("api_key", "").strip() or None
        model_ids = payload.get("models", [])

        if not name or not base_url:
            raise HTTPException(400, "name and base_url are required")
        _validate_provider_name(name)
        _validate_url(base_url)

        if not isinstance(model_ids, list) or not model_ids:
            raise HTTPException(400, "at least one model must be selected")
        if not all(isinstance(m, dict) and "id" in m for m in model_ids):
            raise HTTPException(400, "models must be a list of objects with 'id'")

        models = [
            ModelConfig(id=m["id"], name=m.get("name", m["id"]), provider=name)
            for m in model_ids
        ]
        cfg = ModelProviderConfig(
            name=name,
            base_url=base_url,
            api_key=api_key,
            default_model=models[0].id if models else "",
            models=models,
        )

        agent = get_agent()
        # Prevent overriding static config
        static_names = {p.name for p in agent.settings.providers}
        # Exclude dynamically-added ones to detect true static conflicts
        dyn_names = {p.name for p in agent.provider_manager.get_all()}
        true_static = static_names - dyn_names
        if name in true_static:
            raise HTTPException(
                409, f"Provider name '{name}' conflicts with static config"
            )

        try:
            # Persist
            agent.provider_manager.add(cfg)
            # Update settings + router in-memory (dedupe settings list first)
            agent.settings.providers = [
                p for p in agent.settings.providers if p.name != name
            ]
            agent.settings.providers.append(cfg)
            agent.router.add_provider(cfg.name, OpenAICompatibleProvider(cfg), models)
        except Exception as e:
            # Rollback: remove from manager if it was saved
            try:
                agent.provider_manager.remove(name)
            except Exception:
                logger.warning('Operation failed', exc_info=True)
            agent.settings.providers = [
                p for p in agent.settings.providers if p.name != name
            ]
            agent.router.remove_provider(name)
            raise HTTPException(500, f"Failed to connect provider: {e}") from e

        return {"success": True, "provider": name, "models_added": len(models)}

    @app.patch("/api/providers/{name}")
    async def update_provider(
        name: str,
        payload: dict[str, Any],
        auth: dict[str, Any] = Depends(require_auth_dep),
    ) -> dict[str, Any]:
        """Update an existing provider (e.g. add/change API key)."""
        agent = get_agent()
        api_key = payload.get("api_key", "").strip() or None

        # Find the provider in settings
        target = None
        for p in agent.settings.providers:
            if p.name == name:
                target = p
                break
        if target is None:
            raise HTTPException(404, f"Provider '{name}' not found")

        # Update the config
        target.api_key = api_key

        # Update in dynamic provider_manager if present
        agent.provider_manager.update_api_key(name, api_key or "")

        # Refresh router: remove stale provider and re-add with updated config
        agent.router.remove_provider(name)
        agent.router.add_provider(
            name,
            OpenAICompatibleProvider(target),
            list(target.models),
        )

        # Persist
        try:
            agent.settings.save()
        except Exception as e:
            logger.warning(f"Failed to save config after provider update: {e}")

        return {"success": True, "provider": name}

    @app.delete("/api/providers/{name}")
    async def delete_provider(name: str, auth: dict[str, Any] = Depends(require_auth_dep)) -> dict[str, Any]:
        agent = get_agent()
        # Remove from dynamic provider_manager (if it was added at runtime)
        agent.provider_manager.remove(name)
        # Remove from static settings
        before = len(agent.settings.providers)
        agent.settings.providers = [p for p in agent.settings.providers if p.name != name]
        removed = len(agent.settings.providers) < before
        # Remove from router
        agent.router.remove_provider(name)
        if not removed:
            raise HTTPException(404, f"Provider '{name}' not found")
        # Persist config change
        try:
            agent.settings.save()
        except Exception as e:
            logger.warning(f"Failed to save config after provider removal: {e}")
        # Clean up agent fleet config if it references this provider
        prefix = f"{name}/"
        for role in _agent_config:
            if _agent_config[role].startswith(prefix):
                _agent_config[role] = ""
        return {"success": True}

    @app.get("/api/providers/cloud-presets")
    async def cloud_presets(auth: dict[str, Any] = Depends(require_auth_dep)) -> dict[str, Any]:
        """List all built-in cloud provider presets."""
        from js.models.cloud_providers import list_presets
        return {"presets": list_presets()}

    @app.post("/api/providers/test-cloud")
    async def test_cloud_provider(payload: dict[str, Any], auth: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        """Test a cloud provider preset before adding it."""
        from js.models.cloud_providers import get_preset
        from js.models.provider_manager import ProviderManager

        preset_id = payload.get("preset_id", "").strip()
        api_key = payload.get("api_key", "").strip()

        if not preset_id:
            raise HTTPException(400, "preset_id is required")

        preset = get_preset(preset_id)
        if not preset:
            raise HTTPException(404, f"Unknown preset: {preset_id}")

        if not api_key:
            raise HTTPException(400, "API key required")

        result = await ProviderManager.discover_models(preset.base_url, api_key)
        if "error" in result:
            raise HTTPException(401, result["error"])

        return {
            "success": True,
            "provider": preset_id,
            "name": preset.name,
            "models": result.get("models", []),
        }

    @app.post("/api/providers/add-cloud")
    async def add_cloud_provider(payload: dict[str, Any], auth: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        """One-click add a cloud provider from presets."""
        from js.models.cloud_providers import build_provider_config, get_preset
        from js.models.provider_manager import ProviderManager

        preset_id = payload.get("preset_id", "").strip()
        api_key = payload.get("api_key", "").strip()

        if not preset_id:
            raise HTTPException(400, "preset_id is required")

        preset = get_preset(preset_id)
        if not preset:
            raise HTTPException(404, f"Unknown preset: {preset_id}")

        if not api_key:
            # Try to load from environment
            import os
            api_key = os.getenv(preset.api_key_env, "")
            if not api_key:
                raise HTTPException(
                    400,
                    f"API key required. Set {preset.api_key_env} environment variable or pass api_key in payload."
                )

        cfg = build_provider_config(preset, api_key)

        # Discover actual models from the remote endpoint so the user sees
        # exactly what the provider reports (e.g. LM Studio with 2 loaded
        # models instead of the preset's full catalog).
        discovered = await ProviderManager.discover_models(cfg.base_url, cfg.api_key)
        if "models" in discovered and discovered["models"]:
            from js.config import ModelConfig
            cfg.models = [
                ModelConfig(
                    id=str(m["id"]),
                    name=str(m.get("name") or m["id"]),
                    provider=preset_id,
                )
                for m in discovered["models"]
                if m.get("id")
            ]
            if cfg.models:
                cfg.default_model = cfg.models[0].id

        agent = get_agent()

        # Prevent overriding static config
        static_names = {p.name for p in agent.settings.providers}
        dyn_names = {p.name for p in agent.provider_manager.get_all()}
        true_static = static_names - dyn_names
        if preset_id in true_static:
            raise HTTPException(409, f"Provider '{preset_id}' conflicts with static config")

        try:
            agent.provider_manager.add(cfg)
            agent.settings.providers = [
                p for p in agent.settings.providers if p.name != preset_id
            ]
            agent.settings.providers.append(cfg)
            agent.router.add_provider(cfg.name, OpenAICompatibleProvider(cfg), cfg.models)
        except Exception as e:
            try:
                agent.provider_manager.remove(preset_id)
            except Exception:
                logger.warning('Operation failed', exc_info=True)
            agent.settings.providers = [
                p for p in agent.settings.providers if p.name != preset_id
            ]
            agent.router.remove_provider(preset_id)
            raise HTTPException(500, f"Failed to add provider: {e}") from e

        return {
            "success": True,
            "provider": preset_id,
            "name": preset.name,
            "models_added": len(cfg.models),
        }

    @app.post("/api/providers/scan-lan")
    async def scan_lan(
        payload: dict[str, Any] | None = None,
        auth: dict[str, Any] = Depends(require_admin),
    ) -> dict[str, Any]:
        """Scan the local network for model servers."""
        from ipaddress import ip_network

        from js.models.discovery import LocalModelDiscovery

        subnet = (payload or {}).get("subnet", "192.168")
        try:
            # Validate that the subnet prefix is a valid private CIDR prefix
            # (e.g. "192.168", "10.0.0", "172.16").  We do NOT allow scanning
            # public ranges to prevent SSRF / network enumeration abuse.
            _network = ip_network(f"{subnet}.0/24", strict=False)
            if not _network.is_private:
                raise HTTPException(400, "Only private-network (RFC1918) subnets are allowed")
        except ValueError as exc:
            raise HTTPException(400, f"Invalid subnet format: {exc}") from exc
        discovery = LocalModelDiscovery(timeout=2.0)
        try:
            discovered = await discovery.scan_lan(subnet_prefix=subnet)
            return {
                "success": True,
                "subnet": subnet,
                "found": len(discovered),
                "providers": [
                    {
                        "name": d.name,
                        "type": d.provider_type,
                        "base_url": d.base_url,
                        "models": [{"id": m.id, "name": m.name} for m in d.models],
                        "latency_ms": round(d.latency_ms, 1),
                    }
                    for d in discovered
                ],
            }
        except Exception as e:
            logger.error(f"LAN scan failed: {e}", exc_info=True)
            raise HTTPException(500, f"LAN scan failed: {e}") from e
        finally:
            await discovery.close()

    @app.get("/api/stats/tokens")
    async def token_stats(days: int = 30, auth: dict[str, Any] = Depends(require_auth_dep)) -> dict[str, Any]:
        if _stats_store is None:
            raise HTTPException(503, "Stats store not initialized")
        return _stats_store.get_summary(days=days)

    @app.get("/api/evolution/reports")
    async def evolution_reports(limit: int = 10, auth: dict[str, Any] = Depends(require_auth_dep)) -> dict[str, Any]:
        agent = get_agent()
        reports = agent.metacognition.get_recent_reports(limit=limit)
        return {"reports": reports}

    @app.get("/api/evolution/proposals")
    async def evolution_proposals(limit: int = 20, auth: dict[str, Any] = Depends(require_auth_dep)) -> dict[str, Any]:
        agent = get_agent()
        proposals = agent.metacognition.get_proposals(limit=limit)
        return {"proposals": proposals}

    @app.get("/api/evolution/insights")
    async def evolution_insights(limit: int = 20, auth: dict[str, Any] = Depends(require_auth_dep)) -> dict[str, Any]:
        agent = get_agent()
        return {
            "learning": {
                "stats": agent.learner.get_stats(),
                "insights": agent.learner.get_insights(limit=limit),
                "suggestions": agent.learner.suggest_improvements(),
            },
            "optimization": agent.optimizer.get_report() if agent.optimizer else {},
            "compression": agent.compression_feedback.get_stats() if agent.compression_feedback else {},
        }

    @app.post("/api/evolution/run")
    async def evolution_run(auth: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        agent = get_agent()

        # Pre-flight readiness check
        if not hasattr(agent, "_run_evolution_cycle"):
            raise HTTPException(
                501,
                "Agent does not support evolution cycles. Please restart the server with the latest code.",
            )
        missing = [
            name for name, ok in {
                "metacognition": agent.metacognition is not None,
                "learner": agent.learner is not None,
                "optimizer": agent.optimizer is not None,
                "evolver": agent.evolver is not None,
            }.items() if not ok
        ]
        if missing:
            raise HTTPException(
                503,
                f"Evolution subsystems not ready: {', '.join(missing)}. Please wait for startup to complete.",
            )

        # Feed the recent conversation buffer so the manual run actually
        # updates profiles + extracts memories instead of running empty.
        ds = getattr(agent, "_dream_scheduler", None)
        buffer = ds.snapshot_buffer() if ds is not None and hasattr(ds, "snapshot_buffer") else []
        try:
            report = await agent._run_evolution_cycle(buffer)
            return {
                "success": True,
                "message": "Evolution cycle completed",
                "report": report,
            }
        except Exception as e:
            # If the exception already carries an HTTP-like code in its message,
            # surface a more specific error. Otherwise return generic 500.
            msg = str(e)
            if "404" in msg and "model" in msg.lower():
                raise HTTPException(
                    502,
                    "LLM API returned 404 (model not found). Check your model configuration in settings.",
                ) from e
            logger.error(f"Evolution cycle failed: {e}", exc_info=True)
            raise HTTPException(500, f"Evolution cycle failed: {e}") from e

    @app.post("/api/evolution/reflect")
    async def evolution_reflect(auth: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        """Trigger an immediate metacognition reflection."""
        agent = get_agent()
        if agent.metacognition is None:
            raise HTTPException(503, "Metacognition subsystem not ready")
        try:
            report = await asyncio.to_thread(agent.metacognition.reflect)
        except Exception as e:
            logger.error(f"Metacognition reflect failed: {e}", exc_info=True)
            raise HTTPException(500, f"Reflection failed: {e}") from e
        return {
            "health_score": report.overall_health_score,
            "proposals": len(report.proposals),
            "actions_taken": len(report.actions_taken),
            "timestamp": report.timestamp,
        }

    @app.get("/api/agents/config")
    async def get_agent_config(auth: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        agent = get_agent()
        # Build available models list for the UI
        available_models: list[dict[str, Any]] = []
        for p in agent.settings.providers:
            for m in p.models:
                available_models.append({
                    "id": f"{p.name}/{m.id}",
                    "provider": p.name,
                    "model_id": m.id,
                    "model_name": m.name or m.id,
                    "context_window": m.context_window,
                })
        return {
            "config": _agent_config,
            "available_models": available_models,
            "roles": list(_agent_config.keys()),
        }

    @app.post("/api/agents/config")
    async def set_agent_config(payload: dict[str, Any], auth: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        global _agent_config
        new_config = payload.get("config", {})
        agent = get_agent()
        # Validate model IDs against available providers
        valid_models = {
            f"{p.name}/{m.id}"
            for p in agent.settings.providers
            for m in p.models
        }
        # Also allow preset models (not yet configured)
        from js.models.cloud_providers import ALL_PRESETS
        for preset in ALL_PRESETS:
            for m in preset.models:
                valid_models.add(f"{preset.id}/{m.id}")
        for role, model in new_config.items():
            if not role or not re.fullmatch(r"[a-zA-Z0-9_-]{1,32}", role):
                continue
            if model and model not in valid_models and model != "":
                raise HTTPException(400, f"Invalid model '{model}' for role '{role}'")
            _agent_config[role] = model
        # Propagate to existing fleet so new agents use updated models
        try:
            fleet_instance = fleet.get_fleet()
            fleet_instance.update_agent_config(dict(_agent_config))
        except Exception:
            pass  # Fleet not initialized yet
        return {"success": True, "config": _agent_config}

    @app.get("/api/search")
    async def search_api(query: str, max_results: int = 5, auth: dict[str, Any] = Depends(require_auth_dep)) -> dict[str, Any]:
        agent = get_agent()
        results = await agent.search.search(query, max_results)
        return {
            "results": [
                {"title": r.title, "url": r.url, "snippet": r.snippet, "source": r.source}
                for r in results
            ]
        }

    @app.get("/api/skills")
    async def skills_api(
        category: str | None = None,
        skill_type: str | None = None,
        query: str | None = None,
        auth: dict[str, Any] = Depends(require_auth_dep),
    ) -> dict[str, Any]:
        agent = get_agent()
        from js.skills.spec import SkillType
        st = SkillType(skill_type) if skill_type else None
        skills = agent.skills.list_skills(category=category, skill_type=st, query=query)
        return {
            "skills": skills,
            "categories": agent.skills.list_categories(),
            "global_stats": agent.skills.get_global_stats(),
        }

    @app.get("/api/skills/metrics")
    async def skills_metrics(auth: dict[str, Any] = Depends(require_auth_dep)) -> dict[str, Any]:
        """Return skill execution metrics for observability dashboard."""
        agent = get_agent()
        all_skills = agent.skills.list_skills()
        per_skill: list[dict[str, Any]] = []
        for skill in all_skills:
            stats = agent.skills.get_stats(skill["id"])
            if stats:
                per_skill.append({
                    "id": stats["id"],
                    "name": stats["name"],
                    "type": stats.get("type", "unknown"),
                    "trust_level": stats.get("trust_level", "community"),
                    "usage_count": stats.get("usage_count", 0),
                    "success_rate": round(stats.get("success_rate", 1.0), 3),
                    "avg_latency_ms": round(stats.get("avg_latency_ms", 0.0), 1),
                    "prerequisites_ok": stats.get("prerequisites_ok", True),
                })
        per_skill.sort(key=lambda x: x["usage_count"], reverse=True)
        return {
            "global": agent.skills.get_global_stats(),
            "per_skill": per_skill,
        }

    # NOTE: /api/memory/* endpoints moved to js/web/routers/memory.py

    # Hermes-specific endpoints MUST be defined BEFORE /api/skills/{skill_id}
    # to avoid "hermes" being captured as a skill_id path parameter.
    @app.get("/api/skills/hermes")
    async def hermes_skills_list(auth: dict[str, Any] = Depends(require_auth_dep)) -> dict[str, Any]:
        """List all Hermes skills with bridge diagnostics."""
        agent = get_agent()
        from js.skills.hermes_bridge import get_bridge_stats, is_hermes_skill

        hermes_skills = [
            s.to_summary_dict()
            for s in agent.skills.get_all().values()
            if is_hermes_skill(s.id)
        ]
        stats = get_bridge_stats()
        return {
            "skills": hermes_skills,
            "count": len(hermes_skills),
            "stats": stats.to_dict(),
        }

    @app.post("/api/skills/hermes/refresh")
    async def hermes_skills_refresh(auth: dict[str, Any] = Depends(require_auth_dep)) -> dict[str, Any]:
        """Refresh Hermes skills from disk without restarting the server."""
        agent = get_agent()
        result = agent.skills.refresh_hermes_skills()
        if result.get("success"):
            return result
        raise HTTPException(500, result.get("error", "Refresh failed"))

    @app.get("/api/skills/{skill_id}")
    async def skill_detail(skill_id: str, auth: dict[str, Any] = Depends(require_auth_dep)) -> dict[str, Any]:
        agent = get_agent()
        detail = agent.skills.view_skill(skill_id)
        if not detail:
            raise HTTPException(404, f"Skill '{skill_id}' not found")
        return detail

    @app.post("/api/skills/install")
    async def skill_install(payload: dict[str, Any], auth: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        agent = get_agent()
        source = payload.get("source", "")
        skill_id = payload.get("skill_id")
        try:
            spec = await agent.skills.install(source, skill_id)
            return {
                "success": True,
                "skill_id": spec.id,
                "trust_level": spec.trust_level.value,
                "risk_flags": spec.risk_flags,
            }
        except ValueError as e:
            raise HTTPException(400, str(e)) from e
        except Exception as e:
            logger.error(f"Skill install failed: {e}", exc_info=True)
            raise HTTPException(500, f"Failed to install skill: {e}") from e

    @app.delete("/api/skills/{skill_id}")
    async def skill_uninstall(skill_id: str, auth: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        agent = get_agent()
        if await agent.skills.uninstall(skill_id):
            return {"success": True}
        raise HTTPException(404, "Skill not found or is built-in")

    @app.post("/api/skills/{skill_id}/trust")
    async def skill_trust(skill_id: str, payload: dict[str, Any], auth: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        from js.skills.spec import TrustLevel

        agent = get_agent()
        level = payload.get("level", "")
        try:
            trust_level = TrustLevel(level)
        except ValueError:
            raise HTTPException(400, f"Invalid trust level: {level}") from None
        if agent.skills.trust_skill(skill_id, trust_level):
            return {"success": True, "skill_id": skill_id, "trust_level": level}
        raise HTTPException(404, f"Skill '{skill_id}' not found")

    @app.get("/api/skills/discover")
    async def skill_discover(query: str = "", auth: dict[str, Any] = Depends(require_auth_dep)) -> dict[str, Any]:
        """Search the ClawHub skill marketplace."""
        agent = get_agent()
        if not hasattr(agent, "_clawhub") or agent._clawhub is None:
            from js.skills.clawhub import ClawHubClient

            agent._clawhub = ClawHubClient(agent.settings.state_dir)

        try:
            index = await agent._clawhub.fetch_index()
        except Exception as e:
            logger.error(f"ClawHub fetch failed: {e}", exc_info=True)
            raise HTTPException(502, f"Failed to fetch ClawHub index: {e}") from e
        results = agent._clawhub.search_index(query) if query else index
        return {
            "success": True,
            "total": len(index),
            "results": results[:50],  # Limit to 50 results
        }

    @app.post("/api/skills/discover/install")
    async def skill_discover_install(payload: dict[str, Any], auth: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        """Install a skill from the ClawHub marketplace."""
        from js.skills.clawhub import ClawHubClient

        skill_id = payload.get("skill_id", "")
        if not skill_id:
            raise HTTPException(400, "skill_id is required")

        agent = get_agent()
        clawhub = getattr(agent, "_clawhub", None) or ClawHubClient(agent.settings.state_dir)
        agent._clawhub = clawhub

        source = clawhub.get_skill_source(skill_id)
        if not source:
            raise HTTPException(404, f"Skill '{skill_id}' not found in ClawHub index")

        try:
            spec = await agent.skills.install(source, skill_id)
            return {
                "success": True,
                "skill_id": spec.id,
                "trust_level": spec.trust_level.value,
            }
        except ValueError as e:
            raise HTTPException(400, str(e)) from e
        except Exception as e:
            logger.error(f"ClawHub install failed: {e}", exc_info=True)
            raise HTTPException(500, f"Failed to install skill: {e}") from e

    @app.post("/api/upload")
    async def upload_file(file: UploadFile | None = None, auth: dict[str, Any] = Depends(require_auth_dep)) -> dict[str, Any]:
        """Upload a file to the workspace/uploads directory."""
        if file is None:
            raise HTTPException(400, "No file provided")
        agent = get_agent()
        uploads_dir = agent.settings.workspace / "uploads"
        uploads_dir.mkdir(parents=True, exist_ok=True)

        # Sanitize filename: basename only, no path traversal
        from pathlib import PurePath
        safe_name = PurePath(file.filename or "unnamed").name
        if not safe_name or safe_name.startswith("."):
            safe_name = "unnamed"

        target_path = uploads_dir / safe_name
        # Handle duplicate names
        counter = 1
        stem = target_path.stem
        suffix = target_path.suffix
        while target_path.exists():
            target_path = uploads_dir / f"{stem}_{counter}{suffix}"
            counter += 1

        max_size = 100 * 1024 * 1024  # 100MB
        total = 0
        with target_path.open("wb") as f:
            while True:
                chunk = await file.read(65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_size:
                    target_path.unlink(missing_ok=True)
                    raise HTTPException(413, "File too large (max 100MB)")
                f.write(chunk)

        rel_path = str(target_path.relative_to(agent.settings.workspace))
        return {
            "success": True,
            "filename": safe_name,
            "saved_as": target_path.name,
            "path": rel_path,
            "size": total,
            "content_type": file.content_type or "application/octet-stream",
        }

    @app.get("/api/uploads")
    async def list_uploads(auth: dict[str, Any] = Depends(require_auth_dep)) -> dict[str, Any]:
        """List uploaded files in workspace/uploads."""
        agent = get_agent()
        uploads_dir = agent.settings.workspace / "uploads"
        if not uploads_dir.exists():
            return {"files": []}
        files = []
        for f in sorted(uploads_dir.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
            if f.is_file():
                stat = f.stat()
                files.append({
                    "name": f.name,
                    "path": str(f.relative_to(agent.settings.workspace)),
                    "size": stat.st_size,
                    "modified": stat.st_mtime,
                })
        return {"files": files}

    @app.delete("/api/uploads/{filename}")
    async def delete_upload(filename: str, auth: dict[str, Any] = Depends(require_auth_dep)) -> dict[str, Any]:
        """Delete an uploaded file."""
        agent = get_agent()
        from pathlib import PurePath
        safe_name = PurePath(filename).name
        target = agent.settings.workspace / "uploads" / safe_name
        try:
            target.relative_to(agent.settings.workspace / "uploads")
        except ValueError:
            raise HTTPException(400, "Invalid filename") from None
        if target.exists():
            target.unlink()
            return {"success": True}
        raise HTTPException(404, "File not found")

    @app.get("/api/file-preview")
    async def file_preview(path: str, auth: dict[str, Any] = Depends(require_auth_dep)) -> dict[str, Any]:
        """Preview a file's content or metadata."""
        agent = get_agent()
        try:
            resolved = (agent.settings.workspace / path).resolve()
            resolved.relative_to(agent.settings.workspace.resolve())
        except (ValueError, RuntimeError) as e:
            raise HTTPException(400, f"Invalid path: {e}") from e

        if not resolved.exists():
            raise HTTPException(404, "File not found")

        result: dict[str, Any] = {
            "path": path,
            "name": resolved.name,
            "size": resolved.stat().st_size,
        }

        # Text files: return content preview
        text_suffixes = {".txt", ".md", ".py", ".js", ".json", ".yaml", ".yml", ".csv", ".html", ".css", ".xml", ".sh", ".log"}
        if resolved.suffix.lower() in text_suffixes:
            try:
                content = resolved.read_text(encoding="utf-8", errors="replace")
                result["type"] = "text"
                result["content"] = content[:5000]
                result["truncated"] = len(content) > 5000
            except Exception as e:
                result["type"] = "binary"
                result["error"] = str(e)
        else:
            result["type"] = "binary"

        return result

    @app.websocket("/ws")
    async def websocket_endpoint(websocket: WebSocket) -> None:
        # Authenticate WebSocket connection via X-API-Key header + Origin check.
        # Bootstrap anonymous access is REMOVED — all connections require a
        # valid key (or auth-optional mode with Origin whitelist).
        from js.exceptions import AuthRequiredError
        from js.web.auth import AuthManager, check_origin

        # Origin check first — reject cross-origin WebSocket upgrades
        try:
            check_origin(websocket)
        except HTTPException as exc:
            await websocket.close(code=1008, reason=exc.detail)
            return

        # Browser WebSocket cannot send custom headers, so fall back to
        # query parameter and cookie.
        # Cookie-first auth for WebSocket to avoid leaking the key to
        # browser history, server logs, and referrer headers.
        api_key = (
            websocket.cookies.get("x-api-key", "")
            or websocket.headers.get("x-api-key", "")
            or websocket.query_params.get("x-api-key", "")
        )
        agent = get_agent()
        settings = agent.settings
        ws_owner_hash: str | None = None

        if settings.security.api_key_required:
            auth_mgr = AuthManager(settings.state_dir)
            try:
                auth_ctx = auth_mgr.verify(api_key)
                ws_owner_hash = auth_ctx.get("key_hash")
            except AuthRequiredError as e:
                await websocket.close(code=1008, reason=str(e))
                return
        else:
            # Auth optional: verify if key provided, otherwise anonymous
            if api_key:
                try:
                    auth_ctx = AuthManager(settings.state_dir).verify(api_key)
                    ws_owner_hash = auth_ctx.get("key_hash")
                except AuthRequiredError:
                    pass  # Invalid key → anonymous

        await websocket.accept()
        agent = get_agent()
        session_id: str | None = None
        max_msg_bytes = 1024 * 1024  # 1MB
        ping_interval = 30.0

        async def _receive_with_limit() -> dict[str, Any]:
            raw = await websocket.receive()
            if isinstance(raw, str):
                if len(raw.encode("utf-8")) > max_msg_bytes:
                    raise ValueError("Message too large")
                return json.loads(raw)
            if isinstance(raw, bytes):
                if len(raw) > max_msg_bytes:
                    raise ValueError("Message too large")
                return json.loads(raw.decode("utf-8"))
            # WebSocket text frame from Starlette
            data = raw.get("text") or raw.get("bytes", b"").decode("utf-8")
            if len(data.encode("utf-8")) > max_msg_bytes:
                raise ValueError("Message too large")
            result: dict[str, Any] = json.loads(data)
            return result

        try:
            while True:
                # Receive with timeout to allow periodic ping checks
                try:
                    data = await asyncio.wait_for(_receive_with_limit(), timeout=ping_interval)
                except TimeoutError:
                    try:
                        await websocket.send_json({"type": "ping"})
                    except Exception:
                        break
                    continue

                msg_type = data.get("type", "message")

                if msg_type == "message":
                    user_msg = data.get("content", "")
                    session_id = data.get("session_id") or session_id
                    model = data.get("model") or _active_model or None
                    attachments = data.get("attachments", [])

                    await websocket.send_json({"type": "status", "content": "thinking..."})

                    # Progress callback: notify frontend of each tool execution
                    async def _progress(tool_name: str, result: Any) -> None:
                        try:
                            output_preview = result.output[:200] if getattr(result, "output", None) else ""
                            await websocket.send_json({
                                "type": "progress",
                                "tool": tool_name,
                                "success": getattr(result, "success", False),
                                "preview": output_preview,
                            })
                        except Exception:
                            pass

                    # Propagate session owner to agent layer for memory isolation
                    from js.web.auth import _session_owner_hash
                    token = _session_owner_hash.set(ws_owner_hash)
                    try:
                        state = await agent.run(
                            user_msg,
                            session_id=session_id,
                            model=model,
                            attachments=attachments,
                            progress_callback=_progress,
                        )
                    finally:
                        _session_owner_hash.reset(token)
                    session_id = state.session_id

                    # Record token usage
                    _record_usage(state, explicit_model=model)

                    if state.status == "error":
                        await websocket.send_json(
                            {
                                "type": "error",
                                "content": humanize_error(state.error_message),
                                "session_id": session_id,
                                "turns": state.turn_count,
                                "tokens": state.total_tokens,
                                "cost": round(state.cost_estimate, 6),
                                "model": state.model or model or "unknown",
                            }
                        )
                    else:
                        assistant_msg = ""
                        for msg in reversed(state.messages):
                            if msg.role == "assistant" and isinstance(msg.content, str) and msg.content:
                                assistant_msg = msg.content
                                break

                        await websocket.send_json(
                            {
                                "type": "response",
                                "content": assistant_msg,
                                "session_id": session_id,
                                "turns": state.turn_count,
                                "tokens": state.total_tokens,
                                "cost": round(state.cost_estimate, 6),
                                "status": state.status,
                                "compression": state.compression_stats,
                                "model": state.model or model or "unknown",
                            }
                        )

                elif msg_type == "stream":
                    user_msg = data.get("content", "")
                    session_id = data.get("session_id") or session_id
                    model = data.get("model")
                    attachments = data.get("attachments", [])

                    await websocket.send_json({"type": "status", "content": "streaming..."})

                    # Native token-level streaming for the final assistant response.
                    # Tool-calling turns remain non-streaming (parsed atomically).
                    streamed = False

                    async def _send_token(token: str) -> None:
                        nonlocal streamed
                        streamed = True
                        await websocket.send_json({"type": "token", "content": token})

                    from js.web.auth import _session_owner_hash
                    owner_token = _session_owner_hash.set(ws_owner_hash)
                    try:
                        state = await agent.run(
                            user_msg,
                            session_id=session_id,
                            model=model,
                            attachments=attachments,
                            stream_callback=_send_token,
                        )
                    finally:
                        _session_owner_hash.reset(owner_token)
                    session_id = state.session_id

                    if state.status == "error":
                        await websocket.send_json({
                            "type": "error",
                            "content": humanize_error(state.error_message),
                            "session_id": session_id,
                            "turns": state.turn_count,
                            "tokens": state.total_tokens,
                            "cost": round(state.cost_estimate, 6),
                            "model": state.model or model or "unknown",
                        })
                    else:
                        assistant_msg = ""
                        for msg in reversed(state.messages):
                            if msg.role == "assistant" and isinstance(msg.content, str) and msg.content:
                                assistant_msg = msg.content
                                break

                        # Fallback: if streaming never fired (all tool turns or provider
                        # doesn't support streaming), send the full response in one go.
                        if not streamed and assistant_msg:
                            await websocket.send_json({"type": "response", "content": assistant_msg})

                        await websocket.send_json({
                            "type": "done",
                            "session_id": session_id,
                            "turns": state.turn_count,
                            "tokens": state.total_tokens,
                            "cost": round(state.cost_estimate, 6),
                            "status": state.status,
                            "compression": state.compression_stats,
                        })

                    # Store memories for stream path (same as run() path)
                    try:
                        redacted_msg = agent.secrets.detect_and_redact(user_msg, "user_input")
                        await asyncio.to_thread(
                            agent.memory.store_working,
                            session_id=session_id,
                            key="user_input",
                            value=redacted_msg[:500],
                            category="interaction",
                            importance=5,
                        )
                        await asyncio.to_thread(
                            agent.memory.store_episode,
                            session_id=session_id,
                            summary=f"User: {redacted_msg[:80]}... → Assistant: {assistant_msg[:80]}...",
                            topics=list({
                                word.lower() for word in (redacted_msg + " " + assistant_msg).split()
                                if len(word) > 4 and word.isalpha()
                            })[:5],
                            importance=5,
                        )
                        # Persist conversation messages
                        await asyncio.to_thread(
                            agent.memory.store_messages,
                            session_id,
                            [
                                {"role": "user", "content": redacted_msg},
                                {"role": "assistant", "content": assistant_msg},
                            ],
                        )
                        agent._dream_scheduler.notify_activity(user_msg, assistant_msg)
                    except Exception:
                        logger.warning("Stream memory storage failed", exc_info=True)

                elif msg_type == "ping":
                    await websocket.send_json({"type": "pong"})

        except WebSocketDisconnect:
            logger.info("WebSocket disconnected")
        except Exception as e:
            logger.error(f"WebSocket error: {e}")
            try:
                await websocket.send_json({"type": "error", "content": str(e)})
            except Exception:
                logger.warning("Failed to send error to websocket", exc_info=True)

    @app.websocket("/ws/fleet")
    async def fleet_websocket_endpoint(websocket: WebSocket) -> None:
        """Real-time fleet dashboard WebSocket."""
        from js.exceptions import AuthRequiredError
        from js.web.auth import _ADMIN_ROLE, AuthManager, check_origin
        from js.web.routers.fleet import get_fleet

        # Origin check first — reject cross-origin WebSocket upgrades
        try:
            check_origin(websocket)
        except HTTPException as exc:
            await websocket.close(code=1008, reason=exc.detail)
            return

        # Browser WebSocket cannot send custom headers, so fall back to
        # query parameter and cookie.
        # Cookie-first auth for WebSocket to avoid leaking the key to
        # browser history, server logs, and referrer headers.
        api_key = (
            websocket.cookies.get("x-api-key", "")
            or websocket.headers.get("x-api-key", "")
            or websocket.query_params.get("x-api-key", "")
        )
        settings = get_agent().settings
        if settings.security.api_key_required:
            auth_mgr = AuthManager(settings.state_dir)
            try:
                auth_ctx = auth_mgr.verify(api_key)
            except AuthRequiredError as e:
                await websocket.close(code=1008, reason=str(e))
                return
            if auth_ctx.get("role") != _ADMIN_ROLE:
                await websocket.close(code=1008, reason="Admin role required")
                return
        else:
            # Auth optional: still require admin role for fleet
            if api_key:
                try:
                    auth_ctx = AuthManager(settings.state_dir).verify(api_key)
                except AuthRequiredError as e:
                    await websocket.close(code=1008, reason=str(e))
                    return
                if auth_ctx.get("role") != _ADMIN_ROLE:
                    await websocket.close(code=1008, reason="Admin role required")
                    return
            else:
                await websocket.close(code=1008, reason="API key required for fleet access")
                return
        await websocket.accept()

        fleet = get_fleet()
        event_queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=500)

        async def _on_event(event: dict[str, Any]) -> None:
            try:
                event_queue.put_nowait(event)
            except asyncio.QueueFull:
                pass

        fleet.on_event(_on_event)

        # Send initial status
        try:
            await websocket.send_json({
                "type": "status",
                "data": fleet.get_status(),
            })
        except Exception:
            pass

        try:
            while True:
                # Drain event queue with timeout to also check for client messages
                try:
                    event = await asyncio.wait_for(event_queue.get(), timeout=0.5)
                    await websocket.send_json(event)
                    continue
                except TimeoutError:
                    pass
                except RuntimeError as e:
                    if "disconnect" in str(e).lower():
                        break
                    raise

                # Check for client messages (non-blocking)
                try:
                    raw = await asyncio.wait_for(websocket.receive(), timeout=0.1)
                    if isinstance(raw, str):
                        data = json.loads(raw)
                    else:
                        data = json.loads(raw.get("text") or raw.get("bytes", b"").decode("utf-8"))

                    msg_type = data.get("type", "")
                    if msg_type == "status":
                        await websocket.send_json({
                            "type": "status",
                            "data": fleet.get_status(),
                        })
                    elif msg_type == "collaborate":
                        subtasks_raw = data.get("subtasks", [])
                        subtasks: list[str] = [st.get("description", "") for st in subtasks_raw if st.get("description")]
                        role_mapping_raw = data.get("role_mapping", {})
                        role_mapping: dict[int, str] = {int(k): v for k, v in role_mapping_raw.items() if v}
                        asyncio.create_task(fleet.collaborate(
                            main_task=data.get("task", ""),
                            subtasks=subtasks or None,
                            role_mapping=role_mapping or None,
                            session_id=data.get("session_id") or None,
                            mode=data.get("mode", "auto"),
                        ))
                        await websocket.send_json({"type": "ack", "action": "collaborate"})
                    elif msg_type == "continue":
                        session_id = data.get("session_id")
                        if session_id:
                            asyncio.create_task(fleet.continue_session(
                                session_id=session_id,
                                follow_up=data.get("task", ""),
                            ))
                            await websocket.send_json({"type": "ack", "action": "continue"})
                        else:
                            await websocket.send_json({"type": "error", "message": "session_id required for continue"})
                    elif msg_type == "spawn":
                        # Spawn is no longer supported; agents are created on-demand
                        await websocket.send_json({
                            "type": "ack",
                            "action": "spawn",
                            "warning": "Spawn is deprecated. Agents are created automatically.",
                        })
                    elif msg_type == "ping":
                        await websocket.send_json({"type": "pong"})
                except TimeoutError:
                    pass
                except WebSocketDisconnect:
                    break
                except RuntimeError as e:
                    if "disconnect" in str(e).lower():
                        break
                    raise
                except Exception as e:
                    logger.warning(f"Fleet WS client message error: {e}")
        except WebSocketDisconnect:
            logger.info("Fleet WebSocket disconnected")
        except Exception as e:
            logger.error(f"Fleet WebSocket error: {e}")
        finally:
            fleet.off_event(_on_event)

    # ------------------------------------------------------------------
    # Resource-aware rate-limiting middleware
    # ------------------------------------------------------------------
    global _active_requests, _active_lock

    @app.middleware("http")
    async def resource_limit_middleware(request: Request, call_next: Any) -> Any:
        global _active_requests

        # Skip static files and lightweight health probes
        path = request.url.path
        if path.startswith("/static") or path in ("/api/health", "/api/status", "/api/diag"):
            return await call_next(request)

        agent = _agent
        if agent is None:
            return await call_next(request)

        from js.runtime.governor import ResourceGovernor

        governor = getattr(agent, "_governor", None)
        is_governor = isinstance(governor, ResourceGovernor)

        # Critical memory: reject new requests immediately
        if is_governor:
            assert governor is not None
            if governor.paused:
                return JSONResponse(
                status_code=503,
                content={
                    "detail": "Server is under memory pressure. Please try again later."
                },
            )

        # Dynamic concurrency cap based on memory pressure
        max_concurrent = 100
        if is_governor:
            assert governor is not None
            history = governor.get_history(limit=1)
            if history:
                mem_pct = history[0].get("system_memory_percent", 0)
                if mem_pct > 80:
                    max_concurrent = 20
                elif mem_pct > 60:
                    max_concurrent = 50

        # Wait for a free slot (with 30s total timeout)
        acquired = False
        for _ in range(300):  # 300 * 0.1s = 30s
            async with _active_lock:
                if _active_requests < max_concurrent:
                    _active_requests += 1
                    acquired = True
                    break
            await asyncio.sleep(0.1)

        if not acquired:
            return JSONResponse(
                status_code=503,
                content={"detail": "Server is at maximum capacity. Please try again later."},
            )

        try:
            return await call_next(request)
        finally:
            async with _active_lock:
                _active_requests -= 1

    # ------------------------------------------------------------------
    # Health & resource metrics endpoints
    # ------------------------------------------------------------------

    @app.get("/api/health")
    async def health(auth: dict[str, Any] = Depends(require_auth_dep)) -> dict[str, Any]:
        """Return comprehensive server health including resource usage."""
        agent = get_agent()
        from js.runtime.governor import ResourceGovernor

        governor = getattr(agent, "_governor", None)
        is_governor = isinstance(governor, ResourceGovernor)

        # Latest resource snapshot
        memory_info: dict[str, Any] = {"status": "unknown"}
        agents_info: dict[str, Any] = {"active": 0, "idle": 0, "total_spawned": 0}
        tasks_info: dict[str, Any] = {"in_flight": 0, "completed_today": 0}

        if is_governor:
            assert governor is not None
            history = governor.get_history(limit=1)
            if history:
                snap = history[0]
                mem_pct = snap.get("system_memory_percent", 0)
                mem_status = "normal"
                if mem_pct > 90:
                    mem_status = "critical"
                elif mem_pct > 80:
                    mem_status = "pressure"
                elif mem_pct > 70:
                    mem_status = "warning"

                memory_info = {
                    "process_rss_mb": snap.get("process_rss_mb"),
                    "system_used_percent": mem_pct,
                    "status": mem_status,
                }
                agents_info = {
                    "active": snap.get("active_agents", 0),
                    "idle": snap.get("idle_agents", 0),
                }
                tasks_info = {
                    "in_flight": snap.get("in_flight_tasks", 0),
                }

        # Uptime
        uptime = 0.0
        if _startup_time:
            uptime = round(asyncio.get_event_loop().time() - _startup_time, 1)

        # Overall status
        status = "healthy"
        if is_governor:
            assert governor is not None
            if governor.paused:
                status = "degraded"
        if agent.degraded:
            status = "degraded"

        return {
            "status": status,
            "uptime_seconds": uptime,
            "memory": memory_info,
            "agents": agents_info,
            "tasks": tasks_info,
            "degraded": agent.degraded,
            "paused": governor.paused if is_governor else False,  # type: ignore[union-attr]
        }

    @app.get("/api/metrics/resources")
    async def resource_metrics(
        auth: dict[str, Any] = Depends(require_auth_dep),
    ) -> dict[str, Any]:
        """Return historical resource snapshots for observability."""
        agent = get_agent()
        from js.runtime.governor import ResourceGovernor

        governor = getattr(agent, "_governor", None)
        is_governor = isinstance(governor, ResourceGovernor)
        history = governor.get_history(limit=200) if is_governor else []  # type: ignore[union-attr]
        return {
            "samples": history,
            "count": len(history),
        }

    return app


_TEMPLATE_DIR = Path(__file__).parent / "templates"
_STATIC_DIR = Path(__file__).parent / "static"

def _load_index_html() -> str:
    path = _TEMPLATE_DIR / 'index.html'
    if path.exists():
        return path.read_text(encoding='utf-8')
    return '<h1>Template not found</h1>'


def _is_loopback(request: Request) -> bool:
    """True when the request originates from the local machine."""
    client = request.client
    if client is None:
        return False
    return client.host in ("127.0.0.1", "::1", "localhost")


def _inject_bootstrap_key(html: str, key: str) -> str:
    """Embed the bootstrap admin key so the local browser auto-authenticates."""
    snippet = f"<script>window.__BOOTSTRAP_API_KEY__={json.dumps(key)};</script>"
    if "</head>" in html:
        return html.replace("</head>", snippet + "</head>", 1)
    return snippet + html
