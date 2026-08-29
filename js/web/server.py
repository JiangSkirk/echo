"""FastAPI Web server with WebSocket streaming."""

from __future__ import annotations

import asyncio
import os
import re
import secrets as secrets
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol, cast
from urllib.parse import urlparse

from fastapi import (
    Depends,
    FastAPI,
    Form,
    HTTPException,
    Request,
    UploadFile,
)
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

try:
    from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
    from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
    from prometheus_client import make_asgi_app

    _MONITORING_AVAILABLE = True
except ImportError:
    _MONITORING_AVAILABLE = False
    FastAPIInstrumentor = None  # type: ignore[misc,assignment]
    HTTPXClientInstrumentor = None  # type: ignore[misc,assignment]
    make_asgi_app = None  # type: ignore[assignment]

from js.agent.tool_executor import (
    CONTROL_UPLOAD_MUTATE_TOOL,
)
from js.config import JSSettings, ModelConfig, ModelProviderConfig
from js.echo.effect_interpreter import ToolEffect
from js.echo.ledger.service import (
    EchoSafetyService,
)
from js.echo.turn_runtime import run_echo_turn as run_echo_turn
from js.utils.log import get_logger
from js.web import model_refresh
from js.web.auth import (
    memory_owner,
    require_admin,
    require_admin_write,
    require_auth_dep,
    require_user_write,
    runtime_owner,
)
from js.web.bootstrap import (
    _persist_bootstrap_admin_key as _persist_bootstrap_admin_key,
)
from js.web.bootstrap import (
    _provision_bootstrap_admin_key as _provision_bootstrap_admin_key,
)
from js.web.bootstrap import (
    consume_bootstrap_admin_key_file as consume_bootstrap_admin_key_file,
)
from js.web.deps import (
    AgentConfigState,
    get_active_model,
    get_agent_config_state,
    get_stats_store,
    optional_query_session_id,
)
from js.web.deps import (
    require_path_session_id as _require_path_session_id,
)
from js.web.deps import (
    require_upload_session_id as _require_upload_session_id,
)
from js.web.effects import (
    _execute_evolution_action as _execute_evolution_action,
)
from js.web.effects import (
    _execute_fleet_config_effect as _execute_fleet_config_effect,
)
from js.web.effects import (
    _execute_private_skill_mutation as _execute_private_skill_mutation,
)
from js.web.effects import (
    _execute_provider_discovery_effect as _execute_provider_discovery_effect,
)
from js.web.effects import (
    _execute_provider_mutation_effect as _execute_provider_mutation_effect,
)
from js.web.effects import (
    _execute_session_mutation as _execute_session_mutation,
)
from js.web.effects import (
    _execute_web_tool_effect as _execute_web_tool_effect,
)
from js.web.effects import (
    _raise_control_tool_error as _raise_control_tool_error,
)
from js.web.effects import (
    _raise_session_mutation_error as _raise_session_mutation_error,
)
from js.web.lifespan import lifespan as lifespan

# Imported routers (extracted from this file)
from js.web.routers import chat as chat_router
from js.web.routers import cron, desktop, metrics, setup
from js.web.routers import memory as memory_router
from js.web.routers import plugins as plugins_router
from js.web.routers import scenarios as scenarios_router
from js.web.routers import tasks as tasks_router
from js.web.runtime_context import (
    current_web_runtime,
    install_web_runtime_context,
    web_channel,
)
from js.web.stats_store import TokenStatsStore
from js.web.uploads import (
    list_owned_upload_entries,
    read_agent_attachment,
    safe_upload_filename,
    secure_upload_writer,
)

_OTEL_TRUTHY = frozenset({"1", "true", "yes", "on"})
_HTTPX_INSTRUMENTED = False


def _otel_enabled() -> bool:
    raw = os.environ.get("JS_ENABLE_OTEL", "")
    return raw.strip().lower() in _OTEL_TRUTHY


def _maybe_instrument_httpx() -> None:
    """Instrument httpx only when JS_ENABLE_OTEL is explicitly enabled."""
    global _HTTPX_INSTRUMENTED
    if (
        _HTTPX_INSTRUMENTED
        or not _MONITORING_AVAILABLE
        or HTTPXClientInstrumentor is None
        or not _otel_enabled()
    ):
        return
    HTTPXClientInstrumentor().instrument()
    _HTTPX_INSTRUMENTED = True


logger = get_logger("js.web")

if TYPE_CHECKING:
    from js.agent import JSAgent

# Global agent instance
_agent: JSAgent | None = None
_settings: JSSettings | None = None
_stats_store: TokenStatsStore | None = None
_echo_safety_service: EchoSafetyService | None = None
_active_model: str = ""
_startup_time: float = 0.0
# Plaintext of an admin key minted this session for first-run bootstrap.
# Set only when auth is required and no admin key existed at startup; used to
# auto-authenticate the desktop window / local Host so the fresh install lands
# usable.
_bootstrap_admin_key: str | None = None


def _load_active_model(state_dir: Path) -> str:
    """Load the last selected model from the configured state dir."""
    from js.utils.atomic_state import AtomicStateError, read_text_state

    try:
        return read_text_state(
            state_dir / "active_model.txt",
            max_bytes=512,
        ).strip()
    except AtomicStateError:
        logger.warning("Active model state is unavailable", exc_info=True)
        return ""


def _save_active_model(state_dir: Path, model_id: str) -> None:
    """Persist the selected model so it survives server restarts.

    Keyed off ``settings.state_dir`` (not a hardcoded ``~/.js/state``) so that
    non-default installs work and tests can never pollute the real user file.
    """
    from js.utils.atomic_state import write_text_state

    write_text_state(state_dir / "active_model.txt", model_id, max_bytes=512)


# Loaded during lifespan startup once settings.state_dir is known (and only
# after the model has been validated against the configured providers).
_active_model = ""

# In-flight request tracking for graceful shutdown
_active_requests: int = 0
_active_lock = asyncio.Lock()
_FLEET_SHUTDOWN_TIMEOUT_SECONDS = 5.0


class _PreviewSnapshot(Protocol):
    """Structural preview data shared by Agent and Work file gates."""

    @property
    def name(self) -> str: ...

    @property
    def suffix(self) -> str: ...

    @property
    def size(self) -> int: ...

    @property
    def data(self) -> bytes: ...


async def _drain_inflight(timeout: float = 5.0) -> None:
    """Wait for in-flight HTTP requests to complete."""
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        async with _active_lock:
            if _active_requests <= 0:
                return
        await asyncio.sleep(0.1)


async def _close_runtime_fleet(fleet: Any | None, *, runtime_name: str) -> None:
    """Close a runtime-owned fleet without blocking the rest of shutdown forever."""
    if fleet is None:
        return
    close_all = getattr(fleet, "close_all", None)
    if not callable(close_all):
        logger.warning(
            "Fleet shutdown degraded: runtime fleet has no close_all",
            runtime=runtime_name,
        )
        return
    try:
        await asyncio.wait_for(close_all(), timeout=_FLEET_SHUTDOWN_TIMEOUT_SECONDS)
    except TimeoutError:
        logger.warning(
            "Fleet shutdown degraded: close_all timed out",
            runtime=runtime_name,
            timeout_seconds=_FLEET_SHUTDOWN_TIMEOUT_SECONDS,
        )
    except Exception as exc:
        logger.warning(
            "Fleet shutdown degraded: close_all failed",
            runtime=runtime_name,
            error_type=type(exc).__name__,
            exc_info=True,
        )


def get_agent() -> JSAgent:
    runtime = current_web_runtime()
    if runtime is not None:
        return cast("JSAgent", runtime.agent)
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


def _bots_bot_id() -> str:
    try:
        from js.bots.persona import current_bot_binding

        binding = current_bot_binding()
    except Exception:
        return ""
    return binding.bot_id if binding is not None else ""


def _bots_prefix_id() -> str:
    try:
        from js.bots.persona import current_bot_binding

        binding = current_bot_binding()
    except Exception:
        return ""
    return binding.prefix_id if binding is not None else ""


def _bots_exclude_first_write(buckets: dict[str, Any]) -> bool:
    return (
        int(buckets.get("cache_write", 0) or 0) > 0 and int(buckets.get("cache_read", 0) or 0) == 0
    )


def _record_usage(state: Any, explicit_model: str | None = None) -> None:
    """Record token usage to stats store with provider resolution."""
    stats_store = get_stats_store()
    if stats_store is None:
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
    buckets = getattr(state, "usage_buckets", {}) or {}
    try:
        stats_store.record(
            model=model_id,
            provider=provider,
            prompt_tokens=total_in,
            completion_tokens=total_out,
            cost=state.cost_estimate,
            cached_tokens=cached_tokens,
            session_id=getattr(state, "session_id", ""),
            run_id=getattr(state, "run_id", ""),
            uncached_input=int(buckets.get("uncached_input", max(total_in - cached_tokens, 0))),
            cache_read=int(buckets.get("cache_read", cached_tokens)),
            cache_write=int(buckets.get("cache_write", 0)),
            output=int(buckets.get("output", total_out)),
            reasoning=int(buckets.get("reasoning", 0)),
            input_total=int(buckets.get("input_total", total_in)),
            usage_source=str(getattr(state, "usage_source", "unavailable") or "unavailable"),
            prefix_id=str(getattr(state, "prefix_id", "") or _bots_prefix_id()),
            bot_id=_bots_bot_id(),
            exclude_from_hit_rate=_bots_exclude_first_write(buckets),
        )
    except Exception as exc:
        logger.warning(
            "Token usage telemetry degraded after successful WebSocket chat",
            error_type=type(exc).__name__,
            exc_info=True,
        )


def _assistant_text_from_state(state: Any) -> str:
    for msg in reversed(getattr(state, "messages", ())):
        if msg.role == "assistant" and isinstance(msg.content, str) and msg.content:
            return msg.content
    return ""


class _AdminOnlyASGIMount:
    """Gate a raw ASGI mount (e.g. Prometheus /metrics) behind admin auth.

    ``app.mount()`` bypasses FastAPI dependencies, so the check runs here:
    X-API-Key header or the HttpOnly session cookie must resolve to an admin
    context.  Failures fail closed with 401/403 instead of leaking metrics.
    """

    def __init__(self, inner: Any) -> None:
        self._inner = inner

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self._inner(scope, receive, send)
            return
        from js.web.auth import _ADMIN_ROLE, authenticate_credentials, resolve_session_cookie

        request = Request(scope, receive)
        try:
            from js.appshell.principal import appshell_auth_context_from_scope

            managed, injected_auth = appshell_auth_context_from_scope(scope)
            if managed:
                if injected_auth is None:
                    raise HTTPException(status_code=401, detail="AppShell session is required")
                auth_ctx = injected_auth
            else:
                product_id = "js-agent"
                runtime_settings = getattr(request.app.state, "runtime_settings", None)
                if runtime_settings is not None:
                    product_id = str(
                        getattr(runtime_settings, "product_id", "js-agent") or "js-agent"
                    )
                elif _settings is not None:
                    product_id = str(getattr(_settings, "product_id", "js-agent") or "js-agent")
                auth_ctx = await authenticate_credentials(
                    request.headers.get("x-api-key"),
                    resolve_session_cookie(request.cookies, product_id),
                )
            if auth_ctx.get("role") != _ADMIN_ROLE:
                raise HTTPException(
                    status_code=403,
                    detail="Admin role required",
                )
        except HTTPException as exc:
            response = JSONResponse(
                {"detail": exc.detail},
                status_code=exc.status_code,
                headers=getattr(exc, "headers", None),
            )
            await response(scope, receive, send)
            return
        await self._inner(scope, receive, send)


def create_app(
    *,
    lifespan_context: Any | None = None,
    title: str = "JS Agent",
    runtime_settings: JSSettings | None = None,
    manage_orind: bool = False,
) -> FastAPI:
    _maybe_instrument_httpx()
    selected_lifespan = lifespan if lifespan_context is None else lifespan_context

    @asynccontextmanager
    async def app_lifespan(app: FastAPI) -> AsyncIterator[None]:
        async with selected_lifespan(app):
            runtime = getattr(app.state, "web_runtime", None)
            if runtime is not None:
                cast("Any", runtime).agent_config_state = app.state.agent_config_state
                cast("Any", runtime).model_refresh_state = app.state.model_refresh_state
            yield

    app = FastAPI(
        title=title,
        lifespan=app_lifespan,
        # Do not expose /docs, /redoc, or /openapi.json without auth — the full
        # API schema is reconnaissance value.  app.openapi() remains available
        # to in-process consumers (e.g. system diagnostics).
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.runtime_settings = runtime_settings
    app.state.manage_orind = manage_orind
    app.state.agent_config_state = AgentConfigState()
    app.state.model_refresh_state = model_refresh.ModelRefreshState()

    # CORS: allow localhost origins so browser preflight (OPTIONS) works
    # when custom headers (e.g. X-API-Key) are sent with PATCH/DELETE.
    # Derive allowed origins from the configured bind host/port so the
    # server works on any port without hard-coding :8000.
    from fastapi.middleware.cors import CORSMiddleware

    from js.web.auth import cors_allow_origins

    effective_settings = runtime_settings or _settings
    raw_host = (
        getattr(effective_settings, "bind_host", "127.0.0.1") if effective_settings else "127.0.0.1"
    )
    _bind_host = raw_host if isinstance(raw_host, str) and raw_host else "127.0.0.1"
    raw_port = getattr(effective_settings, "bind_port", 8000) if effective_settings else 8000
    _bind_port = raw_port if isinstance(raw_port, int) else 8000
    # Port-less http://127.0.0.1 and http://localhost mean :80. SameSite
    # cookies ignore ports, so listing those origins would let a page on :80
    # read credentialed GET responses from this bind port.
    _cors_origins = cors_allow_origins(str(_bind_host), int(_bind_port))
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
        if _otel_enabled() and FastAPIInstrumentor is not None:
            FastAPIInstrumentor.instrument_app(app)
        if make_asgi_app is not None:
            app.mount("/metrics", cast("Any", _AdminOnlyASGIMount(make_asgi_app())))

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
    from js.appshell.switch_api import router as appshell_router
    from js.web.routers import approvals, fleet, manual_reviews, system
    from js.web.routers import bots as bots_router
    from js.web.routers import gateway as gateway_router

    app.include_router(chat_router.router)
    app.include_router(cron.router)
    app.include_router(plugins_router.router)
    app.include_router(fleet.router)
    app.include_router(bots_router.router)
    app.include_router(approvals.router)
    app.include_router(manual_reviews.router)
    app.include_router(system.router)
    app.include_router(appshell_router)
    app.include_router(setup.router)
    app.include_router(memory_router.router)
    app.include_router(tasks_router.router)
    app.include_router(scenarios_router.router)
    app.include_router(desktop.router)
    app.include_router(metrics.router)
    app.include_router(gateway_router.router)
    if bool(getattr(effective_settings, "friends_enabled", False)):
        from js.web.routers import friends as friends_router

        app.include_router(friends_router.router)

    @app.get("/", response_class=HTMLResponse)
    async def root() -> str:
        # Credentials are never embedded in an HTTP response. The desktop Host
        # puts the one-time local bootstrap key in a URL fragment, which the
        # window does not transmit to this server or to a reverse proxy.
        settings = app.state.runtime_settings or _settings
        product_name = (
            "JS Agent Work"
            if str(getattr(settings, "product_id", "js-agent")) == "js-work"
            else "JS Agent"
        )
        return _load_index_html(product_name=product_name)

    @app.post("/api/auth/session")
    async def create_auth_session(request: Request) -> JSONResponse:
        """Exchange a valid API key for an HttpOnly session cookie.

        The key may arrive via the X-API-Key header or a JSON body
        (``{"api_key": ...}``).  The returned cookie carries a random token;
        only its hash is stored server-side, with an expiry, and it can be
        revoked via /api/auth/logout (or by revoking the underlying key).
        """
        from js.exceptions import AuthRequiredError
        from js.web.auth import (
            _SESSION_COOKIE,
            _SESSION_TTL_SECONDS,
            AuthManager,
            check_origin,
            session_cookie_name,
        )

        settings = app.state.runtime_settings or _settings
        if settings is None:
            raise HTTPException(
                503, "Server is still starting up. Please wait a moment and try again."
            )
        api_key = request.headers.get("x-api-key")
        if not api_key:
            try:
                body = await request.json()
            except Exception:
                body = None
            if isinstance(body, dict):
                body_key = body.get("api_key")
                if isinstance(body_key, str):
                    api_key = body_key
        # Invalid credentials are 401, not 403-as-Origin. A missing Origin with
        # no valid key still fail-closes in check_origin (CSRF).
        if api_key:
            try:
                AuthManager(settings.state_dir).verify(api_key)
            except AuthRequiredError as exc:
                raise HTTPException(401, str(exc), headers={"WWW-Authenticate": "Bearer"}) from exc
        check_origin(request)
        try:
            token, expires_at = AuthManager(settings.state_dir).create_session(api_key)
        except AuthRequiredError as exc:
            raise HTTPException(401, str(exc), headers={"WWW-Authenticate": "Bearer"}) from exc
        cookie_name = session_cookie_name(
            str(getattr(settings, "product_id", "js-agent") or "js-agent")
        )
        response = JSONResponse({"success": True, "expires_at": expires_at})
        response.set_cookie(
            cookie_name,
            token,
            max_age=_SESSION_TTL_SECONDS,
            httponly=True,
            samesite="strict",
            secure=request.url.scheme == "https",
            path="/",
        )
        # Drop the pre-AppShell host-wide cookie so a stale Personal/Work token
        # cannot keep failing closed as "Invalid session" / HTTP 401.
        if cookie_name != _SESSION_COOKIE:
            response.delete_cookie(_SESSION_COOKIE, path="/")
        consume_bootstrap_admin_key_file(settings.state_dir)
        return response

    @app.post("/api/auth/logout")
    async def revoke_auth_session(request: Request) -> JSONResponse:
        """Revoke the current session server-side and clear the cookie."""
        from js.web.auth import (
            _SESSION_COOKIE,
            AuthManager,
            check_origin,
            resolve_session_cookie,
            session_cookie_name,
        )

        check_origin(request)
        settings = app.state.runtime_settings or _settings
        product_id = (
            str(getattr(settings, "product_id", "js-agent") or "js-agent")
            if settings is not None
            else "js-agent"
        )
        cookie_name = session_cookie_name(product_id)
        token = resolve_session_cookie(request.cookies, product_id)
        if settings is not None and token:
            AuthManager(settings.state_dir).revoke_session(token)
        response = JSONResponse({"success": True})
        response.delete_cookie(cookie_name, path="/")
        # Also clear the legacy unscoped cookie so Personal migrations don't
        # leave a stale host-wide token that Work would ignore but confuse UX.
        if cookie_name != _SESSION_COOKIE:
            response.delete_cookie(_SESSION_COOKIE, path="/")
        return response

    @app.post("/api/cancel/{session_id}")
    async def cancel_session(
        session_id: str,
        request_id: str | None = None,
        run_id: str | None = None,
        auth: dict[str, Any] = Depends(require_user_write),
    ) -> dict[str, Any]:
        """Request cancellation of an active agent run for *session_id*."""
        session_id = _require_path_session_id(session_id)
        if request_id is not None or run_id is not None:
            if request_id is not None and (not request_id.strip() or len(request_id) > 128):
                raise HTTPException(400, "invalid request_id")
            if run_id is not None and (not run_id.strip() or len(run_id) > 128):
                raise HTTPException(400, "invalid run_id")
            cancelled = get_agent().request_cancel(
                session_id,
                owner_key_hash=runtime_owner(auth),
                expected_request_id=request_id,
                expected_run_id=run_id,
            )
            if not cancelled:
                raise HTTPException(409, "active run identity mismatch or already finished")
            return {
                "session_id": session_id,
                "request_id": request_id,
                "run_id": run_id,
                "cancelled": True,
            }
        result = await _execute_session_mutation("cancel", session_id, auth)
        _raise_session_mutation_error(result)
        return {"session_id": session_id, "cancelled": True}

    # NOTE: /api/memory/* and /api/setup/* endpoints moved to dedicated routers

    @app.get("/api/audit")
    async def audit(
        limit: int = 50, auth: dict[str, Any] = Depends(require_admin)
    ) -> dict[str, Any]:
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
    async def list_files(
        path: str = ".",
        session_id: str | None = Depends(optional_query_session_id),
        auth: dict[str, Any] = Depends(require_auth_dep),
    ) -> dict[str, Any]:
        agent = get_agent()
        owner = runtime_owner(auth)
        effect_path = path
        if str(getattr(agent.settings, "product_id", "")) == "js-work":
            from js_work.file_scope import (
                LOCAL_WORK_OWNER,
                WorkFileScopeError,
                WorkOwnerFileScope,
            )

            owner = owner or LOCAL_WORK_OWNER
            work_session = session_id or ""
            if not work_session:
                raise HTTPException(400, "session_id is required")
            try:
                resolved = WorkOwnerFileScope(
                    agent.settings.workspace,
                    owner=owner,
                    session_id=work_session,
                ).resolve_private_read(path)
            except WorkFileScopeError as exc:
                raise HTTPException(exc.status_code, exc.detail) from exc
            effect_path = resolved.relative_to(agent.settings.workspace.resolve()).as_posix()
        else:
            try:
                resolved = (agent.settings.workspace / path).resolve()
                resolved.relative_to(agent.settings.workspace.resolve())
            except (ValueError, RuntimeError):
                return {"success": False, "error": "Invalid path"}
            owner = owner or "local-user"

        runtime = agent.echo_runtime
        runtime_context = runtime.build_context(
            channel=web_channel(agent.settings, "files"),
            owner_key_hash=owner,
            session_id=session_id or "",
            role=str(auth.get("role") or "user"),
            capabilities=("file_list",),
        )
        _message, result = await runtime.execute_tool_effect(
            ToolEffect.from_arguments(
                "file_list",
                {"path": effect_path},
                user_input=f"List files under {path}",
                allowed_tools=("file_list",),
            ),
            runtime_context,
        )
        return {"success": result.success, "output": result.output, "error": result.error}

    @app.get("/api/sessions")
    async def list_sessions(
        limit: int = 30, auth: dict[str, Any] = Depends(require_auth_dep)
    ) -> dict[str, Any]:
        agent = get_agent()
        sessions = agent.memory.get_sessions(limit=limit, owner_key_hash=memory_owner(auth))
        return {"sessions": sessions}

    @app.get("/api/sessions/{session_id}/messages")
    async def session_messages(
        session_id: str, auth: dict[str, Any] = Depends(require_auth_dep)
    ) -> dict[str, Any]:
        session_id = _require_path_session_id(session_id)
        agent = get_agent()
        try:
            messages = agent.memory.get_session_messages(
                session_id, owner_key_hash=memory_owner(auth)
            )
        except PermissionError as e:
            raise HTTPException(status_code=403, detail="Session access denied") from e
        return {"session_id": session_id, "messages": messages}

    @app.delete("/api/sessions/{session_id}")
    async def delete_session(
        session_id: str, auth: dict[str, Any] = Depends(require_user_write)
    ) -> dict[str, Any]:
        session_id = _require_path_session_id(session_id)
        result = await _execute_session_mutation("delete", session_id, auth)
        _raise_session_mutation_error(result)
        return {"success": True, "session_id": session_id}

    @app.get("/api/models")
    async def models(auth: dict[str, Any] = Depends(require_auth_dep)) -> dict[str, Any]:
        agent = get_agent()
        # Trigger refreshes in the background so the list response is not
        # blocked by slow outbound HTTP calls to local/cloud providers.
        model_refresh.maybe_refresh_models_async(agent)

        # A read-only listing must not trigger provider network I/O. Report only
        # health already observed by a prior authorized provider operation.
        health: dict[str, bool] = {}
        health_errors: dict[str, str] = {}
        for provider_config in agent.settings.providers:
            provider = agent.router._providers.get(provider_config.name)
            if provider is None:
                health[provider_config.name] = False
                health_errors[provider_config.name] = "Provider not registered in router"
                continue
            last_check = getattr(provider, "_last_health_check", 0.0)
            health[provider_config.name] = bool(
                last_check and getattr(provider, "_health_status", False)
            )

        # Determine which providers are user-configured (from provider_manager)
        dyn_names = {p.name for p in agent.provider_manager.get_all()}

        # Build provider list with embedded health status
        providers_out: list[dict[str, Any]] = []
        for p in agent.settings.providers:
            has_key = bool(p.api_key)
            providers_out.append(
                {
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
                            "provider": p.name,
                            "context_window": m.context_window,
                            "max_tokens": m.max_tokens,
                            "cost_input": m.cost_input,
                            "cost_output": m.cost_output,
                        }
                        for m in p.models
                    ],
                }
            )

        # Merge router-only dynamic models, but only when the binding uses an
        # exact full ID and its provider is present in settings.providers.
        # This keeps the UI aligned with activation validation without
        # exposing stale bindings for unconfigured providers.
        configured_names = {p.name for p in agent.settings.providers}
        providers_by_name = {p["name"]: p for p in providers_out}
        get_model_bindings = getattr(agent.router, "get_model_bindings", None)
        try:
            router_bindings = get_model_bindings() if callable(get_model_bindings) else ()
        except Exception:
            logger.warning("Router model binding listing failed", exc_info=True)
            router_bindings = ()
        for provider_name, config in router_bindings:
            if provider_name not in configured_names or not isinstance(config, ModelConfig):
                continue
            provider_out = providers_by_name.get(provider_name)
            if provider_out is None:
                continue
            if any(model["id"] == config.id for model in provider_out["models"]):
                continue
            provider_out["models"].append(
                {
                    "id": config.id,
                    "name": config.name or config.id,
                    "provider": provider_name,
                    "context_window": config.context_window,
                    "max_tokens": config.max_tokens,
                    "cost_input": config.cost_input,
                    "cost_output": config.cost_output,
                }
            )

        # Hide providers that are empty, unhealthy, have no key, and were
        # not explicitly configured by the user (usually stale auto-detects).
        providers_out = [
            p
            for p in providers_out
            if not (
                len(p["models"]) == 0
                and not p["healthy"]
                and not p["has_key"]
                and not p["user_configured"]
            )
        ]

        # Include cloud presets that are NOT yet configured
        # so users can see what's available
        from js.models.cloud_providers import ALL_PRESETS

        presets_out = []
        for preset in ALL_PRESETS:
            if preset.id not in configured_names:
                presets_out.append(
                    {
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
                    }
                )

        return {
            "providers": providers_out,
            "presets": presets_out,
            "active_model": get_active_model(),
        }

    @app.post("/api/models/switch")
    async def models_switch(
        body: dict[str, Any], auth: dict[str, Any] = Depends(require_admin)
    ) -> dict[str, Any]:
        raw_model_id = body.get("model_id")
        if not isinstance(raw_model_id, str):
            raise HTTPException(400, "model_id must be a string")
        from js.web.ids import InvalidRuntimeIdError, validate_model_ref

        try:
            model_id = validate_model_ref(raw_model_id)
        except InvalidRuntimeIdError as exc:
            raise HTTPException(400, str(exc)) from exc
        agent = get_agent()

        # A model may only become active when its provider is actually
        # configured AND the model is explicitly declared.  Cloud presets
        # are templates, not live providers, so they must never legitimise
        # a switch on their own.  Router mappings alone are insufficient:
        # a stale or dynamic mapping does not prove configuration.
        from js.models.router import ModelSwitchValidationError, validate_model_for_activation

        configured_providers = {p.name for p in agent.settings.providers}

        def _get_preset(name: str) -> Any:
            from js.models.cloud_providers import get_preset

            return get_preset(name)

        try:
            validate_model_for_activation(
                model_id,
                configured_providers,
                get_model_binding=getattr(agent.router, "get_model_binding", None),
                get_preset=_get_preset,
                provider_models={
                    p.name: {m.id for m in p.models} for p in agent.settings.providers
                },
            )
        except ModelSwitchValidationError as exc:
            if exc.needs_config:
                raise HTTPException(
                    status_code=exc.status_code,
                    detail={"needs_config": True, "error": exc.detail},
                ) from exc
            logger.warning(
                "Model switch rejected: model_id=%r not configured",
                model_id,
            )
            raise HTTPException(exc.status_code, exc.detail) from exc

        result = await _execute_web_tool_effect(
            agent,
            auth,
            channel="model_switch",
            tool_name="control_model_switch",
            arguments={"model_id": model_id},
            user_input="Switch to an administrator-approved configured model",
        )
        _raise_control_tool_error(result, default_status=500)

        return {"success": True, "model_id": model_id, "warning": None}

    def _validate_provider_name(name: str) -> None:
        from js.web.ids import InvalidRuntimeIdError, validate_provider_name

        try:
            validate_provider_name(name)
        except InvalidRuntimeIdError as exc:
            raise HTTPException(400, str(exc)) from exc

    def _validate_url(url: str) -> None:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            raise HTTPException(400, "URL scheme must be http or https")
        if not parsed.hostname:
            raise HTTPException(400, "URL must have a host")
        if parsed.username is not None or parsed.password is not None:
            raise HTTPException(400, "URL credentials are not allowed")
        if parsed.query or parsed.fragment:
            raise HTTPException(400, "URL query strings and fragments are not allowed")

    @app.post("/api/providers/discover")
    async def discover_provider(
        payload: dict[str, Any],
        auth: dict[str, Any] = Depends(require_admin),
    ) -> dict[str, Any]:
        raw_base_url = payload.get("base_url", "")
        if not isinstance(raw_base_url, str):
            raise HTTPException(400, "base_url must be a string")
        base_url = raw_base_url.strip()
        raw_api_key = payload.get("api_key", "")
        if not isinstance(raw_api_key, str):
            raise HTTPException(400, "api_key must be a string")
        api_key = raw_api_key.strip()
        if not base_url:
            raise HTTPException(400, "base_url is required")
        _validate_url(base_url)
        agent = get_agent()
        allow_private = (
            getattr(agent.settings.security, "allow_private_model_providers", False) is True
        )
        result = await _execute_provider_discovery_effect(
            agent,
            auth,
            base_url=base_url,
            api_key=api_key,
            allow_private=allow_private,
            channel="provider_discover",
        )
        _raise_control_tool_error(result, default_status=502)
        models = result.metadata.get("models", [])
        if not isinstance(models, list):
            raise HTTPException(502, "Provider discovery returned an invalid model list")
        return {"base_url": base_url, "models": models}

    @app.post("/api/providers/connect")
    async def connect_provider(
        payload: dict[str, Any], auth: dict[str, Any] = Depends(require_admin)
    ) -> dict[str, Any]:
        raw_name = payload.get("name", "")
        raw_base_url = payload.get("base_url", "")
        raw_api_key = payload.get("api_key", "")
        if not all(isinstance(value, str) for value in (raw_name, raw_base_url, raw_api_key)):
            raise HTTPException(400, "name, base_url, and api_key must be strings")
        name = raw_name.strip()
        base_url = raw_base_url.strip()
        api_key = raw_api_key.strip() or None
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
            ModelConfig(id=m["id"], name=m.get("name", m["id"]), provider=name) for m in model_ids
        ]
        cfg = ModelProviderConfig(
            name=name,
            base_url=base_url,
            api_key=api_key,
            default_model=models[0].id if models else "",
            models=models,
        )

        agent = get_agent()
        result = await _execute_provider_mutation_effect(
            agent,
            auth,
            action="upsert",
            provider=cfg,
            api_key=api_key,
            channel="provider_connect",
        )
        _raise_control_tool_error(result, default_status=500)
        return {
            "success": True,
            "provider": str(result.metadata.get("provider") or name),
            "models_added": int(result.metadata.get("models_added", len(models))),
        }

    @app.patch("/api/providers/{name}")
    async def update_provider(
        name: str,
        payload: dict[str, Any],
        auth: dict[str, Any] = Depends(require_admin_write),
    ) -> dict[str, Any]:
        """Update an existing provider (e.g. add/change API key)."""
        agent = get_agent()
        raw_api_key = payload.get("api_key", "")
        if not isinstance(raw_api_key, str):
            raise HTTPException(400, "api_key must be a string")
        _validate_provider_name(name)
        result = await _execute_provider_mutation_effect(
            agent,
            auth,
            action="update_key",
            name=name,
            api_key=raw_api_key.strip() or None,
            channel="provider_update",
        )
        _raise_control_tool_error(result, default_status=500)
        return {"success": True, "provider": name}

    @app.delete("/api/providers/{name}")
    async def delete_provider(
        name: str,
        request: Request,
        auth: dict[str, Any] = Depends(require_admin_write),
    ) -> dict[str, Any]:
        agent = get_agent()
        _validate_provider_name(name)
        config_state = get_agent_config_state(request)
        async with config_state.lock:
            previous_config = dict(config_state.config)
            desired_config = dict(previous_config)
            prefix = f"{name}/"
            for role, model in desired_config.items():
                if model.startswith(prefix):
                    desired_config[role] = ""

            fleet_changed = desired_config != previous_config
            if fleet_changed:
                fleet_result = await _execute_fleet_config_effect(
                    agent,
                    auth,
                    config=desired_config,
                    channel="provider_delete_fleet_cleanup",
                )
                _raise_control_tool_error(fleet_result, default_status=500)

            result = await _execute_provider_mutation_effect(
                agent,
                auth,
                action="delete",
                name=name,
                channel="provider_delete",
            )
            if not result.success and fleet_changed:
                rollback = await _execute_fleet_config_effect(
                    agent,
                    auth,
                    config=previous_config,
                    channel="provider_delete_fleet_rollback",
                )
                if not rollback.success:
                    logger.critical(
                        "Fleet configuration rollback failed after provider delete failure"
                    )
                    raise HTTPException(500, "Provider deletion rollback failed")
            _raise_control_tool_error(result, default_status=500)
            config_state.config = desired_config
        return {"success": True}

    @app.get("/api/providers/cloud-presets")
    async def cloud_presets(auth: dict[str, Any] = Depends(require_auth_dep)) -> dict[str, Any]:
        """List all built-in cloud provider presets."""
        from js.models.cloud_providers import list_presets

        return {"presets": list_presets()}

    @app.post("/api/providers/test-cloud")
    async def test_cloud_provider(
        payload: dict[str, Any], auth: dict[str, Any] = Depends(require_admin)
    ) -> dict[str, Any]:
        """Test a cloud provider preset before adding it."""
        from js.models.cloud_providers import get_preset

        raw_preset_id = payload.get("preset_id", "")
        raw_api_key = payload.get("api_key", "")
        if not isinstance(raw_preset_id, str) or not isinstance(raw_api_key, str):
            raise HTTPException(400, "preset_id and api_key must be strings")
        preset_id = raw_preset_id.strip()
        api_key = raw_api_key.strip()

        if not preset_id:
            raise HTTPException(400, "preset_id is required")

        preset = get_preset(preset_id)
        if not preset:
            raise HTTPException(404, f"Unknown preset: {preset_id}")

        if not api_key:
            raise HTTPException(400, "API key required")

        agent = get_agent()
        result = await _execute_provider_discovery_effect(
            agent,
            auth,
            base_url=preset.base_url,
            api_key=api_key,
            allow_private=False,
            channel="provider_test_cloud",
        )
        _raise_control_tool_error(result, default_status=502)

        return {
            "success": True,
            "provider": preset_id,
            "name": preset.name,
            "models": result.metadata.get("models", []),
        }

    @app.post("/api/providers/add-cloud")
    async def add_cloud_provider(
        payload: dict[str, Any], auth: dict[str, Any] = Depends(require_admin)
    ) -> dict[str, Any]:
        """One-click add a cloud provider from presets."""
        from js.models.cloud_providers import build_provider_config, get_preset

        raw_preset_id = payload.get("preset_id", "")
        raw_api_key = payload.get("api_key", "")
        if not isinstance(raw_preset_id, str) or not isinstance(raw_api_key, str):
            raise HTTPException(400, "preset_id and api_key must be strings")
        preset_id = raw_preset_id.strip()
        api_key = raw_api_key.strip()

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
                    f"API key required. Set {preset.api_key_env} environment variable or pass api_key in payload.",
                )

        cfg = build_provider_config(preset, api_key)

        # Discover actual models from the remote endpoint so the user sees
        # exactly what the provider reports (e.g. LM Studio with 2 loaded
        # models instead of the preset's full catalog).
        agent = get_agent()
        discovered_result = await _execute_provider_discovery_effect(
            agent,
            auth,
            base_url=cfg.base_url,
            api_key=api_key,
            allow_private=False,
            channel="provider_add_cloud",
        )
        discovered = discovered_result.metadata
        if discovered_result.success and discovered.get("models"):
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

        mutation_result = await _execute_provider_mutation_effect(
            agent,
            auth,
            action="upsert",
            provider=cfg,
            api_key=api_key,
            channel="provider_add_cloud_mutation",
        )
        _raise_control_tool_error(mutation_result, default_status=500)

        return {
            "success": True,
            "provider": preset_id,
            "name": preset.name,
            "models_added": int(mutation_result.metadata.get("models_added", len(cfg.models))),
        }

    @app.post("/api/providers/scan-lan")
    async def scan_lan(
        payload: dict[str, Any] | None = None,
        auth: dict[str, Any] = Depends(require_admin),
    ) -> dict[str, Any]:
        """Reject broad LAN probing outside the authorized Echo network boundary."""
        del payload, auth
        raise HTTPException(
            409,
            "LAN model scanning is disabled; configure an exact provider endpoint explicitly",
        )

    @app.get("/api/stats/tokens")
    async def token_stats(
        days: int = 30, auth: dict[str, Any] = Depends(require_admin)
    ) -> dict[str, Any]:
        stats_store = get_stats_store()
        if stats_store is None:
            raise HTTPException(503, "Stats store not initialized")
        return stats_store.get_summary(days=days)

    @app.get("/api/evolution/reports")
    async def evolution_reports(
        limit: int = 10, auth: dict[str, Any] = Depends(require_admin)
    ) -> dict[str, Any]:
        agent = get_agent()
        reports = agent.metacognition.get_recent_reports(limit=limit)
        return {"reports": reports}

    @app.get("/api/evolution/proposals")
    async def evolution_proposals(
        limit: int = 20, auth: dict[str, Any] = Depends(require_admin)
    ) -> dict[str, Any]:
        agent = get_agent()
        proposals = agent.metacognition.get_proposals(limit=limit)
        from js.evolution.cycle import EvolutionCycle

        cycle_rows = [
            {
                "proposal_id": item.proposal_id,
                "owner": item.owner,
                "kind": item.kind,
                "title": item.title,
                "status": item.status,
                "source": "evolution_cycle",
            }
            for item in EvolutionCycle(agent.settings.state_dir).list_proposals(
                memory_owner(auth) or "local-user",
                limit=limit,
            )
        ]
        return {"proposals": proposals, "cycle_proposals": cycle_rows}

    @app.get("/api/evolution/insights")
    async def evolution_insights(
        limit: int = 20, auth: dict[str, Any] = Depends(require_admin)
    ) -> dict[str, Any]:
        agent = get_agent()
        owner_key_hash = memory_owner(auth)
        learning = (
            {
                "stats": agent.learner.get_stats(owner_key_hash=owner_key_hash),
                "insights": agent.learner.get_insights(
                    limit=limit,
                    owner_key_hash=owner_key_hash,
                ),
                "suggestions": agent.learner.suggest_improvements(
                    owner_key_hash=owner_key_hash,
                ),
            }
            if agent.learner is not None
            else {"stats": {}, "insights": [], "suggestions": []}
        )
        return {
            "learning": learning,
            "optimization": agent.optimizer.get_report() if agent.optimizer else {},
            "compression": agent.compression_feedback.get_stats(
                owner_key_hash=owner_key_hash,
            )
            if agent.compression_feedback
            else {},
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
            name
            for name, ok in {
                "metacognition": agent.metacognition is not None,
                "learner": agent.learner is not None,
                "optimizer": agent.optimizer is not None,
                "evolver": agent.evolver is not None,
            }.items()
            if not ok
        ]
        if missing:
            raise HTTPException(
                503,
                f"Evolution subsystems not ready: {', '.join(missing)}. Please wait for startup to complete.",
            )

        return await _execute_evolution_action("run", auth)

    @app.post("/api/evolution/reflect")
    async def evolution_reflect(auth: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        """Trigger an immediate metacognition reflection."""
        agent = get_agent()
        if agent.metacognition is None:
            raise HTTPException(503, "Metacognition subsystem not ready")
        return await _execute_evolution_action("reflect", auth)

    @app.post("/api/evolution/proposals/{proposal_id}/approve")
    async def evolution_approve(
        proposal_id: str,
        auth: dict[str, Any] = Depends(require_admin),
    ) -> dict[str, Any]:
        return await _execute_evolution_action("approve", auth, proposal_id=proposal_id)

    @app.post("/api/evolution/proposals/{proposal_id}/reject")
    async def evolution_reject(
        proposal_id: str,
        auth: dict[str, Any] = Depends(require_admin),
    ) -> dict[str, Any]:
        return await _execute_evolution_action("reject", auth, proposal_id=proposal_id)

    @app.get("/api/agents/config")
    async def get_agent_config(
        request: Request,
        auth: dict[str, Any] = Depends(require_admin),
    ) -> dict[str, Any]:
        agent = get_agent()
        agent_config = get_agent_config_state(request).config
        # Build available models list for the UI
        available_models: list[dict[str, Any]] = []
        for p in agent.settings.providers:
            for m in p.models:
                available_models.append(
                    {
                        "id": f"{p.name}/{m.id}",
                        "provider": p.name,
                        "model_id": m.id,
                        "model_name": m.name or m.id,
                        "context_window": m.context_window,
                    }
                )
        return {
            "config": agent_config,
            "available_models": available_models,
            "roles": list(agent_config.keys()),
        }

    @app.post("/api/agents/config")
    async def set_agent_config(
        payload: dict[str, Any],
        request: Request,
        auth: dict[str, Any] = Depends(require_admin),
    ) -> dict[str, Any]:
        new_config = payload.get("config")
        if not isinstance(new_config, dict) or len(new_config) > 32:
            raise HTTPException(400, "config must be an object with at most 32 roles")
        agent = get_agent()
        config_state = get_agent_config_state(request)
        # Validate model IDs against available providers
        valid_models = {f"{p.name}/{m.id}" for p in agent.settings.providers for m in p.models}
        # Also allow preset models (not yet configured)
        from js.models.cloud_providers import ALL_PRESETS

        for preset in ALL_PRESETS:
            for m in preset.models:
                valid_models.add(f"{preset.id}/{m.id}")
        for role, model in new_config.items():
            if not isinstance(role, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,31}", role):
                raise HTTPException(400, "Invalid Fleet role")
            if not isinstance(model, str):
                raise HTTPException(400, "Fleet model IDs must be strings")
            if model and model not in valid_models:
                raise HTTPException(400, f"Invalid model '{model}' for role '{role}'")
        async with config_state.lock:
            desired_config = dict(config_state.config)
            desired_config.update(cast("dict[str, str]", new_config))
            result = await _execute_fleet_config_effect(
                agent,
                auth,
                config=desired_config,
                channel="fleet_configure",
            )
            _raise_control_tool_error(result, default_status=500)
            config_state.config = desired_config
            return {"success": True, "config": dict(desired_config)}

    @app.get("/api/search")
    async def search_api(
        query: str, max_results: int = 5, auth: dict[str, Any] = Depends(require_auth_dep)
    ) -> dict[str, Any]:
        agent = get_agent()
        result = await _execute_web_tool_effect(
            agent,
            auth,
            channel="search",
            tool_name="web_search",
            arguments={"query": query, "max_results": max_results},
            user_input=f"Search the web for {query}",
        )
        structured_results = result.metadata.get("results")
        if isinstance(structured_results, list):
            return {"results": structured_results}
        _raise_control_tool_error(result, default_status=502)
        return {"results": []}

    @app.get("/api/skills")
    async def skills_api(
        category: str | None = None,
        skill_type: str | None = None,
        query: str | None = None,
        auth: dict[str, Any] = Depends(require_auth_dep),
    ) -> dict[str, Any]:
        agent = get_agent()
        skills_manager = getattr(agent, "skills", None)
        if skills_manager is None:
            return {
                "skills": [],
                "categories": [],
                "global_stats": {"skills_loaded": 0},
                "disabled": True,
            }
        from js.skills.spec import SkillType

        st = SkillType(skill_type) if skill_type else None
        skills = skills_manager.list_skills(category=category, skill_type=st, query=query)
        return {
            "skills": skills,
            "categories": skills_manager.list_categories(),
            "global_stats": skills_manager.get_global_stats(),
            "disabled": False,
        }

    @app.get("/api/skills/metrics")
    async def skills_metrics(auth: dict[str, Any] = Depends(require_auth_dep)) -> dict[str, Any]:
        """Return skill execution metrics for observability dashboard."""
        agent = get_agent()
        skills_manager = getattr(agent, "skills", None)
        if skills_manager is None:
            return {
                "global": {"skills_loaded": 0},
                "per_skill": [],
                "disabled": True,
            }
        all_skills = skills_manager.list_skills()
        per_skill: list[dict[str, Any]] = []
        for skill in all_skills:
            stats = skills_manager.get_stats(skill["id"])
            if stats:
                per_skill.append(
                    {
                        "id": stats["id"],
                        "name": stats["name"],
                        "type": stats.get("type", "unknown"),
                        "trust_level": stats.get("trust_level", "community"),
                        "usage_count": stats.get("usage_count", 0),
                        "success_rate": round(stats.get("success_rate", 1.0), 3),
                        "avg_latency_ms": round(stats.get("avg_latency_ms", 0.0), 1),
                        "prerequisites_ok": stats.get("prerequisites_ok", True),
                    }
                )
        per_skill.sort(key=lambda x: x["usage_count"], reverse=True)
        return {
            "global": skills_manager.get_global_stats(),
            "per_skill": per_skill,
            "disabled": False,
        }

    # NOTE: /api/memory/* endpoints moved to js/web/routers/memory.py

    # Hermes-specific endpoints MUST be defined BEFORE /api/skills/{skill_id}
    # to avoid "hermes" being captured as a skill_id path parameter.
    @app.get("/api/skills/hermes")
    async def hermes_skills_list(
        auth: dict[str, Any] = Depends(require_auth_dep),
    ) -> dict[str, Any]:
        """List all Hermes skills with bridge diagnostics."""
        agent = get_agent()
        skills_manager = getattr(agent, "skills", None)
        if skills_manager is None:
            return {
                "skills": [],
                "count": 0,
                "stats": {},
                "disabled": True,
            }
        from js.skills.hermes_bridge import get_bridge_stats, is_hermes_skill

        hermes_skills = [
            s.to_summary_dict() for s in skills_manager.get_all().values() if is_hermes_skill(s.id)
        ]
        stats = get_bridge_stats()
        return {
            "skills": hermes_skills,
            "count": len(hermes_skills),
            "stats": stats.to_dict(),
            "disabled": False,
        }

    @app.post("/api/skills/hermes/refresh")
    async def hermes_skills_refresh(
        auth: dict[str, Any] = Depends(require_admin),
    ) -> dict[str, Any]:
        """Refresh Hermes skills from disk without restarting the server."""
        return await _execute_private_skill_mutation("refresh_hermes", {}, auth)

    def _promotion_store_for(agent: Any) -> Any:
        store = getattr(agent, "promotion_store", None)
        if store is None:
            store = getattr(getattr(agent, "skills", None), "promotion_store", None)
        if store is None:
            raise HTTPException(503, "Skill promotion store is not initialized")
        return store

    def _promotion_event_payload(event: Any) -> dict[str, Any]:
        return {
            "event_id": event.event_id,
            "skill_id": event.skill_id,
            "from_level": event.from_level,
            "to_level": event.to_level,
            "source": event.source,
            "reason": event.reason,
            "status": event.status,
            "variant_id": event.variant_id,
            "artifact_path": event.artifact_path,
            "details": event.details,
            "created_at": event.created_at,
            "decided_by": event.decided_by,
            "decided_at": event.decided_at,
            "applied_at": event.applied_at,
            "rolled_back_at": event.rolled_back_at,
        }

    @app.get("/api/skills/promotions")
    async def skill_promotions_list(
        include_all: bool = False,
        limit: int = 50,
        auth: dict[str, Any] = Depends(require_auth_dep),
    ) -> dict[str, Any]:
        """List skill promotion events. Defaults to open proposals only."""
        from js.skills.promotion_store import STATUS_APPROVED, STATUS_PROPOSED

        agent = get_agent()
        if (
            getattr(agent, "promotion_store", None) is None
            and getattr(agent, "skills", None) is None
        ):
            return {"events": [], "count": 0, "disabled": True}
        owner = memory_owner(auth)
        events = _promotion_store_for(agent).list_recent(owner_key_hash=owner, limit=limit)
        if not include_all:
            events = [e for e in events if e.status in {STATUS_PROPOSED, STATUS_APPROVED}]
        return {
            "events": [_promotion_event_payload(e) for e in events],
            "count": len(events),
            "disabled": False,
        }

    @app.get("/api/skills/promotions/{event_id}")
    async def skill_promotion_detail(
        event_id: str,
        auth: dict[str, Any] = Depends(require_auth_dep),
    ) -> dict[str, Any]:
        """Return a single skill promotion event."""
        agent = get_agent()
        event = _promotion_store_for(agent).get(event_id, owner_key_hash=memory_owner(auth))
        if event is None:
            raise HTTPException(404, f"Promotion event '{event_id}' not found")
        return _promotion_event_payload(event)

    @app.post("/api/skills/promotions/{event_id}/approve")
    async def skill_promotion_approve(
        event_id: str,
        auth: dict[str, Any] = Depends(require_admin),
    ) -> dict[str, Any]:
        """Approve and apply a promotion proposal."""
        return await _execute_private_skill_mutation(
            "promotion_approve",
            {"event_id": event_id},
            auth,
        )

    @app.post("/api/skills/promotions/{event_id}/reject")
    async def skill_promotion_reject(
        event_id: str,
        payload: dict[str, Any] | None = None,
        auth: dict[str, Any] = Depends(require_admin),
    ) -> dict[str, Any]:
        """Reject a promotion proposal without mutating the skill."""
        reason = (payload or {}).get("reason", "")
        if not isinstance(reason, str):
            raise HTTPException(400, "reason must be a string")
        return await _execute_private_skill_mutation(
            "promotion_reject",
            {"event_id": event_id, "reason": reason},
            auth,
        )

    @app.post("/api/skills/promotions/{event_id}/revert")
    async def skill_promotion_revert(
        event_id: str,
        auth: dict[str, Any] = Depends(require_admin),
    ) -> dict[str, Any]:
        """Revert an applied promotion."""
        return await _execute_private_skill_mutation(
            "promotion_revert",
            {"event_id": event_id},
            auth,
        )

    @app.post("/api/skills/install")
    async def skill_install(
        payload: dict[str, Any], auth: dict[str, Any] = Depends(require_admin)
    ) -> dict[str, Any]:
        agent = get_agent()
        skills_manager = getattr(agent, "skills", None)
        if skills_manager is None:
            raise HTTPException(503, "Skill system is disabled")
        source = payload.get("source", "")
        skill_id = payload.get("skill_id")
        result = await _execute_web_tool_effect(
            agent,
            auth,
            channel="skills.install",
            tool_name="control_skill_install",
            arguments={"source": source, "skill_id": skill_id},
            user_input="Install the administrator-selected skill",
        )
        _raise_control_tool_error(result, default_status=500)
        return {
            "success": True,
            "skill_id": result.metadata.get("skill_id"),
            "trust_level": result.metadata.get("trust_level"),
            "risk_flags": result.metadata.get("risk_flags", []),
        }

    @app.delete("/api/skills/{skill_id}")
    async def skill_uninstall(
        skill_id: str, auth: dict[str, Any] = Depends(require_admin)
    ) -> dict[str, Any]:
        return await _execute_private_skill_mutation(
            "uninstall",
            {"skill_id": skill_id},
            auth,
        )

    @app.post("/api/skills/{skill_id}/trust")
    async def skill_trust(
        skill_id: str, payload: dict[str, Any], auth: dict[str, Any] = Depends(require_admin)
    ) -> dict[str, Any]:
        level = payload.get("level", "")
        if not isinstance(level, str):
            raise HTTPException(400, "Invalid trust level")
        return await _execute_private_skill_mutation(
            "trust",
            {"skill_id": skill_id, "level": level},
            auth,
        )

    @app.get("/api/skills/discover")
    async def skill_discover(
        query: str = "", auth: dict[str, Any] = Depends(require_auth_dep)
    ) -> dict[str, Any]:
        """Search the ClawHub skill marketplace."""
        agent = get_agent()
        if getattr(agent, "skills", None) is None:
            raise HTTPException(503, "Skill system is disabled")
        result = await _execute_web_tool_effect(
            agent,
            auth,
            channel="skills.discover",
            tool_name="control_clawhub_discover",
            arguments={"query": query},
            user_input="Discover skills in ClawHub",
        )
        _raise_control_tool_error(result, default_status=502)
        return {
            "success": True,
            "total": result.metadata.get("total", 0),
            "results": result.metadata.get("results", []),
        }

    @app.post("/api/skills/discover/install")
    async def skill_discover_install(
        payload: dict[str, Any], auth: dict[str, Any] = Depends(require_admin)
    ) -> dict[str, Any]:
        """Install a skill from the ClawHub marketplace."""
        skill_id = payload.get("skill_id", "")
        if not skill_id:
            raise HTTPException(400, "skill_id is required")

        agent = get_agent()
        skills_manager = getattr(agent, "skills", None)
        if skills_manager is None:
            raise HTTPException(503, "Skill system is disabled")
        result = await _execute_web_tool_effect(
            agent,
            auth,
            channel="skills.discover.install",
            tool_name="control_clawhub_install",
            arguments={"skill_id": skill_id},
            user_input="Install the administrator-selected ClawHub skill",
        )
        _raise_control_tool_error(result, default_status=500)
        return {
            "success": True,
            "skill_id": result.metadata.get("skill_id"),
            "trust_level": result.metadata.get("trust_level"),
        }

    @app.get("/api/skills/{skill_id}")
    async def skill_detail(
        skill_id: str, auth: dict[str, Any] = Depends(require_auth_dep)
    ) -> dict[str, Any]:
        agent = get_agent()
        skills_manager = getattr(agent, "skills", None)
        if skills_manager is None:
            raise HTTPException(503, "Skill system is disabled")
        detail = skills_manager.view_skill(skill_id)
        if not detail:
            raise HTTPException(404, f"Skill '{skill_id}' not found")
        return cast("dict[str, Any]", detail)

    @app.post("/api/upload")
    async def upload_file(
        file: UploadFile | None = None,
        session_id: str | None = Form(default=None),
        auth: dict[str, Any] = Depends(require_user_write),
    ) -> dict[str, Any]:
        """Upload a file to the current owner's upload partition."""
        if file is None:
            raise HTTPException(400, "No file provided")
        agent = get_agent()
        session_id = _require_upload_session_id(session_id)
        owner = runtime_owner(auth)
        safe_name = safe_upload_filename(file.filename)
        max_size = 100 * 1024 * 1024  # 100MB
        from js.echo.upload_quota import UploadQuotaLimits

        def _quota_int(raw: object, default: int) -> int:
            # Reject MagicMock/bool and other non-exact ints (int(MagicMock())==1).
            if type(raw) is not int:
                return default
            return raw if raw >= 0 else default

        security = agent.settings.security
        quota_limits = UploadQuotaLimits(
            owner_max_bytes=_quota_int(
                getattr(security, "upload_owner_max_bytes", None),
                2 * 1024 * 1024 * 1024,
            ),
            owner_max_files=_quota_int(
                getattr(security, "upload_owner_max_files", None),
                5_000,
            ),
            session_max_bytes=_quota_int(
                getattr(security, "upload_session_max_bytes", None),
                512 * 1024 * 1024,
            ),
            session_max_files=_quota_int(
                getattr(security, "upload_session_max_files", None),
                1_000,
            ),
            min_free_disk_bytes=_quota_int(
                getattr(security, "upload_min_free_disk_bytes", None),
                256 * 1024 * 1024,
            ),
        )
        with secure_upload_writer(
            workspace=agent.settings.workspace,
            owner_key_hash=owner,
            session_id=session_id,
            filename=safe_name,
            max_bytes=max_size,
            quota_limits=quota_limits,
        ) as writer:
            while True:
                chunk = await file.read(65536)
                if not chunk:
                    break
                writer.write(chunk)
            payload_ref = agent.stage_upload_commit(owner, session_id, writer)
            if not isinstance(payload_ref, str) or not payload_ref:
                raise HTTPException(503, "Upload admission is unavailable")
            try:
                result = await _execute_web_tool_effect(
                    agent,
                    auth,
                    channel="upload_commit",
                    tool_name=CONTROL_UPLOAD_MUTATE_TOOL,
                    arguments={"action": "commit", "payload_ref": payload_ref},
                    user_input="Commit an owner-bound streamed upload",
                    session_id=session_id,
                )
            finally:
                agent.discard_upload_commit(
                    payload_ref,
                    owner,
                    session_id=session_id,
                )
            _raise_control_tool_error(result, default_status=500)
            result_ref = result.metadata.get("result_ref")
            if not isinstance(result_ref, str) or not result_ref:
                raise HTTPException(500, "Upload result handoff failed")
            upload_result = agent.take_upload_mutation_result(
                result_ref,
                owner,
                product_id=str(getattr(agent.settings, "product_id", "js-agent")),
                session_id=session_id,
            )
            if not isinstance(upload_result, dict):
                raise HTTPException(500, "Upload result handoff failed")

        saved_as = upload_result.get("saved_as")
        rel_path = upload_result.get("path")
        total = upload_result.get("size")
        if (
            not isinstance(saved_as, str)
            or not saved_as
            or not isinstance(rel_path, str)
            or not rel_path
            or not isinstance(total, int)
            or isinstance(total, bool)
            or total < 0
        ):
            raise HTTPException(500, "Upload result handoff failed")
        return {
            "success": True,
            "filename": safe_name,
            "saved_as": saved_as,
            "path": rel_path,
            "size": total,
            "content_type": file.content_type or "application/octet-stream",
            "owner_scoped": True,
            "session_id": session_id,
        }

    @app.get("/api/uploads")
    async def list_uploads(
        session_id: str | None = None,
        auth: dict[str, Any] = Depends(require_auth_dep),
    ) -> dict[str, Any]:
        """List uploaded files owned by the current API key."""
        agent = get_agent()
        session_id = _require_upload_session_id(session_id)
        files = []
        for entry in list_owned_upload_entries(
            agent.settings.workspace,
            runtime_owner(auth),
            session_id,
        ):
            files.append(
                {
                    "name": entry.name,
                    "path": entry.relative_path,
                    "size": entry.size,
                    "modified": entry.modified,
                }
            )
        return {"files": files}

    @app.delete("/api/uploads/{filename}")
    async def delete_upload(
        filename: str,
        session_id: str | None = None,
        auth: dict[str, Any] = Depends(require_user_write),
    ) -> dict[str, Any]:
        """Delete an uploaded file."""
        agent = get_agent()
        session_id = _require_upload_session_id(session_id)
        owner = runtime_owner(auth)
        payload_ref = agent.stage_upload_mutation_payload(
            owner,
            {"filename": filename, "session_id": session_id},
            product_id=str(getattr(agent.settings, "product_id", "js-agent")),
            session_id=session_id,
        )
        if not isinstance(payload_ref, str) or not payload_ref:
            raise HTTPException(503, "Upload deletion admission is unavailable")
        try:
            result = await _execute_web_tool_effect(
                agent,
                auth,
                channel="upload_delete",
                tool_name=CONTROL_UPLOAD_MUTATE_TOOL,
                arguments={"action": "delete", "payload_ref": payload_ref},
                user_input="Delete an owner-bound upload",
                session_id=session_id,
            )
        finally:
            agent.discard_upload_mutation_payload(
                payload_ref,
                owner,
                product_id=str(getattr(agent.settings, "product_id", "js-agent")),
                session_id=session_id,
            )
        _raise_control_tool_error(result, default_status=500)
        return {"success": True}

    @app.get("/api/file-preview")
    async def file_preview(
        path: str,
        session_id: str | None = None,
        auth: dict[str, Any] = Depends(require_user_write),
    ) -> dict[str, Any]:
        """Preview a file's content or metadata."""
        agent = get_agent()
        session_id = _require_upload_session_id(session_id)
        snapshot: _PreviewSnapshot
        if str(getattr(agent.settings, "product_id", "")) == "js-work":
            from js_work.file_scope import (
                LOCAL_WORK_OWNER,
                WorkFileScopeError,
                WorkOwnerFileScope,
            )

            owner = memory_owner(auth) or LOCAL_WORK_OWNER
            work_session = session_id
            try:
                snapshot = WorkOwnerFileScope(
                    agent.settings.workspace,
                    owner=owner,
                    session_id=work_session,
                ).read_routine_input(path)
            except WorkFileScopeError as exc:
                raise HTTPException(exc.status_code, exc.detail) from exc
        else:
            snapshot = read_agent_attachment(
                workspace=agent.settings.workspace,
                path=path,
                owner_key_hash=runtime_owner(auth),
                session_id=session_id,
            )

        result: dict[str, Any] = {
            "path": path,
            "name": snapshot.name,
            "size": snapshot.size,
        }

        # Text files: return content preview
        text_suffixes = {
            ".txt",
            ".md",
            ".py",
            ".js",
            ".json",
            ".yaml",
            ".yml",
            ".csv",
            ".html",
            ".css",
            ".xml",
            ".sh",
            ".log",
        }
        if snapshot.suffix in text_suffixes:
            try:
                content = snapshot.data.decode("utf-8", errors="replace")
                redacted = agent.secrets.detect_and_redact(
                    content,
                    "web_file_preview",
                )
                if isinstance(redacted, str):
                    content = redacted
                result["type"] = "text"
                result["content"] = content[:5000]
                result["truncated"] = len(content) > 5000
            except Exception:
                result["type"] = "binary"
                result["error"] = "Preview unavailable"
        else:
            result["type"] = "binary"

        return result

    from js.web.ws.bots import bots_websocket_endpoint
    from js.web.ws.chat import websocket_endpoint
    from js.web.ws.fleet import fleet_websocket_endpoint

    app.websocket("/ws")(websocket_endpoint)
    app.websocket("/ws/fleet")(fleet_websocket_endpoint)
    app.websocket("/ws/bots")(bots_websocket_endpoint)

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

        try:
            agent = get_agent()
        except HTTPException:
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
                    content={"detail": "Server is under memory pressure. Please try again later."},
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
        runtime = current_web_runtime()
        startup_time = runtime.startup_time if runtime is not None else _startup_time
        if startup_time:
            uptime = round(asyncio.get_event_loop().time() - startup_time, 1)

        # Overall status
        status = "healthy"
        if is_governor:
            assert governor is not None
            if governor.paused:
                status = "degraded"
        if agent.degraded:
            status = "degraded"

        # Echo ledger / safety service status (manual_review, recovery)
        echo_health: dict[str, Any] = {"status": "unknown"}
        try:
            safety = getattr(agent, "echo_safety_service", None)
            if safety is not None:
                eh = safety.health()
                echo_health = {
                    "status": "healthy" if eh.ok else "degraded",
                    "ok": bool(eh.ok),
                    "manual_review_count": int(getattr(eh, "manual_review_effect_count", 0)),
                    "last_verified_at": str(getattr(eh, "last_verified_at", "")),
                }
                if echo_health["manual_review_count"] > 0 or not echo_health["ok"]:
                    status = "degraded"
        except Exception:
            echo_health = {"status": "error"}
            status = "degraded"

        # Cron / daemon status
        cron_status: dict[str, Any] = {"available": False}
        try:
            cron = getattr(agent, "cron_scheduler", None) or getattr(agent, "cron", None)
            if cron is not None:
                cron_status = {"available": True, "running": bool(getattr(cron, "running", False))}
        except Exception:
            pass

        daemon_status: dict[str, Any] = {"available": False}
        try:
            daemon = getattr(agent, "daemon", None)
            if daemon is not None:
                daemon_status = {
                    "available": True,
                    "running": bool(getattr(daemon, "running", False)),
                    "ledger_degraded": bool(getattr(daemon, "ledger_degraded", False)),
                }
                if daemon_status["ledger_degraded"]:
                    # The authoritative daemon ledger is unavailable: never
                    # report healthy on the derived JSON snapshot alone.
                    status = "degraded"
        except Exception:
            pass

        return {
            "status": status,
            "uptime_seconds": uptime,
            "memory": memory_info,
            "agents": agents_info,
            "tasks": tasks_info,
            "degraded": agent.degraded,
            "paused": governor.paused if is_governor else False,  # type: ignore[union-attr]
            "echo_ledger": echo_health,
            "cron": cron_status,
            "daemon": daemon_status,
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

    install_web_runtime_context(app)
    return app


_TEMPLATE_DIR = Path(__file__).parent / "templates"
_STATIC_DIR = Path(__file__).parent / "static"


def _load_index_html(*, product_name: str = "JS Agent") -> str:
    path = _TEMPLATE_DIR / "index.html"
    if path.exists():
        return path.read_text(encoding="utf-8").replace("{{PRODUCT_NAME}}", product_name)
    return "<h1>Template not found</h1>"
