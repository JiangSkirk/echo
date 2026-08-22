"""FastAPI dependencies for the JS Agent web server."""

from __future__ import annotations

import asyncio
import secrets
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, cast

from js.web.auth import require_auth

if TYPE_CHECKING:
    from fastapi import Request

    from js.agent import JSAgent
    from js.config import JSSettings
    from js.echo.ledger.service import EchoSafetyService
    from js.web.stats_store import TokenStatsStore

# These are set during lifespan startup and remain for the app lifetime.
_agent: JSAgent | None = None
_settings: JSSettings | None = None
_stats_store: TokenStatsStore | None = None
_echo_safety_service: EchoSafetyService | None = None
_active_model: str = ""

# Backward-compatible FastAPI dependency alias; auth remains single-sourced.
require_auth_dep = require_auth


@dataclass
class AgentConfigState:
    """Mutable Fleet role configuration owned by one FastAPI application."""

    config: dict[str, str] = field(
        default_factory=lambda: {
            "worker": "",
            "reviewer": "",
        }
    )
    lock: asyncio.Lock = field(default_factory=asyncio.Lock, repr=False)


def get_agent_config_state(request: Request) -> AgentConfigState:
    """Return and bind the Fleet role state owned by the request app."""
    state = cast("AgentConfigState", request.app.state.agent_config_state)

    from js.web.runtime_context import current_web_runtime

    runtime = current_web_runtime()
    if runtime is not None:
        cast("Any", runtime).agent_config_state = state
    return state


def get_runtime_agent_config() -> dict[str, str]:
    """Return Fleet role config for the active app runtime."""
    from js.web.runtime_context import current_web_runtime

    runtime = current_web_runtime()
    state = getattr(runtime, "agent_config_state", None) if runtime is not None else None
    if isinstance(state, AgentConfigState):
        return state.config
    return AgentConfigState().config


def set_globals(
    agent: JSAgent,
    settings: JSSettings,
    stats_store: TokenStatsStore | None = None,
    echo_safety_service: EchoSafetyService | None = None,
) -> None:
    global _agent, _settings, _stats_store, _echo_safety_service
    _agent = agent
    _settings = settings
    if stats_store is not None:
        _stats_store = stats_store
    _echo_safety_service = echo_safety_service


def get_agent() -> JSAgent:
    from fastapi import HTTPException

    from js.web.runtime_context import current_web_runtime

    runtime = current_web_runtime()
    if runtime is not None:
        return cast("JSAgent", runtime.agent)
    if _agent is None:
        raise HTTPException(503, "Agent not initialized yet. Please wait for startup to complete.")
    return _agent


def get_settings() -> JSSettings:
    from js.web.runtime_context import current_web_runtime

    runtime = current_web_runtime()
    if runtime is not None:
        return cast("JSSettings", runtime.settings)
    if _settings is not None:
        return _settings
    raise RuntimeError(
        "Web settings are not initialized. Pass runtime_settings into create_app() "
        "or wait for lifespan startup; refusing silent HOME/default config reload."
    )


def get_stats_store() -> TokenStatsStore | None:
    from js.web.runtime_context import current_web_runtime

    runtime = current_web_runtime()
    if runtime is not None:
        return runtime.stats_store
    return _stats_store


def get_echo_safety_service(settings: JSSettings | None = None) -> EchoSafetyService:
    global _echo_safety_service

    from js.echo.ledger.service import EchoSafetyService
    from js.web.runtime_context import current_web_runtime

    runtime = current_web_runtime()
    resolved = settings or (runtime.settings if runtime is not None else get_settings())
    if runtime is not None and resolved is runtime.settings:
        service = runtime.echo_safety_service
        if service is None or service.state_dir != resolved.state_dir:
            service = EchoSafetyService.from_settings(resolved)
            runtime.echo_safety_service = service
        return service
    if _echo_safety_service is None or _echo_safety_service.state_dir != resolved.state_dir:
        _echo_safety_service = EchoSafetyService.from_settings(resolved)
    return _echo_safety_service


def get_active_model() -> str:
    from js.web.runtime_context import current_web_runtime

    runtime = current_web_runtime()
    if runtime is not None:
        return runtime.active_model
    return _active_model


def set_active_model(model: str) -> None:
    global _active_model
    from js.web.runtime_context import current_web_runtime

    runtime = current_web_runtime()
    if runtime is not None:
        runtime.active_model = model
        return
    _active_model = model


# NOTE: admin gating is provided by js.web.auth.require_admin (which also runs
# the Origin/CSRF check on state-changing methods).  Routers depend on it
# directly; no wrapper is needed here.


# ------------------------------------------------------------------
# Unified session_id validation (F-01)
# ------------------------------------------------------------------


def require_path_session_id(session_id: str) -> str:
    """FastAPI dependency: validate a required path ``session_id``."""
    from fastapi import HTTPException

    from js.web.ids import InvalidRuntimeIdError, validate_session_id

    try:
        return validate_session_id(session_id)
    except InvalidRuntimeIdError as exc:
        raise HTTPException(400, str(exc)) from exc


def optional_query_session_id(session_id: str | None = None) -> str | None:
    """FastAPI dependency: coerce optional query ``session_id``."""
    from fastapi import HTTPException

    from js.web.ids import InvalidRuntimeIdError, coerce_optional_session_id

    try:
        return coerce_optional_session_id(session_id)
    except InvalidRuntimeIdError as exc:
        raise HTTPException(400, str(exc)) from exc


def require_upload_session_id(session_id: str | None) -> str:
    """Validate a required upload/form ``session_id`` (not a Depends wrapper)."""
    from fastapi import HTTPException

    from js.web.ids import InvalidRuntimeIdError, validate_session_id

    if not isinstance(session_id, str) or not session_id.strip():
        raise HTTPException(400, "session_id is required")
    try:
        return validate_session_id(session_id)
    except InvalidRuntimeIdError as exc:
        raise HTTPException(400, str(exc)) from exc


def coerce_body_session_id(raw: object) -> str | None:
    """Validate optional JSON-body ``session_id`` or raise HTTP 400."""
    from fastapi import HTTPException

    from js.web.ids import InvalidRuntimeIdError, coerce_optional_session_id

    try:
        return coerce_optional_session_id(raw)
    except InvalidRuntimeIdError as exc:
        raise HTTPException(400, str(exc)) from exc


def coerce_ws_session_id(raw: object, *, current: str | None) -> str:
    """Validate an inbound WS session id or keep / allocate a provisional one."""
    from js.web.ids import InvalidRuntimeIdError, coerce_optional_session_id

    try:
        validated = coerce_optional_session_id(raw)
    except InvalidRuntimeIdError as exc:
        raise ValueError(str(exc)) from exc
    if validated:
        return validated
    if current:
        return current
    return f"ws-{secrets.token_hex(16)}"
