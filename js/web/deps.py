"""FastAPI dependencies for the JS Agent web server."""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import Depends

if TYPE_CHECKING:
    from js.agent import JSAgent
    from js.config import JSSettings
    from js.web.stats_store import TokenStatsStore

# These are set during lifespan startup and remain for the app lifetime.
_agent: JSAgent | None = None
_settings: JSSettings | None = None
_stats_store: TokenStatsStore | None = None
_active_model: str = ""


def set_globals(
    agent: JSAgent, settings: JSSettings, stats_store: TokenStatsStore | None = None
) -> None:
    global _agent, _settings, _stats_store
    _agent = agent
    _settings = settings
    if stats_store is not None:
        _stats_store = stats_store


def get_agent() -> JSAgent:
    from fastapi import HTTPException

    if _agent is None:
        raise HTTPException(503, "Agent not initialized yet. Please wait for startup to complete.")
    return _agent


def get_settings() -> JSSettings:
    from js.config import JSSettings

    if _settings is None:
        return JSSettings.from_file()
    return _settings


def get_stats_store() -> TokenStatsStore | None:
    return _stats_store


def get_active_model() -> str:
    return _active_model


def set_active_model(model: str) -> None:
    global _active_model
    _active_model = model


# Auth dependency (import here to avoid circular import at module level)
async def require_auth_dep() -> dict[str, object]:
    from js.web.auth import require_auth

    return await require_auth()


async def require_admin_dep(
    auth: dict[str, object] = Depends(require_auth_dep),
) -> dict[str, object]:
    from js.web.auth import require_admin

    return await require_admin(auth)
