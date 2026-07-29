"""Fail-closed compatibility surface for historical automatic model refresh.

Reading ``/api/models`` must not create an unreceipted background network
effect or mutate provider configuration. Provider discovery is therefore an
explicit control-plane operation; these historical hooks intentionally do no
I/O until that operation is routed through an Echo lease.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, cast

if TYPE_CHECKING:
    from js.agent import JSAgent


@dataclass
class ModelRefreshState:
    """Compatibility state retained per web application."""

    last_cloud_refresh: float = 0.0
    last_local_refresh: float = 0.0


def _refresh_state(agent: JSAgent) -> ModelRefreshState:
    from js.web.runtime_context import current_web_runtime

    runtime = current_web_runtime()
    state = getattr(runtime, "model_refresh_state", None) if runtime is not None else None
    if isinstance(state, ModelRefreshState):
        return state

    state = getattr(agent, "_web_model_refresh_state", None)
    if not isinstance(state, ModelRefreshState):
        state = ModelRefreshState()
        cast("Any", agent)._web_model_refresh_state = state
    return state


def reset_throttle(owner: JSAgent | ModelRefreshState | None = None) -> None:
    """Reset one app or agent compatibility state."""
    if isinstance(owner, ModelRefreshState):
        resolved_state = owner
    elif owner is not None:
        resolved_state = _refresh_state(owner)
    else:
        from js.web.runtime_context import current_web_runtime

        runtime = current_web_runtime()
        state = getattr(runtime, "model_refresh_state", None) if runtime is not None else None
        if not isinstance(state, ModelRefreshState):
            return
        resolved_state = state
    resolved_state.last_cloud_refresh = 0.0
    resolved_state.last_local_refresh = 0.0


def maybe_refresh_models_async(agent: JSAgent) -> None:
    """Reject implicit refresh by deliberately scheduling no work."""
    del agent


async def refresh_cloud_provider_models(agent: JSAgent) -> None:
    """Compatibility no-op: cloud discovery requires an explicit Echo effect."""
    del agent


async def refresh_local_provider_models(agent: JSAgent) -> None:
    """Compatibility no-op: local discovery requires an explicit Echo effect."""
    del agent
