"""Runtime helpers shared by HTTP and WebSocket chat paths."""

from __future__ import annotations

import contextvars
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any


@dataclass
class WebRuntime:
    """Mutable resources owned by exactly one FastAPI application."""

    agent: Any
    settings: Any
    fleet: Any | None = None
    fleet_factory: Callable[[], Any] | None = None
    stats_store: Any | None = None
    echo_safety_service: Any | None = None
    active_model: str = ""
    bootstrap_admin_key: str | None = None
    startup_time: float = 0.0
    _fleet_lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    def get_or_create_fleet(self) -> Any | None:
        """Create the runtime-owned fleet lazily and cache it."""
        if self.fleet is not None or not callable(self.fleet_factory):
            return self.fleet
        with self._fleet_lock:
            if self.fleet is None:
                self.fleet = self.fleet_factory()
        return self.fleet


_current_web_runtime: contextvars.ContextVar[WebRuntime | None] = contextvars.ContextVar(
    "current_web_runtime",
    default=None,
)


def current_web_runtime() -> WebRuntime | None:
    """Return the runtime bound to the current HTTP or WebSocket scope."""
    return _current_web_runtime.get(None)


def bind_web_runtime(app: Any, runtime: WebRuntime) -> None:
    """Attach one runtime to one app without mutating module globals."""
    app.state.web_runtime = runtime


def clear_web_runtime(app: Any, runtime: WebRuntime) -> None:
    """Clear only the runtime owned by ``app``."""
    if getattr(app.state, "web_runtime", None) is runtime:
        app.state.web_runtime = None


class WebRuntimeContextMiddleware:
    """Bind an app's runtime for the duration of each ASGI scope."""

    def __init__(self, app: Any, *, owner_app: Any) -> None:
        self.app = app
        self.owner_app = owner_app

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        runtime = getattr(self.owner_app.state, "web_runtime", None)
        token = _current_web_runtime.set(runtime)
        try:
            await self.app(scope, receive, send)
        finally:
            _current_web_runtime.reset(token)


def install_web_runtime_context(app: Any) -> None:
    """Install request and WebSocket runtime binding once for ``app``."""
    if getattr(app.state, "web_runtime_context_installed", False):
        return
    app.state.web_runtime_context_installed = True
    app.add_middleware(WebRuntimeContextMiddleware, owner_app=app)


def web_channel(settings: Any, default: str) -> str:
    """Return a product-specific Echo channel name when configured."""
    prefix = getattr(settings, "_web_channel_prefix", "")
    if isinstance(prefix, str) and prefix:
        return f"{prefix}_{default}"
    return default


def prepare_web_message(settings: Any, message: str) -> str:
    """Allow product variants to prepare chat messages without web importing them."""
    router = getattr(settings, "_work_intent_router", None)
    prepare = getattr(router, "prepare_message", None)
    if callable(prepare):
        prepared = prepare(message)
        if isinstance(prepared, str):
            return prepared
    return message
