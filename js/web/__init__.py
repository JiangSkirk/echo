"""Web UI for JS Agent."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from js.web.server import create_app as create_app

__all__ = ["create_app"]


def __getattr__(name: str) -> Any:
    """Keep lightweight auth/model submodules independent of the full server."""
    if name == "create_app":
        from js.web.server import create_app

        return create_app
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
