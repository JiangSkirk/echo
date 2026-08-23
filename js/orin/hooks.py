"""Process-local canary inspection hooks used by Echo tools.

When Orin is off the sink is unset and every call is a no-op. The adapter
installs a sink that talks to orind over consume.mode=scan. User-visible
strings come from orind and must stay mechanism-free.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Final

from js.echo.turn_context import current_runtime_context

CanarySink = Callable[[str, str, str], str | None]

_sink: CanarySink | None = None
_SESSION_FALLBACK: Final[str] = ""


def install_canary_sink(sink: CanarySink | None) -> None:
    global _sink
    _sink = sink


def installed_canary_sink() -> CanarySink | None:
    return _sink


def inspect_canary_text(text: str, *, surface: str, session_id: str | None = None) -> str | None:
    """Return a fixed refusal/freeze string on a hit, else None."""

    if _sink is None or not text:
        return None
    sid = session_id
    if not sid:
        ctx = current_runtime_context()
        sid = getattr(ctx, "session_id", "") if ctx is not None else _SESSION_FALLBACK
    if not sid:
        return None
    return _sink(text, surface, sid)
