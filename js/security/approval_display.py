"""Approval-card sanitization (ASI09). Display only — never changes binding hashes."""

from __future__ import annotations

import html
from typing import Any

from js.orin import taint as taint_mod

_MAX_DESC = 240

_WORST_CASE: dict[str, str] = {
    "shell": "If approved, this command runs on the machine with the current sandbox grants.",
    "file_write": "If approved, this writes bytes to a workspace path you may not be able to undo.",
    "file_delete": "If approved, this deletes a workspace file.",
    "web_search": "If approved, this sends a query to an external host.",
    "browser_fetch": "If approved, this fetches a remote URL and brings the response into context.",
    "send_mail": "If approved, this sends a message to an external recipient.",
}


def sanitize_approval_display(
    *,
    tool_name: str,
    arguments: dict[str, Any],
    context_taint: int = 0,
    clearance: int = 1,
) -> str:
    """Truncate, escape, badge, and append a template worst-case line."""

    raw = ", ".join(f"{key}={arguments[key]!r}" for key in list(arguments)[:8])
    if len(raw) > _MAX_DESC:
        raw = raw[: _MAX_DESC - 1] + "…"
    escaped = html.escape(raw, quote=True)
    badges: list[str] = []
    if context_taint & taint_mod.WEB_CONTENT:
        badges.append("triggered-by-web")
    if context_taint & taint_mod.MEMORY_READ:
        badges.append("memory-sourced")
    if context_taint & taint_mod.SECRET or clearance >= taint_mod.CLEARANCE_SECRET:
        badges.append("secret-context")
    badge_text = f" [{' '.join(badges)}]" if badges else ""
    worst = _WORST_CASE.get(
        tool_name,
        "If approved, this performs the named tool action with the listed arguments.",
    )
    return f"{html.escape(tool_name)}({escaped}){badge_text}\n{worst}"
