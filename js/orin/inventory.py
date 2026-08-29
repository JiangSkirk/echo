"""C0 enforce-exit classification. Digest drift fail-closes enforce."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from typing import Final

# C0 ``cell`` / ``readonly`` names that may remain registered under enforce.
ENFORCE_ALLOWED_TOOLS: Final[frozenset[str]] = frozenset(
    {
        "browser_fetch",
        "code_search",
        "csv_read",
        "excel_read",
        "file_edit",
        "file_list",
        "file_read",
        "file_search",
        "file_view",
        "file_write",
        "python",
        "shell",
    }
)

# C0 desktop handlers are ambient today; the enforce product path may register
# them only through the Desktop Cell backend. They are classified, not unknown.
DESKTOP_CELL_TOOL_NAMES: Final[frozenset[str]] = frozenset(
    {
        "desktop_app",
        "desktop_clear_stop",
        "desktop_click",
        "desktop_drag",
        "desktop_emergency_stop",
        "desktop_get_permissions",
        "desktop_get_state",
        "desktop_key",
        "desktop_list",
        "desktop_move",
        "desktop_operation_log",
        "desktop_screenshot",
        "desktop_scroll",
        "desktop_set_mode",
        "desktop_type",
        "desktop_window",
    }
)

ENFORCE_DISABLED_TOOL_NAMES: Final[frozenset[str]] = frozenset(
    {
        "browser_open",
        "csv_write",
        "desktop_wizard_action",
        "excel_create",
        "excel_merge",
        "excel_write",
        "fetch_url",
        "file_delete",
        "fleet_collaborate",
        "ask_user",
        "bots_ask",
        "rooms_create",
        "pdf_generate",
        "web_search",
    }
)
ENFORCE_DISABLED_TOOL_PREFIXES: Final[tuple[str, ...]] = (
    "control_",
    "mcp_",
    "skill_",
    "web_",
)

# C4 mapping: these remain disabled-in-enforce until a File Cell backend
# is the live product path. They are classified, not unknown.
FILE_CELL_WRITE_TOOLS: Final[frozenset[str]] = frozenset(
    {
        "csv_write",
        "excel_create",
        "excel_merge",
        "excel_write",
        "pdf_generate",
    }
)
MEMORY_CELL_TOOL_NAMES: Final[frozenset[str]] = frozenset(
    {
        "ask_user",
        "bots_ask",
        "rooms_create",
    }
)

# Pinned after the classified sets above. A changed set is digest drift.
PINNED_INVENTORY_DIGEST: Final[str] = (
    "sha256:2c8b644aba961ba44821b56cd26ea73eee7b5ff0cc8781edb3bcc815f9fa1dba"
)


def inventory_payload() -> dict[str, list[str]]:
    return {
        "allow": sorted(ENFORCE_ALLOWED_TOOLS),
        "deny_names": sorted(ENFORCE_DISABLED_TOOL_NAMES),
        "deny_prefixes": list(ENFORCE_DISABLED_TOOL_PREFIXES),
        "desktop_cell": sorted(DESKTOP_CELL_TOOL_NAMES),
        "file_cell_write": sorted(FILE_CELL_WRITE_TOOLS),
        "memory_cell": sorted(MEMORY_CELL_TOOL_NAMES),
    }


def inventory_digest() -> str:
    payload = json.dumps(inventory_payload(), separators=(",", ":"), sort_keys=True)
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def inventory_digest_matches() -> bool:
    return inventory_digest() == PINNED_INVENTORY_DIGEST


def tool_disabled_under_enforce(name: str) -> bool:
    if name in ENFORCE_DISABLED_TOOL_NAMES:
        return True
    return any(name.startswith(prefix) for prefix in ENFORCE_DISABLED_TOOL_PREFIXES)


def file_cell_mapped_tool(name: str) -> bool:
    return name in FILE_CELL_WRITE_TOOLS


def mcp_or_webbridge_disabled(name: str) -> bool:
    if name in {"browser_open", "fetch_url", "web_search"}:
        return True
    return name.startswith("mcp_") or name.startswith("web_") or name.startswith("control_")


def should_register_product_tool(name: str, *, enforce: bool) -> bool:
    if not enforce:
        return True
    return not tool_disabled_under_enforce(name)


def unclassified_registered_tools(names: Iterable[str]) -> tuple[str, ...]:
    unknown: list[str] = []
    for name in names:
        if name in ENFORCE_ALLOWED_TOOLS or name in DESKTOP_CELL_TOOL_NAMES:
            continue
        if name in MEMORY_CELL_TOOL_NAMES:
            continue
        if tool_disabled_under_enforce(name):
            continue
        unknown.append(name)
    return tuple(sorted(unknown))


def require_no_unclassified_exits(names: Iterable[str]) -> None:
    if not inventory_digest_matches():
        raise RuntimeError("C0 inventory digest drift; unclassified enforce exits are not frozen")
    unknown = unclassified_registered_tools(names)
    if unknown:
        joined = ", ".join(unknown)
        raise RuntimeError(f"unclassified enforce exits: {joined}")


__all__ = [
    "DESKTOP_CELL_TOOL_NAMES",
    "ENFORCE_ALLOWED_TOOLS",
    "ENFORCE_DISABLED_TOOL_NAMES",
    "ENFORCE_DISABLED_TOOL_PREFIXES",
    "FILE_CELL_WRITE_TOOLS",
    "MEMORY_CELL_TOOL_NAMES",
    "PINNED_INVENTORY_DIGEST",
    "file_cell_mapped_tool",
    "inventory_digest",
    "inventory_digest_matches",
    "mcp_or_webbridge_disabled",
    "require_no_unclassified_exits",
    "should_register_product_tool",
    "tool_disabled_under_enforce",
    "unclassified_registered_tools",
]
