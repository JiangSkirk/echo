"""Tool sink bits shared by Echo narrowing and the orind policy table.

Echo must not import ``js.orind``: the C1 worker runtime image omits the
daemon. Classification stays here, next to taint, so both sides share one
table.
"""

from __future__ import annotations

from typing import Final

SINK_FS_READ: Final[int] = 1 << 0
SINK_FS_WRITE: Final[int] = 1 << 1
SINK_FS_OUTSIDE: Final[int] = 1 << 2
SINK_NETWORK_EGRESS: Final[int] = 1 << 3
SINK_SPAWN: Final[int] = 1 << 4
SINK_MEMORY_WRITE: Final[int] = 1 << 5
SINK_POLICY_CHANGE: Final[int] = 1 << 6
SINK_CONNECTOR: Final[int] = 1 << 7

TOOL_SINKS: Final[dict[str, int]] = {
    "file_read": SINK_FS_READ,
    "file_write": SINK_FS_WRITE,
    "file_edit": SINK_FS_WRITE,
    "file_append": SINK_FS_WRITE,
    "file_delete": SINK_FS_WRITE,
    "file_move": SINK_FS_WRITE,
    "file_copy": SINK_FS_WRITE,
    "glob": SINK_FS_READ,
    "grep": SINK_FS_READ,
    "list_dir": SINK_FS_READ,
    "shell": SINK_SPAWN | SINK_FS_WRITE | SINK_FS_OUTSIDE,
    "python": SINK_SPAWN | SINK_FS_WRITE,
    "browser_fetch": SINK_NETWORK_EGRESS,
    "web_search": SINK_NETWORK_EGRESS,
    "email.send_exact": SINK_NETWORK_EGRESS | SINK_CONNECTOR,
    "net.send": SINK_NETWORK_EGRESS | SINK_CONNECTOR,
    "net.fetch": SINK_FS_READ,
    "file.commit": SINK_FS_WRITE | SINK_FS_OUTSIDE,
    "webbridge_navigate": SINK_NETWORK_EGRESS,
    "webbridge_screenshot": SINK_NETWORK_EGRESS,
    "webbridge_read": SINK_NETWORK_EGRESS,
    "send_mail": SINK_NETWORK_EGRESS | SINK_CONNECTOR,
    "memory_store": SINK_MEMORY_WRITE,
    "memory_search": 0,
}

_SINK_PREFIXES: Final[tuple[tuple[str, int], ...]] = (
    ("connector.", SINK_NETWORK_EGRESS | SINK_CONNECTOR),
    ("desktop_", 0),
)


def sinks_for_tool(tool_name: str) -> int:
    """Classify a tool into sink bits by table lookup (fail to default)."""

    if tool_name in TOOL_SINKS:
        return TOOL_SINKS[tool_name]
    for prefix, sinks in _SINK_PREFIXES:
        if tool_name.startswith(prefix):
            return sinks
    return 0
