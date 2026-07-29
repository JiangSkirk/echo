"""Fail-closed compatibility tombstone for the removed raw MCP client.

Runtime MCP schemas are accepted only through :mod:`js.mcp.controlled`.  The
legacy client used to launch arbitrary subprocesses or contact arbitrary URLs
without an Echo effect/lease boundary, so retaining a functional implementation
would reintroduce a bypass even if it were no longer imported by JSAgent.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, NoReturn

_DISABLED = (
    "Raw MCP client disabled by Echo policy; use ControlledMCPConnector with "
    "schema-only execution"
)


@dataclass(frozen=True)
class MCPTool:
    """Legacy schema type retained only for import compatibility."""

    name: str
    description: str
    input_schema: dict[str, Any]


@dataclass(frozen=True)
class MCPResource:
    """Legacy schema type retained only for import compatibility."""

    uri: str
    name: str
    mime_type: str


class MCPClient:
    """Removed unsafe runtime client; every construction attempt is denied."""

    def __init__(self, command: list[str] | None = None, url: str | None = None) -> None:
        del command, url
        raise RuntimeError(_DISABLED)

    @staticmethod
    def _blocked() -> NoReturn:
        raise RuntimeError(_DISABLED)

    async def connect(self) -> None:
        self._blocked()

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> str:
        del name, arguments
        self._blocked()

    def list_tools(self) -> list[MCPTool]:
        self._blocked()

    async def disconnect(self) -> None:
        self._blocked()


__all__ = ["MCPClient", "MCPResource", "MCPTool"]
