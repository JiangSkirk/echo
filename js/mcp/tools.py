"""Fail-closed compatibility tombstone for the removed raw MCP adapter."""

from __future__ import annotations

from typing import Any, NoReturn

_DISABLED = (
    "Raw MCP adapter disabled by Echo policy; use ControlledMCPConnector with "
    "schema-only execution"
)


class MCPToolAdapter:
    """Removed adapter that previously registered raw remote handlers."""

    def __init__(self, client: Any) -> None:
        del client
        raise RuntimeError(_DISABLED)

    @staticmethod
    def _blocked() -> NoReturn:
        raise RuntimeError(_DISABLED)

    async def register_all(self, registry: Any) -> None:
        del registry
        self._blocked()


__all__ = ["MCPToolAdapter"]
