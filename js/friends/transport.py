"""Host-to-Host delivery. Destinations must already be a confirmed friend endpoint."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Protocol

from js.security.net_guard import OutboundURLError, resolve_and_validate

DeliverHandler = Callable[[dict[str, str], bytes], Awaitable[int]]


class FriendsTransport(Protocol):
    async def deliver(self, endpoint: str, headers: dict[str, str], body: bytes) -> int: ...


class LoopbackTransport:
    """In-process delivery used by dual-HOME tests."""

    def __init__(self) -> None:
        self._handlers: dict[str, DeliverHandler] = {}

    def bind(self, endpoint: str, handler: DeliverHandler) -> None:
        self._handlers[endpoint] = handler

    async def deliver(self, endpoint: str, headers: dict[str, str], body: bytes) -> int:
        handler = self._handlers.get(endpoint)
        if handler is None:
            raise LookupError(f"no loopback handler for {endpoint}")
        return await handler(headers, body)


class HttpFriendsTransport:
    """HTTPS POST to a confirmed friend endpoint after net_guard validation."""

    def __init__(self, *, allow_loopback: bool = True) -> None:
        self.allow_loopback = allow_loopback

    async def deliver(self, endpoint: str, headers: dict[str, str], body: bytes) -> int:
        import httpx

        try:
            resolve_and_validate(
                endpoint,
                allow_loopback=self.allow_loopback,
                allow_private=False,
            )
        except OutboundURLError as exc:
            raise ValueError(f"friend endpoint refused: {exc}") from exc
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(endpoint, headers=headers, content=body)
        return int(response.status_code)
