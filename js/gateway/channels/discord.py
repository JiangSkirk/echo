"""Discord channel. Real discord.py is optional; tests inject a transport."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Protocol

from js.gateway.adapter import ChannelPeer, InboundEnvelope
from js.utils.log import get_logger

logger = get_logger("js.gateway.discord")

InboundHandler = Callable[[InboundEnvelope], Awaitable[None]]


class DiscordTransport(Protocol):
    """Byte-pump only. Pairing and Echo stay in GatewayService."""

    async def start(self, handler: InboundHandler) -> None: ...

    async def stop(self) -> None: ...

    async def send(self, peer_id: str, text: str) -> None: ...


class MockDiscordTransport:
    """In-memory Discord transport for tests and local fixtures."""

    def __init__(self) -> None:
        self.outbound: list[tuple[str, str]] = []
        self.started = False
        self._handler: InboundHandler | None = None

    async def start(self, handler: InboundHandler) -> None:
        self._handler = handler
        self.started = True

    async def stop(self) -> None:
        self.started = False
        self._handler = None

    async def send(self, peer_id: str, text: str) -> None:
        self.outbound.append((peer_id, text))

    async def inject(self, envelope: InboundEnvelope) -> None:
        if self._handler is None:
            raise RuntimeError("mock Discord transport is not started")
        await self._handler(envelope)


class DiscordChannelAdapter:
    """Discord adapter with bounded reconnect. Does not run Echo itself."""

    name = "discord"

    def __init__(
        self,
        transport: DiscordTransport,
        *,
        max_retries: int = 5,
        base_delay_seconds: float = 0.5,
    ) -> None:
        self._transport = transport
        self._max_retries = max_retries
        self._base_delay = base_delay_seconds
        self._handler: InboundHandler | None = None

    def set_inbound_handler(self, handler: InboundHandler) -> None:
        self._handler = handler

    async def start(self) -> None:
        if self._handler is None:
            raise RuntimeError("Discord adapter has no inbound handler")
        delay = self._base_delay
        last_error: Exception | None = None
        for attempt in range(self._max_retries):
            try:
                await self._transport.start(self._handler)
                return
            except Exception as exc:
                last_error = exc
                logger.warning(
                    "discord transport start failed attempt=%s error=%s",
                    attempt + 1,
                    type(exc).__name__,
                )
                await asyncio.sleep(delay)
                delay = min(delay * 2, 8.0)
        raise RuntimeError("discord transport failed to start") from last_error

    async def stop(self) -> None:
        await self._transport.stop()

    async def send(self, peer: ChannelPeer, text: str) -> None:
        await self._transport.send(peer.peer_id, text)


def load_discord_transport() -> DiscordTransport:
    """Load the optional discord.py client. Tests should inject MockDiscordTransport."""

    try:
        import importlib

        importlib.import_module("discord")
    except ImportError as exc:
        raise RuntimeError(
            "discord extra is not installed. Run: pip install 'js-agent[discord]'"
        ) from exc
    raise RuntimeError("live Discord transport is configured only when a token is supplied")
