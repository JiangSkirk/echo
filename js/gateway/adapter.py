"""Channel adapter contract. Adapters receive and send; they do not run turns."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable


@dataclass(frozen=True, slots=True)
class ChannelPeer:
    """Stable identity of a sender on one channel."""

    channel: str
    peer_id: str
    display_name: str = ""

    def key(self) -> str:
        return f"{self.channel}:{self.peer_id}"


@dataclass(frozen=True, slots=True)
class InboundEnvelope:
    """One inbound message after the adapter has parsed transport bytes."""

    peer: ChannelPeer
    text: str
    message_id: str
    received_at: float
    attachments: tuple[str, ...] = ()


@runtime_checkable
class ChannelAdapter(Protocol):
    """Receive / send only. Echo construction lives in GatewayService."""

    name: str

    async def start(self) -> None: ...

    async def stop(self) -> None: ...

    async def send(self, peer: ChannelPeer, text: str) -> None: ...
