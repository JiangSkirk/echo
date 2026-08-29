"""Gateway service: disabled by default, unpaired inbound dropped."""

from __future__ import annotations

import pytest

from js.config import GatewayChannelConfig, GatewayConfig, JSSettings
from js.gateway.adapter import ChannelPeer, InboundEnvelope
from js.gateway.service import GatewayService


class _FakeAdapter:
    name = "mock"

    def __init__(self) -> None:
        self.started = False
        self.sent: list[tuple[str, str]] = []

    async def start(self) -> None:
        self.started = True

    async def stop(self) -> None:
        self.started = False

    async def send(self, peer: ChannelPeer, text: str) -> None:
        self.sent.append((peer.key(), text))


def _settings(*, enabled: bool, policy: str = "warn") -> JSSettings:
    settings = JSSettings()
    settings.gateway = GatewayConfig(
        enabled=enabled,
        channels=[
            GatewayChannelConfig(
                name="mock",
                enabled=True,
                bot_id="bot-1",
                owner="owner-a",
                dm_scope="per-peer",
            )
        ],
    )
    settings.security.untrusted_ingestion_policy = policy  # type: ignore[assignment]
    return settings


def _envelope(text: str, peer_id: str = "9") -> InboundEnvelope:
    return InboundEnvelope(
        peer=ChannelPeer(channel="mock", peer_id=peer_id),
        text=text,
        message_id="m1",
        received_at=1.0,
    )


def test_disabled_gateway_drops_inbound() -> None:
    service = GatewayService(_settings(enabled=False))
    decision = service.handle_inbound(_envelope("hello"))
    assert decision.accepted is False
    assert decision.reason == "disabled"


@pytest.mark.asyncio
async def test_disabled_gateway_refuses_start() -> None:
    service = GatewayService(_settings(enabled=False))
    service.register_adapter(_FakeAdapter())
    with pytest.raises(RuntimeError, match="gateway.enabled=false"):
        await service.start()


def test_unpaired_sender_is_dropped() -> None:
    service = GatewayService(_settings(enabled=True))
    decision = service.handle_inbound(_envelope("hello"))
    assert decision.accepted is False
    assert decision.reason == "unpaired"


def test_pairing_then_route() -> None:
    service = GatewayService(_settings(enabled=True))
    code = service.pairing.issue_code("owner-a")
    paired = service.handle_inbound(_envelope(f"/pair {code}"))
    assert paired.reason == "paired"
    accepted = service.handle_inbound(_envelope("hello"))
    assert accepted.accepted is True
    assert accepted.route is not None
    assert accepted.route.bot_id == "bot-1"
    assert accepted.owner == "owner-a"


def test_owner_mismatch_is_dropped() -> None:
    service = GatewayService(_settings(enabled=True))
    peer = ChannelPeer(channel="mock", peer_id="9")
    service.pairing.allow(peer, "other-owner")
    decision = service.handle_inbound(_envelope("hello"))
    assert decision.accepted is False
    assert decision.reason == "owner_mismatch"
