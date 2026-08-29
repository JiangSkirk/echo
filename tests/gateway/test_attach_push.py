"""Gateway attach + push pairing isolation."""

from __future__ import annotations

from types import SimpleNamespace

from js.config import GatewayConfig, JSSettings
from js.gateway.adapter import ChannelPeer
from js.gateway.attach import attach_gateway_service
from js.gateway.push import authorize_push
from js.gateway.service import GatewayService


def test_attach_is_idempotent() -> None:
    settings = JSSettings()
    settings.gateway = GatewayConfig(enabled=True)
    agent = SimpleNamespace(settings=settings)
    first = attach_gateway_service(agent)
    second = attach_gateway_service(agent)
    assert first is second
    assert isinstance(first, GatewayService)


def test_authorize_push_requires_matching_paired_owner() -> None:
    settings = JSSettings()
    settings.gateway = GatewayConfig(enabled=True)
    service = GatewayService(settings)
    alice = ChannelPeer(channel="discord", peer_id="alice")
    service.pairing.allow(alice, "owner-alice")
    assert authorize_push(service, owner="owner-alice", peer=alice) is None
    assert authorize_push(service, owner="owner-bob", peer=alice) == "owner mismatch"
    stranger = ChannelPeer(channel="discord", peer_id="stranger")
    assert authorize_push(service, owner="owner-alice", peer=stranger) == "peer is not paired"
