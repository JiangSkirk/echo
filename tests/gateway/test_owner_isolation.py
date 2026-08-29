"""Paired gateway senders do not share owner, session, or route."""

from __future__ import annotations

from js.config import GatewayChannelConfig, GatewayConfig, JSSettings
from js.gateway.adapter import ChannelPeer, InboundEnvelope
from js.gateway.service import GatewayService


def test_two_paired_senders_keep_separate_owners_and_sessions() -> None:
    settings = JSSettings()
    settings.gateway = GatewayConfig(
        enabled=True,
        channels=[
            GatewayChannelConfig(
                name="webhook",
                enabled=True,
                bot_id="shared-bot",
                owner="unused-default",
                dm_scope="per-peer",
            )
        ],
    )
    service = GatewayService(settings)
    alice = ChannelPeer(channel="webhook", peer_id="alice")
    bob = ChannelPeer(channel="webhook", peer_id="bob")
    service.pairing.allow(alice, "owner-alice")
    service.pairing.allow(bob, "owner-bob")
    service.router.bind(alice, owner="owner-alice", bot_id="bot-alice")
    service.router.bind(bob, owner="owner-bob", bot_id="bot-bob")

    left = service.handle_inbound(
        InboundEnvelope(peer=alice, text="hi", message_id="1", received_at=1.0)
    )
    right = service.handle_inbound(
        InboundEnvelope(peer=bob, text="yo", message_id="2", received_at=1.0)
    )
    assert left.accepted and right.accepted
    assert left.owner == "owner-alice"
    assert right.owner == "owner-bob"
    assert left.route is not None and right.route is not None
    assert left.route.session_key != right.route.session_key
    assert "alice" in left.route.session_key
    assert "bob" in right.route.session_key
