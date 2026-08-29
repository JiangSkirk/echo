"""Gateway pairing desk: clock rollback, process death, and unpaired discard."""

from __future__ import annotations

from pathlib import Path

from js.config import GatewayConfig, JSSettings
from js.gateway.adapter import ChannelPeer, InboundEnvelope
from js.gateway.pairing import PairingStore
from js.gateway.router import GatewayRouter
from js.gateway.service import GatewayService


def test_expired_code_stays_dead_after_clock_rollback() -> None:
    clock = {"now": 1_000.0}
    store = PairingStore(ttl_seconds=10, clock=lambda: clock["now"])
    peer = ChannelPeer(channel="telegram", peer_id="u-1")
    code = store.issue_code("owner-a")
    clock["now"] = 1_020.0
    assert store.redeem(code, peer) is None
    clock["now"] = 1_001.0
    assert store.redeem(code, peer) is None
    assert not store.is_paired(peer)


def test_new_process_does_not_inherit_in_memory_allowlist(tmp_path: Path) -> None:
    peer = ChannelPeer(channel="discord", peer_id="u-2")
    live = PairingStore()
    live.allow(peer, "owner-a")
    assert live.is_paired(peer)
    revived = PairingStore()
    assert not revived.is_paired(peer)
    settings = JSSettings(
        workspace=tmp_path / "workspace",
        state_dir=tmp_path / "state",
        gateway=GatewayConfig(enabled=True),
    )
    service = GatewayService(settings, pairing=revived, router=GatewayRouter())
    decision = service.handle_inbound(
        InboundEnvelope(peer=peer, text="hi", received_at=1.0, message_id="m1")
    )
    assert decision.accepted is False
    assert decision.reason == "unpaired"


def test_unpaired_sender_is_discarded_even_after_flood() -> None:
    store = PairingStore(discard_log_min_interval_seconds=0.0, max_attempts_per_peer=2)
    peer = ChannelPeer(channel="webhook", peer_id="flood")
    logged = [store.record_discard(peer, reason="unpaired") for _ in range(5)]
    assert any(logged)
    assert not store.is_paired(peer)
