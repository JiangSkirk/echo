"""Pairing is fail-closed: unpaired senders never become a route."""

from __future__ import annotations

from js.gateway.adapter import ChannelPeer
from js.gateway.pairing import PairingStore


def test_unpaired_peer_is_not_allowlisted() -> None:
    store = PairingStore(clock=lambda: 100.0)
    peer = ChannelPeer(channel="telegram", peer_id="99")
    assert store.is_paired(peer) is False
    assert store.owner_of(peer) is None


def test_redeem_pairs_peer_once() -> None:
    now = {"t": 10.0}
    store = PairingStore(ttl_seconds=30, clock=lambda: now["t"])
    code = store.issue_code("owner-a")
    peer = ChannelPeer(channel="telegram", peer_id="42")
    assert store.redeem(code, peer) == "owner-a"
    assert store.is_paired(peer) is True
    assert store.redeem(code, peer) is None


def test_expired_code_is_rejected() -> None:
    now = {"t": 10.0}
    store = PairingStore(ttl_seconds=5, clock=lambda: now["t"])
    code = store.issue_code("owner-a")
    now["t"] = 20.0
    peer = ChannelPeer(channel="webhook", peer_id="hook-1")
    assert store.redeem(code, peer) is None
    assert store.is_paired(peer) is False


def test_discard_logging_is_rate_limited() -> None:
    now = {"t": 1.0}
    store = PairingStore(
        discard_log_min_interval_seconds=5.0,
        clock=lambda: now["t"],
    )
    peer = ChannelPeer(channel="telegram", peer_id="7")
    assert store.record_discard(peer, reason="unpaired") is True
    now["t"] = 3.0
    assert store.record_discard(peer, reason="unpaired") is False
    now["t"] = 7.0
    assert store.record_discard(peer, reason="unpaired") is True
