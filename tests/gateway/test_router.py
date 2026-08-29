"""Host configuration selects the route; the model does not."""

from __future__ import annotations

from js.gateway.adapter import ChannelPeer
from js.gateway.router import DmScope, GatewayRouter


def test_explicit_peer_binding_wins() -> None:
    router = GatewayRouter()
    peer = ChannelPeer(channel="telegram", peer_id="1")
    router.set_channel_default(
        "telegram",
        owner="local",
        bot_id="default-bot",
        dm_scope=DmScope.MAIN,
    )
    router.bind(peer, owner="alice", bot_id="alice-bot", dm_scope=DmScope.PER_PEER)
    route = router.resolve(peer)
    assert route is not None
    assert route.owner == "alice"
    assert route.bot_id == "alice-bot"
    assert route.session_key == "gateway:telegram:peer:1"


def test_main_scope_shares_one_session() -> None:
    router = GatewayRouter()
    router.set_channel_default(
        "discord",
        owner="local",
        bot_id="house-bot",
        dm_scope="main",
    )
    a = ChannelPeer(channel="discord", peer_id="a")
    b = ChannelPeer(channel="discord", peer_id="b")
    left = router.resolve(a)
    right = router.resolve(b)
    assert left is not None and right is not None
    assert left.session_key == right.session_key
    assert left.session_key == "gateway:discord:main:house-bot"


def test_unknown_channel_has_no_route() -> None:
    router = GatewayRouter()
    assert router.resolve(ChannelPeer(channel="webhook", peer_id="x")) is None
