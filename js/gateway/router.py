"""Deterministic peer → bot routing. The model never selects the route."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from js.gateway.adapter import ChannelPeer


class DmScope(StrEnum):
    MAIN = "main"
    PER_PEER = "per-peer"


@dataclass(frozen=True, slots=True)
class RouteBinding:
    owner: str
    bot_id: str
    dm_scope: DmScope
    session_key: str


class GatewayRouter:
    """Host-owned binding table. Missing bindings do not invent a destination."""

    def __init__(self) -> None:
        self._peer_bindings: dict[str, RouteBinding] = {}
        self._channel_defaults: dict[str, RouteBinding] = {}

    def bind(
        self,
        peer: ChannelPeer,
        *,
        owner: str,
        bot_id: str,
        dm_scope: DmScope | str = DmScope.PER_PEER,
    ) -> RouteBinding:
        scope = DmScope(dm_scope)
        binding = RouteBinding(
            owner=owner,
            bot_id=bot_id,
            dm_scope=scope,
            session_key=_session_key(peer, scope, bot_id),
        )
        self._peer_bindings[peer.key()] = binding
        return binding

    def set_channel_default(
        self,
        channel: str,
        *,
        owner: str,
        bot_id: str,
        dm_scope: DmScope | str = DmScope.PER_PEER,
    ) -> RouteBinding:
        scope = DmScope(dm_scope)
        placeholder = ChannelPeer(channel=channel, peer_id="*")
        binding = RouteBinding(
            owner=owner,
            bot_id=bot_id,
            dm_scope=scope,
            session_key=_session_key(placeholder, scope, bot_id),
        )
        self._channel_defaults[channel] = binding
        return binding

    def resolve(self, peer: ChannelPeer) -> RouteBinding | None:
        explicit = self._peer_bindings.get(peer.key())
        if explicit is not None:
            return explicit
        default = self._channel_defaults.get(peer.channel)
        if default is None:
            return None
        return RouteBinding(
            owner=default.owner,
            bot_id=default.bot_id,
            dm_scope=default.dm_scope,
            session_key=_session_key(peer, default.dm_scope, default.bot_id),
        )


def _session_key(peer: ChannelPeer, scope: DmScope, bot_id: str) -> str:
    if scope is DmScope.MAIN:
        return f"gateway:{peer.channel}:main:{bot_id}"
    return f"gateway:{peer.channel}:peer:{peer.peer_id}"
