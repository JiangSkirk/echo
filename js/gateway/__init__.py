"""Messaging gateway surface. Echo remains the only turn runtime.

Importing this package must not start adapters or open sockets.
"""

from __future__ import annotations

from js.gateway.adapter import ChannelAdapter, ChannelPeer, InboundEnvelope
from js.gateway.pairing import PairingStore
from js.gateway.router import DmScope, GatewayRouter, RouteBinding
from js.gateway.service import DispatchDecision, GatewayService

__all__ = [
    "ChannelAdapter",
    "ChannelPeer",
    "DispatchDecision",
    "DmScope",
    "GatewayRouter",
    "GatewayService",
    "InboundEnvelope",
    "PairingStore",
    "RouteBinding",
]
