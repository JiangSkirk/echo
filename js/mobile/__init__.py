"""Mobile gateway: iPhone pairing protocol and mobile client contracts.

R5 scope: local network pairing (Bonjour/QR/short code), Personal text/stream/cancel,
view Work task status and authorized artifacts. No API Key storage on phone,
no shell/Python/Fleet/file/network tools on phone.
Mobile Gateway is independent from internal FastAPI.
"""

from __future__ import annotations

from js.mobile.gateway import MobileGateway, PairingSession, PairingStatus
from js.mobile.protocol import (
    MobileMessage,
    MobileMessageKind,
    MobileRequest,
    MobileResponse,
)

__all__ = [
    "MobileGateway",
    "MobileMessage",
    "MobileMessageKind",
    "MobileRequest",
    "MobileResponse",
    "PairingSession",
    "PairingStatus",
]
