"""Mobile protocol contracts: messages, requests, responses.

Pure data contracts. No network, no real credentials.
Phone never stores API Key, never executes tools.
"""

from __future__ import annotations

import hashlib
import re
import secrets
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

_PAIRING_CODE_RE = re.compile(r"^[0-9]{6}$")
_DEVICE_ID_RE = re.compile(r"^[a-f0-9]{64}$")
_MAX_TEXT_LENGTH = 10_000


class MobileMessageKind(StrEnum):
    """Kind of mobile message."""

    TEXT = "text"
    STREAM_CHUNK = "stream_chunk"
    STREAM_END = "stream_end"
    CANCEL = "cancel"
    STATUS_UPDATE = "status_update"
    ARTIFACT_NOTIFICATION = "artifact_notification"
    ERROR = "error"


@dataclass(frozen=True)
class MobileMessage:
    """Message between Mac and iPhone."""

    message_id: str
    kind: MobileMessageKind
    payload: dict[str, Any] = field(default_factory=dict)
    timestamp: float = 0.0

    def as_dict(self) -> dict[str, Any]:
        return {
            "message_id": self.message_id,
            "kind": str(self.kind),
            "payload": dict(self.payload),
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> MobileMessage:
        if not isinstance(data, dict):
            raise ValueError("message must be dict")
        kind = MobileMessageKind(data.get("kind", ""))
        msg_id = str(data.get("message_id", ""))
        if not msg_id:
            raise ValueError("message_id required")
        payload = data.get("payload", {})
        if not isinstance(payload, dict):
            raise ValueError("payload must be dict")
        if kind == MobileMessageKind.TEXT:
            text = payload.get("text", "")
            if not isinstance(text, str) or len(text) > _MAX_TEXT_LENGTH:
                raise ValueError("text too long or invalid")
        return cls(
            message_id=msg_id,
            kind=kind,
            payload=payload,
            timestamp=float(data.get("timestamp", 0.0)),
        )


@dataclass(frozen=True)
class MobileRequest:
    """Request from iPhone to Mac."""

    request_id: str
    action: str
    params: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "action": self.action,
            "params": dict(self.params),
        }


@dataclass(frozen=True)
class MobileResponse:
    """Response from Mac to iPhone."""

    request_id: str
    success: bool
    data: dict[str, Any] = field(default_factory=dict)
    error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "success": self.success,
            "data": dict(self.data),
            "error": self.error,
        }


def generate_pairing_code() -> str:
    """Generate a 6-digit pairing code."""
    return f"{secrets.randbelow(1000000):06d}"


def generate_device_id() -> str:
    """Generate a 64-hex device ID."""
    return secrets.token_hex(32)


def verify_pairing_code(code: str) -> bool:
    """Verify a pairing code format."""
    return bool(_PAIRING_CODE_RE.fullmatch(code))


def hash_device_fingerprint(device_id: str, salt: str) -> str:
    """Hash a device fingerprint with server salt."""
    return hashlib.sha256(f"mobile-device:{device_id}:{salt}".encode()).hexdigest()
