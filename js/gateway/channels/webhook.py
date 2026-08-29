"""HMAC-signed webhook channel. Replay and unsigned bodies are rejected."""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from collections import OrderedDict
from typing import Any

from js.gateway.adapter import ChannelPeer, InboundEnvelope
from js.utils.log import get_logger

logger = get_logger("js.gateway.webhook")

SIGNATURE_HEADER = "x-js-signature"
TIMESTAMP_HEADER = "x-js-timestamp"


class WebhookAuthError(ValueError):
    """Raised when a webhook request fails authentication or replay checks."""


class WebhookReplayCache:
    """Bounded cache of recently accepted signatures."""

    def __init__(self, *, max_entries: int = 4_096) -> None:
        self._seen: OrderedDict[str, None] = OrderedDict()
        self._max_entries = max_entries

    def accept(self, key: str) -> bool:
        if key in self._seen:
            return False
        self._seen[key] = None
        self._seen.move_to_end(key)
        while len(self._seen) > self._max_entries:
            self._seen.popitem(last=False)
        return True


def webhook_signature(secret: str, timestamp: str, body: bytes) -> str:
    payload = timestamp.encode("ascii") + b"." + body
    return hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()


def verify_webhook(
    *,
    secret: str,
    timestamp: str,
    signature: str,
    body: bytes,
    now: float | None = None,
    max_skew_seconds: int = 300,
    replay: WebhookReplayCache | None = None,
) -> None:
    if not secret:
        raise WebhookAuthError("webhook secret is not configured")
    if not timestamp.isdigit():
        raise WebhookAuthError("timestamp must be unix seconds")
    clock = time.time() if now is None else now
    skew = abs(clock - int(timestamp))
    if skew > max_skew_seconds:
        raise WebhookAuthError("timestamp outside replay window")
    expected = webhook_signature(secret, timestamp, body)
    if not hmac.compare_digest(expected, signature.strip().lower()):
        raise WebhookAuthError("invalid webhook signature")
    cache = replay or WebhookReplayCache()
    replay_key = f"{timestamp}:{expected}"
    if not cache.accept(replay_key):
        raise WebhookAuthError("replayed webhook")


def parse_webhook_body(body: bytes, *, received_at: float) -> InboundEnvelope:
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WebhookAuthError("webhook body must be JSON") from exc
    if not isinstance(payload, dict):
        raise WebhookAuthError("webhook body must be an object")
    sender = str(payload.get("sender") or "").strip()
    text = str(payload.get("text") or "")
    message_id = str(payload.get("message_id") or f"webhook-{int(received_at)}")
    if not sender:
        raise WebhookAuthError("sender is required")
    return InboundEnvelope(
        peer=ChannelPeer(channel="webhook", peer_id=sender),
        text=text,
        message_id=message_id,
        received_at=received_at,
    )


class WebhookChannelAdapter:
    """HTTP inbound adapter. Outbound replies are recorded for the caller."""

    name = "webhook"

    def __init__(self) -> None:
        self.outbound: list[tuple[str, str]] = []

    async def start(self) -> None:
        return None

    async def stop(self) -> None:
        return None

    async def send(self, peer: ChannelPeer, text: str) -> None:
        self.outbound.append((peer.key(), text))


def header_map(headers: Any) -> dict[str, str]:
    if hasattr(headers, "items"):
        return {str(key).lower(): str(value) for key, value in headers.items()}
    return {}
