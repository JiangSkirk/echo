"""One-time pairing codes and a fail-closed sender allowlist."""

from __future__ import annotations

import secrets
from collections.abc import Callable
from dataclasses import dataclass

from js.gateway.adapter import ChannelPeer
from js.utils.log import get_logger

logger = get_logger("js.gateway.pairing")

Clock = Callable[[], float]


@dataclass(frozen=True, slots=True)
class PairingCode:
    code: str
    owner: str
    expires_at: float


@dataclass(frozen=True, slots=True)
class DiscardRecord:
    peer_key: str
    count: int
    last_logged_at: float


class PairingStore:
    """In-memory pairing desk. Unpaired peers never become a route."""

    def __init__(
        self,
        *,
        ttl_seconds: int = 600,
        discard_log_min_interval_seconds: float = 5.0,
        max_attempts_per_peer: int = 8,
        clock: Clock | None = None,
    ) -> None:
        if ttl_seconds < 1:
            raise ValueError("ttl_seconds must be >= 1")
        self._ttl = ttl_seconds
        self._discard_interval = discard_log_min_interval_seconds
        self._max_attempts = max_attempts_per_peer
        self._clock: Clock = clock or (lambda: __import__("time").time())
        self._codes: dict[str, PairingCode] = {}
        self._allowlist: dict[str, str] = {}
        self._discards: dict[str, DiscardRecord] = {}

    def issue_code(self, owner: str) -> str:
        owner_key = owner.strip()
        if not owner_key:
            raise ValueError("owner is required")
        code = secrets.token_hex(4)
        now = self._clock()
        self._codes[code] = PairingCode(
            code=code,
            owner=owner_key,
            expires_at=now + self._ttl,
        )
        return code

    def redeem(self, code: str, peer: ChannelPeer) -> str | None:
        record = self._codes.pop(code.strip().lower(), None)
        if record is None:
            record = self._codes.pop(code.strip(), None)
        if record is None:
            return None
        if self._clock() > record.expires_at:
            return None
        self._allowlist[peer.key()] = record.owner
        return record.owner

    def allow(self, peer: ChannelPeer, owner: str) -> None:
        owner_key = owner.strip()
        if not owner_key:
            raise ValueError("owner is required")
        self._allowlist[peer.key()] = owner_key

    def revoke(self, peer: ChannelPeer) -> None:
        self._allowlist.pop(peer.key(), None)

    def owner_of(self, peer: ChannelPeer) -> str | None:
        return self._allowlist.get(peer.key())

    def is_paired(self, peer: ChannelPeer) -> bool:
        return peer.key() in self._allowlist

    def record_discard(self, peer: ChannelPeer, *, reason: str) -> bool:
        """Record an unpaired drop. Returns True when a log line should emit."""

        now = self._clock()
        key = peer.key()
        previous = self._discards.get(key)
        count = 1 if previous is None else previous.count + 1
        last_logged = 0.0 if previous is None else previous.last_logged_at
        should_log = previous is None or (now - last_logged) >= self._discard_interval
        if count > self._max_attempts:
            should_log = should_log and (now - last_logged) >= self._discard_interval
        self._discards[key] = DiscardRecord(
            peer_key=key,
            count=count,
            last_logged_at=now if should_log else last_logged,
        )
        if should_log:
            logger.warning(
                "gateway discarded unpaired peer channel=%s peer=%s reason=%s count=%s",
                peer.channel,
                peer.peer_id,
                reason,
                count,
            )
        return should_log
