"""Mobile gateway: pairing lifecycle and session management.

Pairing flow:
1. Mac generates pairing code + QR
2. iPhone scans QR, sends pairing request with code + device fingerprint
3. Mac confirms pairing, creates MobileSession
4. Session allows Personal text/stream/cancel, Work status/artifact view
5. Phone never stores API Key; session token is opaque and revocable

No real network, no Bonjour daemon, no real iPhone in R5 first pass.
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from js.mobile.protocol import (
    generate_device_id,
    generate_pairing_code,
    hash_device_fingerprint,
    verify_pairing_code,
)

_PAIRING_TTL_SECONDS = 300.0
_SESSION_TTL_SECONDS = 86400.0
_MAX_SESSIONS = 4


class PairingStatus(StrEnum):
    PENDING = "pending"
    CONFIRMED = "confirmed"
    EXPIRED = "expired"
    REVOKED = "revoked"


@dataclass
class PairingSession:
    """One pairing attempt."""

    code: str
    device_id: str
    device_name: str
    created_at: float
    status: PairingStatus = PairingStatus.PENDING
    session_token: str | None = None
    owner_hash: str | None = None
    expires_at: float = 0.0

    def is_expired(self, now: float) -> bool:
        return now > self.expires_at or self.status == PairingStatus.EXPIRED

    def as_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "device_id": self.device_id,
            "device_name": self.device_name,
            "status": str(self.status),
            "created_at": self.created_at,
            "expires_at": self.expires_at,
        }


@dataclass
class MobileSession:
    """Active mobile session after pairing."""

    session_token: str
    device_id: str
    device_name: str
    owner_hash: str
    created_at: float
    expires_at: float
    allowed_actions: tuple[str, ...] = (
        "personal_chat",
        "personal_stream",
        "personal_cancel",
        "work_status",
        "work_artifacts",
    )

    def is_expired(self, now: float) -> bool:
        return now > self.expires_at

    def allows(self, action: str) -> bool:
        return action in self.allowed_actions

    def as_safe_dict(self) -> dict[str, Any]:
        return {
            "device_name": self.device_name,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "allowed_actions": list(self.allowed_actions),
        }


class MobileGateway:
    """Manages mobile pairing and sessions. Independent from FastAPI.

    Security rules:
    - No API Key stored on phone
    - No shell/Python/Fleet/file/network tools on phone
    - Max 4 concurrent sessions
    - Session token is opaque, revocable, hash-bound
    """

    def __init__(self, *, salt: str | None = None) -> None:
        self._salt = salt or secrets.token_hex(16)
        self._pairings: dict[str, PairingSession] = {}
        self._sessions: dict[str, MobileSession] = {}
        self._device_index: dict[str, str] = {}

    def create_pairing(self, *, device_name: str = "iPhone") -> PairingSession:
        """Create a new pairing session with a 6-digit code."""
        code = generate_pairing_code()
        device_id = generate_device_id()
        now = time.time()
        session = PairingSession(
            code=code,
            device_id=device_id,
            device_name=device_name,
            created_at=now,
            expires_at=now + _PAIRING_TTL_SECONDS,
        )
        self._pairings[code] = session
        return session

    def confirm_pairing(
        self,
        code: str,
        *,
        device_fingerprint: str,
        owner_hash: str,
    ) -> PairingSession:
        """Confirm a pairing and create a mobile session."""
        if not verify_pairing_code(code):
            raise ValueError("invalid pairing code format")
        session = self._pairings.get(code)
        if session is None:
            raise ValueError("pairing code not found")
        now = time.time()
        if session.is_expired(now):
            session.status = PairingStatus.EXPIRED
            raise ValueError("pairing code expired")
        if session.status != PairingStatus.PENDING:
            raise ValueError(f"pairing already {session.status}")
        if len(self._sessions) >= _MAX_SESSIONS:
            raise RuntimeError("max concurrent mobile sessions reached")
        expected_fp = hash_device_fingerprint(session.device_id, self._salt)
        if device_fingerprint != expected_fp:
            raise ValueError("device fingerprint mismatch")
        token = secrets.token_urlsafe(32)
        mobile_session = MobileSession(
            session_token=token,
            device_id=session.device_id,
            device_name=session.device_name,
            owner_hash=owner_hash,
            created_at=now,
            expires_at=now + _SESSION_TTL_SECONDS,
        )
        self._sessions[token] = mobile_session
        self._device_index[session.device_id] = token
        session.status = PairingStatus.CONFIRMED
        session.session_token = token
        session.owner_hash = owner_hash
        return session

    def verify_session(self, token: str) -> MobileSession:
        """Verify a session token. Raises if invalid/expired."""
        session = self._sessions.get(token)
        if session is None:
            raise ValueError("invalid session token")
        now = time.time()
        if session.is_expired(now):
            del self._sessions[token]
            self._device_index.pop(session.device_id, None)
            raise ValueError("session expired")
        return session

    def revoke_session(self, token: str) -> bool:
        """Revoke a mobile session."""
        session = self._sessions.pop(token, None)
        if session is not None:
            self._device_index.pop(session.device_id, None)
            return True
        return False

    def revoke_device(self, device_id: str) -> bool:
        """Revoke all sessions for a device."""
        token = self._device_index.pop(device_id, None)
        if token is not None:
            self._sessions.pop(token, None)
            return True
        return False

    def list_sessions(self) -> list[dict[str, Any]]:
        """List active sessions (safe dict, no tokens)."""
        return [s.as_safe_dict() for s in self._sessions.values()]

    def cleanup_expired(self, now: float | None = None) -> int:
        """Remove expired pairings and sessions. Returns count removed."""
        if now is None:
            now = time.time()
        removed = 0
        expired_codes = [
            code for code, s in self._pairings.items() if s.is_expired(now)
        ]
        for code in expired_codes:
            del self._pairings[code]
            removed += 1
        expired_tokens = [
            token for token, s in self._sessions.items() if s.is_expired(now)
        ]
        for token in expired_tokens:
            session = self._sessions.pop(token)
            self._device_index.pop(session.device_id, None)
            removed += 1
        return removed

    @property
    def active_session_count(self) -> int:
        return len(self._sessions)
