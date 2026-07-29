"""Unforgeable, single-use model-call permits for the Echo runtime boundary.

Every real provider call made through :class:`js.models.router.ModelRouter`
must carry a fresh :class:`ModelPermit` issued by a :class:`ModelPermitIssuer`
owned by the Echo turn runtime.  The permit is bound to the concrete routing
decision (provider + model), the exact messages hash, the tools schema hash,
and the product/owner/session/run identity, and it can be consumed exactly
once.  There is intentionally **no** public way to (re)install authorization
callbacks on the router: identity comes from this cryptographic capability,
not from a Python function object that any caller could replace.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from dataclasses import dataclass, replace
from typing import Any

from js.models.providers import ChatMessage


class ModelPermitError(PermissionError):
    """Raised when a model-call permit is missing, forged, stale, or spent."""


def _canonical_json(payload: Any) -> str:
    return json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def hash_messages(messages: list[ChatMessage]) -> str:
    """Deterministic SHA-256 over the exact messages that will be sent."""
    canonical = [
        {
            "role": message.role,
            "content": message.content,
            "tool_calls": message.tool_calls,
            "tool_call_id": message.tool_call_id,
            "name": message.name,
            "reasoning_content": message.reasoning_content,
        }
        for message in messages
    ]
    return hashlib.sha256(_canonical_json(canonical).encode("utf-8")).hexdigest()


def hash_tools_schema(tools: list[dict[str, Any]] | None) -> str:
    """Deterministic SHA-256 over the exact tools schema (empty when absent)."""
    return hashlib.sha256(_canonical_json(tools or []).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ModelPermit:
    """A single-use, HMAC-signed authorization for one provider attempt."""

    provider_name: str
    model: str
    messages_digest: str
    tools_digest: str
    owner_key_hash: str
    session_id: str
    run_id: str
    nonce: str
    expires_at: float
    mac: str

    def _payload(self) -> str:
        return _canonical_json(
            {
                "provider_name": self.provider_name,
                "model": self.model,
                "messages_digest": self.messages_digest,
                "tools_digest": self.tools_digest,
                "owner_key_hash": self.owner_key_hash,
                "session_id": self.session_id,
                "run_id": self.run_id,
                "nonce": self.nonce,
                "expires_at": self.expires_at,
            }
        )


class ModelPermitIssuer:
    """Issues and verifies model-call permits.

    The instance holds a per-runtime random HMAC key.  The Echo turn runtime
    owns the issuer; the router only receives it as a *verifier* at
    construction time.  Permits are single-use: ``verify_and_consume``
    permanently spends the nonce, so retries, fallbacks and stream reconnects
    each require a freshly issued permit.
    """

    # Soft default for long-running daemons: enough for concurrent turns while
    # still bounding memory.  Unexpired nonces are never evicted to make room.
    _DEFAULT_MAX_SPENT_NONCES = 10_000

    def __init__(
        self,
        *,
        key: bytes | None = None,
        ttl_seconds: float = 60.0,
        max_spent_nonces: int | None = None,
    ) -> None:
        if ttl_seconds <= 0:
            raise ValueError("permit ttl_seconds must be positive")
        limit = (
            self._DEFAULT_MAX_SPENT_NONCES if max_spent_nonces is None else int(max_spent_nonces)
        )
        if limit < 1:
            raise ValueError("max_spent_nonces must be positive")
        self._key = key if key is not None else os.urandom(32)
        if len(self._key) < 32:
            raise ValueError("permit key must be at least 32 bytes")
        self._ttl_seconds = float(ttl_seconds)
        self._max_spent_nonces = limit
        # nonce -> expires_at of the permit that spent it
        self._spent_nonces: dict[str, float] = {}
        self._lock = threading.Lock()

    def spent_nonce_count(self) -> int:
        """Number of currently retained spent nonces (for tests / metrics)."""
        with self._lock:
            return len(self._spent_nonces)

    def _purge_expired_unlocked(self, *, now: float) -> None:
        expired = [nonce for nonce, expires_at in self._spent_nonces.items() if expires_at <= now]
        for nonce in expired:
            del self._spent_nonces[nonce]

    def issue(
        self,
        *,
        provider_name: str,
        model: str,
        messages: list[ChatMessage],
        tools: list[dict[str, Any]] | None,
        owner_key_hash: str,
        session_id: str,
        run_id: str,
    ) -> ModelPermit:
        permit = ModelPermit(
            provider_name=provider_name,
            model=model,
            messages_digest=hash_messages(messages),
            tools_digest=hash_tools_schema(tools),
            owner_key_hash=owner_key_hash,
            session_id=session_id,
            run_id=run_id,
            nonce=secrets.token_hex(16),
            expires_at=time.time() + self._ttl_seconds,
            mac="",
        )
        return replace(permit, mac=self._mac(permit))

    def _mac(self, permit: ModelPermit) -> str:
        return hmac.new(self._key, permit._payload().encode("utf-8"), hashlib.sha256).hexdigest()

    def verify_and_consume(
        self,
        permit: ModelPermit | Any,
        *,
        provider_name: str,
        model: str,
        messages: list[ChatMessage],
        tools: list[dict[str, Any]] | None,
    ) -> None:
        """Verify a permit and permanently spend its nonce (fail-closed)."""
        if not isinstance(permit, ModelPermit):
            raise ModelPermitError("model permit missing or not a ModelPermit")
        expected_mac = self._mac(permit)
        if not hmac.compare_digest(expected_mac, permit.mac):
            raise ModelPermitError("model permit MAC mismatch (forged or wrong issuer)")
        # Reject expiry before taking the anti-replay lock...
        if time.time() >= permit.expires_at:
            raise ModelPermitError("model permit expired")
        if permit.provider_name != provider_name or permit.model != model:
            raise ModelPermitError("model permit does not match the routing decision")
        if not hmac.compare_digest(permit.messages_digest, hash_messages(messages)):
            raise ModelPermitError("model permit does not match the request messages")
        if not hmac.compare_digest(permit.tools_digest, hash_tools_schema(tools)):
            raise ModelPermitError("model permit does not match the request tools schema")
        with self._lock:
            now = time.time()
            # Recheck expiry under the lock so a permit that expired while
            # waiting cannot still be accepted.
            if now >= permit.expires_at:
                raise ModelPermitError("model permit expired")
            self._purge_expired_unlocked(now=now)
            existing_expiry = self._spent_nonces.get(permit.nonce)
            if existing_expiry is not None and existing_expiry > now:
                raise ModelPermitError("model permit replayed (nonce already consumed)")
            if len(self._spent_nonces) >= self._max_spent_nonces:
                # Never evict an unexpired nonce to free capacity — fail closed
                # so the provider call cannot proceed without anti-replay state.
                raise ModelPermitError(
                    "model permit spent nonce capacity exhausted; refuse provider call"
                )
            self._spent_nonces[permit.nonce] = permit.expires_at
