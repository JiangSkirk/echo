"""CanaryVault: session honeytokens and dual-evidence matching.

Tokens live in orind only. Matching uses stdlib ``re.escape`` alternation
(3–7 patterns — no Aho-Corasick). Placement is handoff_vault + memory;
deep workspace camouflage paths stay off.
"""

from __future__ import annotations

import hashlib
import re
import secrets
from dataclasses import dataclass
from typing import Final

from js.orind.store import OrinStore

KIND_CREDENTIAL: Final[int] = 1
KIND_SEMANTIC: Final[int] = 2
PLACED_HANDOFF: Final[str] = "handoff_vault"
PLACED_MEMORY: Final[str] = "memory"

# Fixed user-visible wording — never name the trigger mechanism.
REFUSAL_TEXT: Final[str] = "This action is not permitted."
FREEZE_TEXT: Final[str] = "This session is paused pending review."

CREDENTIAL_COUNT: Final[int] = 4
SEMANTIC_COUNT: Final[int] = 2


@dataclass(frozen=True, slots=True)
class CanaryHit:
    session_id: str
    token_hash: str
    surface: str
    dual_evidence: bool


class CanaryVault:
    """Generate, persist, and match per-session canaries."""

    def __init__(self, store: OrinStore, *, enabled: bool = True) -> None:
        self._store = store
        self.enabled = enabled
        self._patterns: dict[str, re.Pattern[str]] = {}

    def ensure_session(self, session_id: str, *, now_ms: int) -> list[str]:
        """Create the session set if missing; return plaintext tokens for placement."""

        existing = self._store.canaries_for_session(session_id)
        if existing:
            self._compile(session_id, [token for token, _h, _k, _r in existing if token])
            return [token for token, _h, _k, _r in existing if token]
        tokens: list[str] = []
        for _ in range(CREDENTIAL_COUNT):
            token = f"sk-orin-canary-{secrets.token_hex(20)}"
            tokens.append(token)
            self._persist(session_id, token, KIND_CREDENTIAL, PLACED_HANDOFF, now_ms)
        for index in range(SEMANTIC_COUNT):
            if index == 0:
                token = f"INV-2026-{secrets.randbelow(9_000_000) + 1_000_000}-ORIN"
            else:
                token = f"ORIN-ENT-{secrets.token_hex(6).upper()}"
            tokens.append(token)
            self._persist(session_id, token, KIND_SEMANTIC, PLACED_MEMORY, now_ms)
        self._compile(session_id, tokens)
        return tokens

    def _persist(
        self,
        session_id: str,
        token: str,
        kind: int,
        placed_at: str,
        now_ms: int,
    ) -> None:
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
        self._store.add_canary(
            token_hash=digest,
            session_id=session_id,
            kind=kind,
            placed_at=placed_at,
            created_at=now_ms,
            token=token,
        )

    def _compile(self, session_id: str, tokens: list[str]) -> None:
        if not tokens:
            return
        parts = [re.escape(token) for token in tokens]
        self._patterns[session_id] = re.compile("|".join(parts))

    def match(self, session_id: str, text: str) -> str | None:
        """Return the token_hash of the first match, or None."""

        if not self.enabled or not text:
            return None
        if session_id not in self._patterns:
            rows = self._store.canaries_for_session(session_id)
            self._compile(session_id, [token for token, _h, _k, _r in rows if token])
        pattern = self._patterns.get(session_id)
        if pattern is None:
            return None
        found = pattern.search(text)
        if found is None:
            return None
        return hashlib.sha256(found.group(0).encode("utf-8")).hexdigest()

    def record_read(self, *, session_id: str, text: str, now_ms: int) -> CanaryHit | None:
        token_hash = self.match(session_id, text)
        if token_hash is None:
            return None
        self._store.mark_canary_read(token_hash=token_hash, read_at=now_ms)
        return CanaryHit(
            session_id=session_id,
            token_hash=token_hash,
            surface="read",
            dual_evidence=False,
        )

    def record_egress(
        self,
        *,
        session_id: str,
        text: str,
        surface: str,
        now_ms: int,
    ) -> CanaryHit | None:
        del now_ms
        token_hash = self.match(session_id, text)
        if token_hash is None:
            return None
        rows = self._store.canaries_for_session(session_id)
        read_at = 0
        for _token, stored_hash, _kind, stored_read in rows:
            if stored_hash == token_hash:
                read_at = stored_read
                break
        return CanaryHit(
            session_id=session_id,
            token_hash=token_hash,
            surface=surface,
            dual_evidence=read_at > 0,
        )

    def record_egress_any(self, *, text: str, surface: str) -> CanaryHit | None:
        """Authority-only scan when an effect draft has no model-set session id.

        Plaintext tokens stay inside orind.  The returned object contains only
        the owning session and a digest, so callers cannot leak the trigger.
        """

        if not self.enabled or not text:
            return None
        for session_id, token, token_hash, _kind, read_at in self._store.all_canaries():
            if token and token in text:
                return CanaryHit(
                    session_id=session_id,
                    token_hash=token_hash,
                    surface=surface,
                    dual_evidence=read_at > 0,
                )
        return None


__all__ = [
    "CREDENTIAL_COUNT",
    "FREEZE_TEXT",
    "KIND_CREDENTIAL",
    "KIND_SEMANTIC",
    "REFUSAL_TEXT",
    "SEMANTIC_COUNT",
    "CanaryHit",
    "CanaryVault",
]
