"""Responder ladder L0–L5.

Stage A implements the orind half of the ladder: persist level, revoke
leases on L3+, emit freeze. Process kill (L4) and policy rollback (L5)
are recorded only. Unfreeze requires an admin master credential — Stage B.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Final

from js.orind.store import OrinStore

LEVEL_OBSERVE: Final[int] = 0
LEVEL_NARROW: Final[int] = 1
LEVEL_SLOW: Final[int] = 2
LEVEL_FREEZE: Final[int] = 3
LEVEL_KILL: Final[int] = 4
LEVEL_QUARANTINE: Final[int] = 5
LEVEL_NAMES: Final[tuple[str, ...]] = (
    "OBSERVE",
    "NARROW",
    "SLOW",
    "FREEZE",
    "KILL",
    "QUARANTINE",
)


class Responder:
    """Monotonic session ladder. ``lock_l0`` is the independent rollback switch."""

    def __init__(
        self,
        store: OrinStore,
        *,
        lock_l0: bool = False,
        freeze_fn: Callable[[str], tuple[str, ...]] | None = None,
    ) -> None:
        self._store = store
        self.lock_l0 = lock_l0
        self._freeze_fn = freeze_fn

    def level_of(self, session_id: str) -> int:
        level, _since, _evidence = self._store.responder_level(session_id)
        return level

    def escalate(
        self,
        *,
        session_id: str,
        level: int,
        now_ms: int,
        evidence: str,
    ) -> int:
        """Raise the session to at least ``level``. Returns the resulting level."""

        if self.lock_l0:
            return LEVEL_OBSERVE
        target = max(0, min(int(level), LEVEL_QUARANTINE))
        current, _since, _evidence = self._store.responder_level(session_id)
        if target <= current:
            return current
        self._store.set_responder_level(
            session_id=session_id,
            level=target,
            since=now_ms,
            evidence=evidence,
        )
        if target >= LEVEL_FREEZE and self._freeze_fn is not None:
            self._freeze_fn(session_id)
        return target

    def unfreeze(self, session_id: str, *, now_ms: int, evidence: str) -> int:
        """R3 de-escalation (K§16.3): requires a verified admin intent.

        Callers MUST have verified an admin IntentEnvelope before invoking —
        the daemon's ``intent op=admin_unfreeze`` path is the only sanctioned
        entry point and Echo cannot mint that signature. Unfreezing clears
        the ladder level; leases already revoked by the freeze stay revoked.
        """

        current, _since, _old_evidence = self._store.responder_level(session_id)
        self._store.set_responder_level(
            session_id=session_id,
            level=LEVEL_OBSERVE,
            since=now_ms,
            evidence=f"admin_unfreeze:{evidence}",
        )
        _ = current
        return LEVEL_OBSERVE


__all__ = [
    "LEVEL_FREEZE",
    "LEVEL_KILL",
    "LEVEL_NARROW",
    "LEVEL_NAMES",
    "LEVEL_OBSERVE",
    "LEVEL_QUARANTINE",
    "LEVEL_SLOW",
    "Responder",
]
