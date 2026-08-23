"""Patrol detectors: rate, egress cardinality, payload entropy.

Detectors only emit tighten advice. They never allow a previously denied
action and never skip another gate. The first 20 observations per session
are warmup (observe only).
"""

from __future__ import annotations

from js.orind.patrol.egress import EgressDetector
from js.orind.patrol.entropy import EntropyDetector
from js.orind.patrol.rate import RateDetector

WARMUP_EVENTS = 20


class PatrolBoard:
    """Fan-in for the three Stage A detectors."""

    def __init__(self, *, record_only: bool = False) -> None:
        self.record_only = record_only
        self.rate = RateDetector()
        self.egress = EgressDetector()
        self.entropy = EntropyDetector()
        self._counts: dict[str, int] = {}

    def observe(
        self,
        *,
        session_id: str,
        now_ms: int,
        failed: bool = False,
        host: str = "",
        payload: str = "",
    ) -> list[str]:
        count = self._counts.get(session_id, 0) + 1
        self._counts[session_id] = count
        advice: list[str] = []
        rate_hit = self.rate.observe(session_id, now_ms=now_ms, failed=failed)
        egress_hit = self.egress.observe(session_id, host) if host else None
        entropy_hit = self.entropy.observe(session_id, payload) if payload else None
        if count <= WARMUP_EVENTS or self.record_only:
            return []
        for item in (rate_hit, egress_hit, entropy_hit):
            if item:
                advice.append(item)
        return advice


__all__ = ["PatrolBoard", "WARMUP_EVENTS"]
