"""Streaming byte-histogram Shannon entropy detector."""

from __future__ import annotations

from dataclasses import dataclass, field

_BINS = 256
_JUMP = 1.5
_MIN_BYTES = 64


@dataclass
class _Hist:
    counts: list[int] = field(default_factory=lambda: [0] * _BINS)
    total: int = 0
    last_entropy: float = 0.0
    primed: bool = False


@dataclass
class EntropyDetector:
    _sessions: dict[str, _Hist] = field(default_factory=dict)

    def observe(self, session_id: str, payload: str) -> str | None:
        if not payload:
            return None
        hist = self._sessions.setdefault(session_id, _Hist())
        data = payload.encode("utf-8", errors="replace")
        for byte in data:
            hist.counts[byte] += 1
        hist.total += len(data)
        if hist.total < _MIN_BYTES:
            return None
        entropy = _shannon(hist.counts, hist.total)
        jumped = hist.primed and entropy > hist.last_entropy * _JUMP and entropy > 5.0
        hist.last_entropy = entropy
        hist.primed = True
        if jumped:
            return "entropy"
        return None


def _shannon(counts: list[int], total: int) -> float:
    if total <= 0:
        return 0.0
    import math

    entropy = 0.0
    inv = 1.0 / total
    for count in counts:
        if count:
            p = count * inv
            entropy -= p * math.log2(p)
    return entropy
