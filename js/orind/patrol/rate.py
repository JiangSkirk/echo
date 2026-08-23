"""Per-session call-rate EWMA detector."""

from __future__ import annotations

import math
from dataclasses import dataclass, field

_ALPHA = 0.3
_SIGMA_THRESHOLD = 3.0
_MIN_SAMPLES = 8


@dataclass
class _Window:
    last_ms: int = 0
    ewma: float = 0.0
    evar: float = 0.0
    samples: int = 0
    failures: int = 0


@dataclass
class RateDetector:
    _sessions: dict[str, _Window] = field(default_factory=dict)

    def observe(self, session_id: str, *, now_ms: int, failed: bool) -> str | None:
        window = self._sessions.setdefault(session_id, _Window())
        if window.last_ms <= 0:
            window.last_ms = now_ms
            window.samples = 1
            if failed:
                window.failures += 1
            return None
        interval = max(float(now_ms - window.last_ms), 1.0)
        rate = 1000.0 / interval
        if window.samples == 1:
            window.ewma = rate
            window.evar = 0.0
        else:
            delta = rate - window.ewma
            window.ewma += _ALPHA * delta
            window.evar = (1.0 - _ALPHA) * (window.evar + _ALPHA * delta * delta)
        window.last_ms = now_ms
        window.samples += 1
        if failed:
            window.failures += 1
        if window.samples < _MIN_SAMPLES:
            return None
        sigma = math.sqrt(max(window.evar, 1e-9))
        if rate > window.ewma + _SIGMA_THRESHOLD * sigma:
            return "rate"
        return None
