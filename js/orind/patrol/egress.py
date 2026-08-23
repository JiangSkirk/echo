"""Host-cardinality detector using a stdlib HyperLogLog approximation."""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass, field

_REGISTERS = 64
_B = 6  # log2(64)
_THRESHOLD = 12.0


@dataclass
class EgressDetector:
    _registers: dict[str, list[int]] = field(default_factory=dict)

    def observe(self, session_id: str, host: str) -> str | None:
        if not host:
            return None
        regs = self._registers.setdefault(session_id, [0] * _REGISTERS)
        digest = hashlib.sha256(host.encode("utf-8")).digest()
        hashed = int.from_bytes(digest[:4], "big")
        index = hashed & (_REGISTERS - 1)
        w = hashed >> _B
        rank = 1
        probe = w
        while probe & 1 == 0 and rank < 32:
            probe >>= 1
            rank += 1
        if w == 0:
            rank = 32 - _B
        if rank > regs[index]:
            regs[index] = rank
        estimate = _estimate(regs)
        if estimate >= _THRESHOLD:
            return "egress_diversity"
        return None


def _estimate(registers: list[int]) -> float:
    harmonic = sum(2.0 ** (-max(reg, 0)) for reg in registers)
    if harmonic <= 0:
        return 0.0
    alpha = 0.7213 / (1 + 1.079 / _REGISTERS)
    raw = alpha * (_REGISTERS**2) / harmonic
    zeros = registers.count(0)
    if raw <= 2.5 * _REGISTERS and zeros:
        return float(_REGISTERS * math.log(_REGISTERS / zeros))
    return float(raw)
