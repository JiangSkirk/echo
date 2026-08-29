"""K§10.4 measurement harness.  Numbers here are observations, not a pass."""

from __future__ import annotations

import platform
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

_DISCLAIMER = "harness 观察 / untested / 非正式 K§10.4"

# K§10.4 goals. Recording an observation does not mean a target was met.
K104_GOALS: dict[str, str] = {
    "authz_p99_ms": "<= 1ms; untested",
    "cell_cold_start_p99_ms": "<= 300ms; untested",
    "orin_rss_mb": "<= 40MB; untested",
    "disconnect_new_effects_ms": "<= 100ms forbid new side effects; untested",
}


@dataclass(frozen=True, slots=True)
class K104Observation:
    name: str
    value_ms: float
    hardware: str
    os_name: str
    payload_label: str
    disclaimer: str = _DISCLAIMER


def _platform_label() -> tuple[str, str]:
    return platform.machine() or "unknown", f"{platform.system()} {platform.release()}"


def observe_callable_ms(
    name: str,
    fn: Callable[[], Any],
    *,
    payload_label: str,
) -> K104Observation:
    hardware, os_name = _platform_label()
    started = time.perf_counter()
    fn()
    elapsed_ms = (time.perf_counter() - started) * 1000
    return K104Observation(
        name=name,
        value_ms=elapsed_ms,
        hardware=hardware,
        os_name=os_name,
        payload_label=payload_label,
    )


def observation_is_not_a_pass(observation: K104Observation) -> bool:
    return observation.disclaimer == _DISCLAIMER and observation.value_ms >= 0


__all__ = [
    "K104Observation",
    "K104_GOALS",
    "observe_callable_ms",
    "observation_is_not_a_pass",
]
