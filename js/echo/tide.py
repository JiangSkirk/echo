"""Echo 2.0 TideController protocol.

TideController governs admission, back-pressure and budget shaping across
pulses. This module defines the protocol surface; policy lives in the concrete
controller implementation.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from js.echo.types import Budget


@runtime_checkable
class TideController(Protocol):
    """Admission and budget shaping authority."""

    def admit(self, now: int, channel: str) -> bool:
        """Return True iff a request from ``channel`` may enter this tick."""
        ...

    def budget_for(self, channel: str) -> Budget:
        """Return the current per-unit budget for ``channel``."""
        ...

    def observe(self, now: int, channel: str, latency_ms: int) -> None:
        """Feed observed latency back into the controller."""
        ...


__all__ = ["TideController"]
