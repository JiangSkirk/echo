"""Echo 2.0 TimingWheel protocol.

TimingWheel hands out deterministic timer slots used by ``Resonate`` actions.
Wall-clock time is always passed in by the caller; the wheel never reads it.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class TimingWheel(Protocol):
    """Deterministic timer scheduler."""

    def schedule(self, fire_at: int, correlation_id: str) -> None:
        """Register a future timer keyed by ``correlation_id``."""
        ...

    def due(self, now: int) -> list[str]:
        """Return correlation ids whose timers have fired by ``now``."""
        ...

    def cancel(self, correlation_id: str) -> bool:
        """Cancel a pending timer; returns True iff one was removed."""
        ...


__all__ = ["TimingWheel"]
