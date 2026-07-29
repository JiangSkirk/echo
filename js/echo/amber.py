"""Echo 2.0 AmberTree protocol aligned with Echo spec §4 / §7.

AmberTree is the kernel's structured working memory across pulses. This module
defines the §7 interface (``root_hash`` + five methods) and the smallest
companion types it returns or accepts:

- ``NodeStatus`` — the §4 ``AmberNode.status`` enum.
- ``ReadyIndex`` — what ``ready_index()`` returns.
- ``ContextView`` — what ``context_view(path)`` returns.
- ``Delta`` — what ``delta_since_last()`` returns.

Companion types live in this module on purpose: they only make sense in the
AmberTree context, and pinning them here keeps :mod:`js.echo.types`
"generic kernel value types" — no back-import from amber.py into types.py.

All shapes are Protocol- or frozen-dataclass-level only; concrete behavior lives
in the Echo implementation modules.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, runtime_checkable


# ---------------------------------------------------------------------------
# Companion enum / data carriers
# ---------------------------------------------------------------------------
class NodeStatus(StrEnum):
    """Status of an ``AmberNode`` as defined in Echo spec §4."""

    PENDING = "pending"
    READY = "ready"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"


@runtime_checkable
class ReadyIndex(Protocol):
    """Ordered view over nodes whose status is ``READY``."""

    def topk(self, n: int) -> list[str]:
        """Return up to ``n`` ready paths in scheduling order."""
        ...


@runtime_checkable
class ContextView(Protocol):
    """A digest-able view of the context relevant to a single path."""

    @property
    def digest(self) -> bytes:
        """Stable content digest for the view (used in audit / replay)."""
        ...


@dataclass(frozen=True)
class Delta:
    """Versioned delta between two AmberTree snapshots."""

    from_version: int
    to_version: int
    payload: bytes


# ---------------------------------------------------------------------------
# AmberTree Protocol (§7)
# ---------------------------------------------------------------------------
@runtime_checkable
class AmberTree(Protocol):
    """Immutable view over the kernel's working memory tree."""

    @property
    def root_hash(self) -> str:
        """Content hash of the tree root; stable across equal snapshots."""
        ...

    def commit_checked(self, path: str, payload: bytes) -> AmberTree:
        """Return a new tree with ``payload`` committed at ``path`` (CoW)."""
        ...

    def mark(self, path: str, status: NodeStatus) -> AmberTree:
        """Return a new tree with ``path`` re-labelled to ``status`` (CoW)."""
        ...

    def ready_index(self) -> ReadyIndex:
        """Return the index of ``READY`` nodes for the scheduler."""
        ...

    def context_view(self, path: str) -> ContextView:
        """Return the context view relevant to ``path``."""
        ...

    def delta_since_last(self) -> Delta:
        """Return the delta between this tree and the previously committed one."""
        ...


__all__ = [
    "AmberTree",
    "ContextView",
    "Delta",
    "NodeStatus",
    "ReadyIndex",
]
