"""Bounded, owner-bound, one-shot storage for private control-plane handoffs."""

from __future__ import annotations

import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import cast

_PENDING = object()


@dataclass
class _Entry[T]:
    owner: str
    value: T | object
    ready: bool
    expires_at: float


class PrivateHandoffVault[T]:
    """Hold bounded private values behind owner-bound opaque references.

    Values are consumed at most once.  A caller may reserve a slot before a
    state-changing operation and commit its result afterwards, preventing the
    operation from succeeding only to be reported as failed because the private
    result relay filled concurrently.
    """

    def __init__(
        self,
        *,
        max_entries: int,
        ttl_seconds: float,
        pending_ttl_seconds: float = 3600.0,
        clock: Callable[[], float] = time.monotonic,
        cleanup: Callable[[T], None] | None = None,
    ) -> None:
        if max_entries <= 0:
            raise ValueError("max_entries must be positive")
        if ttl_seconds <= 0 or pending_ttl_seconds <= 0:
            raise ValueError("private relay TTLs must be positive")
        self._max_entries = max_entries
        self._ttl_seconds = ttl_seconds
        self._pending_ttl_seconds = pending_ttl_seconds
        self._clock = clock
        self._cleanup = cleanup
        self._entries: dict[str, _Entry[T]] = {}
        self._lock = threading.RLock()

    def _purge_expired_locked(self, now: float) -> list[T]:
        expired_values: list[T] = []
        for reference, entry in tuple(self._entries.items()):
            if entry.expires_at > now:
                continue
            self._entries.pop(reference, None)
            if entry.ready:
                expired_values.append(cast("T", entry.value))
        return expired_values

    def _run_cleanup(self, values: list[T]) -> None:
        if self._cleanup is None:
            return
        for value in values:
            try:
                self._cleanup(value)
            except Exception:
                # Cleanup is best-effort and must never expose or replace the
                # admission decision.  Resource implementations are expected
                # to be idempotent.
                continue

    def _new_reference_locked(self) -> str:
        while True:
            reference = secrets.token_urlsafe(24)
            if reference not in self._entries:
                return reference

    def stage(
        self,
        owner: str,
        value: T,
        *,
        reference: str | None = None,
    ) -> str:
        """Store a ready value, returning an opaque reference or ``""``."""
        if not isinstance(owner, str) or not owner:
            return ""
        if reference is not None and (
            not isinstance(reference, str)
            or not reference
            or len(reference) > 512
            or any(ord(character) < 32 or ord(character) == 127 for character in reference)
        ):
            return ""
        now = self._clock()
        with self._lock:
            expired = self._purge_expired_locked(now)
            if len(self._entries) >= self._max_entries or (
                reference is not None and reference in self._entries
            ):
                stored_reference = ""
            else:
                stored_reference = reference or self._new_reference_locked()
                self._entries[stored_reference] = _Entry(
                    owner=owner,
                    value=value,
                    ready=True,
                    expires_at=now + self._ttl_seconds,
                )
        self._run_cleanup(expired)
        return stored_reference

    def reserve(self, owner: str) -> str:
        """Reserve capacity before a state-changing operation begins."""
        if not isinstance(owner, str) or not owner:
            return ""
        now = self._clock()
        with self._lock:
            expired = self._purge_expired_locked(now)
            if len(self._entries) >= self._max_entries:
                reference = ""
            else:
                reference = self._new_reference_locked()
                self._entries[reference] = _Entry(
                    owner=owner,
                    value=_PENDING,
                    ready=False,
                    expires_at=now + self._pending_ttl_seconds,
                )
        self._run_cleanup(expired)
        return reference

    def commit(self, reference: str, owner: str, value: T) -> bool:
        """Publish a value into an existing owner-bound reservation."""
        if not reference or not owner:
            return False
        now = self._clock()
        committed = False
        with self._lock:
            expired = self._purge_expired_locked(now)
            entry = self._entries.get(reference)
            if entry is not None and entry.owner == owner and not entry.ready:
                entry.value = value
                entry.ready = True
                entry.expires_at = now + self._ttl_seconds
                committed = True
        self._run_cleanup(expired)
        return committed

    def take(self, reference: str, owner: str) -> T | None:
        """Consume a ready value exactly once for its owner."""
        if not reference or not owner:
            return None
        now = self._clock()
        value: T | None = None
        with self._lock:
            expired = self._purge_expired_locked(now)
            entry = self._entries.get(reference)
            if entry is not None and entry.owner == owner and entry.ready:
                self._entries.pop(reference, None)
                value = cast("T", entry.value)
        self._run_cleanup(expired)
        return value

    def peek(self, reference: str, owner: str) -> T | None:
        """Read a ready owner-bound value without consuming it."""
        if not reference or not owner:
            return None
        now = self._clock()
        value: T | None = None
        with self._lock:
            expired = self._purge_expired_locked(now)
            entry = self._entries.get(reference)
            if entry is not None and entry.owner == owner and entry.ready:
                value = cast("T", entry.value)
        self._run_cleanup(expired)
        return value

    def discard(self, reference: str, owner: str) -> bool:
        """Remove an entry for its owner and clean up an unconsumed value."""
        if not reference or not owner:
            return False
        now = self._clock()
        discarded: list[T] = []
        removed = False
        with self._lock:
            expired = self._purge_expired_locked(now)
            entry = self._entries.get(reference)
            if entry is not None and entry.owner == owner:
                self._entries.pop(reference, None)
                removed = True
                if entry.ready:
                    discarded.append(cast("T", entry.value))
        self._run_cleanup([*expired, *discarded])
        return removed

    def __len__(self) -> int:
        now = self._clock()
        with self._lock:
            expired = self._purge_expired_locked(now)
            size = len(self._entries)
        self._run_cleanup(expired)
        return size
