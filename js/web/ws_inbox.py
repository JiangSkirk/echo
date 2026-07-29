"""Bounded WebSocket inbox with message-count and byte-budget backpressure."""

from __future__ import annotations

import asyncio
from collections import deque
from dataclasses import dataclass
from typing import Any


class InboxOverloadError(RuntimeError):
    """Raised when the per-connection inbox budget is exhausted."""

    def __init__(self, reason: str = "websocket inbox overload") -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass
class _Entry:
    item: Any
    nbytes: int
    control: bool = False


class BoundedWebSocketInbox:
    """Per-connection inbox that tracks pending message count and byte budget.

    ``put_data`` never blocks forever: when the queue is full or the byte budget
    would be exceeded it raises :class:`InboxOverloadError` immediately so the
    reader can cancel the owner/session run and close with a policy status.

    Disconnect / error notifications use ``put_control``, which:
    - ignores data admission limits so a full inbox cannot drop control signals;
    - is always dequeued ahead of pending data;
    - on overload, atomically discards all pending data so abort is not starved.
    """

    def __init__(
        self,
        *,
        max_messages: int = 32,
        max_bytes: int = 4 * 1024 * 1024,
    ) -> None:
        if max_messages < 1:
            raise ValueError("max_messages must be positive")
        if max_bytes < 1:
            raise ValueError("max_bytes must be positive")
        self._max_messages = int(max_messages)
        self._max_bytes = int(max_bytes)
        self._entries: deque[_Entry] = deque()
        self._pending_bytes = 0
        self._data_count = 0
        self._lock = asyncio.Lock()
        self._not_empty = asyncio.Event()
        self._closed = False

    @property
    def pending_messages(self) -> int:
        return len(self._entries)

    @property
    def pending_bytes(self) -> int:
        return self._pending_bytes

    def _wake(self) -> None:
        if self._entries:
            self._not_empty.set()
        else:
            self._not_empty.clear()

    def _discard_data_unlocked(self) -> None:
        kept: deque[_Entry] = deque()
        pending = 0
        for entry in self._entries:
            if entry.control:
                kept.append(entry)
                pending += entry.nbytes
        self._entries = kept
        self._pending_bytes = pending
        self._data_count = 0

    async def put_data(self, item: Any, *, nbytes: int) -> None:
        if nbytes < 0:
            raise ValueError("nbytes must be non-negative")
        async with self._lock:
            if self._closed:
                raise InboxOverloadError("websocket inbox closed")
            if self._data_count >= self._max_messages:
                raise InboxOverloadError("websocket inbox message limit exceeded")
            if self._pending_bytes + nbytes > self._max_bytes:
                raise InboxOverloadError("websocket inbox byte budget exceeded")
            self._pending_bytes += nbytes
            self._data_count += 1
            self._entries.append(_Entry(item=item, nbytes=nbytes, control=False))
            self._wake()

    async def put_control(
        self,
        item: Any,
        *,
        nbytes: int = 0,
        discard_data: bool | None = None,
    ) -> None:
        """Enqueue disconnect/error/overload control ahead of all data."""
        drop_data = discard_data
        if drop_data is None:
            drop_data = isinstance(item, InboxOverloadError)
        async with self._lock:
            if drop_data:
                self._discard_data_unlocked()
            self._pending_bytes += max(0, nbytes)
            # Control always goes to the front so abort is not FIFO-starved.
            self._entries.appendleft(_Entry(item=item, nbytes=max(0, nbytes), control=True))
            self._wake()

    async def get(self) -> Any:
        while True:
            async with self._lock:
                if self._entries:
                    entry = self._entries.popleft()
                    self._pending_bytes = max(0, self._pending_bytes - entry.nbytes)
                    if not entry.control:
                        self._data_count = max(0, self._data_count - 1)
                    self._wake()
                    return entry.item
                self._not_empty.clear()
            await self._not_empty.wait()

    async def close(self) -> None:
        async with self._lock:
            self._closed = True
            self._entries.clear()
            self._pending_bytes = 0
            self._data_count = 0
            self._not_empty.set()
