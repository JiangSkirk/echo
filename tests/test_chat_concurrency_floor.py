"""Verify: chat semaphore does not throttle 50 concurrent requests.

The SLO contract requires 50 concurrent workers.  The in-process
``_chat_semaphore`` must have a capacity >= 50 so it does not become
the bottleneck.
"""

from __future__ import annotations

from js.web.routers.chat import _MAX_CONCURRENT_CHATS, _chat_semaphore


def test_chat_semaphore_allows_50_concurrent() -> None:
    assert _MAX_CONCURRENT_CHATS >= 50, (
        f"_MAX_CONCURRENT_CHATS={_MAX_CONCURRENT_CHATS} is below the 50-worker SLO"
    )
    # The semaphore capacity must be >= 50
    capacity = _chat_semaphore._value if hasattr(_chat_semaphore, "_value") else _MAX_CONCURRENT_CHATS
    assert capacity >= 50, f"semaphore capacity {capacity} < 50"
