"""Strongly-referenced background asyncio tasks.

``asyncio.create_task`` without a live reference can be garbage-collected
before the coroutine finishes, and exceptions become "never retrieved".
"""

from __future__ import annotations

import asyncio
from collections.abc import Coroutine
from typing import Any

from js.utils.log import get_logger

logger = get_logger("js.utils.async_tasks")

_BACKGROUND_TASKS: set[asyncio.Task[Any]] = set()


def spawn_background_task(
    coro: Coroutine[Any, Any, Any],
    *,
    name: str | None = None,
) -> asyncio.Task[Any]:
    """Schedule ``coro`` and keep a strong reference until it completes."""
    task: asyncio.Task[Any] = asyncio.create_task(coro, name=name)
    _BACKGROUND_TASKS.add(task)

    def _discard(done: asyncio.Task[Any]) -> None:
        _BACKGROUND_TASKS.discard(done)
        if done.cancelled():
            return
        exc = done.exception()
        if exc is not None:
            logger.warning(
                "Background task failed",
                name=name or done.get_name(),
                error_type=type(exc).__name__,
            )

    task.add_done_callback(_discard)
    return task


async def drain_background_tasks(*, timeout: float = 2.0) -> None:
    """Wait briefly for process-wide detached tasks during shutdown."""
    pending = [task for task in _BACKGROUND_TASKS if not task.done()]
    if not pending:
        return
    _done, still_pending = await asyncio.wait(pending, timeout=timeout)
    for task in still_pending:
        task.cancel()
    if still_pending:
        await asyncio.gather(*still_pending, return_exceptions=True)
