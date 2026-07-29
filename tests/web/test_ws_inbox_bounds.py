"""F-05: bounded WebSocket inbox backpressure and control-path delivery."""

from __future__ import annotations

import asyncio

import pytest

from js.web.ws_inbox import BoundedWebSocketInbox, InboxOverloadError


@pytest.mark.asyncio
async def test_put_data_rejects_when_message_limit_reached() -> None:
    inbox = BoundedWebSocketInbox(max_messages=2, max_bytes=10_000)
    await inbox.put_data({"n": 1}, nbytes=10)
    await inbox.put_data({"n": 2}, nbytes=10)
    with pytest.raises(InboxOverloadError, match="message limit"):
        await inbox.put_data({"n": 3}, nbytes=10)
    assert inbox.pending_messages == 2


@pytest.mark.asyncio
async def test_put_data_rejects_when_byte_budget_exceeded() -> None:
    inbox = BoundedWebSocketInbox(max_messages=10, max_bytes=100)
    await inbox.put_data({"n": 1}, nbytes=80)
    with pytest.raises(InboxOverloadError, match="byte budget"):
        await inbox.put_data({"n": 2}, nbytes=40)


@pytest.mark.asyncio
async def test_get_releases_byte_budget() -> None:
    inbox = BoundedWebSocketInbox(max_messages=10, max_bytes=100)
    await inbox.put_data({"n": 1}, nbytes=80)
    assert await inbox.get() == {"n": 1}
    assert inbox.pending_bytes == 0
    await inbox.put_data({"n": 2}, nbytes=80)


@pytest.mark.asyncio
async def test_put_control_never_blocks_on_full_data_queue() -> None:
    inbox = BoundedWebSocketInbox(max_messages=1, max_bytes=50)
    await inbox.put_data({"n": 1}, nbytes=40)
    # Overload control must still enqueue and atomically discard pending data.
    await inbox.put_control(InboxOverloadError("forced"), nbytes=0)
    control = await inbox.get()
    assert isinstance(control, InboxOverloadError)
    assert inbox.pending_messages == 0


@pytest.mark.asyncio
async def test_non_overload_control_prioritized_without_dropping_data() -> None:
    inbox = BoundedWebSocketInbox(max_messages=2, max_bytes=100)
    await inbox.put_data({"n": 1}, nbytes=10)
    await inbox.put_control(RuntimeError("disconnect"), nbytes=0, discard_data=False)
    first = await inbox.get()
    assert isinstance(first, RuntimeError)
    assert await inbox.get() == {"n": 1}


@pytest.mark.asyncio
async def test_close_clears_queue_and_rejects_further_data() -> None:
    inbox = BoundedWebSocketInbox(max_messages=4, max_bytes=1_000)
    await inbox.put_data({"n": 1}, nbytes=10)
    await inbox.close()
    assert inbox.pending_messages == 0
    assert inbox.pending_bytes == 0
    with pytest.raises(InboxOverloadError, match="closed"):
        await inbox.put_data({"n": 2}, nbytes=10)


@pytest.mark.asyncio
async def test_fast_producer_slow_consumer_triggers_overload() -> None:
    inbox = BoundedWebSocketInbox(max_messages=3, max_bytes=10_000)
    overloaded = asyncio.Event()

    async def producer() -> None:
        for i in range(10):
            try:
                await inbox.put_data({"i": i}, nbytes=8)
            except InboxOverloadError:
                await inbox.put_control(InboxOverloadError("overflow"))
                overloaded.set()
                return

    async def consumer() -> list[object]:
        seen: list[object] = []
        while True:
            item = await inbox.get()
            seen.append(item)
            if isinstance(item, InboxOverloadError):
                return seen
            await asyncio.sleep(0.02)

    prod = asyncio.create_task(producer())
    cons = asyncio.create_task(consumer())
    seen = await cons
    await prod
    assert overloaded.is_set()
    assert any(isinstance(item, InboxOverloadError) for item in seen)
