"""Regression tests for lane queue cancellation semantics."""

from __future__ import annotations

import asyncio

import pytest

from js.orchestration.lane_queue import LaneExecutor, LaneTask


class TaskBaseException(BaseException):
    pass


async def _wait_for_queue_size(queue: asyncio.Queue[LaneTask], size: int) -> None:
    for _ in range(100):
        if queue.qsize() >= size:
            return
        await asyncio.sleep(0)
    raise AssertionError(f"queue did not reach size {size}")


@pytest.mark.asyncio
async def test_cancelled_lane_waiter_never_runs_and_lane_continues() -> None:
    executor = LaneExecutor()
    lane = await executor.get_or_create_lane("session-1")
    first_started = asyncio.Event()
    release_first = asyncio.Event()
    side_effects: list[str] = []

    async def first() -> str:
        side_effects.append("first-started")
        first_started.set()
        await release_first.wait()
        side_effects.append("first-finished")
        return "first-result"

    async def second() -> str:
        side_effects.append("second-ran")
        return "second-result"

    async def third() -> str:
        side_effects.append("third-ran")
        return "third-result"

    first_waiter = asyncio.create_task(lane.submit(task=LaneTask(id="first", coro=first)))
    await first_started.wait()

    second_waiter = asyncio.create_task(lane.submit(task=LaneTask(id="second", coro=second)))
    await _wait_for_queue_size(lane._queue, 1)
    second_waiter.cancel()
    with pytest.raises(asyncio.CancelledError):
        await second_waiter

    third_waiter = asyncio.create_task(lane.submit(task=LaneTask(id="third", coro=third)))
    await _wait_for_queue_size(lane._queue, 2)
    release_first.set()

    assert await first_waiter == "first-result"
    assert await third_waiter == "third-result"
    await lane.drain()

    assert side_effects == ["first-started", "first-finished", "third-ran"]
    assert lane._queue.empty()
    assert lane._task is not None
    assert lane._task.done()


@pytest.mark.asyncio
async def test_base_exception_from_task_does_not_stop_lane() -> None:
    executor = LaneExecutor()
    lane = await executor.get_or_create_lane("session-1")

    async def failing() -> None:
        raise TaskBaseException

    async def following() -> str:
        return "following-result"

    failing_waiter = asyncio.create_task(
        lane.submit(task=LaneTask(id="failing", coro=failing))
    )
    with pytest.raises(TaskBaseException):
        await failing_waiter

    assert await lane.submit(task=LaneTask(id="following", coro=following)) == "following-result"
    await lane.drain()


@pytest.mark.asyncio
async def test_cancelling_active_lane_task_does_not_strand_queued_work() -> None:
    executor = LaneExecutor()
    lane = await executor.get_or_create_lane("session-1")
    active_started = asyncio.Event()

    async def active() -> None:
        active_started.set()
        await asyncio.Event().wait()

    async def queued() -> str:
        return "queued-result"

    active_waiter = asyncio.create_task(lane.submit(LaneTask(id="active", coro=active)))
    await active_started.wait()
    queued_waiter = asyncio.create_task(lane.submit(LaneTask(id="queued", coro=queued)))
    await _wait_for_queue_size(lane._queue, 1)
    assert lane._task is not None

    lane._task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await active_waiter
    assert await asyncio.wait_for(queued_waiter, timeout=1.0) == "queued-result"
    await lane.drain()


@pytest.mark.asyncio
async def test_executor_releases_idle_lanes_after_high_session_churn() -> None:
    executor = LaneExecutor()

    for index in range(2_000):
        async def complete(value: int = index) -> int:
            return value

        assert await executor.submit(
            session_id=f"session-{index}",
            coro=complete,
            task_id=f"task-{index}",
        ) == index

    assert executor._lanes == {}
    assert executor._lane_users == {}


@pytest.mark.asyncio
async def test_executor_keeps_one_lane_until_concurrent_session_users_finish() -> None:
    executor = LaneExecutor()
    first_started = asyncio.Event()
    release_first = asyncio.Event()
    order: list[str] = []

    async def first() -> str:
        order.append("first-start")
        first_started.set()
        await release_first.wait()
        order.append("first-end")
        return "first"

    async def second() -> str:
        order.append("second")
        return "second"

    first_waiter = asyncio.create_task(executor.submit("shared", first, "first"))
    await first_started.wait()
    second_waiter = asyncio.create_task(executor.submit("shared", second, "second"))
    await asyncio.sleep(0)

    assert len(executor._lanes) == 1
    assert executor._lane_users == {"shared": 2}
    release_first.set()

    assert await first_waiter == "first"
    assert await second_waiter == "second"
    assert order == ["first-start", "first-end", "second"]
    assert executor._lanes == {}
    assert executor._lane_users == {}


@pytest.mark.asyncio
async def test_cancelling_active_submit_cancels_inner_and_lane_continues() -> None:
    executor = LaneExecutor()
    inner_started = asyncio.Event()
    inner_cancelled = asyncio.Event()
    release_inner = asyncio.Event()

    async def active() -> None:
        inner_started.set()
        try:
            await release_inner.wait()
        except asyncio.CancelledError:
            inner_cancelled.set()
            raise

    async def following() -> str:
        await asyncio.sleep(0)
        return "following-result"

    active_waiter = asyncio.create_task(executor.submit("shared", active, "active"))
    await inner_started.wait()
    lane = executor._lanes["shared"]

    following_waiter = asyncio.create_task(
        executor.submit("shared", following, "following")
    )
    await _wait_for_queue_size(lane._queue, 1)
    active_waiter.cancel()

    cancel_propagated = True
    try:
        await asyncio.wait_for(inner_cancelled.wait(), timeout=1.0)
    except TimeoutError:
        cancel_propagated = False
        release_inner.set()

    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(active_waiter, timeout=1.0)
    assert await asyncio.wait_for(following_waiter, timeout=1.0) == "following-result"
    assert executor._lanes == {}
    assert executor._lane_users == {}
    assert cancel_propagated, "cancelling submit did not promptly cancel its active coroutine"
