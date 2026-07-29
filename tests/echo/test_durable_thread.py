from __future__ import annotations

import asyncio
import threading

import pytest

from js.echo.durable_thread import (
    EchoDurableExecutor,
    EchoDurableExecutorBusyError,
    EchoDurableExecutorClosedError,
    claim_to_thread,
    durable_to_thread,
)


@pytest.mark.asyncio
async def test_durable_executor_does_not_starve_default_executor() -> None:
    executor = EchoDurableExecutor(max_claim_pending=1, max_finish_pending=1)
    started = threading.Event()
    release = threading.Event()

    def block() -> str:
        started.set()
        assert release.wait(timeout=1)
        return "durable"

    claim = await claim_to_thread(
        lambda: "claimed",
        on_cancel=lambda _value: None,
        executor=executor,
    )
    durable_task = asyncio.create_task(durable_to_thread(block, claim=claim))
    try:
        assert await asyncio.to_thread(started.wait, 1)
        unrelated = await asyncio.wait_for(asyncio.to_thread(lambda: "default"), timeout=0.2)
        assert unrelated == "default"
    finally:
        release.set()
        assert await durable_task == "durable"
        executor.shutdown(wait=True)


@pytest.mark.asyncio
async def test_durable_executor_rejects_excess_claim_work_without_queueing() -> None:
    executor = EchoDurableExecutor(max_claim_pending=1, max_finish_pending=1)
    started = threading.Event()
    release = threading.Event()

    def block() -> None:
        started.set()
        assert release.wait(timeout=1)

    first = asyncio.create_task(
        claim_to_thread(block, on_cancel=lambda _value: None, executor=executor)
    )
    try:
        assert await asyncio.to_thread(started.wait, 1)
        with pytest.raises(EchoDurableExecutorBusyError, match="claim lane is full"):
            await claim_to_thread(
                lambda: None,
                on_cancel=lambda _value: None,
                executor=executor,
            )
    finally:
        release.set()
        claim = await first
        await durable_to_thread(lambda: None, claim=claim)
        executor.shutdown(wait=True)


@pytest.mark.asyncio
async def test_cancelled_claim_can_queue_cleanup_when_finish_lane_is_saturated() -> None:
    executor = EchoDurableExecutor(
        max_claim_pending=2,
        max_finish_pending=2,
        finish_workers=1,
    )
    finish_started = threading.Event()
    finish_release = threading.Event()
    claim_started = threading.Event()
    claim_release = threading.Event()
    cleaned = threading.Event()
    claimed_value = object()

    def block_finish() -> None:
        finish_started.set()
        assert finish_release.wait(timeout=1)

    def claim() -> object:
        claim_started.set()
        assert claim_release.wait(timeout=1)
        return claimed_value

    finish_claim = await claim_to_thread(
        lambda: object(),
        on_cancel=lambda _value: None,
        executor=executor,
    )
    finish_task = asyncio.create_task(durable_to_thread(block_finish, claim=finish_claim))
    claim_task = asyncio.create_task(
        claim_to_thread(
            claim,
            on_cancel=lambda value: cleaned.set() if value is claimed_value else None,
            executor=executor,
        )
    )
    try:
        assert await asyncio.to_thread(finish_started.wait, 1)
        assert await asyncio.to_thread(claim_started.wait, 1)
        claim_task.cancel("cancel with saturated finish lane")
        claim_release.set()
        await asyncio.sleep(0.02)
        assert not claim_task.done()
        finish_release.set()
        await finish_task
        with pytest.raises(asyncio.CancelledError, match="saturated finish lane"):
            await claim_task
        assert cleaned.is_set()
    finally:
        claim_release.set()
        finish_release.set()
        await asyncio.gather(finish_task, claim_task, return_exceptions=True)
        executor.shutdown(wait=True)


@pytest.mark.asyncio
async def test_durable_executor_rejects_new_work_after_shutdown() -> None:
    executor = EchoDurableExecutor(max_claim_pending=1, max_finish_pending=1)
    executor.shutdown(wait=True)

    with pytest.raises(EchoDurableExecutorClosedError, match="shut down"):
        await claim_to_thread(
            lambda: None,
            on_cancel=lambda _value: None,
            executor=executor,
        )


@pytest.mark.asyncio
async def test_claim_reserves_bounded_finish_capacity() -> None:
    executor = EchoDurableExecutor(
        max_claim_pending=2,
        max_finish_pending=1,
    )
    first = await claim_to_thread(
        lambda: "first",
        on_cancel=lambda _value: None,
        executor=executor,
    )
    try:
        assert executor.outstanding_claims == 1
        with pytest.raises(EchoDurableExecutorBusyError, match="finish capacity is full"):
            await claim_to_thread(
                lambda: "second",
                on_cancel=lambda _value: None,
                executor=executor,
            )
    finally:
        await durable_to_thread(lambda: None, claim=first)
        executor.shutdown(wait=True)


@pytest.mark.asyncio
async def test_finish_reservation_is_single_use() -> None:
    executor = EchoDurableExecutor(max_claim_pending=1, max_finish_pending=1)
    claim = await claim_to_thread(
        lambda: "value",
        on_cancel=lambda _value: None,
        executor=executor,
    )
    await durable_to_thread(lambda: None, claim=claim)
    with pytest.raises(RuntimeError, match="invalid Echo durable finish reservation"):
        await durable_to_thread(lambda: None, claim=claim)
    executor.shutdown(wait=True)


@pytest.mark.asyncio
async def test_shutdown_refuses_outstanding_claim() -> None:
    executor = EchoDurableExecutor(max_claim_pending=1, max_finish_pending=1)
    claim = await claim_to_thread(
        lambda: "value",
        on_cancel=lambda _value: None,
        executor=executor,
    )
    with pytest.raises(EchoDurableExecutorBusyError, match="outstanding claims"):
        executor.shutdown(wait=True)
    await durable_to_thread(lambda: None, claim=claim)
    executor.shutdown(wait=True)


@pytest.mark.asyncio
async def test_failed_claim_releases_reserved_finish_capacity() -> None:
    executor = EchoDurableExecutor(max_claim_pending=1, max_finish_pending=1)

    def fail_claim() -> None:
        raise OSError("claim failed")

    with pytest.raises(OSError, match="claim failed"):
        await claim_to_thread(
            fail_claim,
            on_cancel=lambda _value: None,
            executor=executor,
        )
    assert executor.outstanding_claims == 0

    claim = await claim_to_thread(
        lambda: "recovered",
        on_cancel=lambda _value: None,
        executor=executor,
    )
    await durable_to_thread(lambda: None, claim=claim)
    executor.shutdown(wait=True)
