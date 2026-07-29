from __future__ import annotations

import asyncio
import gc

import pytest

from js.web import session_locks


@pytest.fixture(autouse=True)
def _reset_session_locks() -> None:
    session_locks._session_locks.clear()


@pytest.mark.asyncio
async def test_same_owner_session_keeps_one_lock_while_referenced() -> None:
    first = await session_locks.get_session_lock("session-a", "owner-a")
    second = await session_locks.get_session_lock("session-a", "owner-a")
    other_owner = await session_locks.get_session_lock("session-a", "owner-b")

    assert first is second
    assert other_owner is not first


@pytest.mark.asyncio
async def test_in_use_lock_cannot_be_replaced_under_session_churn() -> None:
    held = await session_locks.get_session_lock("session-a", "owner-a")
    await held.acquire()
    try:
        for index in range(5_000):
            await session_locks.get_session_lock(f"other-{index}", "owner-a")
        same = await session_locks.get_session_lock("session-a", "owner-a")
        assert same is held
        assert same.locked() is True
    finally:
        held.release()


@pytest.mark.asyncio
async def test_idle_session_locks_do_not_remain_strongly_retained() -> None:
    locks = [
        await session_locks.get_session_lock(f"session-{index}", "owner-a")
        for index in range(2_000)
    ]
    assert len(session_locks._session_locks) == 2_000

    locks.clear()
    gc.collect()
    await asyncio.sleep(0)

    assert len(session_locks._session_locks) == 0
