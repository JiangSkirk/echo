from __future__ import annotations

import asyncio
import sqlite3
from pathlib import Path
from typing import Any
from unittest.mock import Mock

import pytest

from js.agent import JSAgent
from js.config import JSSettings
from js.echo.ledger.service import EchoBlockedError, EchoUnavailableError
from js.echo.turn_context import (
    RuntimeContext,
    reset_runtime_context,
    runtime_partition_key,
    set_runtime_context,
)
from js.echo.turn_loop import EchoTurnLoop


class _RaiseAfterSet(dict[str, tuple[asyncio.Task[Any], str, str | None]]):
    """Leave the active-task entry behind, then fail the setup assignment."""

    def __init__(self, failure: BaseException) -> None:
        super().__init__()
        self.failure = failure

    def __setitem__(
        self,
        key: str,
        value: tuple[asyncio.Task[Any], str, str | None],
    ) -> None:
        super().__setitem__(key, value)
        raise self.failure


def _new_agent(tmp_path: Path) -> JSAgent:
    return JSAgent(
        JSSettings(
            workspace=tmp_path / "workspace",
            state_dir=tmp_path / "state",
            max_turns=1,
            echo_engine="on",
        )
    )


def _new_loop(agent: JSAgent, session_id: str) -> EchoTurnLoop:
    return EchoTurnLoop(
        agent,
        "hello",
        session_id,
        None,
        None,
        None,
        None,
        None,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure_type",
    [RuntimeError, asyncio.CancelledError, EchoBlockedError],
    ids=["runtime-error", "cancelled", "echo-blocked"],
)
async def test_setup_failure_after_registration_is_finalized_and_tokens_are_cleaned(
    tmp_path: Path,
    failure_type: type[BaseException],
) -> None:
    agent = _new_agent(tmp_path)
    owner = "owner-a"
    session_id = "setup-failure"
    run_id = "run-a"
    context = RuntimeContext(
        product_id="js-agent",
        channel="test",
        owner_key_hash=owner,
        session_id=session_id,
        run_id=run_id,
        role="local-user",
        profile="default",
        capabilities=(),
        workspace=agent.settings.workspace,
        state_dir=agent.settings.state_dir,
    )
    partition_key = runtime_partition_key(context.product_id, owner, session_id)
    agent._active_run_tasks = _RaiseAfterSet(failure_type("setup exploded"))
    loop = _new_loop(agent, session_id)

    context_token = set_runtime_context(context)
    try:
        with pytest.raises(failure_type, match="setup exploded"):
            await loop.execute()
    finally:
        reset_runtime_context(context_token)

    lifecycle = agent.lifecycle_store.get(session_id, owner)
    assert lifecycle is not None
    assert (
        loop.state.status,
        lifecycle["status"],
        partition_key in agent._cancel_tokens,
        partition_key in agent._active_run_tasks,
    ) == ("error", "error", False, False)
    assert loop.state.error_message == f"{failure_type.__name__}: setup exploded"


@pytest.mark.asyncio
async def test_setup_failure_before_state_creation_propagates_without_cleanup_access(
    tmp_path: Path,
) -> None:
    agent = _new_agent(tmp_path)
    loop = _new_loop(agent, "setup-without-context")

    with pytest.raises(
        EchoUnavailableError,
        match="turn setup requires an Echo runtime context",
    ):
        await loop.execute()

    assert not hasattr(loop, "state")
    assert agent._cancel_tokens == {}
    assert agent._active_run_tasks == {}


@pytest.mark.asyncio
async def test_locked_working_memory_does_not_abort_setup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    agent = _new_agent(tmp_path)
    agent.logger = Mock()
    session_id = "working-memory-locked"
    owner = "owner-a"
    context = RuntimeContext(
        product_id="js-agent",
        channel="test",
        owner_key_hash=owner,
        session_id=session_id,
        run_id="run-a",
        role="local-user",
        profile="default",
        capabilities=(),
        workspace=agent.settings.workspace,
        state_dir=agent.settings.state_dir,
    )
    loop = _new_loop(agent, session_id)
    run_loop_calls = 0
    finalizer_calls = 0

    async def run_loop() -> None:
        nonlocal run_loop_calls
        run_loop_calls += 1
        loop.state.status = "completed"

    original_finalize = agent._finalize_run

    async def finalize(*args: Any, **kwargs: Any) -> None:
        nonlocal finalizer_calls
        finalizer_calls += 1
        await original_finalize(*args, **kwargs)

    monkeypatch.setattr(loop, "_run_loop", run_loop)
    monkeypatch.setattr(agent, "_finalize_run", finalize)

    def raise_locked(**_: Any) -> None:
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(agent.memory, "store_working", raise_locked)
    context_token = set_runtime_context(context)
    try:
        state = await loop.execute()
    finally:
        reset_runtime_context(context_token)

    partition_key = runtime_partition_key(context.product_id, owner, session_id)
    assert state is loop.state
    assert run_loop_calls == 1
    assert finalizer_calls == 1
    assert state.status == "completed"
    agent.logger.warning.assert_called_once_with("Failed to store working memory", exc_info=True)
    lifecycle = agent.lifecycle_store.get(session_id, owner)
    assert lifecycle is not None
    assert lifecycle["status"] == "completed"
    assert partition_key not in agent._cancel_tokens
    assert partition_key not in agent._active_run_tasks


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure_type",
    [sqlite3.DatabaseError, PermissionError, RuntimeError, asyncio.CancelledError],
    ids=["database-error", "permission-error", "runtime-error", "cancelled"],
)
async def test_working_memory_non_lock_failures_propagate_and_finalize_setup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_type: type[BaseException],
) -> None:
    agent = _new_agent(tmp_path)
    agent.logger = Mock()
    session_id = f"working-memory-{failure_type.__name__}"
    owner = "owner-a"
    context = RuntimeContext(
        product_id="js-agent",
        channel="test",
        owner_key_hash=owner,
        session_id=session_id,
        run_id="run-a",
        role="local-user",
        profile="default",
        capabilities=(),
        workspace=agent.settings.workspace,
        state_dir=agent.settings.state_dir,
    )
    loop = _new_loop(agent, session_id)

    def raise_failure(**_: Any) -> None:
        raise failure_type("working memory unavailable")

    monkeypatch.setattr(agent.memory, "store_working", raise_failure)
    context_token = set_runtime_context(context)
    try:
        with pytest.raises(failure_type, match="working memory unavailable"):
            await loop.execute()
    finally:
        reset_runtime_context(context_token)

    partition_key = runtime_partition_key(context.product_id, owner, session_id)
    lifecycle = agent.lifecycle_store.get(session_id, owner)
    assert lifecycle is not None
    assert lifecycle["status"] == "error"
    assert partition_key not in agent._cancel_tokens
    assert partition_key not in agent._active_run_tasks
