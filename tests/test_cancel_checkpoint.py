"""Tests for cancel API, checkpoint/resume, and graceful shutdown."""

from __future__ import annotations

import asyncio
import threading
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from js.agent import AgentState, JSAgent
from js.config import JSSettings
from js.echo.turn_context import runtime_partition_key
from js.echo.turn_runtime import TurnRequest, run_echo_turn
from js.models.permit import ModelPermitIssuer
from js.models.providers import ChatMessage, ChatResponse, ModelProvider
from js.models.router import ModelRouter
from js.persistence.state_store import StateStore
from js.security.audit import AuditEventType


class SlowMockProvider(ModelProvider):
    """Mock provider with configurable per-response delay."""

    def __init__(self, responses: list[ChatResponse], delay: float = 0.05) -> None:
        self._responses = responses
        self._index = 0
        self.delay = delay
        self.calls: list[list[ChatMessage]] = []

    def set_responses(self, responses: list[ChatResponse]) -> None:
        self._responses = responses
        self._index = 0

    async def chat(
        self,
        messages: list[ChatMessage],
        model: str,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> ChatResponse:
        del max_tokens
        await asyncio.sleep(self.delay)
        self.calls.append(messages)
        resp = self._responses[self._index % len(self._responses)]
        self._index += 1
        return resp

    async def chat_stream(
        self,
        messages: list[ChatMessage],
        model: str,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ):
        del tools, max_tokens
        for token in ("Mock", " stream"):
            yield token

    async def health_check(self) -> bool:
        return True

    async def close(self) -> None:
        pass


class MockRouter(ModelRouter):
    """Router that uses a SlowMockProvider without config file."""

    def __init__(
        self,
        provider: SlowMockProvider,
        *,
        permit_verifier: ModelPermitIssuer,
    ) -> None:
        self.settings = JSSettings()
        self._providers: dict[str, ModelProvider] = {"mock": provider}
        self._model_map = {}
        self._permit_verifier = permit_verifier

    async def select_model(self, task_complexity: str = "medium", preferred: str | None = None) -> Any:
        from js.models.router import RoutingDecision
        return RoutingDecision(
            provider=self._providers["mock"],
            model="gpt",
            provider_name="mock",
            reason="mock",
        )

    async def chat(
        self,
        messages: list[ChatMessage],
        model: str | None = None,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
        before_model_call: Any = None,
        after_model_call: Any = None,
        permit_grant: Any = None,
    ) -> ChatResponse:
        if before_model_call is None or after_model_call is None or permit_grant is None:
            raise RuntimeError("test router requires Echo model callbacks and a permit grant")
        decision = await self.select_model(preferred=model)
        self._consume_model_permit(permit_grant, decision, messages, tools)
        context = await before_model_call(decision, messages, tools)
        try:
            response = await decision.provider.chat(
                messages=messages,
                model=decision.model,
                tools=tools,
                temperature=temperature,
                max_tokens=max_tokens,
            )
        except BaseException as exc:
            await after_model_call(context, None, exc)
            raise
        await after_model_call(context, response, None)
        return response

    async def chat_stream(self, messages: list[ChatMessage], model: str | None = None, temperature: float = 0.7):
        provider = self._providers["mock"]
        async for token in provider.chat_stream(messages, model or "gpt", temperature):
            yield token

    def get_model_config(self, model: str | None = None):
        from js.config import ModelConfig
        return ModelConfig(id="mock", provider="mock")

    async def health_check(self):
        return {"mock": True}


@pytest.fixture
def mock_provider() -> SlowMockProvider:
    return SlowMockProvider([])


@pytest.fixture
def agent(tmp_path: Path, mock_provider: SlowMockProvider) -> JSAgent:
    settings = JSSettings(
        workspace=tmp_path / "workspace",
        state_dir=tmp_path / "state",
        max_turns=10,
    )
    a = JSAgent(settings)
    a.router = MockRouter(
        mock_provider,
        permit_verifier=a._model_permit_issuer,
    )
    return a


class TestCancelAPI:
    @pytest.mark.asyncio
    async def test_request_cancel_sets_event(self, agent: JSAgent) -> None:
        token = asyncio.Event()
        agent._cancel_tokens[
            runtime_partition_key("js-agent", None, "sess-1")
        ] = (token, "run-1", None)
        ok = agent.request_cancel("sess-1")
        assert ok is True
        assert token.is_set()

    @pytest.mark.asyncio
    async def test_request_cancel_unknown_session(self, agent: JSAgent) -> None:
        ok = agent.request_cancel("nonexistent")
        assert ok is False

    @pytest.mark.asyncio
    async def test_request_cancel_owned_session_requires_matching_owner(self, agent: JSAgent) -> None:
        token = asyncio.Event()
        agent._cancel_tokens[
            runtime_partition_key(
                "js-agent",
                "owner-a",
                "sess-owned",
            )
        ] = (
            token,
            "run-1",
            "owner-a",
        )

        assert agent.request_cancel("sess-owned") is False
        assert agent.request_cancel("sess-owned", owner_key_hash="owner-b") is False

        assert not token.is_set()
        assert agent.request_cancel("sess-owned", owner_key_hash="owner-a") is True
        assert token.is_set()

    @pytest.mark.asyncio
    async def test_request_owned_cancel_distinguishes_cancelled_idle_and_denied(
        self,
        agent: JSAgent,
    ) -> None:
        victim_token = asyncio.Event()
        agent.bind_cancel_token(
            "shared-session",
            victim_token,
            owner_key_hash="victim-owner",
            run_id="victim-run",
        )

        denied = agent.request_owned_cancel(
            "shared-session",
            owner_key_hash="attacker-owner",
        )
        assert str(denied) == "denied"
        assert not victim_token.is_set()

        cancelled = agent.request_owned_cancel(
            "shared-session",
            owner_key_hash="victim-owner",
        )
        assert str(cancelled) == "cancelled"
        assert victim_token.is_set()

        idle = agent.request_owned_cancel(
            "missing-session",
            owner_key_hash="victim-owner",
        )
        assert str(idle) == "idle"

    @pytest.mark.parametrize(
        ("session_id", "owner_key_hash"),
        [("", "owner"), (" ", "owner"), ("session", ""), ("session", " ")],
    )
    def test_request_owned_cancel_rejects_unverifiable_binding(
        self,
        agent: JSAgent,
        session_id: str,
        owner_key_hash: str,
    ) -> None:
        with pytest.raises(ValueError):
            agent.request_owned_cancel(session_id, owner_key_hash=owner_key_hash)

    def test_request_owned_cancel_denies_legacy_unowned_same_session(
        self,
        agent: JSAgent,
    ) -> None:
        legacy_token = asyncio.Event()
        agent.bind_cancel_token(
            "legacy-session",
            legacy_token,
            owner_key_hash=None,
            run_id="legacy-run",
        )

        result = agent.request_owned_cancel(
            "legacy-session",
            owner_key_hash="authenticated-owner",
        )

        assert str(result) == "denied"
        assert not legacy_token.is_set()

    @pytest.mark.asyncio
    async def test_same_session_id_cancels_only_matching_owner(
        self,
        agent: JSAgent,
        mock_provider: SlowMockProvider,
    ) -> None:
        mock_provider.delay = 10.0
        mock_provider.set_responses(
            [
                ChatResponse(
                    content="too late",
                    tool_calls=[],
                    model="mock",
                    usage={"prompt_tokens": 1, "completion_tokens": 1},
                    finish_reason="stop",
                )
            ]
        )
        session_id = "shared-owner-session"
        owner_a = asyncio.create_task(
            run_echo_turn(
                agent,
                "owner a",
                channel="test",
                owner_key_hash="owner-a",
                session_id=session_id,
            )
        )
        owner_b = asyncio.create_task(
            run_echo_turn(
                agent,
                "owner b",
                channel="test",
                owner_key_hash="owner-b",
                session_id=session_id,
            )
        )
        for _ in range(100):
            if len(agent._cancel_tokens) == 2:
                break
            await asyncio.sleep(0.01)

        assert len(agent._cancel_tokens) == 2
        assert agent.request_cancel(session_id, owner_key_hash="owner-a") is True
        state_a = await asyncio.wait_for(owner_a, timeout=0.5)
        assert state_a.status == "cancelled"
        assert not owner_b.done()

        assert agent.request_cancel(session_id, owner_key_hash="owner-b") is True
        state_b = await asyncio.wait_for(owner_b, timeout=0.5)
        assert state_b.status == "cancelled"

    @pytest.mark.asyncio
    async def test_runtime_rejects_cross_product_context_and_cleans_valid_turn(
        self,
        agent: JSAgent,
        mock_provider: SlowMockProvider,
    ) -> None:
        owner = "owner-a"
        session_id = "cross-product-session"
        agent_partition = runtime_partition_key("js-agent", owner, session_id)
        work_partition = runtime_partition_key("js-work", owner, session_id)
        mock_provider.set_responses(
            [
                ChatResponse(
                    content="done",
                    tool_calls=[],
                    model="mock",
                    usage={"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
                    finish_reason="stop",
                )
            ]
        )

        base_context = agent.echo_runtime.build_context(
            channel="test",
            owner_key_hash=owner,
            session_id=session_id,
            run_id="agent-run",
        )
        work_context = replace(base_context, product_id="js-work", run_id="work-run")
        with pytest.raises(PermissionError, match="context scope"):
            await agent.echo_runtime.run_turn(
                TurnRequest(message="work", context=work_context)
            )

        assert work_partition not in agent._lane_executor._lanes
        assert work_partition not in agent._cancel_tokens
        assert work_partition not in agent._active_run_tasks

        state = await agent.echo_runtime.run_turn(
            TurnRequest(message="agent", context=base_context)
        )

        assert state.status == "completed"
        assert agent_partition not in agent._lane_executor._lanes
        assert agent_partition not in agent._cancel_tokens
        assert agent_partition not in agent._active_run_tasks

    @pytest.mark.asyncio
    async def test_run_cancels_between_turns(self, agent: JSAgent, mock_provider: SlowMockProvider) -> None:
        """Cancel is observed at the start of the next turn."""
        mock_provider.set_responses([
            ChatResponse(
                content="",
                tool_calls=[{
                    "id": "call_1",
                    "type": "function",
                    "function": {"name": "file_list", "arguments": '{"path": "."}'},
                }],
                model="mock",
                usage={"prompt_tokens": 5, "completion_tokens": 5, "total_tokens": 10},
                finish_reason="tool_calls",
            ),
            ChatResponse(
                content="Should not reach",
                tool_calls=[],
                model="mock",
                usage={"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8},
                finish_reason="stop",
            ),
        ])

        session_id = "test-cancel-session"
        run_task = asyncio.create_task(agent.run("List files", session_id=session_id))
        # Allow first turn to start and provider to be called
        await asyncio.sleep(0.02)
        # Cancel before second turn begins
        agent.request_cancel(session_id)
        state = await run_task

        assert state.status == "cancelled"
        assert state.error_message == "Run cancelled by user request"
        assert state.turn_count >= 1

    @pytest.mark.asyncio
    async def test_request_cancel_interrupts_inflight_model_call(
        self,
        agent: JSAgent,
        mock_provider: SlowMockProvider,
    ) -> None:
        """Cancellation must interrupt an await, not wait for the next turn."""
        mock_provider.delay = 10.0
        mock_provider.set_responses(
            [
                ChatResponse(
                    content="too late",
                    tool_calls=[],
                    model="mock",
                    usage={"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
                    finish_reason="stop",
                )
            ]
        )

        session_id = "cancel-inflight"
        run_task = asyncio.create_task(agent.run("wait", session_id=session_id))
        for _ in range(50):
            if (
                runtime_partition_key("js-agent", None, session_id)
                in agent._cancel_tokens
            ):
                break
            await asyncio.sleep(0.01)

        assert agent.request_cancel(session_id) is True
        state = await asyncio.wait_for(run_task, timeout=0.5)

        assert state.status == "cancelled"
        assert state.error_message == "Run cancelled by user request"
        lifecycle = agent.lifecycle_store.get(session_id, "local-user")
        assert lifecycle is not None
        assert lifecycle["status"] == "cancelled"

    @pytest.mark.asyncio
    async def test_cancel_before_finalizer_commit_finishes_cancelled_and_cleans_up(
        self,
        agent: JSAgent,
        mock_provider: SlowMockProvider,
    ) -> None:
        mock_provider.delay = 0
        mock_provider.set_responses(
            [
                ChatResponse(
                    content="done",
                    tool_calls=[],
                    model="mock",
                    usage={"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
                    finish_reason="stop",
                )
            ]
        )
        finalizer_entered = asyncio.Event()
        release_finalizer = asyncio.Event()
        cleanup_finished = asyncio.Event()
        stored_message_batches: list[list[dict[str, str]]] = []
        episode_calls: list[dict[str, Any]] = []
        learner_calls: list[dict[str, Any]] = []
        original_store_messages = agent.memory.store_messages
        original_store_episode = agent.memory.store_episode

        def capture_messages(
            stored_session_id: str,
            messages: list[dict[str, str]],
            owner_key_hash: str | None = None,
        ) -> Any:
            stored_message_batches.append(messages)
            return original_store_messages(stored_session_id, messages, owner_key_hash)

        def capture_episode(**kwargs: Any) -> Any:
            episode_calls.append(kwargs)
            return original_store_episode(**kwargs)

        agent.memory.store_messages = capture_messages  # type: ignore[method-assign]
        agent.memory.store_episode = capture_episode  # type: ignore[method-assign]
        if agent.learner is not None:
            agent.learner.record_interaction = (  # type: ignore[method-assign]
                lambda **kwargs: learner_calls.append(kwargs)
            )
        original_finalize = agent._finalize_run

        async def paused_finalize(*args: Any, **kwargs: Any) -> None:
            finalizer_entered.set()
            await release_finalizer.wait()
            await original_finalize(*args, **kwargs)
            cleanup_finished.set()

        agent._finalize_run = paused_finalize  # type: ignore[method-assign]
        session_id = "cancel-before-finalizer-commit"
        run_task = asyncio.create_task(agent.run("finish", session_id=session_id))
        await asyncio.wait_for(finalizer_entered.wait(), timeout=1)

        assert agent.request_cancel(session_id) is True
        assert agent.request_cancel(session_id) is True
        release_finalizer.set()
        state = await asyncio.wait_for(run_task, timeout=1)

        assert state.status == "cancelled"
        assert cleanup_finished.is_set()
        lifecycle = agent.lifecycle_store.get(session_id, "local-user")
        assert lifecycle is not None
        assert lifecycle["status"] == "cancelled"
        assert stored_message_batches == [[{"role": "user", "content": "finish"}]]
        assert episode_calls == []
        assert learner_calls == []
        cancel_events = agent.audit.query(
            session_id=session_id,
            run_id=state.run_id,
            event_type=AuditEventType.CANCELLED,
        )
        assert len(cancel_events) == 1

    @pytest.mark.asyncio
    async def test_cancel_after_terminal_commit_is_rejected_and_cleanup_completes(
        self,
        agent: JSAgent,
        mock_provider: SlowMockProvider,
    ) -> None:
        mock_provider.delay = 0
        mock_provider.set_responses(
            [
                ChatResponse(
                    content="done",
                    tool_calls=[],
                    model="mock",
                    usage={"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
                    finish_reason="stop",
                )
            ]
        )
        cleanup_started = threading.Event()
        release_cleanup = threading.Event()
        original_store_messages = agent.memory.store_messages

        def paused_store_messages(*args: Any, **kwargs: Any) -> Any:
            cleanup_started.set()
            assert release_cleanup.wait(timeout=1)
            return original_store_messages(*args, **kwargs)

        agent.memory.store_messages = paused_store_messages  # type: ignore[method-assign]
        session_id = "cancel-after-finalizer-commit"
        run_task = asyncio.create_task(agent.run("finish", session_id=session_id))
        assert await asyncio.to_thread(cleanup_started.wait, 1)

        assert agent.request_cancel(session_id) is False
        release_cleanup.set()
        state = await asyncio.wait_for(run_task, timeout=1)

        assert state.status == "completed"
        lifecycle = agent.lifecycle_store.get(session_id, "local-user")
        assert lifecycle is not None
        assert lifecycle["status"] == "completed"


class TestCheckpoint:
    @pytest.mark.asyncio
    async def test_save_and_load_checkpoint(self, agent: JSAgent) -> None:
        state = AgentState(session_id="s1", run_id="r1")
        state.turn_count = 3
        state.messages.append(ChatMessage(role="user", content="hello"))
        state.messages.append(ChatMessage(role="assistant", content="hi"))
        state.total_tokens = {"input": 10, "output": 5}
        state.cost_estimate = 0.001
        state.status = "running"

        await agent.save_checkpoint(state)
        loaded = await agent.load_checkpoint("s1")

        assert loaded is not None
        assert loaded.session_id == "s1"
        assert loaded.run_id == "r1"
        assert loaded.turn_count == 3
        assert len(loaded.messages) == 2
        assert loaded.messages[0].role == "user"
        assert loaded.messages[0].content == "hello"
        assert loaded.total_tokens == {"input": 10, "output": 5}
        assert loaded.cost_estimate == pytest.approx(0.001)
        assert loaded.status == "running"

    @pytest.mark.asyncio
    async def test_load_missing_checkpoint(self, agent: JSAgent) -> None:
        loaded = await agent.load_checkpoint("no-such-session")
        assert loaded is None

    @pytest.mark.asyncio
    async def test_resume_from_checkpoint(self, agent: JSAgent, mock_provider: SlowMockProvider) -> None:
        """Resume continues from saved state and completes."""
        # First run: one turn with tool call, then cancel
        mock_provider.set_responses([
            ChatResponse(
                content="",
                tool_calls=[{
                    "id": "call_1",
                    "type": "function",
                    "function": {"name": "file_list", "arguments": '{"path": "."}'},
                }],
                model="mock",
                usage={"prompt_tokens": 5, "completion_tokens": 5, "total_tokens": 10},
                finish_reason="tool_calls",
            ),
            ChatResponse(
                content="Done",
                tool_calls=[],
                model="mock",
                usage={"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8},
                finish_reason="stop",
            ),
        ])

        session_id = "resume-test"
        state = await agent.run("List files", session_id=session_id)
        assert state.status == "completed"
        assert state.turn_count == 2

        # Resume from checkpoint with new user input
        mock_provider.set_responses([
            ChatResponse(
                content="Resumed",
                tool_calls=[],
                model="mock",
                usage={"prompt_tokens": 2, "completion_tokens": 2, "total_tokens": 4},
                finish_reason="stop",
            ),
        ])

        resumed = await agent.resume(session_id, user_input="Continue")
        assert resumed.status == "completed"
        assert any(m.role == "user" and m.content == "Continue" for m in resumed.messages)


class TestStateStore:
    def test_save_load_delete(self, tmp_path: Path) -> None:
        store = StateStore(tmp_path / "checkpoints.db")
        store.save(
            session_id="s1",
            run_id="r1",
            turn_count=2,
            messages=[{"role": "user", "content": "hi"}],
            tool_results=[{"success": True, "output": "ok"}],
            total_tokens={"input": 5, "output": 3},
            cost_estimate=0.001,
            status="running",
            error_message="",
            compression_stats={"level": "none"},
        )

        data = store.load("s1")
        assert data is not None
        assert data["run_id"] == "r1"
        assert data["turn_count"] == 2
        assert data["messages"][0]["content"] == "hi"

        store.delete("s1")
        assert store.load("s1") is None

    def test_list_sessions(self, tmp_path: Path) -> None:
        store = StateStore(tmp_path / "checkpoints.db")
        for i in range(3):
            store.save(
                session_id=f"sess-{i}",
                run_id=f"run-{i}",
                turn_count=i,
                messages=[],
                tool_results=[],
                total_tokens={},
                cost_estimate=0.0,
                status="running",
                error_message="",
                compression_stats={},
            )
        sessions = store.list_sessions()
        assert len(sessions) == 3
        assert "sess-0" in sessions

    def test_upsert(self, tmp_path: Path) -> None:
        store = StateStore(tmp_path / "checkpoints.db")
        store.save(
            session_id="s1", run_id="r1", turn_count=1,
            messages=[], tool_results=[], total_tokens={},
            cost_estimate=0.0, status="running", error_message="",
            compression_stats={},
        )
        store.save(
            session_id="s1", run_id="r1", turn_count=2,
            messages=[], tool_results=[], total_tokens={},
            cost_estimate=0.0, status="completed", error_message="",
            compression_stats={},
        )
        data = store.load("s1")
        assert data["turn_count"] == 2
        assert data["status"] == "completed"


class TestGracefulShutdown:
    @pytest.mark.asyncio
    async def test_close_waits_for_terminal_persistence_before_releasing_resources(
        self,
        agent: JSAgent,
        mock_provider: SlowMockProvider,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        mock_provider.delay = 0
        mock_provider.set_responses(
            [
                ChatResponse(
                    content="done",
                    tool_calls=[],
                    model="mock",
                    usage={"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
                    finish_reason="stop",
                )
            ]
        )
        episode_started = threading.Event()
        release_episode = threading.Event()
        episode_finished = threading.Event()
        original_store_episode = agent.memory.store_episode

        def paused_store_episode(**kwargs: Any) -> Any:
            episode_started.set()
            assert release_episode.wait(timeout=2)
            result = original_store_episode(**kwargs)
            episode_finished.set()
            return result

        agent.memory.store_episode = paused_store_episode  # type: ignore[method-assign]
        real_wait = asyncio.wait

        async def wait_without_internal_timeout(
            futures: Any,
            *,
            timeout: float | None = None,
            return_when: str = asyncio.ALL_COMPLETED,
        ) -> Any:
            assert timeout is None, "agent.close must not abandon terminal persistence"
            return await real_wait(futures, return_when=return_when)

        monkeypatch.setattr(asyncio, "wait", wait_without_internal_timeout)

        session_id = "shutdown-finalizer-barrier"
        partition_key = runtime_partition_key(
            "js-agent",
            None,
            session_id,
        )
        run_task = asyncio.create_task(agent.run("finish", session_id=session_id))
        close_task: asyncio.Task[None] | None = None
        try:
            assert await asyncio.to_thread(episode_started.wait, 1)
            close_task = asyncio.create_task(agent.close())
            await asyncio.sleep(0.05)

            assert partition_key in agent._active_run_tasks
            assert not close_task.done()
        finally:
            release_episode.set()
            tasks = [run_task]
            if close_task is not None:
                tasks.append(close_task)
            await asyncio.gather(*tasks, return_exceptions=True)

        assert episode_finished.is_set()
        assert partition_key not in agent._active_run_tasks
        state = run_task.result()
        assert state.status == "completed"

    @pytest.mark.asyncio
    async def test_close_cancels_active_sessions(self, agent: JSAgent, mock_provider: SlowMockProvider) -> None:
        """close() signals cancellation for active sessions."""
        mock_provider.set_responses([
            ChatResponse(
                content="",
                tool_calls=[{
                    "id": "call_1",
                    "type": "function",
                    "function": {"name": "file_list", "arguments": '{"path": "."}'},
                }],
                model="mock",
                usage={"prompt_tokens": 5, "completion_tokens": 5, "total_tokens": 10},
                finish_reason="tool_calls",
            ),
        ])

        session_id = "shutdown-test"
        run_task = asyncio.create_task(agent.run("List files", session_id=session_id))
        await asyncio.sleep(0.02)  # Let run start

        # close() should signal cancellation
        await agent.close()

        state = await run_task
        assert state.status == "cancelled"
