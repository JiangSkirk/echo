"""Tests for PR-4.4 Fleet real-time streaming events.

Scope: drive ``AgentFleet._execute_single`` with a mock worker that simulates
the PR-4.3 ``stream_callback`` / ``event_callback`` flow and assert the
fleet WebSocket event bus (``_emit``) receives the new live frames:

* ``agent_token``       — final-response text deltas
* ``agent_thinking``    — model reasoning deltas (live)
* ``agent_tool_call``   — streaming tool-call fragments (live)
* ``agent_usage``       — in-stream usage event
* ``agent_error``       — streaming provider error
* ``agent_done``        — task complete (already present in pre-PR fleet)

Also covered:

* Dedup: when the post-scan loop sees the same reasoning / tool-call that
  was already streamed live, it does NOT re-emit (UI doesn't see doubles).
* No-stream turn (``run_echo_turn`` / ``echo_runtime.run_agent_turn`` does not
  invoke the live callbacks at all) still surfaces reasoning / tool_calls
  via the post-scan path — backward-compat with the pre-PR fleet behaviour.
* Channel / owner / session lineage is passed through ``run_echo_turn``.

The fleet is built via ``AgentFleet.__new__`` so we don't have to spin up
settings, state dirs, or a full JSAgent. Only the attributes
``_execute_single`` reads are populated.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from js.agent.state import AgentState
from js.echo.turn_context import RuntimeContext, reset_runtime_context, set_runtime_context
from js.echo.turn_runtime import EchoRuntime, TurnRequest
from js.models.providers import ChatMessage
from js.orchestration.fleet import AgentFleet, AgentInstance, AgentRole, Task


def _make_fleet() -> AgentFleet:
    """Build a minimal AgentFleet that ``_execute_single`` can run on."""
    fleet = AgentFleet.__new__(AgentFleet)
    fleet._semaphore = asyncio.Semaphore(2)  # type: ignore[attr-defined]
    fleet._event_callbacks = []  # type: ignore[attr-defined]
    return fleet


class _Pulse:
    def observe(self, **_kwargs: Any) -> Any:
        return SimpleNamespace(admitted=True)


class _ScriptedLoop:
    def __init__(self, agent: _ScriptedAgent, request: TurnRequest) -> None:
        self._agent = agent
        self._request = request

    async def execute(self) -> AgentState:
        request = self._request
        runtime = self._agent.echo_runtime
        runtime.calls.append(  # type: ignore[attr-defined]
            {
                "message": request.message,
                "channel": request.context.channel,
                "owner_key_hash": request.context.owner_key_hash,
                "session_id": request.context.session_id,
                "model": request.model,
                "attachments": list(request.attachments),
            }
        )
        return await self._agent._drive(
            request.message,
            model=request.model,
            progress_callback=request.progress_callback,
            stream_callback=request.stream_callback,
            event_callback=request.event_callback,
        )


class _ScriptedAgent:
    """Fake ``JSAgent`` whose ``echo_runtime.run_agent_turn`` drives callbacks."""

    def __init__(
        self,
        *,
        tokens: list[str] | None = None,
        events: list[dict[str, Any]] | None = None,
        final_message: str = "ok",
        final_status: str = "completed",
        messages: list[ChatMessage] | None = None,
    ) -> None:
        self._tokens = tokens or []
        self._events = events or []
        self._final = final_message
        self._status = final_status
        self._extra_messages = messages or []
        self.settings = SimpleNamespace(
            workspace=Path("/tmp"),
            state_dir=Path("/tmp"),
            echo_engine="on",
            product_id="js-agent",
        )
        self.registry = SimpleNamespace(list_tools=lambda: [])
        self._current_allowed_tools: set[str] = set()
        self._lane_executor = None
        self._shutdown_requested = False
        self.echo_runtime = EchoRuntime(
            self,
            pulse_runtime=_Pulse(),
            turn_loop_factory=lambda agent, request: _ScriptedLoop(agent, request),
        )
        self.echo_runtime.calls = []  # type: ignore[attr-defined]

    async def _drive(
        self,
        prompt: str,
        *,
        model: str | None = None,
        progress_callback: Any = None,
        stream_callback: Any = None,
        event_callback: Any = None,
    ) -> AgentState:
        del prompt, model, progress_callback  # unused in scripted path
        # Live deltas first
        for t in self._tokens:
            if stream_callback is not None:
                await stream_callback(t)
        for ev in self._events:
            if event_callback is not None:
                await event_callback(ev)

        # Build a state with whatever extra messages the test wanted (used
        # for the post-scan fallback path) plus the final assistant reply.
        msgs: list[ChatMessage] = list(self._extra_messages)
        msgs.append(ChatMessage(role="assistant", content=self._final))
        state = AgentState(session_id="s1", run_id="r1")
        state.messages = msgs
        state.status = self._status
        return state


def _worker(
    agent: _ScriptedAgent,
    name: str = "w1",
    *,
    product_id: str = "js-agent",
    owner_key_hash: str = "fleet-local",
) -> AgentInstance:
    return AgentInstance(
        id=f"a-{name}",
        name=name,
        role=AgentRole("worker"),
        agent=agent,  # type: ignore[arg-type]
        product_id=product_id,
        owner_key_hash=owner_key_hash,
        model="m1",
    )


def _task(desc: str = "do thing") -> Task:
    return Task(id="t1", description=desc, role_hint=AgentRole("worker"))


@pytest.mark.asyncio
class TestFleetRealtimeEvents:
    async def test_worker_stream_events_reach_only_matching_owner_subscription(self) -> None:
        fleet = _make_fleet()
        received_a: list[dict[str, Any]] = []
        received_b: list[dict[str, Any]] = []

        async def collect_a(event: dict[str, Any]) -> None:
            received_a.append(event)

        async def collect_b(event: dict[str, Any]) -> None:
            received_b.append(event)

        fleet.on_event(collect_a, product_id="js-agent", owner_key_hash="owner-a")
        fleet.on_event(collect_b, product_id="js-agent", owner_key_hash="owner-b")
        agent = _ScriptedAgent(
            tokens=["result-a"],
            events=[
                {"kind": "thinking_delta", "text": "thinking-a"},
                {
                    "kind": "tool_call_delta",
                    "tool_call": {
                        "id": "call-a",
                        "name": "search",
                        "arguments_delta": "{}",
                    },
                },
            ],
            final_message="result-a",
        )
        parent = RuntimeContext(
            product_id="js-agent",
            channel="api_chat",
            owner_key_hash="owner-a",
            session_id="session-a",
            run_id="run-a",
            role="local-user",
            profile="default",
            capabilities=(),
            workspace=Path("/tmp"),
            state_dir=Path("/tmp"),
        )
        token = set_runtime_context(parent)
        try:
            await fleet._execute_single(
                _task("owner-a task"),
                _worker(agent, owner_key_hash="owner-a"),
            )
        finally:
            reset_runtime_context(token)

        event_types = {event["type"] for event in received_a}
        assert {
            "agent_start",
            "agent_token",
            "agent_thinking",
            "agent_tool_call",
            "agent_done",
        } <= event_types
        assert received_b == []
        assert all("owner_key_hash" not in event for event in received_a)

    async def test_live_text_tokens_emit_agent_token_frames(self) -> None:
        fleet = _make_fleet()
        received: list[dict[str, Any]] = []

        async def collect(ev: dict[str, Any]) -> None:
            received.append(ev)

        fleet.on_event(collect)

        agent = _ScriptedAgent(tokens=["hello ", "world"], final_message="hello world")
        await fleet._execute_single(_task(), _worker(agent))

        token_frames = [e for e in received if e["type"] == "agent_token"]
        assert [t["content"] for t in token_frames] == ["hello ", "world"]
        # Every frame carries enough attribution for the dashboard.
        for frame in token_frames:
            assert frame["agent_id"] == "a-w1"
            assert frame["agent_role"] == "worker"
            assert frame["task_id"] == "t1"

        identities = {
            (frame["request_id"], frame["turn_id"], frame["session_id"])
            for frame in received
        }
        assert len(identities) == 1
        assert all(identities.pop())

    async def test_direct_worker_executions_do_not_share_generated_identity(self) -> None:
        fleet = _make_fleet()
        received: list[dict[str, Any]] = []

        async def collect(event: dict[str, Any]) -> None:
            received.append(event)

        fleet.on_event(collect)
        task_a = Task(id="task-a", description="first", role_hint=AgentRole("worker"))
        task_b = Task(id="task-b", description="second", role_hint=AgentRole("worker"))

        await asyncio.gather(
            fleet._execute_single(task_a, _worker(_ScriptedAgent(), name="a")),
            fleet._execute_single(task_b, _worker(_ScriptedAgent(), name="b")),
        )

        identities_by_task = {
            task_id: {
                (event["request_id"], event["turn_id"], event["session_id"])
                for event in received
                if event.get("task_id") == task_id
            }
            for task_id in ("task-a", "task-b")
        }
        assert all(len(identities) == 1 for identities in identities_by_task.values())
        assert identities_by_task["task-a"] != identities_by_task["task-b"]

    async def test_thinking_delta_emits_agent_thinking_live(self) -> None:
        fleet = _make_fleet()
        received: list[dict[str, Any]] = []

        async def collect(ev: dict[str, Any]) -> None:
            received.append(ev)

        fleet.on_event(collect)

        agent = _ScriptedAgent(
            events=[{"kind": "thinking_delta", "text": "let me consider"}],
            final_message="answer",
        )
        await fleet._execute_single(_task(), _worker(agent))

        thinking = [e for e in received if e["type"] == "agent_thinking"]
        assert len(thinking) == 1
        assert thinking[0]["content"] == "let me consider"

    async def test_tool_call_delta_emits_agent_tool_call(self) -> None:
        fleet = _make_fleet()
        received: list[dict[str, Any]] = []

        async def collect(ev: dict[str, Any]) -> None:
            received.append(ev)

        fleet.on_event(collect)

        agent = _ScriptedAgent(
            events=[
                {
                    "kind": "tool_call_delta",
                    "tool_call": {
                        "index": 0,
                        "id": "call_xyz",
                        "name": "lookup",
                        "arguments_delta": '{"q":"x"',
                    },
                }
            ],
            final_message="done",
        )
        await fleet._execute_single(_task(), _worker(agent))

        tcs = [e for e in received if e["type"] == "agent_tool_call"]
        assert len(tcs) == 1
        assert tcs[0]["tool_name"] == "lookup"
        assert tcs[0]["arguments"] == '{"q":"x"'

    async def test_usage_event_emits_agent_usage(self) -> None:
        fleet = _make_fleet()
        received: list[dict[str, Any]] = []

        async def collect(ev: dict[str, Any]) -> None:
            received.append(ev)

        fleet.on_event(collect)

        agent = _ScriptedAgent(
            events=[
                {
                    "kind": "usage",
                    "usage": {
                        "prompt_tokens": 11,
                        "completion_tokens": 22,
                        "total_tokens": 33,
                        "cached_tokens": 0,
                    },
                }
            ],
            final_message="x",
        )
        await fleet._execute_single(_task(), _worker(agent))

        usage = [e for e in received if e["type"] == "agent_usage"]
        assert len(usage) == 1
        assert usage[0]["usage"]["completion_tokens"] == 22

    async def test_error_event_emits_agent_error(self) -> None:
        fleet = _make_fleet()
        received: list[dict[str, Any]] = []

        async def collect(ev: dict[str, Any]) -> None:
            received.append(ev)

        fleet.on_event(collect)

        agent = _ScriptedAgent(
            events=[{"kind": "error", "error": "upstream rate-limited"}],
            final_message="partial",
        )
        await fleet._execute_single(_task(), _worker(agent))

        errs = [e for e in received if e["type"] == "agent_error"]
        assert len(errs) == 1
        assert "rate-limited" in errs[0]["content"]

    async def test_live_thinking_dedupes_post_scan(self) -> None:
        """If a thinking_delta arrived live AND the same reasoning is on the
        final assistant message, the post-scan loop must NOT re-emit it."""
        fleet = _make_fleet()
        received: list[dict[str, Any]] = []

        async def collect(ev: dict[str, Any]) -> None:
            received.append(ev)

        fleet.on_event(collect)

        live_text = "live reasoning that also lands on the msg"
        post_msg = ChatMessage(role="assistant", content="ignored")
        # Stash the same reasoning on the message log so the post-scan
        # path sees it. ChatMessage allows reasoning_content as a field.
        post_msg.reasoning_content = live_text  # type: ignore[attr-defined]

        agent = _ScriptedAgent(
            events=[{"kind": "thinking_delta", "text": live_text}],
            final_message="final",
            messages=[post_msg],
        )
        await fleet._execute_single(_task(), _worker(agent))

        thinking = [e for e in received if e["type"] == "agent_thinking"]
        # Live event landed; post-scan did NOT add a second one.
        assert len(thinking) == 1
        assert thinking[0]["content"] == live_text

    async def test_no_stream_turn_still_surfaces_reasoning_via_postscan(self) -> None:
        """Tool-using turns that bypass the stream still emit thinking /
        tool_call via the post-scan fallback — backward-compat with the
        pre-PR-4.4 behaviour."""
        fleet = _make_fleet()
        received: list[dict[str, Any]] = []

        async def collect(ev: dict[str, Any]) -> None:
            received.append(ev)

        fleet.on_event(collect)

        only_post_msg = ChatMessage(role="assistant", content="hi")
        only_post_msg.reasoning_content = "post-scan reasoning"  # type: ignore[attr-defined]
        only_post_msg.tool_calls = [  # type: ignore[attr-defined]
            {
                "id": "call_q",
                "function": {"name": "search", "arguments": '{"q":"a"}'},
            }
        ]

        # No live tokens, no live events — the live path is silent.
        agent = _ScriptedAgent(
            tokens=[],
            events=[],
            final_message="hi",
            messages=[only_post_msg],
        )
        await fleet._execute_single(_task(), _worker(agent))

        thinking = [e for e in received if e["type"] == "agent_thinking"]
        tcs = [e for e in received if e["type"] == "agent_tool_call"]
        assert len(thinking) == 1
        assert thinking[0]["content"] == "post-scan reasoning"
        assert len(tcs) == 1
        assert tcs[0]["tool_name"] == "search"

    async def test_full_event_sequence_includes_start_token_done(self) -> None:
        """End-to-end ordering smoke test: start → token(s) → done."""
        fleet = _make_fleet()
        received: list[dict[str, Any]] = []

        async def collect(ev: dict[str, Any]) -> None:
            received.append(ev)

        fleet.on_event(collect)

        agent = _ScriptedAgent(
            tokens=["a", "b"],
            events=[
                {
                    "kind": "usage",
                    "usage": {
                        "prompt_tokens": 1,
                        "completion_tokens": 2,
                        "total_tokens": 3,
                        "cached_tokens": 0,
                    },
                }
            ],
            final_message="ab",
        )
        await fleet._execute_single(_task(), _worker(agent))

        kinds = [e["type"] for e in received]
        # Sanity: start first, done last.
        assert kinds[0] == "agent_start"
        assert kinds[-1] == "agent_done"
        # All new live channels are present somewhere in between.
        assert "agent_token" in kinds
        assert "agent_usage" in kinds

    async def test_cancelled_worker_preserves_cancelled_terminal_status(self) -> None:
        fleet = _make_fleet()
        received: list[dict[str, Any]] = []

        async def collect(event: dict[str, Any]) -> None:
            received.append(event)

        fleet.on_event(collect)
        task = _task("cancelled synthetic task")
        agent = _ScriptedAgent(final_message="", final_status="cancelled")

        await fleet._execute_single(task, _worker(agent))

        assert task.status == "cancelled"
        assert task.result == "Task was cancelled"
        done = [event for event in received if event["type"] == "agent_done"]
        assert done[-1]["status"] == "cancelled"

    async def test_cancelling_fleet_coroutine_records_cancelled_terminal(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        fleet = _make_fleet()
        received: list[dict[str, Any]] = []
        started = asyncio.Event()

        async def collect(event: dict[str, Any]) -> None:
            received.append(event)

        async def block_turn(*_args: Any, **_kwargs: Any) -> AgentState:
            started.set()
            await asyncio.Event().wait()
            raise AssertionError("unreachable")

        monkeypatch.setattr("js.orchestration.fleet.run_echo_turn", block_turn)
        fleet.on_event(collect)
        task = _task("cancelled coroutine task")
        execution = asyncio.create_task(
            fleet._execute_single(task, _worker(_ScriptedAgent()))
        )
        await started.wait()
        execution.cancel()

        with pytest.raises(asyncio.CancelledError):
            await execution

        assert task.status == "cancelled"
        assert task.result == "Task was cancelled"
        done = [event for event in received if event["type"] == "agent_done"]
        assert done[-1]["status"] == "cancelled"

    async def test_worker_defaults_channel_owner_session_lineage(self) -> None:
        """Without parent runtime context, worker uses fleet defaults."""
        fleet = _make_fleet()
        agent = _ScriptedAgent(tokens=["x"], final_message="x")
        await fleet._execute_single(_task("lineage default"), _worker(agent))

        assert len(agent.echo_runtime.calls) == 1
        call = agent.echo_runtime.calls[0]
        assert call["channel"] == "fleet_worker"
        assert call["owner_key_hash"] == "fleet-local"
        assert call["session_id"]
        assert call["model"] == "m1"
        assert call["message"] == "lineage default"

    async def test_worker_inherits_parent_owner_and_session(self) -> None:
        """When a parent Echo context is bound, fleet reuses its lineage."""
        fleet = _make_fleet()
        agent = _ScriptedAgent(tokens=["y"], final_message="y")
        parent = RuntimeContext(
            product_id="js-agent",
            channel="api_chat",
            owner_key_hash="owner-from-parent",
            session_id="session-from-parent",
            run_id="run-parent",
            role="local-user",
            profile="default",
            capabilities=(),
            workspace=Path("/tmp"),
            state_dir=Path("/tmp"),
        )
        token = set_runtime_context(parent)
        try:
            await fleet._execute_single(
                _task("lineage inherit"),
                _worker(agent, owner_key_hash="owner-from-parent"),
            )
        finally:
            reset_runtime_context(token)

        assert len(agent.echo_runtime.calls) == 1
        call = agent.echo_runtime.calls[0]
        assert call["channel"] == "fleet_worker"
        assert call["owner_key_hash"] == "owner-from-parent"
        assert call["session_id"] == "session-from-parent"

    async def test_worker_rejects_mismatched_owner_lineage(self) -> None:
        fleet = _make_fleet()
        agent = _ScriptedAgent(final_message="must not run")
        parent = RuntimeContext(
            product_id="js-agent",
            channel="api_chat",
            owner_key_hash="owner-b",
            session_id="session-b",
            run_id="run-b",
            role="local-user",
            profile="default",
            capabilities=(),
            workspace=Path("/tmp"),
            state_dir=Path("/tmp"),
        )
        token = set_runtime_context(parent)
        try:
            _task_id, result = await fleet._execute_single(
                _task("cross-owner"),
                _worker(agent, owner_key_hash="owner-a"),
            )
        finally:
            reset_runtime_context(token)

        assert result == "Fleet task failed safely"
        assert "owner-a" not in result
        assert "owner-b" not in result
        assert agent.echo_runtime.calls == []

    async def test_coordinator_uses_fleet_coordinator_channel(self) -> None:
        """Manager/reviewer one-offs go through fleet_coordinator channel."""
        fleet = _make_fleet()
        agent = _ScriptedAgent(final_message="coord-ok")
        text = await fleet._run_agent(_worker(agent, name="mgr"), "synthesize")
        assert text == "coord-ok"
        assert len(agent.echo_runtime.calls) == 1
        call = agent.echo_runtime.calls[0]
        assert call["channel"] == "fleet_coordinator"
        assert call["owner_key_hash"] == "fleet-local"
        assert call["model"] == "m1"
        assert call["message"] == "synthesize"

    async def test_run_parallel_parent_cancel_cancels_all_children(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """D-fix: 父任务取消必须级联取消所有子任务，零 pending Task."""
        fleet = _make_fleet()
        started = asyncio.Event()

        async def block_turn(*_args: Any, **_kwargs: Any) -> AgentState:
            started.set()
            await asyncio.Event().wait()  # block forever
            raise AssertionError("unreachable")

        monkeypatch.setattr("js.orchestration.fleet.run_echo_turn", block_turn)

        tasks = [_task("t1"), _task("t2")]
        tasks[0].id = "t1"
        tasks[1].id = "t2"
        workers = [
            _worker(_ScriptedAgent(), name="w1"),
            _worker(_ScriptedAgent(), name="w2"),
        ]

        parallel_exec = asyncio.create_task(
            fleet._run_parallel(tasks, workers)
        )
        await started.wait()

        # Cancel parent
        parallel_exec.cancel()
        with pytest.raises(asyncio.CancelledError):
            await parallel_exec

        # Both child tasks must be cancelled (not still running)
        assert tasks[0].status == "cancelled", f"t1 应为 cancelled, got {tasks[0].status}"
        assert tasks[1].status == "cancelled", f"t2 应为 cancelled, got {tasks[1].status}"
