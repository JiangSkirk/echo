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
* No-stream turn (worker.agent.run does not invoke the live callbacks at
  all) still surfaces reasoning / tool_calls via the post-scan path —
  backward-compat with the pre-PR fleet behaviour.

The fleet is built via ``AgentFleet.__new__`` so we don't have to spin up
settings, state dirs, or a full JSAgent. Only the attributes
``_execute_single`` reads are populated.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from js.agent.state import AgentState
from js.models.providers import ChatMessage
from js.orchestration.fleet import AgentFleet, AgentInstance, AgentRole, Task


def _make_fleet() -> AgentFleet:
    """Build a minimal AgentFleet that ``_execute_single`` can run on."""
    fleet = AgentFleet.__new__(AgentFleet)
    fleet._semaphore = asyncio.Semaphore(2)  # type: ignore[attr-defined]
    fleet._event_callbacks = []  # type: ignore[attr-defined]
    return fleet


class _ScriptedAgent:
    """Fake ``JSAgent`` whose ``run`` drives the PR-4.3 callback contract."""

    def __init__(
        self,
        *,
        tokens: list[str] | None = None,
        events: list[dict[str, Any]] | None = None,
        final_message: str = "ok",
        messages: list[ChatMessage] | None = None,
    ) -> None:
        self._tokens = tokens or []
        self._events = events or []
        self._final = final_message
        self._extra_messages = messages or []

    async def run(
        self,
        prompt: str,
        *,
        model: str | None = None,
        progress_callback: Any = None,
        stream_callback: Any = None,
        event_callback: Any = None,
    ) -> AgentState:
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
        state.status = "completed"
        return state


def _worker(agent: _ScriptedAgent, name: str = "w1") -> AgentInstance:
    return AgentInstance(
        id=f"a-{name}",
        name=name,
        role=AgentRole("worker"),
        agent=agent,  # type: ignore[arg-type]
        model="m1",
    )


def _task(desc: str = "do thing") -> Task:
    return Task(id="t1", description=desc, role_hint=AgentRole("worker"))


@pytest.mark.asyncio
class TestFleetRealtimeEvents:
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
