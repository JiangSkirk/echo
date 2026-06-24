"""Regression: WebSocket progress_callback must receive redacted tool output.

v0.1.4-alpha P1: ``_execute_tool_call`` previously redacted ``result.output``
AFTER the progress_callback fired, so the WebSocket frontend received the
raw ``result.output[:200]`` preview. That window was wide enough to leak the
first ~200 chars of API keys / Bearer tokens / SK-prefixed secrets surfaced
by tools like ``shell`` (e.g. ``cat .env``) or ``file_read``.

This test exercises the real ``ToolExecutorMixin._execute_tool_call`` against
a stub tool whose output contains a secret-shaped string, and asserts the
progress_callback observes the REDACTED form.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from js.agent.tool_executor import ToolExecutorMixin
from js.security.secrets import SecretManager
from js.tools.registry import ToolParam, ToolRegistry, ToolResult, ToolSpec

_SECRET = "sk-test12345678901234567890ABCDEFGH"


class _NoopAudit:
    def log(self, *args: Any, **kwargs: Any) -> None:
        return None


class _NoopEventStore:
    def emit(self, *args: Any, **kwargs: Any) -> None:
        return None


class _NoopGuard:
    def check_repeated_failure(self, run_id: str, tool_name: str, success: bool) -> Any:
        class _R:
            decision = "allow"

        return _R()

    def check_loop(self, *args: Any, **kwargs: Any) -> Any:
        class _R:
            decision = None  # not BLOCK
            reason = ""

        return _R()

    def check_tool_result(self, *args: Any, **kwargs: Any) -> Any:
        class _R:
            decision = None  # not WARN/BLOCK
            reason = ""

        return _R()


class _NoopApprovals:
    def request(self, *args: Any, **kwargs: Any) -> bool:
        return True


class _NoopDefenseStrategies:
    def evaluate(self, ctx: Any) -> Any:
        class _R:
            blocked = False
            reason = ""

        return _R()


class _Settings:
    class _Sec:
        pass

    security = _Sec()


class _Executor(ToolExecutorMixin):
    """Concrete subclass exposing _execute_tool_call without the full Agent stack."""

    def __init__(self, tmp_path: Any) -> None:
        # Attributes the mixin reads directly.
        self.audit = _NoopAudit()
        self.event_store = _NoopEventStore()
        self.guard = _NoopGuard()
        self.approvals = _NoopApprovals()
        self.defense_strategies = _NoopDefenseStrategies()
        self.settings = _Settings()
        self.secrets = SecretManager(tmp_path / "state")
        self._current_allowed_tools: set[str] = {"stub_tool"}
        self._role = None  # disable role-based whitelist

        from js.config import ToolLimits

        real_registry = ToolRegistry(limits=ToolLimits(), guard=self.guard)
        spec = ToolSpec(
            name="stub_tool",
            description="stub",
            parameters=[ToolParam("x", "string", "x", required=False)],
            dangerous=False,
            read_only=False,
        )

        async def _handler(**_kwargs: Any) -> ToolResult:
            return ToolResult(success=True, output=f"raw token {_SECRET} ok")

        real_registry.register(spec, _handler)
        self.registry = real_registry

        import logging

        self.logger = logging.getLogger("test.tool_executor")


@pytest.mark.asyncio
async def test_progress_callback_receives_redacted_output(tmp_path):
    executor = _Executor(tmp_path)

    captured: list[tuple[str, ToolResult]] = []

    async def progress(tool_name: str, result: ToolResult) -> None:
        # Snapshot the output at callback time so a later redact cannot
        # silently mutate what we asserted on.
        captured.append((tool_name, ToolResult(success=result.success, output=result.output)))

    tc = {
        "id": "call_1",
        "function": {"name": "stub_tool", "arguments": "{}"},
    }
    msg, final_result = await executor._execute_tool_call(
        tc,
        session_id="s1",
        run_id="r1",
        user_input="hi",
        progress_callback=progress,
    )

    # Callback fired exactly once, with the redacted preview — no raw secret.
    assert len(captured) == 1
    cb_tool, cb_result = captured[0]
    assert cb_tool == "stub_tool"
    assert _SECRET not in cb_result.output
    assert "[REDACTED" in cb_result.output

    # Final result the model sees is also redacted (existing behavior preserved).
    assert _SECRET not in final_result.output
    assert "[REDACTED" in final_result.output

    # ChatMessage content the model receives is redacted too.
    assert _SECRET not in (msg.content or "")


@pytest.mark.asyncio
async def test_progress_callback_failure_does_not_break_run(tmp_path):
    """A throwing progress_callback must not abort the tool call."""
    executor = _Executor(tmp_path)

    async def bad_progress(tool_name: str, result: ToolResult) -> None:
        raise RuntimeError("frontend exploded")

    tc = {
        "id": "call_2",
        "function": {"name": "stub_tool", "arguments": "{}"},
    }
    _msg, final_result = await executor._execute_tool_call(
        tc,
        session_id="s1",
        run_id="r1",
        user_input="hi",
        progress_callback=bad_progress,
    )
    assert final_result.success is True
    assert _SECRET not in final_result.output


def test_module_imports():
    # Sanity import — keeps coverage reporters from flagging the helpers
    # as unused when the asyncio test collector misbehaves.
    assert asyncio.iscoroutinefunction(_Executor.__init__) is False
