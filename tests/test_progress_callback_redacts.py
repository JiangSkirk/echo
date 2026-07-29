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
import dataclasses
from typing import Any

import pytest

from js.agent.tool_executor import ToolExecutorMixin
from js.echo.capability import LeaseAuthority, sign_tool_execution_context
from js.echo.durable_thread import EchoDurableExecutor
from js.echo.ledger.service import EchoSafetyService
from js.echo.primitives import stable_payload_hash
from js.echo.turn_context import RuntimeContext, reset_runtime_context, set_runtime_context
from js.echo.types import CapabilityLease
from js.security.approvals import ApprovalDecision, ApprovalDecisionType
from js.security.secrets import SecretManager
from js.tools.registry import (
    EchoToolExecutionContext,
    ToolParam,
    ToolRegistry,
    ToolResult,
    ToolSpec,
)

_SECRET = "sk-test12345678901234567890ABCDEFGH"

_TEST_DURABLE_EXECUTOR = EchoDurableExecutor(
    max_claim_pending=8,
    max_finish_pending=8,
    claim_workers=2,
    finish_workers=2,
    thread_name_prefix="echo-progress-test",
)
_TEST_SAFETY_SERVICES: list[EchoSafetyService] = []


@pytest.fixture(scope="module", autouse=True)
def _close_echo_test_resources() -> Any:
    yield
    for service in reversed(_TEST_SAFETY_SERVICES):
        service.close()
    _TEST_DURABLE_EXECUTOR.shutdown(wait=True)


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


class _DecisionApprovals:
    def __init__(self, decision: ApprovalDecision) -> None:
        self.decision = decision
        self.requests: list[dict[str, Any]] = []

    def request_decision(self, *args: Any, **kwargs: Any) -> ApprovalDecision:
        self.requests.append({"args": args, "kwargs": kwargs})
        return self.decision

    def request(self, *args: Any, **kwargs: Any) -> bool:
        raise AssertionError("dangerous Echo tools must use request_decision")


class _PendingThenApprove:
    def __init__(self) -> None:
        self.polls = 0
        self.request_kwargs: dict[str, Any] = {}

    def request_decision(self, *args: Any, **kwargs: Any) -> ApprovalDecision:
        self.request_kwargs = kwargs
        return ApprovalDecision(
            ApprovalDecisionType.PENDING,
            request_id="approval-pending",
        )

    def take_decision(
        self,
        request_id: str,
        *,
        owner_key_hash: str | None = None,
    ) -> ApprovalDecision | None:
        assert request_id == "approval-pending"
        assert owner_key_hash == "owner-a"
        self.polls += 1
        if self.polls < 2:
            return None
        return ApprovalDecision(
            ApprovalDecisionType.APPROVE,
            request_id=request_id,
            reason="web operator",
        )

    def get_pending_request(
        self,
        request_id: str,
        *,
        owner_key_hash: str | None = None,
    ) -> Any:
        assert request_id == "approval-pending"
        assert owner_key_hash == "owner-a"
        return type("_Pending", (), {"timeout_seconds": 1.0})()


class _ResolvedBetweenPollAndPendingLookup:
    def __init__(self) -> None:
        self.take_calls = 0

    def take_decision(
        self,
        request_id: str,
        *,
        owner_key_hash: str | None = None,
    ) -> ApprovalDecision | None:
        assert request_id == "approval-race"
        assert owner_key_hash == "owner-a"
        self.take_calls += 1
        if self.take_calls == 1:
            return None
        return ApprovalDecision(
            ApprovalDecisionType.APPROVE,
            request_id=request_id,
        )

    def get_pending_request(
        self,
        request_id: str,
        *,
        owner_key_hash: str | None = None,
    ) -> None:
        assert request_id == "approval-race"
        assert owner_key_hash == "owner-a"
        return None


class _NoopDefenseStrategies:
    def evaluate(self, ctx: Any) -> Any:
        class _R:
            blocked = False
            reason = ""

        return _R()


class _BlockEditedDefenseStrategies:
    def __init__(self) -> None:
        self.arguments_seen: list[dict[str, Any]] = []

    def evaluate(self, ctx: Any) -> Any:
        self.arguments_seen.append(dict(ctx.arguments))

        class _R:
            blocked = ctx.arguments.get("x") == "blocked-after-edit"
            reason = "edited arguments are blocked"

        return _R()


class _Settings:
    class _Sec:
        pass

    security = _Sec()
    echo_engine = "on"


class _Executor(ToolExecutorMixin):
    """Concrete subclass exposing _execute_tool_call without the full Agent stack."""

    def __init__(
        self,
        tmp_path: Any,
        *,
        read_only: bool = False,
        dangerous: bool = False,
        approvals: Any | None = None,
        handler_result: ToolResult | None = None,
    ) -> None:
        # Attributes the mixin reads directly.
        self.audit = _NoopAudit()
        self.event_store = _NoopEventStore()
        self.guard = _NoopGuard()
        self.approvals = approvals or _NoopApprovals()
        self.defense_strategies = _NoopDefenseStrategies()
        self.settings = _Settings()
        self.settings.state_dir = tmp_path / "state"
        self.settings.workspace = tmp_path / "workspace"
        self.secrets = SecretManager(tmp_path / "state")
        self._echo_durable_executor = _TEST_DURABLE_EXECUTOR
        self.echo_safety_service = EchoSafetyService(state_dir=self.settings.state_dir)
        _TEST_SAFETY_SERVICES.append(self.echo_safety_service)
        self._current_allowed_tools: set[str] = {"stub_tool"}
        self._role = None  # disable role-based whitelist
        self.handler_calls = 0
        self.last_kwargs: dict[str, Any] = {}

        from js.config import ToolLimits

        real_registry = ToolRegistry(limits=ToolLimits(), guard=self.guard)
        spec = ToolSpec(
            name="stub_tool",
            description="stub",
            parameters=[ToolParam("x", "string", "x", required=False)],
            dangerous=dangerous,
            read_only=read_only,
        )

        async def _handler(**_kwargs: Any) -> ToolResult:
            self.handler_calls += 1
            self.last_kwargs = dict(_kwargs)
            return handler_result or ToolResult(success=True, output=f"raw token {_SECRET} ok")

        real_registry.register(spec, _handler)
        self.registry = real_registry

        import logging

        self.logger = logging.getLogger("test.tool_executor")


class _TrackingAuthority:
    def __init__(self) -> None:
        self._inner = LeaseAuthority(mac_key=b"tool-lease-test-key", now_fn=lambda: 1_000)
        self._now = self._inner._now
        self.issued: list[dict[str, Any]] = []
        self.verified = 0
        self.consumed = 0

    def issue(self, **kwargs: Any) -> CapabilityLease:
        self.issued.append(dict(kwargs))
        return self._inner.issue(**kwargs)

    def verify(self, *args: Any, **kwargs: Any) -> None:
        self.verified += 1
        return self._inner.verify(*args, **kwargs)

    def consume(self, *args: Any, **kwargs: Any) -> None:
        self.consumed += 1
        return self._inner.consume(*args, **kwargs)

    def verify_execution_context(self, *args: Any, **kwargs: Any) -> None:
        return self._inner.verify_execution_context(*args, **kwargs)

    def consume_execution_context(self, *args: Any, **kwargs: Any) -> None:
        self.consumed += 1
        return self._inner.consume_execution_context(*args, **kwargs)

    def _context_signing_key(self) -> bytes:
        return self._inner._context_signing_key()


class _TamperingAuthority:
    def __init__(self) -> None:
        self._inner = LeaseAuthority(mac_key=b"tool-lease-test-key", now_fn=lambda: 1_000)

    def issue(self, **kwargs: Any) -> CapabilityLease:
        kwargs["owner_key_hash"] = "other-owner"
        return self._inner.issue(**kwargs)

    def verify(self, *args: Any, **kwargs: Any) -> None:
        return self._inner.verify(*args, **kwargs)

    def consume(self, *args: Any, **kwargs: Any) -> None:
        return self._inner.consume(*args, **kwargs)

    def verify_execution_context(self, *args: Any, **kwargs: Any) -> None:
        return self._inner.verify_execution_context(*args, **kwargs)

    def consume_execution_context(self, *args: Any, **kwargs: Any) -> None:
        return self._inner.consume_execution_context(*args, **kwargs)

    def _context_signing_key(self) -> bytes:
        return self._inner._context_signing_key()


class _CrossRunAuthority(_TrackingAuthority):
    def issue(self, **kwargs: Any) -> CapabilityLease:
        lease = super().issue(**kwargs)
        return dataclasses.replace(lease, run_id="other-run")


class _ArgsMismatchAuthority(_TrackingAuthority):
    def issue(self, **kwargs: Any) -> CapabilityLease:
        lease = super().issue(**kwargs)
        return dataclasses.replace(lease, args_schema="other-args")


def test_runtime_context_role_overrides_shared_agent_role(tmp_path):
    executor = _Executor(tmp_path)
    executor._role = "coder"
    context = RuntimeContext(
        product_id="js-agent",
        channel="ws_stream",
        owner_key_hash="owner-a",
        session_id="s1",
        run_id="r1",
        role="reviewer",
        profile="default",
        capabilities=("stub_tool",),
        workspace=tmp_path,
        state_dir=tmp_path / "state",
    )
    token = set_runtime_context(context)
    try:
        assert executor._effective_tool_role("s1", "r1") == "reviewer"
    finally:
        reset_runtime_context(token)


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
async def test_tool_result_redacts_error_and_metadata_before_downstream_use(tmp_path):
    raw_result = ToolResult(
        success=True,
        output=f"output {_SECRET}",
        error=f"provider failed with {_SECRET}",
        metadata={
            "token": _SECRET,
            "nested": [{"detail": f"private {_SECRET}"}],
        },
    )
    executor = _Executor(tmp_path, handler_result=raw_result)
    executor.registry._is_cacheable = lambda _tool_name: True
    captured: list[ToolResult] = []

    async def progress(_tool_name: str, result: ToolResult) -> None:
        captured.append(
            ToolResult(
                success=result.success,
                output=result.output,
                error=result.error,
                metadata=dict(result.metadata),
            )
        )

    msg, final_result = await executor._execute_tool_call(
        {"id": "call-private-result", "function": {"name": "stub_tool", "arguments": "{}"}},
        session_id="s-private-result",
        run_id="r-private-result",
        user_input="hi",
        progress_callback=progress,
    )

    assert _SECRET not in str(captured)
    assert _SECRET not in str(final_result)
    assert _SECRET not in (msg.content or "")
    assert "[REDACTED" in final_result.error
    assert "[REDACTED" in str(final_result.metadata)
    assert executor.registry._result_cache == {}


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


@pytest.mark.asyncio
async def test_run_local_allowed_tools_override_shared_agent_state(tmp_path):
    executor = _Executor(tmp_path)
    executor._current_allowed_tools = {"stub_tool"}

    tc = {
        "id": "call_3",
        "function": {"name": "stub_tool", "arguments": "{}"},
    }
    msg, final_result = await executor._execute_tool_call(
        tc,
        session_id="s1",
        run_id="r1",
        user_input="hi",
        allowed_tools={"other_tool"},
    )

    assert final_result.success is False
    assert "not available" in (final_result.error or "")
    assert msg.name == "stub_tool"


@pytest.mark.asyncio
async def test_echo_tool_execution_consumes_capability_lease(tmp_path):
    executor = _Executor(tmp_path)
    authority = LeaseAuthority(mac_key=b"tool-lease-test-key", now_fn=lambda: 1_000)
    executor._tool_lease_authority = authority

    tc = {
        "id": "call_4",
        "function": {"name": "stub_tool", "arguments": '{"x":"ok"}'},
    }
    _msg, final_result = await executor._execute_tool_call(
        tc,
        session_id="s1",
        run_id="r1",
        user_input="hi",
        allowed_tools={"stub_tool"},
    )

    assert final_result.success is True
    assert executor.handler_calls == 1
    assert authority._nonces == {}


@pytest.mark.asyncio
async def test_dangerous_echo_tool_reject_decision_blocks_before_lease(tmp_path):
    decision = ApprovalDecision(
        action=ApprovalDecisionType.REJECT,
        request_id="approval-reject",
        reason="too broad",
    )
    approvals = _DecisionApprovals(decision)
    executor = _Executor(tmp_path, dangerous=True, approvals=approvals)
    authority = _TrackingAuthority()
    executor._tool_lease_authority = authority

    tc = {
        "id": "call_reject",
        "function": {"name": "stub_tool", "arguments": '{"x":"unsafe"}'},
    }
    msg, final_result = await executor._execute_tool_call(
        tc,
        session_id="s1",
        run_id="r1",
        user_input="hi",
        allowed_tools={"stub_tool"},
    )

    assert final_result.success is False
    assert "approval rejected" in final_result.error.lower()
    assert executor.handler_calls == 0
    # P0-1 fix: approval effect now issues a real CapabilityLease for echo_approval
    tool_leases = [lease for lease in authority.issued if lease["tool_name"] != "echo_approval"]
    assert tool_leases == []
    assert msg.name == "stub_tool"


@pytest.mark.asyncio
async def test_dangerous_echo_tool_edit_decision_reissues_lease_for_edited_args(tmp_path):
    decision = ApprovalDecision(
        action=ApprovalDecisionType.EDIT,
        request_id="approval-edit",
        edited_arguments={"x": "safe"},
        reason="narrow args",
    )
    approvals = _DecisionApprovals(decision)
    executor = _Executor(tmp_path, dangerous=True, approvals=approvals)
    authority = _TrackingAuthority()
    executor._tool_lease_authority = authority

    tc = {
        "id": "call_edit",
        "function": {"name": "stub_tool", "arguments": '{"x":"unsafe"}'},
    }
    _msg, final_result = await executor._execute_tool_call(
        tc,
        session_id="s1",
        run_id="r1",
        user_input="hi",
        allowed_tools={"stub_tool"},
    )

    assert final_result.success is True
    assert executor.handler_calls == 1
    assert executor.last_kwargs == {"x": "safe"}
    # P0-1 fix: approval lease is issued first, tool-execution lease second
    tool_leases = [lease for lease in authority.issued if lease["tool_name"] == "stub_tool"]
    assert len(tool_leases) == 1
    assert tool_leases[0]["args_schema"] == stable_payload_hash({"x": "safe"})


@pytest.mark.asyncio
async def test_dangerous_echo_tool_edit_reruns_defense_strategies(tmp_path):
    decision = ApprovalDecision(
        action=ApprovalDecisionType.EDIT,
        request_id="approval-edit-blocked",
        edited_arguments={"x": "blocked-after-edit"},
        reason="operator supplied replacement",
    )
    executor = _Executor(
        tmp_path,
        dangerous=True,
        approvals=_DecisionApprovals(decision),
    )
    strategies = _BlockEditedDefenseStrategies()
    executor.defense_strategies = strategies
    authority = _TrackingAuthority()
    executor._tool_lease_authority = authority

    _message, result = await executor._execute_tool_call(
        {
            "id": "call_edit_blocked",
            "function": {"name": "stub_tool", "arguments": '{"x":"safe"}'},
        },
        session_id="s1",
        run_id="r1",
        user_input="hi",
        allowed_tools={"stub_tool"},
    )

    assert result.success is False
    assert "edited arguments are blocked" in result.error
    assert strategies.arguments_seen == [
        {"x": "safe"},
        {"x": "blocked-after-edit"},
    ]
    assert executor.handler_calls == 0
    # P0-1 fix: approval effect issues a real lease; only tool-execution leases should be absent
    tool_leases = [lease for lease in authority.issued if lease["tool_name"] != "echo_approval"]
    assert tool_leases == []


@pytest.mark.asyncio
async def test_dangerous_echo_tool_respond_decision_returns_message_without_execution(tmp_path):
    decision = ApprovalDecision(
        action=ApprovalDecisionType.RESPOND,
        request_id="approval-respond",
        response="I need your explicit release approval first.",
    )
    approvals = _DecisionApprovals(decision)
    executor = _Executor(tmp_path, dangerous=True, approvals=approvals)
    authority = _TrackingAuthority()
    executor._tool_lease_authority = authority

    tc = {
        "id": "call_respond",
        "function": {"name": "stub_tool", "arguments": '{"x":"unsafe"}'},
    }
    _msg, final_result = await executor._execute_tool_call(
        tc,
        session_id="s1",
        run_id="r1",
        user_input="hi",
        allowed_tools={"stub_tool"},
    )

    assert final_result.success is True
    assert final_result.output == "I need your explicit release approval first."
    assert final_result.metadata["echo_approval"] == "respond"
    assert executor.handler_calls == 0
    # P0-1 fix: approval effect issues a real lease; only tool-execution leases should be absent
    tool_leases = [lease for lease in authority.issued if lease["tool_name"] != "echo_approval"]
    assert tool_leases == []


@pytest.mark.asyncio
async def test_dangerous_echo_tool_respond_redacts_secret_before_model_context(tmp_path):
    decision = ApprovalDecision(
        action=ApprovalDecisionType.RESPOND,
        request_id="approval-respond-secret",
        response=f"operator note {_SECRET}",
    )
    executor = _Executor(
        tmp_path,
        dangerous=True,
        approvals=_DecisionApprovals(decision),
    )
    executor._tool_lease_authority = _TrackingAuthority()

    message, result = await executor._execute_tool_call(
        {
            "id": "call_respond_secret",
            "function": {"name": "stub_tool", "arguments": '{"x":"safe"}'},
        },
        session_id="s1",
        run_id="r1",
        user_input="hi",
        allowed_tools={"stub_tool"},
    )

    assert _SECRET not in result.output
    assert _SECRET not in message.content
    assert "[REDACTED:openai_key]" in result.output
    assert executor.handler_calls == 0


@pytest.mark.asyncio
async def test_dangerous_web_tool_waits_for_pending_approval_then_executes(tmp_path):
    approvals = _PendingThenApprove()
    executor = _Executor(tmp_path, dangerous=True, approvals=approvals)
    executor._approval_poll_interval = 0.0
    context = RuntimeContext(
        product_id="js-agent",
        channel="ws_stream",
        owner_key_hash="owner-a",
        session_id="s1",
        run_id="r1",
        role="admin",
        profile="default",
        capabilities=("stub_tool",),
        workspace=tmp_path,
        state_dir=tmp_path / "state",
    )
    token = set_runtime_context(context)
    try:
        _message, result = await executor._execute_tool_call(
            {
                "id": "call_pending",
                "function": {"name": "stub_tool", "arguments": '{"x":"safe"}'},
            },
            session_id="s1",
            run_id="r1",
            user_input="run the approved action",
            allowed_tools={"stub_tool"},
        )
    finally:
        reset_runtime_context(token)

    assert approvals.request_kwargs["context"] == "web"
    assert approvals.request_kwargs["queue_if_unhandled"] is True
    assert result.success is True
    assert executor.handler_calls == 1


@pytest.mark.asyncio
async def test_pending_approval_consumes_decision_resolved_during_pending_lookup(
    tmp_path,
):
    approvals = _ResolvedBetweenPollAndPendingLookup()
    executor = _Executor(tmp_path, dangerous=True, approvals=approvals)

    decision = await executor._await_pending_approval(
        "approval-race",
        owner_key_hash="owner-a",
    )

    assert decision.action == ApprovalDecisionType.APPROVE
    assert approvals.take_calls == 2


@pytest.mark.asyncio
async def test_echo_tool_execution_default_authority_writes_persistent_lease_ledger(tmp_path):
    executor = _Executor(tmp_path)

    tc = {
        "id": "call_persistent",
        "function": {"name": "stub_tool", "arguments": '{"x":"persist"}'},
    }
    _msg, final_result = await executor._execute_tool_call(
        tc,
        session_id="s1",
        run_id="r1",
        user_input="hi",
        allowed_tools={"stub_tool"},
    )

    assert final_result.success is True
    ledger_path = executor.settings.state_dir / "echo_tool_lease.jsonl"
    text = ledger_path.read_text(encoding="utf-8")
    assert '"event_type":"issue"' in text
    assert '"event_type":"consume"' in text


@pytest.mark.asyncio
async def test_echo_tool_execution_issues_and_consumes_lease_on_cache_hit(tmp_path):
    executor = _Executor(
        tmp_path,
        read_only=True,
        handler_result=ToolResult(success=True, output="cache-safe-result"),
    )
    authority = _TrackingAuthority()
    executor._tool_lease_authority = authority

    tc = {
        "id": "call_cache",
        "function": {"name": "stub_tool", "arguments": '{"x":"cached"}'},
    }
    first = await executor._execute_tool_call(
        tc,
        session_id="s1",
        run_id="r1",
        user_input="hi",
        allowed_tools={"stub_tool"},
    )
    second = await executor._execute_tool_call(
        tc,
        session_id="s1",
        run_id="r1",
        user_input="hi",
        allowed_tools={"stub_tool"},
    )

    assert first[1].success is True
    assert second[1].success is True
    assert executor.handler_calls == 1
    assert len(authority.issued) == 2
    assert authority.verified == 2
    assert authority.consumed == 2


@pytest.mark.asyncio
async def test_echo_tool_execution_blocks_tampered_capability_lease(tmp_path):
    executor = _Executor(tmp_path)
    executor._tool_lease_authority = _TamperingAuthority()

    tc = {
        "id": "call_5",
        "function": {"name": "stub_tool", "arguments": "{}"},
    }
    msg, final_result = await executor._execute_tool_call(
        tc,
        session_id="s1",
        run_id="r1",
        user_input="hi",
        allowed_tools={"stub_tool"},
    )

    assert final_result.success is False
    assert "CapabilityLease" in (final_result.error or "")
    assert executor.handler_calls == 0
    assert msg.name == "stub_tool"


@pytest.mark.asyncio
async def test_echo_tool_execution_blocks_cross_run_lease_before_registry(tmp_path):
    executor = _Executor(tmp_path)
    executor._tool_lease_authority = _CrossRunAuthority()

    tc = {
        "id": "call_cross_run",
        "function": {"name": "stub_tool", "arguments": "{}"},
    }
    _msg, final_result = await executor._execute_tool_call(
        tc,
        session_id="s1",
        run_id="r1",
        user_input="hi",
        allowed_tools={"stub_tool"},
    )

    assert final_result.success is False
    assert "CapabilityLease" in (final_result.error or "")
    assert executor.handler_calls == 0


@pytest.mark.asyncio
async def test_echo_tool_execution_blocks_args_hash_mismatch_before_registry(tmp_path):
    executor = _Executor(tmp_path)
    executor._tool_lease_authority = _ArgsMismatchAuthority()

    tc = {
        "id": "call_args_mismatch",
        "function": {"name": "stub_tool", "arguments": '{"x":"real"}'},
    }
    _msg, final_result = await executor._execute_tool_call(
        tc,
        session_id="s1",
        run_id="r1",
        user_input="hi",
        allowed_tools={"stub_tool"},
    )

    assert final_result.success is False
    assert "CapabilityLease" in (final_result.error or "")
    assert executor.handler_calls == 0


def test_module_imports():
    # Sanity import — keeps coverage reporters from flagging the helpers
    # as unused when the asyncio test collector misbehaves.
    assert asyncio.iscoroutinefunction(_Executor.__init__) is False


@pytest.mark.asyncio
async def test_tool_registry_rejects_direct_execution_without_context(tmp_path):
    executor = _Executor(tmp_path)

    result = await executor.registry.execute("r1", "stub_tool", {"x": "direct"})

    assert result.success is False
    assert "Echo execution context required" in result.error
    assert executor.handler_calls == 0


@pytest.mark.asyncio
async def test_tool_registry_accepts_matching_consumed_execution_context(tmp_path):
    executor = _Executor(tmp_path)
    args = {"x": "direct"}
    context = EchoToolExecutionContext(
        owner_key_hash="owner",
        run_id="r1",
        tool_name="stub_tool",
        args_hash=stable_payload_hash(args),
        resource_scope="session:test",
        fs_roots=(str(executor.settings.workspace),),
        network_policy="deny",
        max_bytes=20_000,
        max_duration_ms=1_000,
    )
    authority = LeaseAuthority(mac_key=b"tool-lease-test-key", now_fn=lambda: 1_000)
    lease = authority.issue(
        product_id=context.product_id,
        session_id=context.session_id,
        owner_key_hash=context.owner_key_hash,
        run_id=context.run_id,
        tool_name=context.tool_name,
        args_schema=context.args_hash,
        resource_scope=context.resource_scope,
        fs_roots=context.fs_roots,
        network_policy=context.network_policy,
        max_bytes=context.max_bytes,
        max_duration_ms=context.max_duration_ms,
        ttl_ms=60_000,
    )
    context = sign_tool_execution_context(context, lease=lease, authority=authority, now=1_000)
    executor._install_echo_tool_context_verifier(authority)

    result = await executor.registry.execute("r1", "stub_tool", args, echo_context=context)

    assert result.success is True
    assert executor.handler_calls == 1
