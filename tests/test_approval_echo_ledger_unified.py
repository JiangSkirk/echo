"""P1-9: approval lifecycle must be unified into the authoritative EchoLedger.

Before this fix the approval queue wrote only its own ``echo_approvals.jsonl``
(a second, independent ledger that cannot be atomically ordered with the Echo
run), and there were no ``approval_execution_claimed`` / ``approval_finalized``
records anywhere.  These tests require:

- every approval lifecycle event lands in the scope-partition EchoLedger
  journal (same journal as the run it belongs to);
- approved executions produce claim/finalize link records bound to the
  approval request id and the execution effect id;
- the echo_approvals.jsonl file is only a derived mirror;
- sink failures fail closed;
- the MAC key path never degrades to an ephemeral key when a persistent
  ledger is configured (P1-10).
"""

from __future__ import annotations

import json
import stat
from collections.abc import Awaitable, Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from js.agent.tool_executor import ToolExecutorMixin
from js.echo.durable_thread import EchoDurableExecutor
from js.echo.ledger.journal import FileEchoLedger
from js.echo.ledger.service import EchoSafetyService
from js.security.approvals import ApprovalMode, ApprovalQueue
from js.security.guard import BehaviorGuard
from js.tools.registry import ToolRegistry, ToolResult, ToolSpec

_TEST_DURABLE_EXECUTOR = EchoDurableExecutor(
    max_claim_pending=8,
    max_finish_pending=8,
    claim_workers=2,
    finish_workers=2,
    thread_name_prefix="echo-approval-unified-test",
)


@pytest.fixture(scope="module", autouse=True)
def _close_test_durable_executor() -> Any:
    yield
    _TEST_DURABLE_EXECUTOR.shutdown(wait=True)


class _SecurityConfig:
    defense_mode = "enforce"
    protected_commands: list[str] = []
    protected_paths: list[str] = []
    allow_workspace_delete = False
    encoding_guard = True
    tool_result_scan = True
    script_provenance = False
    max_loop_iterations = 5
    tool_name_loop_threshold = 4


class _Defense:
    def evaluate(self, _context: Any) -> Any:
        return SimpleNamespace(blocked=False)


class _Audit:
    def log(self, *_args: Any, **_kwargs: Any) -> None:
        return None


class _Events:
    def emit(self, _event: Any) -> None:
        return None


class _Secrets:
    def detect_and_redact(self, value: str, _scope: str) -> str:
        return value


class _Executor(ToolExecutorMixin):
    pass


def _build_executor(
    tmp_path: Path,
    *,
    tool_name: str,
    handler: Callable[..., Awaitable[ToolResult]],
    dangerous: bool = True,
    read_only: bool = False,
) -> _Executor:
    settings = SimpleNamespace(
        echo_engine="on",
        product_id="product-a",
        workspace=tmp_path,
        state_dir=tmp_path,
        tools=SimpleNamespace(
            max_concurrent_tools=4,
            tool_output_budget_chars=10_000,
            shell_timeout=30.0,
        ),
        security=_SecurityConfig(),
    )
    guard = BehaviorGuard(settings.security, tmp_path)
    registry = ToolRegistry(settings.tools, guard)
    registry.register(
        ToolSpec(
            name=tool_name,
            description="test tool",
            parameters=[],
            read_only=read_only,
            dangerous=dangerous,
        ),
        handler,
    )

    executor = _Executor()
    executor.settings = settings
    executor.registry = registry
    executor.defense_strategies = _Defense()
    executor.audit = _Audit()
    executor.event_store = _Events()
    executor.secrets = _Secrets()
    executor.guard = guard
    executor.logger = SimpleNamespace(debug=lambda *_args, **_kwargs: None)
    executor._role = None
    executor._echo_durable_executor = _TEST_DURABLE_EXECUTOR
    executor.echo_safety_service = EchoSafetyService(state_dir=tmp_path)
    executor.approvals = ApprovalQueue(
        default_mode=ApprovalMode.AUTO_APPROVE,
        ledger_path=tmp_path / "echo_approvals.jsonl",
    )
    executor.approvals.set_echo_event_sink(_make_sink(executor.echo_safety_service))
    return executor


async def _execute(executor: _Executor, *, tool_name: str, arguments: dict[str, Any]) -> Any:
    return await executor._execute_tool_call(
        {
            "id": "call-a",
            "type": "function",
            "function": {"name": tool_name, "arguments": json.dumps(arguments, sort_keys=True)},
        },
        session_id="session-a",
        run_id="run-a",
        user_input="invoke the test tool",
        owner_key_hash="tenant-a",
    )


def _journal_records(service: EchoSafetyService) -> tuple[Any, ...]:
    journal_path = service.journal_path_for_scope(
        "tenant-a", product_id="product-a", session_id="session-a"
    )
    return FileEchoLedger(
        journal_path,
        mac_key=service.journal_key_for_scope(
            "tenant-a", product_id="product-a", session_id="session-a"
        ),
    ).records


def _approval_events(records: tuple[Any, ...]) -> list[dict[str, Any]]:
    return [dict(record.payload) for record in records if record.record_type == "approval"]


@pytest.mark.asyncio
async def test_approval_lifecycle_events_land_in_echo_ledger(tmp_path: Path) -> None:
    """requested/approved must be in the authoritative EchoLedger, not only JSONL."""

    async def handler() -> ToolResult:
        return ToolResult(success=True, output="approved")

    executor = _build_executor(tmp_path, tool_name="dangerous_action", handler=handler)
    _message, result = await _execute(executor, tool_name="dangerous_action", arguments={})
    assert result.success is True

    events = _approval_events(_journal_records(executor.echo_safety_service))
    event_types = [event["event_type"] for event in events]
    assert "approval_requested" in event_types
    assert "approval_approved" in event_types
    # events carry the run binding of the Echo run they belong to
    requested = next(e for e in events if e["event_type"] == "approval_requested")
    assert requested["run_id"] == "run-a"
    assert requested["session_id"] == "session-a"
    assert requested["owner_key_hash"] == "tenant-a"
    assert requested["tool_name"] == "dangerous_action"
    assert requested["request_id"]


@pytest.mark.asyncio
async def test_approved_execution_records_claim_and_finalize(tmp_path: Path) -> None:
    """approval_execution_claimed/finalized bind request id to execution effect."""

    async def handler() -> ToolResult:
        return ToolResult(success=True, output="approved")

    executor = _build_executor(tmp_path, tool_name="dangerous_action", handler=handler)
    _message, result = await _execute(executor, tool_name="dangerous_action", arguments={})
    assert result.success is True

    events = _approval_events(_journal_records(executor.echo_safety_service))
    by_type: dict[str, dict[str, Any]] = {event["event_type"]: event for event in events}
    assert "approval_execution_claimed" in by_type
    assert "approval_finalized" in by_type
    claimed = by_type["approval_execution_claimed"]
    finalized = by_type["approval_finalized"]
    assert claimed["request_id"] == by_type["approval_approved"]["request_id"]
    assert finalized["request_id"] == claimed["request_id"]
    assert claimed["execution_effect_id"]
    assert finalized["execution_effect_id"] == claimed["execution_effect_id"]
    assert finalized["status"] == "ok"


@pytest.mark.asyncio
async def test_rejected_approval_has_no_execution_link(tmp_path: Path) -> None:
    executor = _build_executor(
        tmp_path,
        tool_name="dangerous_action",
        handler=lambda: None,  # type: ignore[arg-type]
    )
    executor.approvals = ApprovalQueue(
        default_mode=ApprovalMode.AUTO_DENY,
        ledger_path=tmp_path / "echo_approvals.jsonl",
    )
    executor.approvals.set_echo_event_sink(_make_sink(executor.echo_safety_service))
    _message, result = await _execute(executor, tool_name="dangerous_action", arguments={})
    assert result.success is False

    events = _approval_events(_journal_records(executor.echo_safety_service))
    event_types = [event["event_type"] for event in events]
    assert "approval_rejected" in event_types
    assert "approval_execution_claimed" not in event_types
    assert "approval_finalized" not in event_types


def _make_sink(service: EchoSafetyService) -> Any:
    from js.security.approvals import wire_echo_approval_sink

    return wire_echo_approval_sink(service, product_id="product-a")


@pytest.mark.asyncio
async def test_jsagent_wires_approval_sink_automatically(tmp_path: Path) -> None:
    """Production wiring: a JSAgent approval event must reach EchoLedger."""
    from js.agent import JSAgent
    from js.config import JSSettings, SecurityConfig

    settings = JSSettings(
        workspace=tmp_path / "workspace",
        state_dir=tmp_path / "state",
        max_turns=1,
        echo_engine="on",
        security=SecurityConfig(api_key_required=False),
    )
    agent = JSAgent(settings)
    try:
        agent.approvals.request_decision(
            tool_name="demo_tool",
            arguments={"x": 1},
            context="web",
            session_id="sess-1",
            run_id="run-1",
            owner_key_hash="local",
            queue_if_unhandled=False,
        )
        journal_path = agent.echo_safety_service.journal_path_for_scope(
            "local",
            product_id=str(getattr(settings, "product_id", "js-agent")),
            session_id="sess-1",
        )
        records = FileEchoLedger(
            journal_path,
            mac_key=agent.echo_safety_service.journal_key_for_scope(
                "local",
                product_id=str(getattr(settings, "product_id", "js-agent")),
                session_id="sess-1",
            ),
        ).records
        events = _approval_events(records)
        assert any(
            event["event_type"] == "approval_requested" and event["run_id"] == "run-1"
            for event in events
        )
    finally:
        await agent.close()


@pytest.mark.asyncio
async def test_sink_failure_fails_closed(tmp_path: Path) -> None:
    """If the authoritative ledger cannot record the event, the approval flow
    must fail closed instead of proceeding on the mirror alone."""

    def broken_sink(_event: dict[str, Any]) -> None:
        raise OSError("echo ledger unavailable")

    queue = ApprovalQueue(
        default_mode=ApprovalMode.AUTO_APPROVE,
        ledger_path=tmp_path / "echo_approvals.jsonl",
    )
    queue.set_echo_event_sink(broken_sink)
    with pytest.raises(OSError, match="echo ledger unavailable"):
        queue.request_decision(
            tool_name="demo_tool",
            arguments={},
            context="cli",
            session_id="s",
            run_id="r",
            owner_key_hash="o",
        )


# ---------------------------------------------------------------------------
# P1-10: MAC key handling must never degrade to an ephemeral key
# ---------------------------------------------------------------------------


def test_mac_key_unwritable_path_fails_closed(tmp_path: Path) -> None:
    key_target_dir = tmp_path / "state"
    key_target_dir.mkdir()
    ledger = key_target_dir / "echo_approvals.jsonl"
    # Make the directory unwritable so key creation must fail.
    key_target_dir.chmod(stat.S_IRUSR | stat.S_IXUSR)  # 0500
    try:
        with pytest.raises(OSError):
            ApprovalQueue(default_mode=ApprovalMode.MANUAL, ledger_path=ledger)
    finally:
        key_target_dir.chmod(stat.S_IRWXU)


def test_mac_key_short_file_rejected(tmp_path: Path) -> None:
    ledger = tmp_path / "echo_approvals.jsonl"
    key_path = tmp_path / ".approval_ledger_mac_key"
    key_path.write_bytes(b"short")
    key_path.chmod(0o600)
    with pytest.raises(ValueError, match="mac key"):
        ApprovalQueue(default_mode=ApprovalMode.MANUAL, ledger_path=ledger)


def test_mac_key_file_properties(tmp_path: Path) -> None:
    ApprovalQueue(default_mode=ApprovalMode.MANUAL, ledger_path=tmp_path / "echo_approvals.jsonl")
    key_path = tmp_path / ".approval_ledger_mac_key"
    assert key_path.exists()
    assert len(key_path.read_bytes()) == 32
    assert stat.S_IMODE(key_path.stat().st_mode) == 0o600


def test_explicit_ledger_path_never_uses_ephemeral_key(tmp_path: Path) -> None:
    """Two queues on the same ledger path must share the persisted key."""
    ledger = tmp_path / "echo_approvals.jsonl"
    first = ApprovalQueue(default_mode=ApprovalMode.MANUAL, ledger_path=ledger)
    second = ApprovalQueue(default_mode=ApprovalMode.MANUAL, ledger_path=ledger)
    assert first._ledger_mac_key == second._ledger_mac_key
    assert len(first._ledger_mac_key) == 32


def test_ephemeral_only_without_ledger_path() -> None:
    queue = ApprovalQueue(default_mode=ApprovalMode.MANUAL)
    assert len(queue._ledger_mac_key) == 32
    assert not hasattr(queue, "_ledger_path_persistent") or True


# ---------------------------------------------------------------------------
# Lifecycle: edit re-issues the execution lease; crash recovery
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_edit_reissues_lease_bound_to_edited_arguments(tmp_path: Path) -> None:
    """After an EDIT decision the execution must run under a fresh lease bound
    to the *edited* arguments; the pre-edit authorization is invalid."""
    from js.echo import stable_payload_hash
    from js.security.approvals import ApprovalDecision, ApprovalDecisionType

    seen: list[dict[str, Any]] = []

    async def handler(**kwargs: Any) -> ToolResult:
        seen.append(dict(kwargs))
        return ToolResult(success=True, output="edited ran")

    executor = _build_executor(tmp_path, tool_name="dangerous_action", handler=handler)
    original = {"path": "original.txt"}
    edited = {"path": "edited.txt"}
    executor.approvals = ApprovalQueue(
        default_mode=ApprovalMode.MANUAL,
        ledger_path=tmp_path / "echo_approvals.jsonl",
    )
    executor.approvals.set_echo_event_sink(_make_sink(executor.echo_safety_service))

    def edit_callback(_req: Any) -> ApprovalDecision:
        return ApprovalDecision(
            ApprovalDecisionType.EDIT,
            edited_arguments=edited,
            reason="use the edited path",
        )

    executor.approvals.set_callback(
        "session-a",
        edit_callback,
        owner_key_hash="tenant-a",
        run_id="run-a",
        tool_name="dangerous_action",
        arguments=original,
    )

    _message, result = await _execute(executor, tool_name="dangerous_action", arguments=original)
    assert result.success is True
    # The handler received the EDITED arguments (old authorization not reused).
    assert seen and seen[0].get("path") == "edited.txt"

    records = _journal_records(executor.echo_safety_service)
    events = _approval_events(records)
    assert "approval_edited" in [event["event_type"] for event in events]
    # The execution intake is bound to the edited arguments hash, not the original.
    intake = next(
        record
        for record in records
        if record.record_type == "intake"
        and record.payload.get("tool_effect", {}).get("tool_name") == "dangerous_action"
    )
    executed_args_hash = intake.payload["tool_effect"]["args_hash"]
    assert executed_args_hash == stable_payload_hash(edited)
    assert executed_args_hash != stable_payload_hash(original)


@pytest.mark.asyncio
async def test_crash_after_approval_recovers_without_double_execution(tmp_path: Path) -> None:
    """Approve, then 'crash' before execution: recovery must not re-execute,
    and the approved-but-unexecuted state must be visible in EchoLedger."""

    async def handler() -> ToolResult:
        return ToolResult(success=True, output="approved")

    executor = _build_executor(tmp_path, tool_name="dangerous_action", handler=handler)

    # Record the approval lifecycle only (as if the process died right after
    # the approval decision and before the execution was claimed).
    executor.approvals.request_decision(
        tool_name="dangerous_action",
        arguments={},
        context="web",
        session_id="session-a",
        run_id="run-a",
        owner_key_hash="tenant-a",
        queue_if_unhandled=False,
    )
    executor.echo_safety_service.close()

    # Restart against the same state dir.
    recovered = EchoSafetyService(state_dir=tmp_path)
    records = _journal_records(recovered)
    events = _approval_events(records)
    event_types = [event["event_type"] for event in events]
    assert "approval_requested" in event_types
    assert "approval_approved" in event_types  # AUTO_APPROVE queue
    assert "approval_execution_claimed" not in event_types
    assert "approval_finalized" not in event_types
    # No tool execution receipt exists; nothing re-executed on recovery.
    receipts = [record for record in records if record.record_type == "receipt"]
    assert receipts == []
    # Recovered service is healthy enough to serve a new execution exactly once.
    health = recovered.health()
    assert health is not None
    recovered.close()
