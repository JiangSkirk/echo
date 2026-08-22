"""Durable Echo outbox coverage for real tool execution side effects."""

from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import threading
from collections.abc import Awaitable, Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from js.agent.tool_executor import ToolExecutorMixin
from js.config import EchoLedgerConfig
from js.echo import stable_payload_hash
from js.echo.durable_thread import EchoDurableExecutor
from js.echo.ledger.effects import EffectReceipt
from js.echo.ledger.journal import FileEchoLedger
from js.echo.ledger.service import EchoSafetyService, EchoUnavailableError
from js.echo.mode_contract import AppMode, ArtifactRefV1, TaskRef
from js.echo.turn_context import RuntimeContext, reset_runtime_context, set_runtime_context
from js.security.approvals import ApprovalMode, ApprovalQueue
from js.security.guard import BehaviorGuard
from js.security.secrets import SecretManager
from js.tools.registry import ToolRegistry, ToolResult, ToolSpec


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


class _Executor(ToolExecutorMixin):
    pass


def test_effect_receipt_without_artifacts_remains_backward_compatible() -> None:
    receipt = EffectReceipt(
        receipt_id="receipt:legacy",
        effect_id="effect-legacy",
        tenant_id="tenant-a",
        status="ok",
        output_ref="sha256:" + "0" * 64,
        replay_class="idempotent",
    )

    assert receipt.artifact_refs == ()


def test_artifact_ref_receipt_restarts_and_lists_exact_verified_ref(tmp_path: Path) -> None:
    service = EchoSafetyService(state_dir=tmp_path)
    context = service.begin_tool_effect(
        tenant_id="tenant-a",
        product_id="js-agent",
        session_id="session-a",
        run_id="run-a",
        tool_name="excel_write",
        tool_call_id="call-a",
        args_hash="sha256:" + "1" * 64,
        lease_id="lease-a",
        replay_class="non_idempotent",
    )
    ref = ArtifactRefV1(
        mode=AppMode.PERSONAL,
        owner="tenant-a",
        session="session-a",
        workspace=None,
        kind="spreadsheet",
        uri="echo://artifact/exact-a",
        digest="sha256:" + "2" * 64,
        acl="owner",
        created_by_run="run-a",
    )
    service.finish_tool_effect(
        context,
        status="ok",
        output_hash=ref.digest,
        artifact_refs=(ref,),
    )
    later = service.begin_tool_effect(
        tenant_id="tenant-a",
        product_id="js-agent",
        session_id="session-a",
        run_id="run-b",
        tool_name="file_write",
        tool_call_id="call-b",
        args_hash="sha256:" + "3" * 64,
        lease_id="lease-b",
        replay_class="non_idempotent",
    )
    service.finish_tool_effect(
        later,
        status="ok",
        output_hash="sha256:" + "4" * 64,
    )
    service.close()

    restarted = EchoSafetyService(state_dir=tmp_path)
    assert restarted.list_verified_artifact_refs(
        tenant_id="tenant-a",
        mode=AppMode.PERSONAL,
        workspace=None,
        limit=50,
    ) == (ref,)


def test_artifact_ref_survives_required_archive_compaction_and_restart(
    tmp_path: Path,
) -> None:
    config = EchoLedgerConfig(retain_records=2, trigger_records=100, max_archives=1)
    service = EchoSafetyService(state_dir=tmp_path, ledger_config=config)
    context = service.begin_tool_effect(
        tenant_id="tenant-a",
        product_id="js-agent",
        session_id="session-a",
        run_id="run-a",
        tool_name="excel_write",
        tool_call_id="call-a",
        args_hash="sha256:" + "1" * 64,
        lease_id="lease-a",
        replay_class="non_idempotent",
    )
    ref = ArtifactRefV1(
        mode=AppMode.PERSONAL,
        owner="tenant-a",
        session="session-a",
        workspace=None,
        kind="spreadsheet",
        uri="echo://artifact/archived-a",
        digest="sha256:" + "2" * 64,
        acl="owner",
        created_by_run="run-a",
    )
    service.finish_tool_effect(
        context,
        status="ok",
        output_hash=ref.digest,
        artifact_refs=(ref,),
    )
    later = service.begin_tool_effect(
        tenant_id="tenant-a",
        product_id="js-agent",
        session_id="session-a",
        run_id="run-after-artifact",
        tool_name="file_write",
        tool_call_id="call-after-artifact",
        args_hash="sha256:" + "3" * 64,
        lease_id="lease-after-artifact",
        replay_class="non_idempotent",
    )
    service.finish_tool_effect(
        later,
        status="ok",
        output_hash="sha256:" + "4" * 64,
    )
    journal_path = service.journal_path_for_scope(
        "tenant-a",
        product_id="js-agent",
        session_id="session-a",
    )
    assert service.compact_journals(max_records=2)[str(journal_path)] is True
    active_records = FileEchoLedger(
        journal_path,
        mac_key=service.journal_key_for_scope(
            "tenant-a",
            product_id="js-agent",
            session_id="session-a",
        ),
    ).records
    assert not any(
        record.record_type == "receipt" and record.payload.get("artifact_refs")
        for record in active_records
    ), "artifact receipt must be recovered from the required archive, not active tail"
    assert service.list_verified_artifact_refs(
        tenant_id="tenant-a",
        mode=AppMode.PERSONAL,
        workspace=None,
    ) == (ref,)
    service.close()

    restarted = EchoSafetyService(state_dir=tmp_path, ledger_config=config)
    assert restarted.list_verified_artifact_refs(
        tenant_id="tenant-a",
        mode=AppMode.PERSONAL,
        workspace=None,
    ) == (ref,)


def test_artifact_ref_remains_visible_after_session_partition_retirement(
    tmp_path: Path,
) -> None:
    """A verified ref remains reconstructible after its journal is retired."""
    config = EchoLedgerConfig(max_session_partitions_per_owner=2)
    service = EchoSafetyService(state_dir=tmp_path, ledger_config=config)
    context = service.begin_tool_effect(
        tenant_id="tenant-a",
        product_id="js-agent",
        session_id="artifact-session",
        run_id="artifact-run",
        tool_name="excel_write",
        tool_call_id="artifact-call",
        args_hash="sha256:" + "1" * 64,
        lease_id="artifact-lease",
        replay_class="non_idempotent",
    )
    ref = ArtifactRefV1(
        mode=AppMode.PERSONAL,
        owner="tenant-a",
        session="artifact-session",
        workspace=None,
        kind="spreadsheet",
        uri="echo://artifact/retired-session",
        digest="sha256:" + "2" * 64,
        acl="owner",
        created_by_run="artifact-run",
    )
    service.finish_tool_effect(
        context,
        status="ok",
        output_hash=ref.digest,
        artifact_refs=(ref,),
    )
    artifact_journal = service.journal_path_for_scope(
        "tenant-a",
        product_id="js-agent",
        session_id="artifact-session",
    )
    os.utime(artifact_journal, ns=(1_000_000_000, 1_000_000_000))

    for index in range(2):
        later = service.begin_tool_effect(
            tenant_id="tenant-a",
            product_id="js-agent",
            session_id=f"later-session-{index}",
            run_id=f"later-run-{index}",
            tool_name="file_write",
            tool_call_id=f"later-call-{index}",
            args_hash="sha256:" + str(index + 3) * 64,
            lease_id=f"later-lease-{index}",
            replay_class="non_idempotent",
        )
        service.finish_tool_effect(
            later,
            status="ok",
            output_hash="sha256:" + str(index + 5) * 64,
        )

    assert service.health().retired_session_partition_count >= 1
    assert not artifact_journal.exists()
    service.close()
    restarted = EchoSafetyService(state_dir=tmp_path, ledger_config=config)
    assert restarted.list_verified_artifact_refs(
        tenant_id="tenant-a",
        mode=AppMode.PERSONAL,
        workspace=None,
    ) == (ref,)


def test_artifact_ref_binding_mismatch_fails_before_receipt_append(tmp_path: Path) -> None:
    service = EchoSafetyService(state_dir=tmp_path)
    context = service.begin_tool_effect(
        tenant_id="tenant-a",
        product_id="js-agent",
        session_id="session-a",
        run_id="run-a",
        tool_name="excel_write",
        tool_call_id="call-a",
        args_hash="sha256:" + "1" * 64,
        lease_id="lease-a",
        replay_class="non_idempotent",
    )
    before = service.journal_path_for_scope(
        "tenant-a", product_id="js-agent", session_id="session-a"
    ).read_bytes()
    wrong_owner = ArtifactRefV1(
        mode=AppMode.PERSONAL,
        owner="tenant-b",
        session="session-a",
        workspace=None,
        kind="spreadsheet",
        uri="echo://artifact/wrong-owner",
        digest="sha256:" + "2" * 64,
        acl="owner",
        created_by_run="run-a",
    )

    with pytest.raises(ValueError, match="owner"):
        service.finish_tool_effect(
            context,
            status="ok",
            output_hash=wrong_owner.digest,
            artifact_refs=(wrong_owner,),
        )

    after = service.journal_path_for_scope(
        "tenant-a", product_id="js-agent", session_id="session-a"
    ).read_bytes()
    assert after == before


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("session", "session-b"),
        ("created_by_run", "run-b"),
        ("mode", AppMode.WORK),
    ),
)
def test_artifact_ref_scope_mismatch_fails_before_receipt_append(
    tmp_path: Path,
    field: str,
    replacement: object,
) -> None:
    service = EchoSafetyService(state_dir=tmp_path)
    context = service.begin_tool_effect(
        tenant_id="tenant-a",
        product_id="js-agent",
        session_id="session-a",
        run_id="run-a",
        tool_name="excel_write",
        tool_call_id="call-a",
        args_hash="sha256:" + "1" * 64,
        lease_id="lease-a",
        replay_class="non_idempotent",
    )
    values: dict[str, object] = {
        "mode": AppMode.PERSONAL,
        "owner": "tenant-a",
        "session": "session-a",
        "workspace": None,
        "kind": "spreadsheet",
        "uri": "echo://artifact/scope-mismatch",
        "digest": "sha256:" + "2" * 64,
        "acl": "owner",
        "created_by_run": "run-a",
    }
    values[field] = replacement
    if field == "mode":
        values["mode"] = AppMode.WORK
        values["workspace"] = "ws-" + "a" * 64
    ref = ArtifactRefV1(**values)  # type: ignore[arg-type]
    before = service.journal_path_for_scope(
        "tenant-a", product_id="js-agent", session_id="session-a"
    ).read_bytes()

    with pytest.raises(ValueError, match=field):
        service.finish_tool_effect(
            context,
            status="ok",
            output_hash=ref.digest,
            artifact_refs=(ref,),
        )

    assert service.journal_path_for_scope(
        "tenant-a", product_id="js-agent", session_id="session-a"
    ).read_bytes() == before


def test_work_artifact_workspace_mismatch_fails_before_receipt_append(
    tmp_path: Path,
) -> None:
    service = EchoSafetyService(state_dir=tmp_path)
    expected_workspace = "ws-" + "a" * 64
    context = service.begin_tool_effect(
        tenant_id="tenant-a",
        product_id="js-work",
        session_id="session-a",
        run_id="run-a",
        tool_name="excel_write",
        tool_call_id="call-a",
        args_hash="sha256:" + "1" * 64,
        lease_id="lease-a",
        replay_class="non_idempotent",
        workspace=expected_workspace,
    )
    ref = ArtifactRefV1(
        mode=AppMode.WORK,
        owner="tenant-a",
        session="session-a",
        workspace="ws-" + "b" * 64,
        kind="spreadsheet",
        uri="echo://artifact/wrong-workspace",
        digest="sha256:" + "2" * 64,
        acl="workspace",
        created_by_run="run-a",
    )
    before = service.journal_path_for_scope(
        "tenant-a", product_id="js-work", session_id="session-a"
    ).read_bytes()

    with pytest.raises(ValueError, match="workspace"):
        service.finish_tool_effect(
            context,
            status="ok",
            output_hash=ref.digest,
            artifact_refs=(ref,),
        )

    assert service.journal_path_for_scope(
        "tenant-a", product_id="js-work", session_id="session-a"
    ).read_bytes() == before


def test_failed_receipt_rejects_artifact_refs_before_append(tmp_path: Path) -> None:
    service = EchoSafetyService(state_dir=tmp_path)
    context = service.begin_tool_effect(
        tenant_id="tenant-a",
        product_id="js-agent",
        session_id="session-a",
        run_id="run-a",
        tool_name="excel_write",
        tool_call_id="call-a",
        args_hash="sha256:" + "1" * 64,
        lease_id="lease-a",
        replay_class="non_idempotent",
    )
    ref = ArtifactRefV1(
        mode=AppMode.PERSONAL,
        owner="tenant-a",
        session="session-a",
        workspace=None,
        kind="spreadsheet",
        uri="echo://artifact/failed",
        digest="sha256:" + "2" * 64,
        acl="owner",
        created_by_run="run-a",
    )

    with pytest.raises(ValueError, match="successful"):
        service.finish_tool_effect(
            context,
            status="failed",
            output_hash=ref.digest,
            artifact_refs=(ref,),
        )


@pytest.mark.parametrize("oversized", ("count", "bytes"))
def test_tool_finish_artifact_limits_fail_before_receipt_append(
    tmp_path: Path,
    oversized: str,
) -> None:
    service = EchoSafetyService(state_dir=tmp_path)
    context = service.begin_tool_effect(
        tenant_id="tenant-a",
        product_id="js-agent",
        session_id="session-artifact-limit",
        run_id="run-artifact-limit",
        tool_name="excel_write",
        tool_call_id="call-artifact-limit",
        args_hash="sha256:" + "1" * 64,
        lease_id="lease-artifact-limit",
        replay_class="non_idempotent",
    )
    count = 33 if oversized == "count" else 32
    uri_padding = 8 if oversized == "count" else 3_980
    refs = tuple(
        ArtifactRefV1(
            mode=AppMode.PERSONAL,
            owner="tenant-a",
            session="session-artifact-limit",
            workspace=None,
            kind="spreadsheet",
            uri=f"echo://artifact/{index}-" + "a" * uri_padding,
            digest="sha256:" + f"{(index % 15) + 1:x}" * 64,
            acl="owner",
            created_by_run="run-artifact-limit",
        )
        for index in range(count)
    )
    before = service.journal_path_for_scope(
        "tenant-a",
        product_id="js-agent",
        session_id="session-artifact-limit",
    ).read_bytes()

    with pytest.raises(ValueError, match="artifact refs.*limit"):
        service.finish_tool_effect(
            context,
            status="ok",
            output_hash="sha256:" + "f" * 64,
            artifact_refs=refs,
        )

    assert service.journal_path_for_scope(
        "tenant-a",
        product_id="js-agent",
        session_id="session-artifact-limit",
    ).read_bytes() == before


@pytest.mark.parametrize(
    "malformed_artifact_refs",
    (
        "not-a-list",
        [
            {
                "schema_version": 1,
                "mode": "personal",
                "owner": "tenant-a",
                "session": "session-a",
                "workspace": None,
                "kind": "spreadsheet",
                "uri": "echo://artifact/malformed",
                "digest": "sha256:" + "2" * 64,
                "acl": "owner",
                "created_by_run": "run-a",
                "physical_path": "/must/not/be-accepted",
            }
        ],
    ),
)
def test_malformed_artifact_receipt_payload_fails_semantic_replay_closed(
    tmp_path: Path,
    malformed_artifact_refs: object,
) -> None:
    service = EchoSafetyService(state_dir=tmp_path)
    context = service.begin_tool_effect(
        tenant_id="tenant-a",
        product_id="js-agent",
        session_id="session-a",
        run_id="run-a",
        tool_name="excel_write",
        tool_call_id="call-a",
        args_hash="sha256:" + "1" * 64,
        lease_id="lease-a",
        replay_class="non_idempotent",
    )
    journal = FileEchoLedger(
        service.journal_path_for_scope(
            "tenant-a", product_id="js-agent", session_id="session-a"
        ),
        mac_key=service.journal_key_for_scope(
            "tenant-a", product_id="js-agent", session_id="session-a"
        ),
    )
    journal.append(
        record_type="receipt",
        tenant_id="tenant-a",
        run_id="run-a",
        payload={
            "effect_id": context.effect_id,
            "outbox_id": context.outbox_id,
            "status": "ok",
            "output_ref": "sha256:" + "2" * 64,
            "replay_class": "non_idempotent",
            "artifact_refs": malformed_artifact_refs,
        },
    )
    service.close()

    restarted = EchoSafetyService(state_dir=tmp_path)
    with pytest.raises(EchoUnavailableError, match="verified projection"):
        restarted.list_verified_artifact_refs(
            tenant_id="tenant-a",
            mode=AppMode.PERSONAL,
            workspace=None,
        )


def test_other_owner_corrupt_partition_cannot_block_or_influence_verified_artifacts(
    tmp_path: Path,
) -> None:
    service = EchoSafetyService(state_dir=tmp_path)
    owned_context = service.begin_tool_effect(
        tenant_id="tenant-a",
        product_id="js-agent",
        session_id="session-a",
        run_id="run-a",
        tool_name="excel_write",
        tool_call_id="call-a",
        args_hash="sha256:" + "1" * 64,
        lease_id="lease-a",
        replay_class="non_idempotent",
    )
    owned_ref = ArtifactRefV1(
        mode=AppMode.PERSONAL,
        owner="tenant-a",
        session="session-a",
        workspace=None,
        kind="spreadsheet",
        uri="echo://artifact/owned",
        digest="sha256:" + "2" * 64,
        acl="owner",
        created_by_run="run-a",
    )
    service.finish_tool_effect(
        owned_context,
        status="ok",
        output_hash=owned_ref.digest,
        artifact_refs=(owned_ref,),
    )
    other = service.begin_tool_effect(
        tenant_id="tenant-b",
        product_id="js-agent",
        session_id="session-a",
        run_id="run-a",
        tool_name="excel_write",
        tool_call_id="call-b",
        args_hash="sha256:" + "3" * 64,
        lease_id="lease-b",
        replay_class="non_idempotent",
    )
    other_path = service.journal_path_for_scope(
        "tenant-b", product_id="js-agent", session_id="session-a"
    )
    other_journal = FileEchoLedger(
        other_path,
        mac_key=service.journal_key_for_scope(
            "tenant-b", product_id="js-agent", session_id="session-a"
        ),
    )
    other_journal.append(
        record_type="receipt",
        tenant_id="tenant-b",
        run_id="run-a",
        payload={
            "effect_id": other.effect_id,
            "outbox_id": other.outbox_id,
            "status": "ok",
            "output_ref": "sha256:" + "4" * 64,
            "replay_class": "non_idempotent",
            "artifact_refs": "corrupt-other-owner",
        },
    )
    service.close()

    restarted = EchoSafetyService(state_dir=tmp_path)
    assert restarted.list_verified_artifact_refs(
        tenant_id="tenant-a",
        mode=AppMode.PERSONAL,
        workspace=None,
    ) == (owned_ref,)


_TEST_DURABLE_EXECUTOR = EchoDurableExecutor(
    max_claim_pending=8,
    max_finish_pending=8,
    claim_workers=2,
    finish_workers=2,
    thread_name_prefix="echo-tool-test",
)


@pytest.fixture(scope="module", autouse=True)
def _close_test_durable_executor() -> Any:
    yield
    _TEST_DURABLE_EXECUTOR.shutdown(wait=True)


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


def _build_executor(
    tmp_path: Path,
    *,
    tool_name: str,
    read_only: bool,
    handler: Callable[..., Awaitable[ToolResult]],
    dangerous: bool = False,
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
    executor.approvals = ApprovalQueue(default_mode=ApprovalMode.AUTO_APPROVE)
    return executor


async def _execute(
    executor: _Executor,
    *,
    tool_name: str,
    arguments: dict[str, Any],
    tool_call_id: str = "call-a",
) -> tuple[Any, ToolResult]:
    return await executor._execute_tool_call(
        {
            "id": tool_call_id,
            "type": "function",
            "function": {
                "name": tool_name,
                "arguments": json.dumps(arguments, sort_keys=True),
            },
        },
        session_id="session-a",
        run_id="run-a",
        user_input="invoke the test tool",
        owner_key_hash="tenant-a",
    )


@pytest.mark.asyncio
async def test_successful_excel_write_result_records_verified_artifact_ref(
    tmp_path: Path,
) -> None:
    digest_hex = "3" * 64

    async def handler() -> ToolResult:
        return ToolResult(
            success=True,
            output="spreadsheet written",
            metadata={"content_sha256": digest_hex},
        )

    executor = _build_executor(
        tmp_path,
        tool_name="excel_write",
        read_only=False,
        handler=handler,
    )
    executor.settings.product_id = "js-agent"
    try:
        _message, result = await _execute(
            executor,
            tool_name="excel_write",
            arguments={},
        )
        assert result.success is True

        refs = executor.echo_safety_service.list_verified_artifact_refs(
            tenant_id="tenant-a",
            mode=AppMode.PERSONAL,
            workspace=None,
        )
        assert len(refs) == 1
        ref = refs[0]
        assert ref.mode is AppMode.PERSONAL
        assert ref.owner == "tenant-a"
        assert ref.session == "session-a"
        assert ref.created_by_run == "run-a"
        assert ref.workspace is None
        assert ref.kind == "spreadsheet"
        assert ref.digest == "sha256:" + digest_hex
        assert ref.uri.startswith("echo://artifact/")
        assert ref.acl == "owner"
    finally:
        executor.echo_safety_service.close()


@pytest.mark.asyncio
async def test_work_excel_write_binds_artifact_to_runtime_workspace(
    tmp_path: Path,
) -> None:
    digest_hex = "4" * 64
    workspace_handle = "ws-" + "a" * 32
    workspace_root = tmp_path / "workspace"
    workspace_root.mkdir()

    async def handler() -> ToolResult:
        return ToolResult(
            success=True,
            output="spreadsheet written",
            metadata={"content_sha256": digest_hex},
        )

    executor = _build_executor(
        tmp_path,
        tool_name="excel_write",
        read_only=False,
        handler=handler,
    )
    executor.settings.product_id = "js-work"
    context = RuntimeContext(
        product_id="js-work",
        channel="test",
        owner_key_hash="tenant-a",
        session_id="session-a",
        run_id="run-a",
        role="user",
        profile="default",
        capabilities=("excel_write",),
        workspace=workspace_root,
        state_dir=tmp_path / "state",
        fs_roots=(workspace_root,),
        task_ref=TaskRef(
            mode=AppMode.WORK,
            owner="tenant-a",
            session="session-a",
            run="run-a",
            workspace=workspace_handle,
        ),
    )
    token = set_runtime_context(context)
    try:
        _message, result = await _execute(
            executor,
            tool_name="excel_write",
            arguments={},
        )
        assert result.success is True

        refs = executor.echo_safety_service.list_verified_artifact_refs(
            tenant_id="tenant-a",
            mode=AppMode.WORK,
            workspace=workspace_handle,
        )
        assert len(refs) == 1
        ref = refs[0]
        assert ref.mode is AppMode.WORK
        assert ref.owner == "tenant-a"
        assert ref.session == "session-a"
        assert ref.created_by_run == "run-a"
        assert ref.workspace == workspace_handle
        assert ref.digest == "sha256:" + digest_hex
    finally:
        reset_runtime_context(token)
        executor.echo_safety_service.close()


@pytest.mark.asyncio
async def test_tool_execution_fails_closed_without_initialized_safety_service(
    tmp_path: Path,
) -> None:
    executed = False

    async def handler() -> ToolResult:
        nonlocal executed
        executed = True
        return ToolResult(success=True, output="must not execute")

    executor = _build_executor(
        tmp_path,
        tool_name="missing_safety_service",
        read_only=True,
        handler=handler,
    )
    executor.echo_safety_service.close()
    del executor.echo_safety_service

    with pytest.raises(RuntimeError, match="initialized EchoSafetyService"):
        await _execute(
            executor,
            tool_name="missing_safety_service",
            arguments={},
        )
    assert not executed


@pytest.mark.asyncio
async def test_tool_execution_blocks_secret_arguments_before_handler(
    tmp_path: Path,
) -> None:
    executed = False

    async def handler(**_kwargs: Any) -> ToolResult:
        nonlocal executed
        executed = True
        return ToolResult(success=True, output="must not execute")

    executor = _build_executor(
        tmp_path,
        tool_name="secret_argument_tool",
        read_only=True,
        handler=handler,
    )
    executor.secrets = SecretManager(tmp_path / "secret-state")
    secret = "sk-test12345678901234567890"

    _message, result = await _execute(
        executor,
        tool_name="secret_argument_tool",
        arguments={"token": secret},
    )

    assert result.success is False
    assert "secret material" in (result.error or "").lower()
    assert not executed


def _records(service: EchoSafetyService) -> tuple[Any, ...]:
    return FileEchoLedger(
        _tool_journal_path(service),
        mac_key=service.journal_key_for_scope(
            "tenant-a", product_id="product-a", session_id="session-a"
        ),
    ).records


def _tool_journal_path(service: EchoSafetyService) -> Path:
    return service.journal_path_for_scope(
        "tenant-a", product_id="product-a", session_id="session-a"
    )


@pytest.mark.asyncio
async def test_dangerous_tool_approval_has_its_own_echo_effect_and_receipt(
    tmp_path: Path,
) -> None:
    async def handler() -> ToolResult:
        return ToolResult(success=True, output="approved")

    executor = _build_executor(
        tmp_path,
        tool_name="dangerous_action",
        read_only=False,
        dangerous=True,
        handler=handler,
    )

    _message, result = await _execute(
        executor,
        tool_name="dangerous_action",
        arguments={},
    )

    assert result.success is True
    records = _records(executor.echo_safety_service)
    intake_tools = [
        record.payload.get("tool_effect", {}).get("tool_name")
        for record in records
        if record.record_type == "intake"
    ]
    assert intake_tools == ["echo_approval", "dangerous_action"]
    receipts = [record for record in records if record.record_type == "receipt"]
    assert len(receipts) == 2
    assert all(record.payload["status"] == "ok" for record in receipts)


def _tool_state(service: EchoSafetyService) -> Any:
    return service._partition_state(
        tenant_id="tenant-a", product_id="product-a", session_id="session-a"
    )


def _sqlite_archive_path(journal_path: Path) -> Path:
    return journal_path.with_suffix(journal_path.suffix + ".archive.sqlite3")


def _archive_contains_effect(service: EchoSafetyService, effect_id: str) -> bool:
    journal = FileEchoLedger(
        _tool_journal_path(service),
        mac_key=service.journal_key_for_scope(
            "tenant-a", product_id="product-a", session_id="session-a"
        ),
    )
    return journal.contains_archived_effect(effect_id)


def _record(records: tuple[Any, ...], record_type: str) -> Any:
    return next(item for item in records if item.record_type == record_type)


@pytest.mark.asyncio
async def test_tool_success_is_claimed_before_execution_and_merged_with_ok_receipt(
    tmp_path: Path,
) -> None:
    executed_after_claim = False

    async def handler(path: str) -> ToolResult:
        nonlocal executed_after_claim
        service = executor.echo_safety_service
        executed_after_claim = service.health().claimed_effect_count == 1
        return ToolResult(success=True, output=f"read {path}")

    executor = _build_executor(
        tmp_path,
        tool_name="file_read",
        read_only=True,
        handler=handler,
    )
    try:
        _message, result = await _execute(
            executor,
            tool_name="file_read",
            arguments={"path": "safe.txt"},
        )
        records = _records(executor.echo_safety_service)

        assert result.success is True
        assert executed_after_claim is True
        assert tuple(item.record_type for item in records) == (
            "intake",
            "decision",
            "policy_decision",
            "permit",
            "outbox",
            "outbox_claimed",
            "receipt",
            "merge",
        )
        outbox = _record(records, "outbox").payload
        seal = outbox["seal"]
        bridge = outbox["execution_contract"]
        assert seal["action_kind"] == "tool.file_read"
        assert seal["granted_scopes"] == ["tool:file_read"]
        assert seal["replay_class"] == "idempotent"
        assert bridge["executor_kind"] == "tool"
        assert bridge["tenant_id"] == "tenant-a"
        assert bridge["session_id"] == "session-a"
        assert bridge["run_id"] == "run-a"
        assert bridge["effect"]["input_hash"] == stable_payload_hash({"path": "safe.txt"})
        assert bridge["state_mapping"]["product_id"] == "product-a"
        assert bridge["state_mapping"]["tool_call_id"] == "call-a"
        assert bridge["state_mapping"]["lease_id"]
        receipt = _record(records, "receipt").payload
        assert receipt["status"] == "ok"
        assert receipt["replay_class"] == "idempotent"
        assert executor.echo_safety_service.health().claimed_effect_count == 0
    finally:
        executor.echo_safety_service.close()


@pytest.mark.asyncio
async def test_tool_result_failure_writes_failed_receipt_for_non_idempotent_effect(
    tmp_path: Path,
) -> None:
    async def handler(target: str) -> ToolResult:
        return ToolResult(success=False, error=f"could not update {target}")

    executor = _build_executor(
        tmp_path,
        tool_name="file_write",
        read_only=False,
        handler=handler,
    )
    try:
        _message, result = await _execute(
            executor,
            tool_name="file_write",
            arguments={"target": "safe.txt"},
        )
        records = _records(executor.echo_safety_service)

        assert result.success is False
        assert _record(records, "outbox").payload["seal"]["replay_class"] == ("non_idempotent")
        assert _record(records, "receipt").payload["status"] == "failed"
        assert _record(records, "merge").payload["status"] == "failed"
    finally:
        executor.echo_safety_service.close()


@pytest.mark.asyncio
async def test_tool_cancellation_writes_cancelled_receipt_then_reraises(
    tmp_path: Path,
) -> None:
    async def handler() -> ToolResult:
        raise asyncio.CancelledError

    executor = _build_executor(
        tmp_path,
        tool_name="long_write",
        read_only=False,
        handler=handler,
    )
    try:
        with pytest.raises(asyncio.CancelledError):
            await _execute(executor, tool_name="long_write", arguments={})

        records = _records(executor.echo_safety_service)
        assert _record(records, "receipt").payload["status"] == "cancelled"
        assert _record(records, "merge").payload["status"] == "cancelled"
        assert executor.echo_safety_service.health().claimed_effect_count == 0
    finally:
        executor.echo_safety_service.close()


@pytest.mark.asyncio
async def test_tool_begin_cancellation_finishes_claim_without_running_handler(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executed = False

    async def handler() -> ToolResult:
        nonlocal executed
        executed = True
        return ToolResult(success=True, output="must not run")

    executor = _build_executor(
        tmp_path,
        tool_name="long_write",
        read_only=False,
        handler=handler,
    )
    begin_started = threading.Event()
    begin_release = threading.Event()
    original_begin = executor.echo_safety_service.begin_tool_effect

    def blocking_begin(*args: Any, **kwargs: Any) -> Any:
        begin_started.set()
        assert begin_release.wait(timeout=1)
        return original_begin(*args, **kwargs)

    monkeypatch.setattr(executor.echo_safety_service, "begin_tool_effect", blocking_begin)
    try:
        task = asyncio.create_task(_execute(executor, tool_name="long_write", arguments={}))
        assert await asyncio.to_thread(begin_started.wait, 1)
        task.cancel("cancel tool begin")
        begin_release.set()
        with pytest.raises(asyncio.CancelledError):
            await task

        records = _records(executor.echo_safety_service)
        assert executed is False
        assert _record(records, "receipt").payload["status"] == "cancelled"
        assert _record(records, "merge").payload["status"] == "cancelled"
        assert executor.echo_safety_service.health().claimed_effect_count == 0
        assert executor.echo_safety_service._claim_lock_fds == {}
    finally:
        executor.echo_safety_service.close()


@pytest.mark.asyncio
async def test_tool_finish_persists_receipt_before_double_cancellation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def handler() -> ToolResult:
        return ToolResult(success=True, output="completed")

    executor = _build_executor(
        tmp_path,
        tool_name="long_write",
        read_only=False,
        handler=handler,
    )
    finish_started = threading.Event()
    finish_release = threading.Event()
    original_finish = executor.echo_safety_service.finish_tool_effect

    def blocking_finish(*args: Any, **kwargs: Any) -> Any:
        finish_started.set()
        assert finish_release.wait(timeout=1)
        return original_finish(*args, **kwargs)

    monkeypatch.setattr(executor.echo_safety_service, "finish_tool_effect", blocking_finish)
    try:
        task = asyncio.create_task(_execute(executor, tool_name="long_write", arguments={}))
        assert await asyncio.to_thread(finish_started.wait, 1)
        task.cancel("cancel tool finish")
        await asyncio.sleep(0)
        assert not task.done()
        task.cancel("cancel durable tool finish")
        await asyncio.sleep(0)
        assert not task.done()
        finish_release.set()
        with pytest.raises(asyncio.CancelledError):
            await task

        records = _records(executor.echo_safety_service)
        assert _record(records, "receipt").payload["status"] == "ok"
        assert _record(records, "merge").payload["status"] == "ok"
        assert executor.echo_safety_service.health().claimed_effect_count == 0
        assert executor.echo_safety_service._claim_lock_fds == {}
    finally:
        executor.echo_safety_service.close()


@pytest.mark.asyncio
async def test_registry_exception_writes_failed_receipt_then_reraises_same_exception(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def handler() -> ToolResult:
        return ToolResult(success=True, output="not reached")

    executor = _build_executor(
        tmp_path,
        tool_name="mutate",
        read_only=False,
        handler=handler,
    )
    original = RuntimeError("registry failed with private detail")

    async def raise_original(*_args: Any, **_kwargs: Any) -> ToolResult:
        raise original

    monkeypatch.setattr(executor.registry, "execute", raise_original)
    try:
        with pytest.raises(RuntimeError) as raised:
            await _execute(executor, tool_name="mutate", arguments={"value": "private"})

        assert raised.value is original
        records = _records(executor.echo_safety_service)
        receipt = _record(records, "receipt").payload
        assert receipt["status"] == "failed"
        assert receipt["output_hash"] == stable_payload_hash(
            {
                "status": "failed",
                "exception_type": "RuntimeError",
                "exception": "internal error details withheld",
            }
        )
        assert _record(records, "merge").payload["status"] == "failed"
        assert "registry failed with private detail" not in (
            _tool_journal_path(executor.echo_safety_service).read_text(encoding="utf-8")
        )
    finally:
        executor.echo_safety_service.close()


@pytest.mark.asyncio
async def test_finish_failure_is_fail_closed_and_does_not_return_tool_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def handler() -> ToolResult:
        return ToolResult(success=True, output="side effect completed")

    executor = _build_executor(
        tmp_path,
        tool_name="mutate",
        read_only=False,
        handler=handler,
    )

    def fail_finish(*_args: Any, **_kwargs: Any) -> None:
        raise OSError("journal unavailable")

    monkeypatch.setattr(
        executor.echo_safety_service,
        "finish_tool_effect",
        fail_finish,
        raising=False,
    )
    try:
        with pytest.raises(OSError, match="journal unavailable"):
            await _execute(executor, tool_name="mutate", arguments={})

        records = _records(executor.echo_safety_service)
        assert "receipt" not in {item.record_type for item in records}
        assert "merge" not in {item.record_type for item in records}
        assert executor.echo_safety_service.health().claimed_effect_count == 1
    finally:
        executor.echo_safety_service.close()


def test_claimed_tool_effect_enters_manual_review_after_service_restart(
    tmp_path: Path,
) -> None:
    service = EchoSafetyService(state_dir=tmp_path)
    context = service.begin_tool_effect(
        tenant_id="tenant-a",
        product_id="product-a",
        session_id="session-a",
        run_id="run-a",
        tool_name="file_write",
        tool_call_id="call-a",
        args_hash=stable_payload_hash({"path": "safe.txt"}),
        lease_id="lease-a",
        replay_class="non_idempotent",
    )

    assert context.outbox_id
    assert service.health().claimed_effect_count == 1
    service.close()

    restarted = EchoSafetyService(state_dir=tmp_path)
    try:
        reviews = restarted.list_manual_reviews(tenant_id="tenant-a")
        assert restarted.health().claimed_effect_count == 0
        assert restarted.health().manual_review_effect_count == 1
        assert len(reviews) == 1
        assert reviews[0].effect_id == context.effect_id
        assert reviews[0].action_kind == "tool.file_write"
    finally:
        restarted.close()


def test_tool_receipt_can_finish_after_start_permit_deadline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock_ns = [1_000_000_000]
    monkeypatch.setattr(
        "js.echo.ledger.service.monotonic_ns",
        lambda: clock_ns[0],
    )
    service = EchoSafetyService(state_dir=tmp_path)
    try:
        context = service.begin_tool_effect(
            tenant_id="tenant-a",
            product_id="product-a",
            session_id="session-a",
            run_id="run-a",
            tool_name="long_write",
            tool_call_id="call-a",
            args_hash=stable_payload_hash({"path": "safe.txt"}),
            lease_id="lease-a",
            replay_class="non_idempotent",
        )
        clock_ns[0] += 61_000_000_000

        service.finish_tool_effect(
            context,
            status="ok",
            output_hash=stable_payload_hash({"status": "ok"}),
        )

        assert service.health().claimed_effect_count == 0
    finally:
        service.close()


def test_new_lease_cannot_reissue_same_uncertain_logical_tool_effect(
    tmp_path: Path,
) -> None:
    service = EchoSafetyService(state_dir=tmp_path)
    try:
        first = service.begin_tool_effect(
            tenant_id="tenant-a",
            product_id="product-a",
            session_id="session-a",
            run_id="run-a",
            tool_name="file_write",
            tool_call_id="call-a",
            args_hash=stable_payload_hash({"path": "safe.txt"}),
            lease_id="lease-a",
            replay_class="non_idempotent",
        )
        assert first.outbox_id
    finally:
        service.close()

    restarted = EchoSafetyService(state_dir=tmp_path)
    try:
        with pytest.raises(PermissionError, match="durable|already"):
            restarted.begin_tool_effect(
                tenant_id="tenant-a",
                product_id="product-a",
                session_id="session-a",
                run_id="run-a",
                tool_name="file_write",
                tool_call_id="call-a",
                args_hash=stable_payload_hash({"path": "safe.txt"}),
                lease_id="lease-b",
                replay_class="non_idempotent",
            )
        assert restarted.health().manual_review_effect_count == 1
    finally:
        restarted.close()


def test_compaction_preserves_non_idempotent_effect_tombstone(
    tmp_path: Path,
) -> None:
    config = EchoLedgerConfig(retain_records=2, trigger_records=100, max_archives=1)
    service = EchoSafetyService(state_dir=tmp_path, ledger_config=config)
    try:
        first = service.begin_tool_effect(
            tenant_id="tenant-a",
            product_id="product-a",
            session_id="session-a",
            run_id="run-a",
            tool_name="file_write",
            tool_call_id="call-a",
            args_hash=stable_payload_hash({"path": "safe.txt"}),
            lease_id="lease-a",
            replay_class="non_idempotent",
        )
        service.finish_tool_effect(
            first,
            status="ok",
            output_hash=stable_payload_hash({"status": "ok"}),
        )
        later = service.begin_tool_effect(
            tenant_id="tenant-a",
            product_id="product-a",
            session_id="session-a",
            run_id="later-run",
            tool_name="file_write",
            tool_call_id="later-call",
            args_hash=stable_payload_hash({"path": "later.txt"}),
            lease_id="later-lease",
            replay_class="non_idempotent",
        )
        service.finish_tool_effect(
            later,
            status="ok",
            output_hash=stable_payload_hash({"status": "later-ok"}),
        )
        tenant_path = _tool_journal_path(service)
        assert service.compact_journals(max_records=2)[str(tenant_path)] is True

        records = _records(service)
        assert records[0].record_type == "snapshot_anchor"
        assert "effect_tombstones" not in records[0].payload
        assert _archive_contains_effect(service, first.effect_id) is True
        with pytest.raises(PermissionError, match="durable|already"):
            service.begin_tool_effect(
                tenant_id="tenant-a",
                product_id="product-a",
                session_id="session-a",
                run_id="run-a",
                tool_name="file_write",
                tool_call_id="call-a",
                args_hash=stable_payload_hash({"path": "safe.txt"}),
                lease_id="lease-b",
                replay_class="non_idempotent",
            )
    finally:
        service.close()


def test_compaction_tombstone_does_not_conflict_with_retained_effect_tail(
    tmp_path: Path,
) -> None:
    config = EchoLedgerConfig(retain_records=4, trigger_records=100, max_archives=1)
    service = EchoSafetyService(state_dir=tmp_path, ledger_config=config)
    context = service.begin_tool_effect(
        tenant_id="tenant-a",
        product_id="product-a",
        session_id="session-a",
        run_id="run-a",
        tool_name="file_write",
        tool_call_id="call-a",
        args_hash=stable_payload_hash({"path": "safe.txt"}),
        lease_id="lease-a",
        replay_class="non_idempotent",
    )
    service.finish_tool_effect(
        context,
        status="ok",
        output_hash=stable_payload_hash({"status": "ok"}),
    )
    tenant_path = _tool_journal_path(service)
    assert service.compact_journals(max_records=4)[str(tenant_path)] is True
    service.close()

    restarted = EchoSafetyService(state_dir=tmp_path, ledger_config=config)
    try:
        retained = _records(restarted)
        assert [record.record_type for record in retained] == [
            "snapshot_anchor",
            "outbox",
            "outbox_claimed",
            "receipt",
            "merge",
        ]
        assert "effect_tombstones" not in retained[0].payload
        assert _archive_contains_effect(restarted, context.effect_id) is False

        later = restarted.begin_tool_effect(
            tenant_id="tenant-a",
            product_id="product-a",
            session_id="session-a",
            run_id="later-run",
            tool_name="file_write",
            tool_call_id="later-call",
            args_hash=stable_payload_hash({"path": "later.txt"}),
            lease_id="later-lease",
            replay_class="non_idempotent",
        )
        restarted.finish_tool_effect(
            later,
            status="ok",
            output_hash=stable_payload_hash({"status": "later-ok"}),
        )
        assert restarted.compact_journals(max_records=2)[str(tenant_path)] is True
        assert restarted.compact_journals(max_records=2)[str(tenant_path)] is True
        compacted = _records(restarted)
        assert "effect_tombstones" not in compacted[0].payload
        assert _archive_contains_effect(restarted, context.effect_id) is True
    finally:
        restarted.close()

    restarted_again = EchoSafetyService(state_dir=tmp_path, ledger_config=config)
    try:
        with pytest.raises(PermissionError, match="durable|already"):
            restarted_again.begin_tool_effect(
                tenant_id="tenant-a",
                product_id="product-a",
                session_id="session-a",
                run_id="run-a",
                tool_name="file_write",
                tool_call_id="call-a",
                args_hash=stable_payload_hash({"path": "safe.txt"}),
                lease_id="lease-b",
                replay_class="non_idempotent",
            )
    finally:
        restarted_again.close()


@pytest.mark.parametrize("max_records", (1, 2, 3, 4))
def test_compaction_expands_tail_to_complete_tool_effect_lifecycle(
    tmp_path: Path,
    max_records: int,
) -> None:
    config = EchoLedgerConfig(retain_records=100, trigger_records=200, max_archives=1)
    service = EchoSafetyService(state_dir=tmp_path, ledger_config=config)
    context = service.begin_tool_effect(
        tenant_id="tenant-a",
        product_id="product-a",
        session_id="session-a",
        run_id="run-a",
        tool_name="file_write",
        tool_call_id="call-a",
        args_hash=stable_payload_hash({"path": "safe.txt"}),
        lease_id="lease-a",
        replay_class="non_idempotent",
    )
    service.finish_tool_effect(
        context,
        status="ok",
        output_hash=stable_payload_hash({"status": "ok"}),
    )
    tenant_path = _tool_journal_path(service)
    assert service.compact_journals(max_records=max_records)[str(tenant_path)] is True
    assert [record.record_type for record in _records(service)] == [
        "snapshot_anchor",
        "outbox",
        "outbox_claimed",
        "receipt",
        "merge",
    ]
    service.close()

    restarted = EchoSafetyService(state_dir=tmp_path, ledger_config=config)
    try:
        assert restarted.health().ok is True
        with pytest.raises(PermissionError, match="durable|already"):
            restarted.begin_tool_effect(
                tenant_id="tenant-a",
                product_id="product-a",
                session_id="session-a",
                run_id="run-a",
                tool_name="file_write",
                tool_call_id="call-a",
                args_hash=stable_payload_hash({"path": "safe.txt"}),
                lease_id="lease-b",
                replay_class="non_idempotent",
            )
    finally:
        restarted.close()


def test_tool_receipt_append_ignores_temporary_required_archive_damage(
    tmp_path: Path,
) -> None:
    config = EchoLedgerConfig(retain_records=100, trigger_records=200, max_archives=1)
    service = EchoSafetyService(state_dir=tmp_path, ledger_config=config)
    seed = service.begin_tool_effect(
        tenant_id="tenant-a",
        product_id="product-a",
        session_id="session-a",
        run_id="seed-run",
        tool_name="file_write",
        tool_call_id="seed-call",
        args_hash=stable_payload_hash({"path": "seed.txt"}),
        lease_id="seed-lease",
        replay_class="non_idempotent",
    )
    service.finish_tool_effect(
        seed,
        status="ok",
        output_hash=stable_payload_hash({"status": "seeded"}),
    )
    tenant_path = _tool_journal_path(service)
    assert service.compact_journals(max_records=2)[str(tenant_path)] is True
    context = service.begin_tool_effect(
        tenant_id="tenant-a",
        product_id="product-a",
        session_id="session-a",
        run_id="run-a",
        tool_name="file_write",
        tool_call_id="call-a",
        args_hash=stable_payload_hash({"path": "safe.txt"}),
        lease_id="lease-a",
        replay_class="non_idempotent",
    )
    archive = _sqlite_archive_path(tenant_path)
    archive.write_bytes(b"temporarily unavailable")

    try:
        result = service.finish_tool_effect(
            context,
            status="ok",
            output_hash=stable_payload_hash({"status": "ok"}),
        )

        assert result.ok is True
        assert [record.record_type for record in _records(service)[-2:]] == [
            "receipt",
            "merge",
        ]
    finally:
        service.close()


@pytest.mark.parametrize("damage", ("missing", "tampered"))
def test_tool_effect_entry_fails_closed_on_required_archive_damage(
    tmp_path: Path,
    damage: str,
) -> None:
    config = EchoLedgerConfig(retain_records=2, trigger_records=100, max_archives=1)
    service = EchoSafetyService(state_dir=tmp_path, ledger_config=config)
    seed = service.begin_tool_effect(
        tenant_id="tenant-a",
        product_id="product-a",
        session_id="session-a",
        run_id="seed-run",
        tool_name="file_write",
        tool_call_id="seed-call",
        args_hash=stable_payload_hash({"path": "seed.txt"}),
        lease_id="seed-lease",
        replay_class="non_idempotent",
    )
    service.finish_tool_effect(
        seed,
        status="ok",
        output_hash=stable_payload_hash({"status": "seeded"}),
    )
    tenant_path = _tool_journal_path(service)
    assert service.compact_journals(max_records=2)[str(tenant_path)] is True
    archive = _sqlite_archive_path(tenant_path)
    if damage == "missing":
        archive.unlink()
    else:
        with sqlite3.connect(archive) as connection:
            connection.execute(
                "UPDATE archive_records SET canonical_payload = '{}' WHERE sequence = 1"
            )

    assert service.health().ok is False
    journal_before = tenant_path.read_bytes()
    try:
        with pytest.raises(EchoUnavailableError, match="archive"):
            service.begin_tool_effect(
                tenant_id="tenant-a",
                product_id="product-a",
                session_id="session-a",
                run_id="run-a",
                tool_name="file_write",
                tool_call_id="call-a",
                args_hash=stable_payload_hash({"path": "safe.txt"}),
                lease_id="lease-a",
                replay_class="non_idempotent",
            )
        assert tenant_path.read_bytes() == journal_before
        assert service._claim_lock_fds == {}
    finally:
        try:
            service.close()
        except ValueError:
            pass


def test_tool_effect_entry_fails_closed_on_cached_active_journal_tamper(
    tmp_path: Path,
) -> None:
    service = EchoSafetyService(state_dir=tmp_path)
    seed = service.begin_tool_effect(
        tenant_id="tenant-a",
        product_id="product-a",
        session_id="session-a",
        run_id="seed-run",
        tool_name="file_write",
        tool_call_id="seed-call",
        args_hash=stable_payload_hash({"path": "seed.txt"}),
        lease_id="seed-lease",
        replay_class="non_idempotent",
    )
    service.finish_tool_effect(
        seed,
        status="ok",
        output_hash=stable_payload_hash({"status": "seeded"}),
    )
    tenant_path = _tool_journal_path(service)
    journal_text = tenant_path.read_text(encoding="utf-8")
    assert '"run_id":"seed-run"' in journal_text
    tenant_path.write_text(
        journal_text.replace('"run_id":"seed-run"', '"run_id":"seed-bad"', 1),
        encoding="utf-8",
    )

    assert service.health().ok is False
    journal_before = tenant_path.read_bytes()
    try:
        with pytest.raises(EchoUnavailableError, match="journal"):
            service.begin_tool_effect(
                tenant_id="tenant-a",
                product_id="product-a",
                session_id="session-a",
                run_id="run-a",
                tool_name="file_write",
                tool_call_id="call-a",
                args_hash=stable_payload_hash({"path": "safe.txt"}),
                lease_id="lease-a",
                replay_class="non_idempotent",
            )
        assert tenant_path.read_bytes() == journal_before
        assert service._claim_lock_fds == {}
    finally:
        try:
            service.close()
        except ValueError:
            pass


def test_cached_observer_rechecks_claim_after_live_owner_drops_lock(
    tmp_path: Path,
) -> None:
    owner = EchoSafetyService(state_dir=tmp_path)
    observer = EchoSafetyService(state_dir=tmp_path)
    context = owner.begin_tool_effect(
        tenant_id="tenant-a",
        product_id="product-a",
        session_id="session-a",
        run_id="run-a",
        tool_name="file_write",
        tool_call_id="call-a",
        args_hash=stable_payload_hash({"path": "safe.txt"}),
        lease_id="lease-a",
        replay_class="non_idempotent",
    )
    try:
        assert observer.list_manual_reviews(tenant_id="tenant-a") == ()

        owner_state = _tool_state(owner)
        owner._release_claim_lock(owner_state, context.outbox_id)

        reviews = observer.list_manual_reviews(tenant_id="tenant-a")
        assert len(reviews) == 1
        assert reviews[0].effect_id == context.effect_id
        assert observer.health().claimed_effect_count == 0
        assert observer.health().manual_review_effect_count == 1
    finally:
        owner.close()
        observer.close()


def test_cached_observer_recovers_claim_before_direct_manual_review_resolution(
    tmp_path: Path,
) -> None:
    owner = EchoSafetyService(state_dir=tmp_path)
    observer = EchoSafetyService(state_dir=tmp_path)
    context = owner.begin_tool_effect(
        tenant_id="tenant-a",
        product_id="product-a",
        session_id="session-a",
        run_id="run-a",
        tool_name="file_write",
        tool_call_id="call-a",
        args_hash=stable_payload_hash({"path": "safe.txt"}),
        lease_id="lease-a",
        replay_class="non_idempotent",
    )
    try:
        assert observer.health().claimed_effect_count == 1
        assert observer.health().manual_review_effect_count == 0

        owner_state = _tool_state(owner)
        owner._release_claim_lock(owner_state, context.outbox_id)

        result = observer.resolve_manual_review(
            tenant_id="tenant-a",
            effect_id=context.effect_id,
            action="cancel",
            operator="tester",
            reason="owner stopped before producing a receipt",
        )

        assert result.ok is True
        assert observer.health().ok is True
        assert observer.health().claimed_effect_count == 0
        assert observer.health().manual_review_effect_count == 0
    finally:
        owner.close()
        observer.close()


@pytest.mark.asyncio
async def test_tool_journal_contains_hashes_not_raw_sensitive_args_or_output(
    tmp_path: Path,
) -> None:
    sensitive_arg = "private-argument-7f3b2a"
    sensitive_output = "private-output-9d4c1e"

    async def handler(secret_value: str) -> ToolResult:
        assert secret_value == sensitive_arg
        return ToolResult(success=True, output=sensitive_output)

    executor = _build_executor(
        tmp_path,
        tool_name="secret_sink",
        read_only=False,
        handler=handler,
    )
    arguments = {"secret_value": sensitive_arg}
    try:
        _message, result = await _execute(
            executor,
            tool_name="secret_sink",
            arguments=arguments,
        )
        journal_text = _tool_journal_path(executor.echo_safety_service).read_text(
            encoding="utf-8"
        )

        assert result.success is True
        assert sensitive_arg not in journal_text
        assert sensitive_output not in journal_text
        assert stable_payload_hash(arguments) in journal_text
        assert "output_hash" in journal_text
    finally:
        executor.echo_safety_service.close()
