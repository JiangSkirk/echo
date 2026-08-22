"""R4-B Task B8: Real connector E2E - Personal import and Work approved publish."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from js.connectors.contracts import (
    ConnectionRefV2,
    ConnectorExecutionRequestV1,
    canonical_params_digest,
)
from js.echo.capability import LeaseAuthority
from js.echo.ledger.service import EchoSafetyService
from js.echo.mode_contract import (
    AppMode,
    ConnectionRefV1,
    ConnectorManifestV1,
    DirectoryGrantV1,
    TaskRef,
)
from js.echo.turn_runtime import EchoRuntime
from js.security.approvals import (
    ApprovalMode,
    ApprovalQueue,
)


def _settings(tmp_path: Path, fs_roots: tuple[str, ...] = ()) -> SimpleNamespace:
    workspace = tmp_path / "workspace"
    state_dir = tmp_path / "state"
    workspace.mkdir(parents=True, exist_ok=True)
    state_dir.mkdir(parents=True, exist_ok=True)
    return SimpleNamespace(
        product_id="js-agent",
        workspace=workspace,
        state_dir=state_dir,
        security=SimpleNamespace(network_enabled=False, network_allowlist=()),
        echo_budget=SimpleNamespace(max_elapsed_ms=900_000),
        fs_roots=fs_roots,
    )


def _agent(tmp_path: Path, fs_roots: tuple[str, ...] = ()) -> tuple[Any, EchoRuntime, Any]:
    settings = _settings(tmp_path, fs_roots=fs_roots)
    authority = LeaseAuthority(
        mac_key=b"r4-e2e-lease-key-32-bytes!!!",
        now_fn=lambda: 1_000,
        ledger_path=tmp_path / "state" / "leases.jsonl",
    )
    echo_service = EchoSafetyService(state_dir=tmp_path / "state" / "echo")
    agent = SimpleNamespace(
        settings=settings,
        approvals=ApprovalQueue(
            default_mode=ApprovalMode.MANUAL,
            ledger_path=tmp_path / "approvals.jsonl",
        ),
        _current_allowed_tools=set(),
        _tool_lease_authority=authority,
        _echo_safety_service=echo_service,
    )
    agent._get_echo_tool_lease_authority = lambda: authority
    if fs_roots:
        agent._echo_fs_roots_resolver = lambda _owner, _session: fs_roots
    runtime = EchoRuntime(agent)
    agent.echo_runtime = runtime
    return agent, runtime, authority


def _import_manifest() -> ConnectorManifestV1:
    return ConnectorManifestV1(
        connector_type="local_import",
        capabilities=("read",),
        read_scopes=("files",),
        write_scopes=(),
        approval_policy="read_only",
    )


def _publish_manifest() -> ConnectorManifestV1:
    return ConnectorManifestV1(
        connector_type="local_publish",
        capabilities=("read", "write"),
        read_scopes=("artifacts",),
        write_scopes=("publish",),
        approval_policy="explicit",
    )


def _task_ref(mode: AppMode = AppMode.PERSONAL, workspace: str | None = None) -> TaskRef:
    return TaskRef(
        mode=mode,
        owner="owner-a",
        session="session-a",
        run="run-a",
        workspace=workspace,
    )


def _import_request(
    context: Any,
    authority: LeaseAuthority,
    grant_root: str,
    params: dict[str, Any],
) -> ConnectorExecutionRequestV1:
    manifest = _import_manifest()
    task_ref = context.task_ref or _task_ref()
    connection = ConnectionRefV2(
        ref=ConnectionRefV1(
            mode=task_ref.mode,
            owner=task_ref.owner,
            workspace=task_ref.workspace,
            connector_type="local_import",
            connection_id="import-e2e",
            authorized_by="owner-a",
        ),
        manifest_digest=manifest.canonical_hash(),
        vault_ref=None,
    )
    grant = DirectoryGrantV1(
        mode=task_ref.mode,
        workspace=task_ref.workspace,
        root=grant_root,
    )
    # Compute authority binding hash (doesn't include lease)
    binding_payload = {
        "task_ref_hash": task_ref.canonical_hash(),
        "connection_ref_hash": connection.canonical_hash(),
        "manifest_hash": manifest.canonical_hash(),
        "operation": "read",
        "scope": "files",
        "params_digest": canonical_params_digest(params),
        "directory_grant_hash": grant.canonical_hash(),
        "vault_ref_hash": None,
    }
    import hashlib as _hl
    import json as _json
    binding_hash = "sha256:" + _hl.sha256(
        ("js-agent:connector-execution:v1\0" + _json.dumps(binding_payload, sort_keys=True, separators=(",", ":"))).encode("utf-8")
    ).hexdigest()
    lease = authority.issue(
        product_id="js-agent",
        owner_key_hash=task_ref.owner,
        session_id=task_ref.session,
        run_id=task_ref.run,
        tool_name="connector.local_import.read",
        args_schema=binding_hash,
        resource_scope="connection:import-e2e:files",
        fs_roots=(grant_root,),
        network_policy="deny",
        network_hosts=(),
        max_bytes=10 * 1024 * 1024,
        max_duration_ms=30_000,
        max_invocations=1,
        ttl_ms=60_000,
    )
    return ConnectorExecutionRequestV1(
        task_ref=task_ref,
        connection=connection,
        manifest=manifest,
        operation="read",
        scope="files",
        params_digest=canonical_params_digest(params),
        directory_grant=grant,
        approval_id=None,
        lease=lease,
    )


@pytest.mark.asyncio
async def test_personal_import_e2e(tmp_path: Path) -> None:
    """Real Personal import: create file, import via EchoRuntime, verify artifact."""
    # Create source file
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    source_file = source_dir / "test.txt"
    source_file.write_text("hello world", encoding="utf-8")

    agent, runtime, authority = _agent(tmp_path, fs_roots=(str(source_dir),))
    context = runtime.build_context(
        channel="test",
        owner_key_hash="owner-a",
        session_id="session-a",
        run_id="run-a",
    )

    params = {"path": "test.txt"}
    request = _import_request(context, authority, str(source_dir), params)

    outcome = await runtime.execute_connector_effect(request, params=params, context=context)

    assert outcome.success is True
    assert len(outcome.effects) == 1
    assert outcome.effects[0].effect_type == "read"
    assert outcome.effects[0].bytes_processed == len("hello world")
    assert len(outcome.artifact_refs) == 1
    ref = outcome.artifact_refs[0]
    assert ref.owner == "owner-a"
    assert ref.mode == AppMode.PERSONAL
    assert ref.session == "session-a"
    assert ref.created_by_run == "run-a"

    # Source file should not be modified
    assert source_file.read_text() == "hello world"

    # Replay should fail (lease consumed)
    with pytest.raises((PermissionError, Exception), match="nonce|already|replay|consumed"):
        await runtime.execute_connector_effect(request, params=params, context=context)


@pytest.mark.asyncio
async def test_personal_import_rejects_symlink(tmp_path: Path) -> None:
    """Import must reject symlink source files."""
    import os

    source_dir = tmp_path / "source"
    source_dir.mkdir()
    real_file = source_dir / "real.txt"
    real_file.write_text("real", encoding="utf-8")
    link_path = source_dir / "link.txt"
    os.symlink(real_file, link_path)

    agent, runtime, authority = _agent(tmp_path, fs_roots=(str(source_dir),))
    context = runtime.build_context(
        channel="test",
        owner_key_hash="owner-a",
        session_id="session-a",
        run_id="run-a",
    )

    params = {"path": "link.txt"}
    request = _import_request(context, authority, str(source_dir), params)

    outcome = await runtime.execute_connector_effect(request, params=params, context=context)
    assert outcome.success is False


@pytest.mark.asyncio
async def test_personal_import_rejects_root_grant(tmp_path: Path) -> None:
    """Import must reject grant root = '/'."""
    agent, runtime, authority = _agent(tmp_path, fs_roots=("/",))
    context = runtime.build_context(
        channel="test",
        owner_key_hash="owner-a",
        session_id="session-a",
        run_id="run-a",
    )
    params = {"path": "test.txt"}
    request = _import_request(context, authority, "/", params)

    with pytest.raises(PermissionError, match="filesystem root"):
        await runtime.execute_connector_effect(request, params=params, context=context)
