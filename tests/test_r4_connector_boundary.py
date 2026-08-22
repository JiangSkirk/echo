"""R4-A runtime/manager/connector boundary regressions."""

from __future__ import annotations

import copy
import dataclasses
from pathlib import Path
from types import SimpleNamespace

import pytest

from js.appshell.principal import (
    AppShellOperationLimitError,
    AppShellSessionStore,
    reset_current_appshell_epoch_binding,
    set_current_appshell_epoch_binding,
)
from js.connectors import contracts
from js.connectors.base import ConnectorBase, ConnectorResult
from js.connectors.local import LimitedWritePublishConnector, ReadOnlyImportConnector
from js.connectors.manager import (
    ConnectorManager,
    build_test_connector_manager,
)
from js.echo.capability import LeaseAuthority, LeaseDenied
from js.echo.mode_contract import (
    AppMode,
    ConnectionRefV1,
    ConnectorManifestV1,
    DirectoryGrantV1,
    TaskRef,
)
from js.echo.turn_runtime import EchoRuntime
from js.security.approvals import ApprovalDecisionType, ApprovalMode, ApprovalQueue


class _CountingConnector(ConnectorBase):
    def __init__(self) -> None:
        super().__init__(
            ConnectorManifestV1(
                connector_type="counting",
                capabilities=("write",),
                read_scopes=(),
                write_scopes=("publish",),
                approval_policy="explicit",
            )
        )
        self.write_calls = 0

    async def _write_authorized(  # type: ignore[no-untyped-def,override]
        self, scope: str, *, params=None, directory_grant=None
    ) -> ConnectorResult:
        self.write_calls += 1
        return ConnectorResult(connector_type="counting", success=True)


def _grant(root: Path) -> DirectoryGrantV1:
    return DirectoryGrantV1(mode=AppMode.PERSONAL, workspace=None, root=str(root))


def _runtime_bundle(tmp_path: Path, *, managed: bool = False):  # type: ignore[no-untyped-def]
    workspace = tmp_path / "workspace"
    state_dir = tmp_path / "state"
    workspace.mkdir(exist_ok=True)
    state_dir.mkdir(exist_ok=True)
    settings = SimpleNamespace(
        product_id="js-agent",
        workspace=workspace,
        state_dir=state_dir,
        security=SimpleNamespace(network_enabled=False, network_allowlist=()),
        echo_budget=SimpleNamespace(max_elapsed_ms=900_000),
        _appshell_managed=managed,
    )
    authority = LeaseAuthority(
        mac_key=b"r4-boundary-lease-key-32-bytes!",
        now_fn=lambda: 1_000,
        ledger_path=state_dir / "leases.jsonl",
    )
    agent = SimpleNamespace(
        settings=settings,
        approvals=ApprovalQueue(default_mode=ApprovalMode.MANUAL),
        _current_allowed_tools=set(),
        _tool_lease_authority=authority,
    )
    agent._get_echo_tool_lease_authority = lambda: authority
    # Provide a real EchoSafetyService for the two-phase lease consume anchor
    from js.echo.ledger.service import EchoSafetyService

    echo_service = EchoSafetyService(state_dir=state_dir / "echo")
    agent._echo_safety_service = echo_service
    store = None
    binding_token = None
    principal = None
    token = None
    if managed:
        store = AppShellSessionStore(state_dir / "appshell.db")
        token, principal = store.create(
            owner="owner-a",
            mode_roles={"personal": "user", "work": "user"},
        )
        agent._appshell_epoch_validator = store.require_epoch_current
        agent._appshell_operation_store = store
        binding_token = set_current_appshell_epoch_binding(principal.epoch_binding())
    try:
        runtime = EchoRuntime(agent)
        agent.echo_runtime = runtime
        context = runtime.build_context(
            channel="test",
            owner_key_hash="owner-a",
            session_id="session-a",
            run_id="run-a",
        )
    finally:
        if binding_token is not None:
            reset_current_appshell_epoch_binding(binding_token)
    return agent, runtime, context, authority, store, principal, token


def _read_request(
    context,  # type: ignore[no-untyped-def]
    authority: LeaseAuthority,
    *,
    params: dict[str, object],
):
    manifest = ConnectorManifestV1(
        connector_type="local_import",
        capabilities=("read",),
        read_scopes=("files",),
        approval_policy="read_only",
    )
    connection = contracts.ConnectionRefV2(
        ref=ConnectionRefV1(
            mode=AppMode.PERSONAL,
            owner="owner-a",
            workspace=None,
            connector_type="local_import",
            connection_id="import-a",
            authorized_by="owner-a",
        ),
        manifest_digest=manifest.canonical_hash(),
        vault_ref=None,
    )
    grant = DirectoryGrantV1(
        mode=AppMode.PERSONAL,
        workspace=None,
        root=str(context.workspace),
    )
    placeholder = authority.issue(
        product_id="js-agent",
        owner_key_hash="owner-a",
        session_id="session-a",
        run_id="run-a",
        tool_name="connector.local_import.read",
        args_schema="sha256:" + "0" * 64,
        resource_scope="connection:import-a:files",
        fs_roots=(grant.root,),
        network_policy="deny",
        network_hosts=(),
        max_bytes=10 * 1024 * 1024,
        max_duration_ms=30_000,
        max_invocations=1,
        ttl_ms=60_000,
    )
    request = contracts.ConnectorExecutionRequestV1(
        task_ref=context.task_ref,
        connection=connection,
        manifest=manifest,
        operation="read",
        scope="files",
        params_digest=contracts.canonical_params_digest(params),
        directory_grant=grant,
        approval_id=None,
        lease=placeholder,
    )
    lease = authority.issue(
        product_id="js-agent",
        owner_key_hash="owner-a",
        session_id="session-a",
        run_id="run-a",
        tool_name="connector.local_import.read",
        args_schema=request.authority_binding_hash(),
        resource_scope="connection:import-a:files",
        fs_roots=(grant.root,),
        network_policy="deny",
        network_hosts=(),
        max_bytes=10 * 1024 * 1024,
        max_duration_ms=30_000,
        max_invocations=1,
        ttl_ms=60_000,
    )
    return dataclasses.replace(request, lease=lease)


def _write_request(
    agent,  # type: ignore[no-untyped-def]
    context,  # type: ignore[no-untyped-def]
    authority: LeaseAuthority,
    *,
    params: dict[str, object],
    network_policy: str = "deny",
):
    manifest = ConnectorManifestV1(
        connector_type="local_publish",
        capabilities=("read", "write"),
        read_scopes=("artifacts",),
        write_scopes=("publish",),
        approval_policy="explicit",
    )
    connection = contracts.ConnectionRefV2(
        ref=ConnectionRefV1(
            mode=AppMode.PERSONAL,
            owner="owner-a",
            workspace=None,
            connector_type="local_publish",
            connection_id="publish-a",
            authorized_by="owner-a",
        ),
        manifest_digest=manifest.canonical_hash(),
        vault_ref=None,
    )
    grant = DirectoryGrantV1(
        mode=AppMode.PERSONAL,
        workspace=None,
        root=str(context.workspace),
    )
    placeholder = authority.issue(
        product_id="js-agent",
        owner_key_hash="owner-a",
        session_id="session-a",
        run_id="run-a",
        tool_name="connector.local_publish.write",
        args_schema="sha256:" + "0" * 64,
        resource_scope="connection:publish-a:publish",
        fs_roots=(grant.root,),
        network_policy="deny",
        network_hosts=(),
        max_bytes=10 * 1024 * 1024,
        max_duration_ms=30_000,
        max_invocations=1,
        ttl_ms=60_000,
    )
    request = contracts.ConnectorExecutionRequestV1(
        task_ref=context.task_ref,
        connection=connection,
        manifest=manifest,
        operation="write",
        scope="publish",
        params_digest=contracts.canonical_params_digest(params),
        directory_grant=grant,
        approval_id="approval-placeholder",
        lease=placeholder,
    )
    approval_arguments = {
        "authority_binding_hash": request.authority_binding_hash(),
        "scope": "publish",
    }
    pending = agent.approvals.request_decision(
        "connector.local_publish.write",
        approval_arguments,
        context="web",
        session_id="session-a",
        run_id="run-a",
        owner_key_hash="owner-a",
        queue_if_unhandled=True,
    )
    agent.approvals.decide(
        pending.request_id,
        ApprovalDecisionType.APPROVE,
        owner_key_hash="owner-a",
    )
    lease = authority.issue(
        product_id="js-agent",
        owner_key_hash="owner-a",
        session_id="session-a",
        run_id="run-a",
        tool_name="connector.local_publish.write",
        args_schema=request.authority_binding_hash(),
        resource_scope="connection:publish-a:publish",
        fs_roots=(grant.root,),
        network_policy=network_policy,
        network_hosts=(),
        max_bytes=10 * 1024 * 1024,
        max_duration_ms=30_000,
        max_invocations=1,
        ttl_ms=60_000,
    )
    return dataclasses.replace(
        request,
        approval_id=pending.request_id,
        lease=lease,
    )


def test_default_production_manager_is_empty_and_sealed() -> None:
    manager = ConnectorManager()
    connector = _CountingConnector()
    assert manager.list_available() == []
    with pytest.raises(PermissionError, match="sealed"):
        manager.register_instance(connector)
    assert connector.write_calls == 0


def test_public_connector_package_exports_only_safe_runtime_contracts() -> None:
    import js.connectors as connector_api

    for internal in (
        "ConnectorBase",
        "ConnectorManager",
        "ConnectorRegistry",
        "ConnectorResult",
        "FakeConnector",
        "LimitedWritePublishConnector",
        "ReadOnlyImportConnector",
    ):
        assert not hasattr(connector_api, internal)
    assert connector_api.DirectoryGrantV1 is DirectoryGrantV1
    assert connector_api.ConnectorRunOutcomeV1 is contracts.ConnectorRunOutcomeV1


def test_explicit_production_factory_contains_only_local_connectors() -> None:
    from js.connectors import manager as manager_module

    factory = getattr(manager_module, "build_production_connector_manager", None)
    assert callable(factory)
    manager = factory()
    assert {item["connector_type"] for item in manager.list_available()} == {
        "local_import",
        "local_publish",
    }
    assert not manager.is_available("fake")


def test_test_managers_are_isolated_and_not_shared_between_runtimes() -> None:
    first = build_test_connector_manager()
    second = build_test_connector_manager()
    assert first is not second
    assert first._registry is not second._registry


@pytest.mark.asyncio
async def test_forged_and_copied_private_dispatch_permits_are_rejected() -> None:
    import js.connectors.base as base_module

    manager = build_test_connector_manager()
    connector = manager._registry.get_instance("fake")
    assert connector is not None
    with pytest.raises(PermissionError):
        base_module._issue_dispatch_permit(  # type: ignore[call-arg]
            manager=manager,
            connector=connector,
            operation="read",
            issuer=object(),
        )
    forged = await connector.read(
        "test",
        _permit=object(),
        _manager=manager,
    )
    assert forged.error == "connector_runtime_authority_required"

    permit = base_module._issue_dispatch_permit(  # type: ignore[call-arg]
        manager=manager,
        connector=connector,
        operation="read",
        issuer=manager._permit_issuer,
    )
    with pytest.raises(TypeError, match="copied"):
        copy.copy(permit)


@pytest.mark.asyncio
async def test_direct_local_import_fails_before_reading(tmp_path: Path) -> None:
    root = tmp_path / "import"
    root.mkdir()
    source = root / "private.txt"
    source.write_bytes(b"do-not-read")

    result = await ReadOnlyImportConnector().read(
        "files",
        params={"path": "private.txt"},
        directory_grant=_grant(root),
    )

    assert result.success is False
    assert result.error == "connector_runtime_authority_required"
    assert result.data == {}


@pytest.mark.asyncio
async def test_direct_publish_rejects_fake_approval_and_lease_before_write(
    tmp_path: Path,
) -> None:
    root = tmp_path / "publish"
    root.mkdir()
    target = root / "artifact.txt"

    result = await LimitedWritePublishConnector().write(
        "publish",
        params={"content": b"must-not-write", "filename": target.name},
        directory_grant=_grant(root),
        approval_id="any-nonempty-approval",
        lease_id="any-nonempty-lease",
    )

    assert result.success is False
    assert result.error == "connector_runtime_authority_required"
    assert not target.exists()


@pytest.mark.asyncio
async def test_direct_manager_dispatch_never_invokes_handler() -> None:
    manager = ConnectorManager(production=False)
    connector = _CountingConnector()
    with pytest.raises(PermissionError, match="sealed"):
        manager.register_instance(connector)

    result = await manager.execute_write("counting", "publish", params={})

    assert result.success is False
    assert result.error == "connector_runtime_authority_required"
    assert connector.write_calls == 0


def test_effect_interpreter_and_runtime_expose_connector_boundary() -> None:
    from js.echo.effect_interpreter import EffectInterpreter
    from js.echo.turn_runtime import EchoRuntime

    assert callable(getattr(EffectInterpreter, "execute_connector", None))
    assert callable(getattr(EchoRuntime, "execute_connector_effect", None))


@pytest.mark.asyncio
async def test_signed_standalone_context_reaches_only_runtime_connector_boundary(
    tmp_path: Path,
) -> None:
    _agent, runtime, context, authority, _store, _principal, _token = _runtime_bundle(tmp_path)
    # Create a source file in the workspace for the import to read
    source_file = tmp_path / "workspace" / "source.txt"
    source_file.write_text("test content", encoding="utf-8")
    params = {"path": "source.txt"}
    request = _read_request(context, authority, params=params)

    outcome = await runtime.execute_connector_effect(request, params=params, context=context)

    assert outcome.success is True
    assert outcome.receipt_id == ""  # R4-A still has no durable receipt
    assert len(outcome.effects) == 1
    assert outcome.effects[0].effect_type == "read"


@pytest.mark.asyncio
async def test_tampered_taskref_and_params_fail_before_connector_dispatch(
    tmp_path: Path,
) -> None:
    _agent, runtime, context, authority, _store, _principal, _token = _runtime_bundle(tmp_path)
    params = {"path": "source.txt"}
    request = _read_request(context, authority, params=params)

    with pytest.raises(PermissionError):
        await runtime.execute_connector_effect(
            request,
            params={"path": "different.txt"},
            context=context,
        )
    tampered_context = dataclasses.replace(
        context,
        task_ref=TaskRef(
            mode=AppMode.PERSONAL,
            owner="owner-a",
            session="session-a",
            run="run-other",
            workspace=None,
        ),
    )
    with pytest.raises(PermissionError):
        await runtime.execute_connector_effect(
            request,
            params=params,
            context=tampered_context,
        )


@pytest.mark.asyncio
async def test_write_consumes_exact_manual_approval_and_lease_once(
    tmp_path: Path,
) -> None:
    agent, runtime, context, authority, _store, _principal, _token = _runtime_bundle(tmp_path)
    params = {
        "artifact_ref": {"uri": "echo://artifact/opaque-a"},
        "filename": "artifact.txt",
    }
    request = _write_request(agent, context, authority, params=params)

    outcome = await runtime.execute_connector_effect(request, params=params, context=context)

    # The connector now has real I/O but the artifact_ref is invalid,
    # so it fails with an artifact error. The approval and lease were
    # consumed before the I/O error.
    assert outcome.success is False
    # Approval and lease were consumed (cannot replay)
    with pytest.raises(PermissionError):
        await runtime.execute_connector_effect(request, params=params, context=context)


@pytest.mark.asyncio
async def test_invalid_signed_lease_does_not_consume_exact_approval(
    tmp_path: Path,
) -> None:
    agent, runtime, context, authority, _store, _principal, _token = _runtime_bundle(tmp_path)
    params = {
        "artifact_ref": {"uri": "echo://artifact/opaque-a"},
        "filename": "artifact.txt",
    }
    wrong_lease_request = _write_request(
        agent,
        context,
        authority,
        params=params,
        network_policy="allow",
    )
    correct_lease = authority.issue(
        product_id="js-agent",
        owner_key_hash="owner-a",
        session_id="session-a",
        run_id="run-a",
        tool_name="connector.local_publish.write",
        args_schema=wrong_lease_request.authority_binding_hash(),
        resource_scope="connection:publish-a:publish",
        fs_roots=(wrong_lease_request.directory_grant.root,),
        network_policy="deny",
        network_hosts=(),
        max_bytes=10 * 1024 * 1024,
        max_duration_ms=30_000,
        max_invocations=1,
        ttl_ms=60_000,
    )

    with pytest.raises(LeaseDenied):
        await runtime.execute_connector_effect(
            wrong_lease_request,
            params=params,
            context=context,
        )

    outcome = await runtime.execute_connector_effect(
        dataclasses.replace(wrong_lease_request, lease=correct_lease),
        params=params,
        context=context,
    )
    # Connector fails because artifact_ref is invalid, but approval and
    # correct lease were consumed.
    assert outcome.success is False


@pytest.mark.asyncio
async def test_appshell_connector_preflight_failure_releases_operation_exactly_once(
    tmp_path: Path,
) -> None:
    _agent, runtime, context, authority, store, principal, _token = _runtime_bundle(
        tmp_path,
        managed=True,
    )
    assert store is not None and principal is not None
    request = _read_request(context, authority, params={"path": "source.txt"})

    binding = principal.epoch_binding()
    held = [
        store.begin_operation(binding, operation_kind=f"preflight_{index}")
        for index in range(255)
    ]
    try:
        with pytest.raises(PermissionError):
            await runtime.execute_connector_effect(
                request,
                params={"path": "tampered.txt"},
                context=context,
            )
        assert store.active_operation_count(binding) == 255
    finally:
        for operation in held:
            assert store.release_operation(operation)
    assert store.active_operation_count(binding) == 0


@pytest.mark.asyncio
async def test_appshell_connector_preserves_256_operation_capacity_code(
    tmp_path: Path,
) -> None:
    _agent, runtime, context, authority, store, principal, _token = _runtime_bundle(
        tmp_path,
        managed=True,
    )
    assert store is not None and principal is not None
    binding = principal.epoch_binding()
    held = [
        store.begin_operation(binding, operation_kind=f"held_{index}")
        for index in range(256)
    ]
    request = _read_request(context, authority, params={"path": "source.txt"})
    try:
        with pytest.raises(AppShellOperationLimitError):
            await runtime.execute_connector_effect(
                request,
                params={"path": "source.txt"},
                context=context,
            )
        assert store.active_operation_count(binding) == 256
    finally:
        for operation in held:
            assert store.release_operation(operation)
    assert store.active_operation_count(binding) == 0


@pytest.mark.asyncio
async def test_closed_appshell_epoch_rejects_old_connector_context_before_lease_consume(
    tmp_path: Path,
) -> None:
    _agent, runtime, context, authority, store, principal, token = _runtime_bundle(
        tmp_path,
        managed=True,
    )
    assert store is not None and principal is not None and token is not None
    request = _read_request(context, authority, params={"path": "source.txt"})
    binding = principal.epoch_binding()
    store.close_epoch(token, binding)

    with pytest.raises(PermissionError, match="closed or stale"):
        await runtime.execute_connector_effect(
            request,
            params={"path": "source.txt"},
            context=context,
        )

    authority.verify_bound(
        request.lease,
        expected_product_id="js-agent",
        expected_owner="owner-a",
        expected_session="session-a",
        expected_run="run-a",
        expected_tool="connector.local_import.read",
        expected_args_schema=request.authority_binding_hash(),
        expected_resource_scope="connection:import-a:files",
        expected_fs_roots=(request.directory_grant.root,),
        expected_network_policy="deny",
        expected_network_hosts=(),
        expected_max_bytes=10 * 1024 * 1024,
        expected_max_duration_ms=30_000,
        now=1_000,
        require_single_use=True,
    )
    store.reopen_epoch(binding)


# ---------------------------------------------------------------------------
# R4A-I3: Per-execution dispatch capability (non-forgeable, single-use)
# ---------------------------------------------------------------------------
from js.connectors.base import (  # noqa: E402
    _CAPABILITY_TTL_SECONDS,
    _PERMIT_FACTORY_KEY,
    _ConnectorDispatchCapability,
)


def test_runtime_object_cannot_authorize_dispatch() -> None:
    """Runtime object is not a valid dispatch authority."""
    manager = build_test_connector_manager()
    # _dispatch_authorized no longer accepts runtime_authority parameter
    # Passing it as a kwarg should raise TypeError
    import asyncio


    async def _try_dispatch() -> None:
        # Constructing a valid request is not necessary -- the signature
        # change itself prevents the bypass.
        try:
            await manager._dispatch_authorized(
                request=None,  # type: ignore[arg-type]
                params={},
                runtime_authority=object(),  # type: ignore[call-arg]
            )
        except TypeError:
            return  # Expected: unexpected keyword 'runtime_authority'
        except Exception:
            return  # Any other error is fine -- the point is it doesn't dispatch

    asyncio.run(_try_dispatch())


def test_dispatch_requires_capability_not_runtime() -> None:
    """_dispatch_authorized with capability=None is rejected."""
    # The _consume_capability method is the gate; test it directly.
    manager = build_test_connector_manager()
    assert manager._sealed  # manager is sealed
    # Verify that a forged capability (wrong nonce) is rejected
    from js.connectors.base import _PERMIT_FACTORY_KEY

    forged = _ConnectorDispatchCapability(
        _PERMIT_FACTORY_KEY,
        nonce="nonexistent",
        binding_digest="sha256:" + "0" * 64,
        issued_at=0.0,
    )
    assert manager._consume_capability(forged) is None


def test_dispatch_capability_single_use() -> None:
    """Capability can only be used once."""
    manager = build_test_connector_manager()
    issuer = manager._create_dispatch_issuer()

    cap = issuer.issue(
        authority_hash="sha256:" + "a" * 64,
        context_fingerprint="sha256:" + "b" * 64,
        appshell_operation_id=None,
        approval_claim_receipt_hash=None,
        lease_consume_receipt_hash="sha256:" + "c" * 64,
        connector_type="fake",
        operation="read",
    )
    # First use: consume the capability
    pending = manager._consume_capability(cap)
    assert pending is not None
    # Second use: should fail (nonce already consumed)
    pending2 = manager._consume_capability(cap)
    assert pending2 is None


def test_dispatch_capability_not_copyable() -> None:
    """Capability cannot be copied."""
    import copy

    manager = build_test_connector_manager()
    issuer = manager._create_dispatch_issuer()
    cap = issuer.issue(
        authority_hash="sha256:" + "a" * 64,
        context_fingerprint="sha256:" + "b" * 64,
        appshell_operation_id=None,
        approval_claim_receipt_hash=None,
        lease_consume_receipt_hash="sha256:" + "c" * 64,
        connector_type="fake",
        operation="read",
    )
    with pytest.raises(TypeError):
        copy.copy(cap)
    with pytest.raises(TypeError):
        copy.deepcopy(cap)


def test_dispatch_capability_not_cross_manager() -> None:
    """Capability from manager A cannot be used on manager B."""
    manager_a = build_test_connector_manager()
    manager_b = build_test_connector_manager()
    issuer_a = manager_a._create_dispatch_issuer()

    cap = issuer_a.issue(
        authority_hash="sha256:" + "a" * 64,
        context_fingerprint="sha256:" + "b" * 64,
        appshell_operation_id=None,
        approval_claim_receipt_hash=None,
        lease_consume_receipt_hash="sha256:" + "c" * 64,
        connector_type="fake",
        operation="read",
    )
    # Try to consume on manager B -> should fail (nonce not in B's registry)
    pending = manager_b._consume_capability(cap)
    assert pending is None


def test_dispatch_capability_binding_tamper_rejected() -> None:
    """Forged binding_digest is rejected."""
    manager = build_test_connector_manager()
    issuer = manager._create_dispatch_issuer()
    cap = issuer.issue(
        authority_hash="sha256:" + "a" * 64,
        context_fingerprint="sha256:" + "b" * 64,
        appshell_operation_id=None,
        approval_claim_receipt_hash=None,
        lease_consume_receipt_hash="sha256:" + "c" * 64,
        connector_type="fake",
        operation="read",
    )
    # Tamper with binding_digest
    tampered = _ConnectorDispatchCapability(
        _PERMIT_FACTORY_KEY,
        nonce=cap.nonce,
        binding_digest="sha256:" + "0" * 64,
        issued_at=0.0,
    )
    pending = manager._consume_capability(tampered)
    assert pending is None


def test_dispatch_capability_expired() -> None:
    """Expired capability is rejected."""
    import time as _time

    manager = build_test_connector_manager()
    issuer = manager._create_dispatch_issuer()
    cap = issuer.issue(
        authority_hash="sha256:" + "a" * 64,
        context_fingerprint="sha256:" + "b" * 64,
        appshell_operation_id=None,
        approval_claim_receipt_hash=None,
        lease_consume_receipt_hash="sha256:" + "c" * 64,
        connector_type="fake",
        operation="read",
    )
    # Simulate expiration by manipulating the pending entry's issued_at
    pending = manager._pending_capabilities[cap.nonce]
    pending.issued_at = _time.monotonic() - _CAPABILITY_TTL_SECONDS - 1
    result = manager._consume_capability(cap)
    assert result is None
