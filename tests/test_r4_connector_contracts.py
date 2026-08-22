"""Strict R4-A connector authority contract regressions."""

from __future__ import annotations

import dataclasses
import math
from pathlib import Path

import pytest

import js.connectors as connector_api
from js.connectors import contracts
from js.echo.capability import LeaseAuthority
from js.echo.mode_contract import (
    AppMode,
    ConnectionRefV1,
    ConnectorManifestV1,
    DirectoryGrantV1,
    TaskRef,
)


def _lease(*, args_schema: str = "sha256:" + "1" * 64):
    authority = LeaseAuthority(mac_key=b"r4-contract-test-key-32-bytes!!", now_fn=lambda: 1_000)
    return authority.issue(
        product_id="js-agent",
        owner_key_hash="owner-a",
        session_id="session-a",
        run_id="run-a",
        tool_name="connector.local_import.read",
        args_schema=args_schema,
        resource_scope="connection:import-a:files",
        fs_roots=("/tmp/r4-grant",),
        network_policy="deny",
        network_hosts=(),
        max_bytes=1024,
        max_duration_ms=1_000,
        max_invocations=1,
        ttl_ms=60_000,
    )


def _manifest() -> ConnectorManifestV1:
    return ConnectorManifestV1(
        connector_type="local_import",
        capabilities=("read",),
        read_scopes=("files",),
        write_scopes=(),
        approval_policy="read_only",
    )


def _task() -> TaskRef:
    return TaskRef(
        mode=AppMode.PERSONAL,
        owner="owner-a",
        session="session-a",
        run="run-a",
        workspace=None,
    )


def _connection(manifest: ConnectorManifestV1):
    ref = ConnectionRefV1(
        mode=AppMode.PERSONAL,
        owner="owner-a",
        workspace=None,
        connector_type="local_import",
        connection_id="import-a",
        authorized_by="owner-a",
    )
    return contracts.ConnectionRefV2(
        ref=ref,
        manifest_digest=manifest.canonical_hash(),
        vault_ref=None,
    )


def test_connector_api_has_one_directory_grant_authority() -> None:
    """Removing the R1 grant must make this fail; duplicate connector grants are forbidden."""
    assert not hasattr(contracts, "DirectoryGrant")
    assert not hasattr(connector_api, "DirectoryGrant")
    assert contracts.DirectoryGrantV1 is DirectoryGrantV1


def test_canonical_params_digest_is_prefixed_and_rejects_non_json_values() -> None:
    assert contracts.canonical_params_digest({"b": [True, None], "a": 1}) == (
        "sha256:1cc69c7fa23616ca2ec3ee70d24390a6225c8832db8a4c814c7e0e7f942f8668"
    )
    for invalid in (
        {"bytes": b"secret"},
        {"path": Path("relative")},
        {"nan": math.nan},
        {"infinity": math.inf},
        {"custom": object()},
    ):
        with pytest.raises((TypeError, ValueError)):
            contracts.canonical_params_digest(invalid)


def test_v2_request_uses_exact_r1_values_and_server_only_lease() -> None:
    manifest = _manifest()
    params_digest = contracts.canonical_params_digest({"path": "document.txt"})
    request = contracts.ConnectorExecutionRequestV1(
        task_ref=_task(),
        connection=_connection(manifest),
        manifest=manifest,
        operation="read",
        scope="files",
        params_digest=params_digest,
        directory_grant=DirectoryGrantV1(
            mode=AppMode.PERSONAL,
            workspace=None,
            root="/tmp/r4-grant",
        ),
        approval_id=None,
        lease=_lease(),
    )

    assert type(request.task_ref) is TaskRef
    assert type(request.directory_grant) is DirectoryGrantV1
    assert request.connection.ref.connector_type == request.manifest.connector_type
    assert request.connection.manifest_digest == request.manifest.canonical_hash()
    assert request.to_safe_dict()["lease_id"] == request.lease.lease_id
    assert "mac" not in repr(request.to_safe_dict()).casefold()
    assert contracts.ConnectorExecutionRequestV1.from_dict(
        request.to_safe_dict(), lease=request.lease
    ) == request


@pytest.mark.parametrize(
    "change",
    [
        {"operation": "write"},
        {"scope": "unknown"},
        {"approval_id": "unexpected-read-approval"},
        {"params_digest": "1" * 64},
        {"directory_grant": object()},
        {"lease": "lease-id-only"},
    ],
)
def test_request_rejects_invalid_or_cross_bound_fields(change: dict[str, object]) -> None:
    manifest = _manifest()
    values: dict[str, object] = {
        "task_ref": _task(),
        "connection": _connection(manifest),
        "manifest": manifest,
        "operation": "read",
        "scope": "files",
        "params_digest": contracts.canonical_params_digest({"path": "document.txt"}),
        "directory_grant": DirectoryGrantV1(
            mode=AppMode.PERSONAL,
            workspace=None,
            root="/tmp/r4-grant",
        ),
        "approval_id": None,
        "lease": _lease(),
    }
    values.update(change)
    with pytest.raises((TypeError, ValueError)):
        contracts.ConnectorExecutionRequestV1(**values)  # type: ignore[arg-type]


def test_authority_binding_hash_changes_for_each_authority_field() -> None:
    manifest = _manifest()
    request = contracts.ConnectorExecutionRequestV1(
        task_ref=_task(),
        connection=_connection(manifest),
        manifest=manifest,
        operation="read",
        scope="files",
        params_digest=contracts.canonical_params_digest({"path": "document.txt"}),
        directory_grant=DirectoryGrantV1(
            mode=AppMode.PERSONAL,
            workspace=None,
            root="/tmp/r4-grant",
        ),
        approval_id=None,
        lease=_lease(),
    )
    baseline = request.authority_binding_hash()
    assert baseline.startswith("sha256:") and len(baseline) == 71

    replacements = (
        dataclasses.replace(request, params_digest="sha256:" + "2" * 64),
        dataclasses.replace(
            request,
            directory_grant=DirectoryGrantV1(
                mode=AppMode.PERSONAL,
                workspace=None,
                root="/tmp/r4-other",
            ),
        ),
    )
    assert all(candidate.authority_binding_hash() != baseline for candidate in replacements)

    with pytest.raises(ValueError, match="connection authority"):
        dataclasses.replace(
            request,
            task_ref=TaskRef(
                mode=AppMode.PERSONAL,
                owner="owner-b",
                session="session-a",
                run="run-a",
                workspace=None,
            ),
        )


def test_vault_ref_is_opaque_and_exactly_bound_to_connection() -> None:
    with pytest.raises(ValueError):
        contracts.VaultRefV1(
            vault_id="https://vault.invalid/item?token=secret",
            mode=AppMode.WORK,
            owner="owner-a",
            workspace="ws-a",
            connection_id="work-a",
        )

    manifest = ConnectorManifestV1(
        connector_type="remote_schema",
        capabilities=("read",),
        read_scopes=("items",),
        approval_policy="read_only",
    )
    ref = ConnectionRefV1(
        mode=AppMode.WORK,
        owner="owner-a",
        workspace="ws-a",
        connector_type="remote_schema",
        connection_id="work-a",
        authorized_by="owner-a",
    )
    with pytest.raises(ValueError):
        contracts.ConnectionRefV2(
            ref=ref,
            manifest_digest=manifest.canonical_hash(),
            vault_ref=contracts.VaultRefV1(
                vault_id="vault-a",
                mode=AppMode.WORK,
                owner="owner-a",
                workspace="ws-a",
                connection_id="work-b",
            ),
        )
