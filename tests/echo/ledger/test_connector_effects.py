"""R4-B Task B5: Connector durable effect, receipt, and artifact provenance."""

from __future__ import annotations

from pathlib import Path

import pytest

from js.echo.ledger.service import EchoSafetyService
from js.echo.mode_contract import (
    AppMode,
    ArtifactRefV1,
    ConnectorManifestV1,
    TaskRef,
)


def _service(tmp_path: Path) -> EchoSafetyService:
    return EchoSafetyService(state_dir=tmp_path / "echo")


def _manifest() -> ConnectorManifestV1:
    return ConnectorManifestV1(
        connector_type="local_import",
        capabilities=("read",),
        read_scopes=("import",),
        write_scopes=(),
        approval_policy="read_only",
    )


def _task_ref() -> TaskRef:
    return TaskRef(
        mode=AppMode.PERSONAL,
        owner="owner-a",
        session="session-a",
        run="run-a",
        workspace=None,
    )


def test_begin_connector_effect_produces_connector_action_kind(tmp_path: Path) -> None:
    """begin_connector_effect must produce action_kind='connector.<type>.<op>'."""
    service = _service(tmp_path)
    ctx = service.begin_connector_effect(
        tenant_id="owner-a",
        product_id="js-agent",
        session_id="session-a",
        run_id="run-a",
        workspace=None,
        connector_type="local_import",
        operation="read",
        connection_id="conn-a",
        task_ref_hash="sha256:" + "1" * 64,
        manifest_digest="sha256:" + "2" * 64,
        binding_hash="sha256:" + "3" * 64,
        params_digest="sha256:" + "4" * 64,
        directory_grant_hash="sha256:" + "5" * 64,
        vault_ref_hash=None,
        approval_id=None,
        lease_id="lease-a",
    )
    assert ctx.effect_id.startswith("eff_")
    assert ctx.outbox_id.startswith("out_")
    assert ctx.replay_class == "idempotent"  # read = idempotent


def test_finish_connector_effect_writes_receipt_with_artifact_refs(
    tmp_path: Path,
) -> None:
    """finish_connector_effect must write a receipt with artifact_refs."""
    service = _service(tmp_path)
    ctx = service.begin_connector_effect(
        tenant_id="owner-a",
        product_id="js-agent",
        session_id="session-a",
        run_id="run-a",
        workspace=None,
        connector_type="local_import",
        operation="read",
        connection_id="conn-a",
        task_ref_hash="sha256:" + "1" * 64,
        manifest_digest="sha256:" + "2" * 64,
        binding_hash="sha256:" + "3" * 64,
        params_digest="sha256:" + "4" * 64,
        directory_grant_hash="sha256:" + "5" * 64,
        vault_ref_hash=None,
        approval_id=None,
        lease_id="lease-a",
    )
    ref = ArtifactRefV1(
        owner="owner-a",
        mode=AppMode.PERSONAL,
        workspace=None,
        session="session-a",
        created_by_run="run-a",
        digest="sha256:" + "a" * 64,
        uri="echo://artifact/test-1",
        kind="document",
        acl="owner",
    )
    result = service.finish_connector_effect(
        ctx,
        status="ok",
        output_hash="sha256:" + "6" * 64,
        artifact_refs=(ref,),
    )
    assert result.ok


def test_failed_receipt_cannot_carry_artifact_refs(tmp_path: Path) -> None:
    """Non-ok status with artifact_refs must be rejected."""
    service = _service(tmp_path)
    ctx = service.begin_connector_effect(
        tenant_id="owner-a",
        product_id="js-agent",
        session_id="session-a",
        run_id="run-a",
        workspace=None,
        connector_type="local_import",
        operation="read",
        connection_id="conn-a",
        task_ref_hash="sha256:" + "1" * 64,
        manifest_digest="sha256:" + "2" * 64,
        binding_hash="sha256:" + "3" * 64,
        params_digest="sha256:" + "4" * 64,
        directory_grant_hash="sha256:" + "5" * 64,
        vault_ref_hash=None,
        approval_id=None,
        lease_id="lease-a",
    )
    ref = ArtifactRefV1(
        owner="owner-a",
        mode=AppMode.PERSONAL,
        workspace=None,
        session="session-a",
        created_by_run="run-a",
        digest="sha256:" + "b" * 64,
        uri="echo://artifact/test-2",
        kind="document",
        acl="owner",
    )
    with pytest.raises(ValueError, match="artifact refs require a successful"):
        service.finish_connector_effect(
            ctx,
            status="failed",
            output_hash="sha256:" + "7" * 64,
            artifact_refs=(ref,),
        )


def test_write_connector_effect_is_non_idempotent(tmp_path: Path) -> None:
    """Write operation must have replay_class='non_idempotent'."""
    service = _service(tmp_path)
    ctx = service.begin_connector_effect(
        tenant_id="owner-a",
        product_id="js-agent",
        session_id="session-a",
        run_id="run-a",
        workspace=None,
        connector_type="local_publish",
        operation="write",
        connection_id="conn-b",
        task_ref_hash="sha256:" + "1" * 64,
        manifest_digest="sha256:" + "2" * 64,
        binding_hash="sha256:" + "3" * 64,
        params_digest="sha256:" + "4" * 64,
        directory_grant_hash="sha256:" + "5" * 64,
        vault_ref_hash=None,
        approval_id="approval-a",
        lease_id="lease-b",
    )
    assert ctx.replay_class == "non_idempotent"


def test_connector_receipt_visible_in_verified_artifact_receipts(
    tmp_path: Path,
) -> None:
    """Connector artifacts must appear in list_verified_artifact_receipts."""
    service = _service(tmp_path)
    ctx = service.begin_connector_effect(
        tenant_id="owner-a",
        product_id="js-agent",
        session_id="session-a",
        run_id="run-a",
        workspace=None,
        connector_type="local_import",
        operation="read",
        connection_id="conn-c",
        task_ref_hash="sha256:" + "1" * 64,
        manifest_digest="sha256:" + "2" * 64,
        binding_hash="sha256:" + "3" * 64,
        params_digest="sha256:" + "4" * 64,
        directory_grant_hash="sha256:" + "5" * 64,
        vault_ref_hash=None,
        approval_id=None,
        lease_id="lease-c",
    )
    ref = ArtifactRefV1(
        owner="owner-a",
        mode=AppMode.PERSONAL,
        workspace=None,
        session="session-a",
        created_by_run="run-a",
        digest="sha256:" + "c" * 64,
        uri="echo://artifact/test-3",
        kind="document",
        acl="owner",
    )
    service.finish_connector_effect(
        ctx,
        status="ok",
        output_hash="sha256:" + "8" * 64,
        artifact_refs=(ref,),
    )
    receipts = service.list_verified_artifact_receipts(
        tenant_id="owner-a",
        mode=AppMode.PERSONAL,
        workspace=None,
    )
    assert len(receipts) >= 1
    found = any(
        any(ar.digest == ref.digest for ar in r.artifact_refs) for r in receipts
    )
    assert found, "connector artifact ref must appear in verified receipts"


def test_connector_receipt_survives_restart(tmp_path: Path) -> None:
    """Receipt must survive close/restart of EchoSafetyService."""
    service = _service(tmp_path)
    ctx = service.begin_connector_effect(
        tenant_id="owner-a",
        product_id="js-agent",
        session_id="session-a",
        run_id="run-a",
        workspace=None,
        connector_type="local_import",
        operation="read",
        connection_id="conn-d",
        task_ref_hash="sha256:" + "1" * 64,
        manifest_digest="sha256:" + "2" * 64,
        binding_hash="sha256:" + "3" * 64,
        params_digest="sha256:" + "4" * 64,
        directory_grant_hash="sha256:" + "5" * 64,
        vault_ref_hash=None,
        approval_id=None,
        lease_id="lease-d",
    )
    ref = ArtifactRefV1(
        owner="owner-a",
        mode=AppMode.PERSONAL,
        workspace=None,
        session="session-a",
        created_by_run="run-a",
        digest="sha256:" + "d" * 64,
        uri="echo://artifact/test-4",
        kind="document",
        acl="owner",
    )
    service.finish_connector_effect(
        ctx,
        status="ok",
        output_hash="sha256:" + "9" * 64,
        artifact_refs=(ref,),
    )
    service.close()

    restarted = EchoSafetyService(state_dir=tmp_path / "echo")
    receipts = restarted.list_verified_artifact_receipts(
        tenant_id="owner-a",
        mode=AppMode.PERSONAL,
        workspace=None,
    )
    assert len(receipts) >= 1
    found = any(
        any(ar.digest == ref.digest for ar in r.artifact_refs) for r in receipts
    )
    assert found, "connector artifact ref must survive restart"


def test_cross_owner_artifact_ref_rejected(tmp_path: Path) -> None:
    """Artifact ref with wrong owner must be rejected."""
    service = _service(tmp_path)
    ctx = service.begin_connector_effect(
        tenant_id="owner-a",
        product_id="js-agent",
        session_id="session-a",
        run_id="run-a",
        workspace=None,
        connector_type="local_import",
        operation="read",
        connection_id="conn-e",
        task_ref_hash="sha256:" + "1" * 64,
        manifest_digest="sha256:" + "2" * 64,
        binding_hash="sha256:" + "3" * 64,
        params_digest="sha256:" + "4" * 64,
        directory_grant_hash="sha256:" + "5" * 64,
        vault_ref_hash=None,
        approval_id=None,
        lease_id="lease-e",
    )
    wrong_ref = ArtifactRefV1(
        owner="owner-b",  # wrong owner
        mode=AppMode.PERSONAL,
        workspace=None,
        session="session-a",
        created_by_run="run-a",
        digest="sha256:" + "e" * 64,
        uri="echo://artifact/test-5",
        kind="document",
        acl="owner",
    )
    with pytest.raises(ValueError, match="owner does not match"):
        service.finish_connector_effect(
            ctx,
            status="ok",
            output_hash="sha256:" + "a" * 64,
            artifact_refs=(wrong_ref,),
        )
