"""SAME-FILE v2 coverage for verified artifacts in retired session partitions."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any

import pytest

from js.config import EchoLedgerConfig
from js.echo.ledger import service as service_module
from js.echo.ledger._hashing import stable_hash, stable_hmac
from js.echo.ledger.partition_retention import (
    PartitionRetentionError,
    RetentionReceiptInput,
    RetiredArtifactReceiptInput,
    clear_pending_retirement,
    load_and_verify_checkpoint,
    stage_retirement,
)
from js.echo.ledger.service import EchoSafetyService, EchoUnavailableError
from js.echo.mode_contract import AppMode, ArtifactRefV1


def _finish_artifact(
    service: EchoSafetyService,
    *,
    session: str,
    run: str,
    ordinal: int = 0,
    acl: str = "owner",
) -> ArtifactRefV1:
    context = service.begin_tool_effect(
        tenant_id="tenant-a",
        product_id="js-agent",
        session_id=session,
        run_id=run,
        tool_name="excel_write",
        tool_call_id=f"artifact-call-{ordinal}",
        args_hash="sha256:" + f"{ordinal + 1:x}" * 64,
        lease_id=f"artifact-lease-{ordinal}",
        replay_class="non_idempotent",
    )
    ref = ArtifactRefV1(
        mode=AppMode.PERSONAL,
        owner="tenant-a",
        session=session,
        workspace=None,
        kind="spreadsheet",
        uri=f"echo://artifact/retired-{session}-{ordinal}",
        digest="sha256:" + f"{ordinal + 2:x}" * 64,
        acl=acl,
        created_by_run=run,
    )
    service.finish_tool_effect(
        context,
        status="ok",
        output_hash=ref.digest,
        artifact_refs=(ref,),
    )
    return ref


def _finish_empty(service: EchoSafetyService, *, session: str, ordinal: int) -> None:
    context = service.begin_tool_effect(
        tenant_id="tenant-a",
        product_id="js-agent",
        session_id=session,
        run_id=f"empty-run-{ordinal}",
        tool_name="file_write",
        tool_call_id=f"empty-call-{ordinal}",
        args_hash="sha256:" + f"{ordinal + 3:x}" * 64,
        lease_id=f"empty-lease-{ordinal}",
        replay_class="non_idempotent",
    )
    service.finish_tool_effect(
        context,
        status="ok",
        output_hash="sha256:" + f"{ordinal + 5:x}" * 64,
    )


def _finish_artifact_batch(
    service: EchoSafetyService,
    *,
    session: str,
    batch: int,
    count: int,
    uri_padding: int,
) -> None:
    run = f"batch-run-{batch}"
    context = service.begin_tool_effect(
        tenant_id="tenant-a",
        product_id="js-agent",
        session_id=session,
        run_id=run,
        tool_name="excel_write",
        tool_call_id=f"batch-call-{batch}",
        args_hash="sha256:" + f"{batch + 1:x}" * 64,
        lease_id=f"batch-lease-{batch}",
        replay_class="non_idempotent",
    )
    refs = tuple(
        ArtifactRefV1(
            mode=AppMode.PERSONAL,
            owner="tenant-a",
            session=session,
            workspace=None,
            kind="spreadsheet",
            uri=f"echo://artifact/batch-{batch}-{index}-" + "a" * uri_padding,
            digest="sha256:" + f"{((batch + index) % 15) + 1:x}" * 64,
            acl="owner",
            created_by_run=run,
        )
        for index in range(count)
    )
    service.finish_tool_effect(
        context,
        status="ok",
        output_hash="sha256:" + "f" * 64,
        artifact_refs=refs,
    )


def _journal(service: EchoSafetyService, session: str) -> Path:
    return service.journal_path_for_scope(
        "tenant-a",
        product_id="js-agent",
        session_id=session,
    )


def _make_oldest(service: EchoSafetyService, session: str) -> None:
    os.utime(_journal(service, session), ns=(1_000_000_000, 1_000_000_000))


def _checkpoint_path(service: EchoSafetyService, session: str) -> Path:
    return _journal(service, session).parent.parent / "retired-sessions.json"


def _checkpoint(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _stage_public_checkpoint(
    path: Path,
    *,
    key: bytes,
    sequence: int,
    with_artifact: bool,
    max_receipts: int = 8,
) -> None:
    session_id = f"public-session-{sequence}"
    session_partition = "session_" + f"{sequence:x}" * 32
    run_id = f"public-run-{sequence}"
    refs: tuple[ArtifactRefV1, ...] = ()
    if with_artifact:
        refs = (
            ArtifactRefV1(
                mode=AppMode.PERSONAL,
                owner="public-owner",
                session=session_id,
                workspace=None,
                kind="spreadsheet",
                uri=f"echo://artifact/public-{sequence}",
                digest="sha256:" + f"{sequence + 1:x}" * 64,
                acl="owner",
                created_by_run=run_id,
            ),
        )
    stage_retirement(
        path,
        mac_key=key,
        product_partition="product_public",
        owner_partition="owner_public",
        max_receipts=max_receipts,
        max_artifact_refs=64,
        max_artifact_bytes=1024 * 1024,
        receipt=RetentionReceiptInput(
            session_partition=session_partition,
            source_files_hash="sha256:" + f"{sequence + 2:x}" * 64,
            source_file_count=1,
            source_total_bytes=128,
            journal_record_count=8,
            journal_tip_hash="sha256:" + f"{sequence + 3:x}" * 64,
            retired_at=f"2026-08-0{sequence}T00:00:00+00:00",
        ),
        artifact_receipts=(
            (
                RetiredArtifactReceiptInput(
                    receipt_id=f"receipt:public-effect-{sequence}",
                    effect_id=f"public-effect-{sequence}",
                    tenant_id="public-owner",
                    run_id=run_id,
                    product_id="js-agent",
                    workspace=None,
                    session_id=session_id,
                    artifact_refs=refs,
                ),
            )
            if refs
            else ()
        ),
    )


def _clear_public_pending(
    path: Path,
    *,
    key: bytes,
    max_receipts: int = 8,
) -> None:
    row = _checkpoint(path)
    pending = row["pending_retirement"]
    clear_pending_retirement(
        path,
        mac_key=key,
        product_partition="product_public",
        owner_partition="owner_public",
        max_receipts=max_receipts,
        max_artifact_refs=64,
        max_artifact_bytes=1024 * 1024,
        session_partition=pending["session_partition"],
        source_files_hash=pending["source_files_hash"],
    )


def _write_resigned_checkpoint(path: Path, *, key: bytes, body: dict[str, Any]) -> None:
    path.write_text(
        json.dumps(
            {**body, "mac": stable_hmac(key, body).hex()},
            sort_keys=True,
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )


def _load_public_checkpoint(path: Path, *, key: bytes, max_receipts: int = 8) -> None:
    load_and_verify_checkpoint(
        path,
        mac_key=key,
        product_partition="product_public",
        owner_partition="owner_public",
        max_receipts=max_receipts,
        max_artifact_refs=64,
        max_artifact_bytes=1024 * 1024,
    )


def test_pending_null_rejects_matching_catalog_group(tmp_path: Path) -> None:
    path = tmp_path / "retired-sessions.json"
    key = b"p" * 32
    _stage_public_checkpoint(path, key=key, sequence=1, with_artifact=True)
    row = _checkpoint(path)
    body = {field: value for field, value in row.items() if field != "mac"}
    body["pending_retirement"]["artifact_group_hash"] = None
    _write_resigned_checkpoint(path, key=key, body=body)

    with pytest.raises(PartitionRetentionError, match="pending retirement"):
        _load_public_checkpoint(path, key=key)


def test_pending_non_null_rejects_unrelated_latest_catalog_group(tmp_path: Path) -> None:
    path = tmp_path / "retired-sessions.json"
    key = b"q" * 32
    _stage_public_checkpoint(path, key=key, sequence=1, with_artifact=True)
    _clear_public_pending(path, key=key)
    _stage_public_checkpoint(path, key=key, sequence=2, with_artifact=False)
    row = _checkpoint(path)
    body = {field: value for field, value in row.items() if field != "mac"}
    body["pending_retirement"]["artifact_group_hash"] = body["artifact_catalog"][0][
        "group_hash"
    ]
    _write_resigned_checkpoint(path, key=key, body=body)

    with pytest.raises(PartitionRetentionError, match="pending retirement"):
        _load_public_checkpoint(path, key=key)


def test_pending_rejects_multiple_matching_catalog_groups(tmp_path: Path) -> None:
    path = tmp_path / "retired-sessions.json"
    key = b"s" * 32
    _stage_public_checkpoint(path, key=key, sequence=1, with_artifact=True)
    row = _checkpoint(path)
    body = {field: value for field, value in row.items() if field != "mac"}
    first = body["artifact_catalog"][0]
    second = json.loads(json.dumps(first))
    second["prev_hash"] = first["group_hash"]
    second["artifacts"][0]["artifact_ref"]["uri"] = "echo://artifact/public-duplicate"
    second_body = {
        field: value for field, value in second.items() if field != "group_hash"
    }
    second["group_hash"] = stable_hash(second_body)
    body["artifact_catalog"].append(second)
    body["artifact_catalog_tip"] = second["group_hash"]
    body["artifact_ref_count"] = 2
    body["artifact_bytes"] = sum(
        len(json.dumps(group, sort_keys=True, separators=(",", ":")).encode("utf-8"))
        for group in body["artifact_catalog"]
    )
    body["pending_retirement"]["artifact_group_hash"] = second["group_hash"]
    _write_resigned_checkpoint(path, key=key, body=body)

    with pytest.raises(PartitionRetentionError, match="pending retirement|duplicate"):
        _load_public_checkpoint(path, key=key)


def test_catalog_rejects_duplicate_retirement_sequence_after_receipt_compaction(
    tmp_path: Path,
) -> None:
    path = tmp_path / "retired-sessions.json"
    key = b"t" * 32
    _stage_public_checkpoint(
        path,
        key=key,
        sequence=1,
        with_artifact=True,
        max_receipts=1,
    )
    _clear_public_pending(path, key=key, max_receipts=1)
    _stage_public_checkpoint(
        path,
        key=key,
        sequence=2,
        with_artifact=True,
        max_receipts=1,
    )
    _clear_public_pending(path, key=key, max_receipts=1)
    row = _checkpoint(path)
    body = {field: value for field, value in row.items() if field != "mac"}
    second = body["artifact_catalog"][1]
    second["retirement_seq"] = 1
    receipt_body = {
        "seq": second["retirement_seq"],
        "session_partition": second["session_partition"],
        "source_files_hash": second["source_files_hash"],
        "source_file_count": second["source_file_count"],
        "source_total_bytes": second["source_total_bytes"],
        "journal_record_count": second["journal_record_count"],
        "journal_tip_hash": second["journal_tip_hash"],
        "retired_at": second["retired_at"],
        "prev_hash": second["retirement_prev_hash"],
    }
    second["retirement_receipt_hash"] = stable_hash(receipt_body)
    second_body = {
        field: value for field, value in second.items() if field != "group_hash"
    }
    second["group_hash"] = stable_hash(second_body)
    body["artifact_catalog_tip"] = second["group_hash"]
    body["artifact_bytes"] = sum(
        len(json.dumps(group, sort_keys=True, separators=(",", ":")).encode("utf-8"))
        for group in body["artifact_catalog"]
    )
    _write_resigned_checkpoint(path, key=key, body=body)

    with pytest.raises(PartitionRetentionError, match="duplicate|sequence"):
        _load_public_checkpoint(path, key=key, max_receipts=1)


def test_zero_ref_pending_keeps_null_group_hash(tmp_path: Path) -> None:
    path = tmp_path / "retired-sessions.json"
    key = b"u" * 32
    _stage_public_checkpoint(path, key=key, sequence=1, with_artifact=False)

    loaded = load_and_verify_checkpoint(
        path,
        mac_key=key,
        product_partition="product_public",
        owner_partition="owner_public",
        max_receipts=8,
        max_artifact_refs=64,
        max_artifact_bytes=1024 * 1024,
    )

    assert loaded["artifact_catalog"] == []
    assert loaded["pending_retirement"]["artifact_group_hash"] is None


def test_retired_artifact_config_rejects_unbounded_values() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        EchoLedgerConfig(max_retired_artifact_refs_per_owner=65_537)
    with pytest.raises(ValidationError):
        EchoLedgerConfig(max_retired_artifact_bytes_per_owner=64 * 1024 * 1024 + 1)


@pytest.mark.parametrize("kind", ("oversized", "fifo", "symlink"))
def test_checkpoint_rejects_unsafe_file_before_parsing(
    tmp_path: Path,
    kind: str,
) -> None:
    path = tmp_path / "retired-sessions.json"
    if kind == "oversized":
        with path.open("wb") as handle:
            handle.truncate(70 * 1024 * 1024)
    elif kind == "fifo":
        os.mkfifo(path, mode=0o600)
        assert stat.S_ISFIFO(path.lstat().st_mode)
    else:
        target = tmp_path / "target.json"
        target.write_text("{}", encoding="utf-8")
        path.symlink_to(target)

    with pytest.raises(PartitionRetentionError, match="size|regular"):
        load_and_verify_checkpoint(
            path,
            mac_key=b"v" * 32,
            product_partition="product_public",
            owner_partition="owner_public",
            max_receipts=256,
            max_artifact_refs=1024,
            max_artifact_bytes=4 * 1024 * 1024,
        )


def test_active_required_archive_and_retired_catalog_merge_after_restart(
    tmp_path: Path,
) -> None:
    config = EchoLedgerConfig(
        retain_records=2,
        trigger_records=100,
        max_archives=1,
        max_session_partitions_per_owner=2,
    )
    service = EchoSafetyService(state_dir=tmp_path, ledger_config=config)
    retired = _finish_artifact(
        service,
        session="retired-session",
        run="retired-run",
    )
    retired_journal = _journal(service, "retired-session")
    _make_oldest(service, "retired-session")
    active = _finish_artifact(
        service,
        session="active-session",
        run="active-run",
        ordinal=1,
    )
    active_journal = _journal(service, "active-session")
    assert service.compact_journals(max_records=2)[str(active_journal)] is True
    _finish_empty(service, session="trigger-session", ordinal=2)
    assert not retired_journal.exists()
    service.close()

    restarted = EchoSafetyService(state_dir=tmp_path, ledger_config=config)
    projection = restarted.project_verified_artifacts(
        tenant_id="tenant-a",
        mode=AppMode.PERSONAL,
        workspace=None,
        limit=50,
    )
    assert projection.retired_history_complete is True
    assert projection.refs == tuple(
        sorted(
            (active, retired),
            key=lambda ref: (ref.created_by_run, ref.session, ref.digest, ref.uri),
        )
    )
    checkpoint = _checkpoint(_checkpoint_path(restarted, "active-session"))
    assert checkpoint["schema_version"] == "echo-session-retention-v2"
    assert checkpoint["artifact_ref_count"] == 1
    assert len(checkpoint["artifact_catalog"]) == 1


def test_catalog_groups_survive_retirement_receipt_compaction(tmp_path: Path) -> None:
    config = EchoLedgerConfig(
        max_session_partitions_per_owner=2,
        max_retired_session_receipts_per_owner=1,
    )
    service = EchoSafetyService(state_dir=tmp_path, ledger_config=config)
    first = _finish_artifact(service, session="compact-first", run="compact-first-run")
    first_journal = _journal(service, "compact-first")
    _make_oldest(service, "compact-first")
    second = _finish_artifact(
        service,
        session="compact-second",
        run="compact-second-run",
        ordinal=1,
    )
    _finish_empty(service, session="compact-trigger-one", ordinal=2)
    assert not first_journal.exists()
    second_journal = _journal(service, "compact-second")
    _make_oldest(service, "compact-second")
    _finish_empty(service, session="compact-trigger-two", ordinal=3)
    assert not second_journal.exists()

    checkpoint = _checkpoint(_checkpoint_path(service, "compact-trigger-two"))
    assert checkpoint["retired_count"] == 2
    assert checkpoint["compacted_count"] == 1
    assert len(checkpoint["receipts"]) == 1
    assert len(checkpoint["artifact_catalog"]) == 2
    refs = service.list_verified_artifact_refs(
        tenant_id="tenant-a",
        mode=AppMode.PERSONAL,
        workspace=None,
    )
    assert {ref.digest for ref in refs} == {first.digest, second.digest}


def test_real_duplicate_refs_are_preserved_while_crash_retry_is_deduplicated(
    tmp_path: Path,
) -> None:
    config = EchoLedgerConfig(max_session_partitions_per_owner=2)
    service = EchoSafetyService(state_dir=tmp_path, ledger_config=config)
    context = service.begin_tool_effect(
        tenant_id="tenant-a",
        product_id="js-agent",
        session_id="duplicate-ref-session",
        run_id="duplicate-ref-run",
        tool_name="excel_write",
        tool_call_id="duplicate-ref-call",
        args_hash="sha256:" + "1" * 64,
        lease_id="duplicate-ref-lease",
        replay_class="non_idempotent",
    )
    ref = ArtifactRefV1(
        mode=AppMode.PERSONAL,
        owner="tenant-a",
        session="duplicate-ref-session",
        workspace=None,
        kind="spreadsheet",
        uri="echo://artifact/duplicate-real-ref",
        digest="sha256:" + "2" * 64,
        acl="owner",
        created_by_run="duplicate-ref-run",
    )
    service.finish_tool_effect(
        context,
        status="ok",
        output_hash=ref.digest,
        artifact_refs=(ref, ref),
    )
    duplicate_journal = _journal(service, "duplicate-ref-session")
    _make_oldest(service, "duplicate-ref-session")
    _finish_empty(service, session="duplicate-existing", ordinal=1)
    _finish_empty(service, session="duplicate-trigger", ordinal=2)
    assert not duplicate_journal.exists()

    assert service.list_verified_artifact_refs(
        tenant_id="tenant-a",
        mode=AppMode.PERSONAL,
        workspace=None,
    ) == (ref, ref)
    checkpoint = _checkpoint(_checkpoint_path(service, "duplicate-trigger"))
    assert checkpoint["artifact_ref_count"] == 2
    assert len(checkpoint["artifact_catalog"]) == 1


def test_v1_retired_history_is_incomplete_but_v1_zero_is_complete(tmp_path: Path) -> None:
    service = EchoSafetyService(state_dir=tmp_path)
    _finish_artifact(service, session="active-session", run="active-run")
    checkpoint_path = _checkpoint_path(service, "active-session")
    checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
    key_path = checkpoint_path.parent / "retention.key"
    key = b"r" * 32
    key_path.write_text(key.hex(), encoding="ascii")
    os.chmod(key_path, 0o600)

    for retired_count, expected_complete in ((0, True), (1, False)):
        receipts: list[dict[str, Any]] = []
        tip = "sha256:" + "0" * 64
        if retired_count:
            receipt_body = {
                "seq": 1,
                "session_partition": "session_" + "a" * 32,
                "source_files_hash": "sha256:" + "1" * 64,
                "source_file_count": 1,
                "source_total_bytes": 1,
                "journal_record_count": 1,
                "journal_tip_hash": "sha256:" + "2" * 64,
                "retired_at": "2026-08-02T00:00:00+00:00",
                "prev_hash": tip,
            }
            tip = stable_hash(receipt_body)
            receipts = [{**receipt_body, "receipt_hash": tip}]
        body = {
            "schema_version": "echo-session-retention-v1",
            "product_partition": checkpoint_path.parent.parent.name,
            "owner_partition": checkpoint_path.parent.name,
            "retired_count": retired_count,
            "compacted_count": 0,
            "compacted_tip": "sha256:" + "0" * 64,
            "tip": tip,
            "receipts": receipts,
        }
        checkpoint_path.write_text(
            json.dumps(
                {**body, "mac": stable_hmac(key, body).hex()},
                sort_keys=True,
                separators=(",", ":"),
            ),
            encoding="utf-8",
        )
        projection = service.project_verified_artifacts(
            tenant_id="tenant-a",
            mode=AppMode.PERSONAL,
            workspace=None,
        )
        assert projection.retired_history_complete is expected_complete


def test_artifact_quota_blocks_retirement_without_deleting_source_or_catalog(
    tmp_path: Path,
) -> None:
    config = EchoLedgerConfig(
        max_session_partitions_per_owner=2,
        max_retired_artifact_refs_per_owner=1,
    )
    service = EchoSafetyService(state_dir=tmp_path, ledger_config=config)
    first = _finish_artifact(service, session="first-artifact", run="first-run")
    _make_oldest(service, "first-artifact")
    second = _finish_artifact(
        service,
        session="second-artifact",
        run="second-run",
        ordinal=1,
    )
    third = _finish_artifact(
        service,
        session="first-trigger",
        run="first-trigger-run",
        ordinal=2,
    )
    checkpoint_path = _checkpoint_path(service, "second-artifact")
    before = checkpoint_path.read_bytes()
    second_journal = _journal(service, "second-artifact")
    _make_oldest(service, "second-artifact")

    with pytest.raises(EchoUnavailableError, match="retirement failed"):
        service.begin_tool_effect(
            tenant_id="tenant-a",
            product_id="js-agent",
            session_id="quota-overflow",
            run_id="quota-run",
            tool_name="file_write",
            tool_call_id="quota-call",
            args_hash="sha256:" + "9" * 64,
            lease_id="quota-lease",
            replay_class="non_idempotent",
        )

    assert second_journal.is_file()
    assert checkpoint_path.read_bytes() == before
    assert service.list_verified_artifact_refs(
        tenant_id="tenant-a",
        mode=AppMode.PERSONAL,
        workspace=None,
    ) == tuple(
        sorted(
            (
                first,
                second,
                third,
            ),
            key=lambda ref: (ref.created_by_run, ref.session, ref.digest, ref.uri),
        )
    )


def test_artifact_byte_quota_blocks_retirement_and_preserves_source(tmp_path: Path) -> None:
    config = EchoLedgerConfig(
        max_session_partitions_per_owner=2,
        max_retired_artifact_bytes_per_owner=1,
    )
    service = EchoSafetyService(state_dir=tmp_path, ledger_config=config)
    _finish_artifact(service, session="byte-quota-artifact", run="byte-quota-run")
    source_journal = _journal(service, "byte-quota-artifact")
    _make_oldest(service, "byte-quota-artifact")
    _finish_artifact(
        service,
        session="byte-quota-existing",
        run="byte-quota-existing-run",
        ordinal=1,
    )

    with pytest.raises(EchoUnavailableError, match="retirement failed") as raised:
        service.begin_tool_effect(
            tenant_id="tenant-a",
            product_id="js-agent",
            session_id="byte-quota-trigger",
            run_id="byte-quota-trigger-run",
            tool_name="file_write",
            tool_call_id="byte-quota-trigger-call",
            args_hash="sha256:" + "d" * 64,
            lease_id="byte-quota-trigger-lease",
            replay_class="non_idempotent",
        )

    assert "byte quota exceeded" in str(raised.value)
    assert source_journal.is_file()
    assert not _checkpoint_path(service, "byte-quota-existing").exists()


def test_zero_ref_session_can_retire_when_artifact_quota_is_full(tmp_path: Path) -> None:
    config = EchoLedgerConfig(
        max_session_partitions_per_owner=2,
        max_retired_artifact_refs_per_owner=1,
    )
    service = EchoSafetyService(state_dir=tmp_path, ledger_config=config)
    _finish_artifact(service, session="catalog-fill", run="fill-run")
    _make_oldest(service, "catalog-fill")
    _finish_artifact(
        service,
        session="quota-blocked-artifact",
        run="quota-blocked-run",
        ordinal=1,
    )
    _finish_empty(service, session="first-trigger", ordinal=2)
    assert service.health().retired_session_partition_count == 1
    blocked_journal = _journal(service, "quota-blocked-artifact")
    zero_ref_journal = _journal(service, "first-trigger")
    os.utime(blocked_journal, ns=(1_000_000_000, 1_000_000_000))
    os.utime(zero_ref_journal, ns=(2_000_000_000, 2_000_000_000))
    _finish_empty(service, session="second-trigger", ordinal=3)
    assert not zero_ref_journal.exists()
    assert blocked_journal.is_file()
    checkpoint = _checkpoint(_checkpoint_path(service, "second-trigger"))
    assert checkpoint["retired_count"] == 2
    assert checkpoint["artifact_ref_count"] == 1


@pytest.mark.parametrize(
    ("batch_sizes", "uri_padding", "expected_error"),
    (
        ((32, 32, 1), 8, "ref count exceeds hard limit"),
        ((20, 20, 20), 3_980, "artifact bytes exceed hard limit"),
    ),
)
def test_per_retirement_hard_limits_preserve_the_source_partition(
    tmp_path: Path,
    batch_sizes: tuple[int, ...],
    uri_padding: int,
    expected_error: str,
) -> None:
    config = EchoLedgerConfig(max_session_partitions_per_owner=2)
    service = EchoSafetyService(state_dir=tmp_path, ledger_config=config)
    session = "hard-limit-artifacts"
    for batch, count in enumerate(batch_sizes):
        _finish_artifact_batch(
            service,
            session=session,
            batch=batch,
            count=count,
            uri_padding=uri_padding,
        )
    source_journal = _journal(service, session)
    _make_oldest(service, session)
    open_context = service.begin_tool_effect(
        tenant_id="tenant-a",
        product_id="js-agent",
        session_id="hard-limit-existing",
        run_id="hard-limit-open-run",
        tool_name="file_write",
        tool_call_id="hard-limit-open-call",
        args_hash="sha256:" + "a" * 64,
        lease_id="hard-limit-open-lease",
        replay_class="non_idempotent",
    )
    assert open_context.outbox_id

    with pytest.raises(EchoUnavailableError, match="retirement failed") as raised:
        service.begin_tool_effect(
            tenant_id="tenant-a",
            product_id="js-agent",
            session_id="hard-limit-trigger",
            run_id="hard-limit-trigger-run",
            tool_name="file_write",
            tool_call_id="hard-limit-trigger-call",
            args_hash="sha256:" + "e" * 64,
            lease_id="hard-limit-trigger-lease",
            replay_class="non_idempotent",
        )

    assert expected_error in str(raised.value)
    assert source_journal.is_file()
    assert not (_checkpoint_path(service, "hard-limit-existing")).exists()


@pytest.mark.parametrize(
    "fault",
    ("before_rename", "before_delete", "before_clear_pending"),
)
def test_pending_retirement_crash_recovery_is_idempotent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fault: str,
) -> None:
    config = EchoLedgerConfig(max_session_partitions_per_owner=2)
    service = EchoSafetyService(state_dir=tmp_path, ledger_config=config)
    ref = _finish_artifact(service, session="crash-artifact", run="crash-run")
    _make_oldest(service, "crash-artifact")
    _finish_empty(service, session="existing-session", ordinal=1)

    if fault == "before_rename":
        original = service_module.os.rename

        def crash_before_rename(source: Path, target: Path) -> None:
            if Path(source).name.startswith("session_") and Path(target).name == ".retiring":
                raise OSError("crash before rename")
            original(source, target)

        monkeypatch.setattr(service_module.os, "rename", crash_before_rename)
    elif fault == "before_delete":
        monkeypatch.setattr(
            service_module,
            "_remove_retired_partition",
            lambda _root: (_ for _ in ()).throw(OSError("crash before delete")),
        )
    else:
        monkeypatch.setattr(
            service_module,
            "clear_pending_retirement",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                OSError("crash before clear pending")
            ),
            raising=False,
        )

    with pytest.raises(EchoUnavailableError, match="retirement failed"):
        service.begin_tool_effect(
            tenant_id="tenant-a",
            product_id="js-agent",
            session_id="crash-trigger",
            run_id="crash-trigger-run",
            tool_name="file_write",
            tool_call_id="crash-trigger-call",
            args_hash="sha256:" + "8" * 64,
            lease_id="crash-trigger-lease",
            replay_class="non_idempotent",
        )
    monkeypatch.undo()
    service.close()

    restarted = EchoSafetyService(state_dir=tmp_path, ledger_config=config)
    assert restarted.list_verified_artifact_refs(
        tenant_id="tenant-a",
        mode=AppMode.PERSONAL,
        workspace=None,
    ) == (ref,)
    checkpoint = _checkpoint(_checkpoint_path(restarted, "existing-session"))
    assert checkpoint["pending_retirement"] is None
    assert checkpoint["artifact_ref_count"] == 1
    assert len(checkpoint["artifact_catalog"]) == 1


@pytest.mark.parametrize("crash_location", ("active", "retiring"))
def test_pending_retirement_evidence_mismatch_preserves_source_and_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    crash_location: str,
) -> None:
    config = EchoLedgerConfig(max_session_partitions_per_owner=2)
    service = EchoSafetyService(state_dir=tmp_path, ledger_config=config)
    _finish_artifact(service, session="evidence-artifact", run="evidence-run")
    source_root = _journal(service, "evidence-artifact").parent
    _make_oldest(service, "evidence-artifact")
    _finish_empty(service, session="evidence-existing", ordinal=1)
    owner_root = source_root.parent
    if crash_location == "active":
        original = service_module.os.rename

        def crash_before_rename(source: Path, target: Path) -> None:
            if Path(source) == source_root and Path(target).name == ".retiring":
                raise OSError("crash before rename")
            original(source, target)

        monkeypatch.setattr(service_module.os, "rename", crash_before_rename)
    else:
        monkeypatch.setattr(
            service_module,
            "_remove_retired_partition",
            lambda _root: (_ for _ in ()).throw(OSError("crash before delete")),
        )
    with pytest.raises(EchoUnavailableError, match="retirement failed"):
        service.begin_tool_effect(
            tenant_id="tenant-a",
            product_id="js-agent",
            session_id="evidence-trigger",
            run_id="evidence-trigger-run",
            tool_name="file_write",
            tool_call_id="evidence-trigger-call",
            args_hash="sha256:" + "c" * 64,
            lease_id="evidence-trigger-lease",
            replay_class="non_idempotent",
        )
    monkeypatch.undo()
    retained_root = source_root if crash_location == "active" else owner_root / ".retiring"
    unexpected = retained_root / "unexpected-private-file"
    unexpected.write_text("must remain", encoding="utf-8")
    service.close()

    if crash_location == "retiring":
        with pytest.raises(EchoUnavailableError, match="retirement recovery failed"):
            EchoSafetyService(state_dir=tmp_path, ledger_config=config)
        assert retained_root.is_dir()
        assert unexpected.read_text(encoding="utf-8") == "must remain"
        return
    restarted = EchoSafetyService(state_dir=tmp_path, ledger_config=config)
    assert restarted.health().ok is False
    assert retained_root.is_dir()
    assert unexpected.read_text(encoding="utf-8") == "must remain"
    with pytest.raises((EchoUnavailableError, PartitionRetentionError, ValueError)):
        restarted.project_verified_artifacts(
            tenant_id="tenant-a",
            mode=AppMode.PERSONAL,
            workspace=None,
        )


def test_retiring_symlink_is_never_followed_or_deleted(tmp_path: Path) -> None:
    service = EchoSafetyService(state_dir=tmp_path)
    _finish_empty(service, session="anchor", ordinal=1)
    owner_root = _journal(service, "anchor").parent.parent
    sentinel = tmp_path / "private-sentinel"
    sentinel.write_text("keep", encoding="utf-8")
    (owner_root / ".retiring").symlink_to(sentinel)
    service.close()

    with pytest.raises(EchoUnavailableError, match="retirement recovery failed"):
        EchoSafetyService(state_dir=tmp_path)
    assert sentinel.read_text(encoding="utf-8") == "keep"
    assert (owner_root / ".retiring").is_symlink()


@pytest.mark.parametrize(
    "tamper",
    (
        "mac",
        "unknown_field",
        "ref_count",
        "artifact_bytes",
        "catalog_chain",
        "artifact_roundtrip",
        "owner",
        "product",
        "mode",
        "workspace",
        "session",
        "run",
        "receipt_binding",
    ),
)
def test_retired_catalog_tamper_blocks_health_and_projection(
    tmp_path: Path,
    tamper: str,
) -> None:
    config = EchoLedgerConfig(max_session_partitions_per_owner=2)
    service = EchoSafetyService(state_dir=tmp_path, ledger_config=config)
    _finish_artifact(service, session="tamper-artifact", run="tamper-run")
    _make_oldest(service, "tamper-artifact")
    _finish_empty(service, session="tamper-existing", ordinal=1)
    _finish_empty(service, session="tamper-trigger", ordinal=2)
    checkpoint_path = _checkpoint_path(service, "tamper-existing")
    row = _checkpoint(checkpoint_path)
    key = bytes.fromhex(
        (checkpoint_path.parent / "retention.key").read_text(encoding="ascii").strip()
    )
    body = {field: value for field, value in row.items() if field != "mac"}
    entry = body["artifact_catalog"][0]["artifacts"][0]
    if tamper == "unknown_field":
        body["unknown"] = "forged"
    elif tamper == "ref_count":
        body["artifact_ref_count"] += 1
    elif tamper == "artifact_bytes":
        body["artifact_bytes"] += 1
    elif tamper == "catalog_chain":
        body["artifact_catalog"][0]["prev_hash"] = "sha256:" + "9" * 64
    elif tamper == "artifact_roundtrip":
        entry["artifact_ref"]["physical_path"] = "/private/forged"
    elif tamper == "owner":
        entry["artifact_ref"]["owner"] = "tenant-b"
    elif tamper == "product":
        entry["binding"]["product_id"] = "js-work"
    elif tamper == "mode":
        entry["artifact_ref"]["mode"] = "work"
        entry["artifact_ref"]["workspace"] = "ws-" + "a" * 64
    elif tamper == "workspace":
        entry["binding"]["workspace"] = "ws-" + "a" * 64
    elif tamper == "session":
        entry["binding"]["session_id"] = "forged-session"
    elif tamper == "run":
        entry["binding"]["run_id"] = "forged-run"
    elif tamper == "receipt_binding":
        entry["receipt_id"] = "receipt:forged-effect"
    group = body["artifact_catalog"][0]
    if tamper not in {"mac", "unknown_field", "ref_count", "artifact_bytes"}:
        group_body = {
            field: value for field, value in group.items() if field != "group_hash"
        }
        group["group_hash"] = stable_hash(group_body)
        body["artifact_catalog_tip"] = group["group_hash"]
        body["artifact_bytes"] = len(
            json.dumps(group, sort_keys=True, separators=(",", ":")).encode("utf-8")
        )
    mac = row["mac"] if tamper == "mac" else stable_hmac(key, body).hex()
    if tamper == "mac":
        mac = ("0" if mac[0] != "0" else "1") + mac[1:]
    checkpoint_path.write_text(
        json.dumps(
            {**body, "mac": mac},
            sort_keys=True,
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
    service.close()

    restarted = EchoSafetyService(state_dir=tmp_path, ledger_config=config)
    assert restarted.health().ok is False
    with pytest.raises((EchoUnavailableError, PartitionRetentionError, ValueError)):
        restarted.project_verified_artifacts(
            tenant_id="tenant-a",
            mode=AppMode.PERSONAL,
            workspace=None,
        )
