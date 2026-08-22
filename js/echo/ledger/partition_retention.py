from __future__ import annotations

import json
import os
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from js.echo.ledger._hashing import canonical_json, hmac_matches, stable_hash, stable_hmac
from js.echo.mode_contract import AppMode, ArtifactRefV1

SCHEMA_VERSION_V1 = "echo-session-retention-v1"
SCHEMA_VERSION = "echo-session-retention-v2"
GENESIS_HASH = "sha256:" + "0" * 64
MAX_ARTIFACT_REFS_PER_RETIREMENT = 64
MAX_ARTIFACT_BYTES_PER_RETIREMENT = 256 * 1024
MAX_RETIRED_ARTIFACT_REFS_PER_OWNER = 65_536
MAX_RETIRED_ARTIFACT_BYTES_PER_OWNER = 64 * 1024 * 1024
_MAX_CHECKPOINT_RECEIPT_COUNT_FOR_SIZE = 65_536
_MAX_CHECKPOINT_RECEIPT_BYTES = 2 * 1024
_MAX_CHECKPOINT_FIXED_BYTES = 1024 * 1024


class PartitionRetentionError(RuntimeError):
    """A bounded session-retention checkpoint is missing or invalid."""


class PartitionArtifactCapacityError(PartitionRetentionError):
    """A verified artifact catalog cannot admit this otherwise safe retirement."""


@dataclass(frozen=True, slots=True)
class RetentionReceiptInput:
    session_partition: str
    source_files_hash: str
    source_file_count: int
    source_total_bytes: int
    journal_record_count: int
    journal_tip_hash: str
    retired_at: str


@dataclass(frozen=True, slots=True)
class RetiredArtifactReceiptInput:
    """Verified receipt metadata staged with one retiring session."""

    receipt_id: str
    effect_id: str
    tenant_id: str
    run_id: str
    product_id: str
    workspace: str | None
    session_id: str
    artifact_refs: tuple[ArtifactRefV1, ...]


def empty_checkpoint(*, product_partition: str, owner_partition: str) -> dict[str, Any]:
    """Return the legacy empty shape for backward-compatible callers/readers."""
    return {
        "schema_version": SCHEMA_VERSION_V1,
        "product_partition": product_partition,
        "owner_partition": owner_partition,
        "retired_count": 0,
        "compacted_count": 0,
        "compacted_tip": GENESIS_HASH,
        "tip": GENESIS_HASH,
        "receipts": [],
    }


def load_and_verify_checkpoint(
    path: Path,
    *,
    mac_key: bytes,
    product_partition: str,
    owner_partition: str,
    max_receipts: int,
    max_artifact_refs: int = 1024,
    max_artifact_bytes: int = 4 * 1024 * 1024,
) -> dict[str, Any]:
    if max_receipts < 1:
        raise ValueError("max_receipts must be positive")
    if not 1 <= max_artifact_refs <= MAX_RETIRED_ARTIFACT_REFS_PER_OWNER:
        raise ValueError("retired artifact ref limit is out of range")
    if not 1 <= max_artifact_bytes <= MAX_RETIRED_ARTIFACT_BYTES_PER_OWNER:
        raise ValueError("retired artifact byte limit is out of range")
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return empty_checkpoint(
            product_partition=product_partition,
            owner_partition=owner_partition,
        )
    except OSError as exc:
        raise PartitionRetentionError("retention checkpoint is unreadable") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
    ):
        raise PartitionRetentionError("retention checkpoint is not a regular file")
    size_limit = _checkpoint_size_limit(
        max_receipts=max_receipts,
        max_artifact_bytes=max_artifact_bytes,
    )
    if metadata.st_size > size_limit:
        raise PartitionRetentionError("retention checkpoint size exceeds configured limit")
    fd = -1
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        opened = os.fstat(fd)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino)
            or opened.st_size > size_limit
        ):
            raise PartitionRetentionError(
                "retention checkpoint changed or exceeds configured size"
            )
        with os.fdopen(fd, "rb") as handle:
            fd = -1
            payload = handle.read(size_limit + 1)
            after = os.fstat(handle.fileno())
        if len(payload) > size_limit or after.st_size > size_limit:
            raise PartitionRetentionError("retention checkpoint size exceeds configured limit")
        if (
            (after.st_dev, after.st_ino) != (opened.st_dev, opened.st_ino)
            or after.st_size != opened.st_size
        ):
            raise PartitionRetentionError("retention checkpoint changed while reading")
        row = json.loads(payload.decode("utf-8"))
    except PartitionRetentionError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PartitionRetentionError("retention checkpoint is unreadable") from exc
    finally:
        if fd >= 0:
            os.close(fd)
    if not isinstance(row, dict):
        raise PartitionRetentionError("retention checkpoint is not an object")
    mac_hex = row.get("mac")
    if not isinstance(mac_hex, str):
        raise PartitionRetentionError("retention checkpoint MAC is missing")
    try:
        mac = bytes.fromhex(mac_hex)
    except ValueError as exc:
        raise PartitionRetentionError("retention checkpoint MAC is invalid") from exc
    body = {key: value for key, value in row.items() if key != "mac"}
    if not hmac_matches(mac_key, body, mac):
        raise PartitionRetentionError("retention checkpoint MAC mismatch")
    _verify_checkpoint_body(
        body,
        product_partition=product_partition,
        owner_partition=owner_partition,
        max_receipts=max_receipts,
        max_artifact_refs=max_artifact_refs,
        max_artifact_bytes=max_artifact_bytes,
    )
    return body


def append_retirement_receipt(
    path: Path,
    *,
    mac_key: bytes,
    product_partition: str,
    owner_partition: str,
    max_receipts: int,
    receipt: RetentionReceiptInput,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Legacy v1 writer retained for exact backward compatibility."""
    checkpoint = load_and_verify_checkpoint(
        path,
        mac_key=mac_key,
        product_partition=product_partition,
        owner_partition=owner_partition,
        max_receipts=max_receipts,
    )
    if checkpoint["schema_version"] != SCHEMA_VERSION_V1:
        raise PartitionRetentionError("legacy append cannot rewrite a v2 checkpoint")
    updated, stored_receipt = _append_receipt(
        checkpoint,
        receipt=receipt,
        max_receipts=max_receipts,
        allow_latest_reuse=True,
    )
    _verify_checkpoint_body(
        updated,
        product_partition=product_partition,
        owner_partition=owner_partition,
        max_receipts=max_receipts,
        max_artifact_refs=1024,
        max_artifact_bytes=4 * 1024 * 1024,
    )
    _atomic_write_checkpoint(path, body=updated, mac_key=mac_key)
    return updated, stored_receipt


def stage_retirement(
    path: Path,
    *,
    mac_key: bytes,
    product_partition: str,
    owner_partition: str,
    max_receipts: int,
    max_artifact_refs: int,
    max_artifact_bytes: int,
    receipt: RetentionReceiptInput,
    artifact_receipts: tuple[RetiredArtifactReceiptInput, ...],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Atomically stage receipt, catalog group, and pending retirement in v2."""
    checkpoint = load_and_verify_checkpoint(
        path,
        mac_key=mac_key,
        product_partition=product_partition,
        owner_partition=owner_partition,
        max_receipts=max_receipts,
        max_artifact_refs=max_artifact_refs,
        max_artifact_bytes=max_artifact_bytes,
    )
    checkpoint = _as_v2(checkpoint)
    pending = checkpoint["pending_retirement"]
    if pending is not None:
        if (
            pending["session_partition"] == receipt.session_partition
            and pending["source_files_hash"] == receipt.source_files_hash
        ):
            stored = _receipt_for_hash(checkpoint, pending["retirement_receipt_hash"])
            if stored is None:
                raise PartitionRetentionError("pending retirement receipt is unavailable")
            return checkpoint, stored
        raise PartitionRetentionError("another retirement is already pending")

    updated, stored_receipt = _append_receipt(
        checkpoint,
        receipt=receipt,
        max_receipts=max_receipts,
        allow_latest_reuse=False,
    )
    entries = _artifact_entries(artifact_receipts)
    if len(entries) > MAX_ARTIFACT_REFS_PER_RETIREMENT:
        raise PartitionArtifactCapacityError(
            "retirement artifact ref count exceeds hard limit"
        )
    catalog = list(updated["artifact_catalog"])
    group_hash: str | None = None
    if entries:
        group_body: dict[str, Any] = {
            "retirement_seq": stored_receipt["seq"],
            "retirement_prev_hash": stored_receipt["prev_hash"],
            "retirement_receipt_hash": stored_receipt["receipt_hash"],
            "session_partition": stored_receipt["session_partition"],
            "source_files_hash": stored_receipt["source_files_hash"],
            "source_file_count": stored_receipt["source_file_count"],
            "source_total_bytes": stored_receipt["source_total_bytes"],
            "journal_record_count": stored_receipt["journal_record_count"],
            "journal_tip_hash": stored_receipt["journal_tip_hash"],
            "retired_at": stored_receipt["retired_at"],
            "artifacts": entries,
            "prev_hash": updated["artifact_catalog_tip"],
        }
        group_hash = stable_hash(group_body)
        group = {**group_body, "group_hash": group_hash}
        group_bytes = _serialized_bytes(group)
        if group_bytes > MAX_ARTIFACT_BYTES_PER_RETIREMENT:
            raise PartitionArtifactCapacityError(
                "retirement artifact bytes exceed hard limit"
            )
        new_ref_count = int(updated["artifact_ref_count"]) + len(entries)
        new_artifact_bytes = int(updated["artifact_bytes"]) + group_bytes
        if new_ref_count > max_artifact_refs:
            raise PartitionArtifactCapacityError("retired artifact ref quota exceeded")
        if new_artifact_bytes > max_artifact_bytes:
            raise PartitionArtifactCapacityError("retired artifact byte quota exceeded")
        catalog.append(group)
        updated["artifact_ref_count"] = new_ref_count
        updated["artifact_bytes"] = new_artifact_bytes
        updated["artifact_catalog_tip"] = group_hash
    updated["artifact_catalog"] = catalog
    updated["pending_retirement"] = {
        "session_partition": receipt.session_partition,
        "source_files_hash": receipt.source_files_hash,
        "retirement_receipt_hash": stored_receipt["receipt_hash"],
        "artifact_group_hash": group_hash,
    }
    _verify_checkpoint_body(
        updated,
        product_partition=product_partition,
        owner_partition=owner_partition,
        max_receipts=max_receipts,
        max_artifact_refs=max_artifact_refs,
        max_artifact_bytes=max_artifact_bytes,
    )
    _atomic_write_checkpoint(path, body=updated, mac_key=mac_key)
    verified = load_and_verify_checkpoint(
        path,
        mac_key=mac_key,
        product_partition=product_partition,
        owner_partition=owner_partition,
        max_receipts=max_receipts,
        max_artifact_refs=max_artifact_refs,
        max_artifact_bytes=max_artifact_bytes,
    )
    return verified, stored_receipt


def clear_pending_retirement(
    path: Path,
    *,
    mac_key: bytes,
    product_partition: str,
    owner_partition: str,
    max_receipts: int,
    max_artifact_refs: int,
    max_artifact_bytes: int,
    session_partition: str,
    source_files_hash: str,
) -> dict[str, Any]:
    checkpoint = load_and_verify_checkpoint(
        path,
        mac_key=mac_key,
        product_partition=product_partition,
        owner_partition=owner_partition,
        max_receipts=max_receipts,
        max_artifact_refs=max_artifact_refs,
        max_artifact_bytes=max_artifact_bytes,
    )
    if checkpoint["schema_version"] != SCHEMA_VERSION:
        raise PartitionRetentionError("pending retirement requires v2 checkpoint")
    pending = checkpoint["pending_retirement"]
    if pending is None:
        return checkpoint
    if (
        pending["session_partition"] != session_partition
        or pending["source_files_hash"] != source_files_hash
    ):
        raise PartitionRetentionError("pending retirement identity mismatch")
    checkpoint["pending_retirement"] = None
    _verify_checkpoint_body(
        checkpoint,
        product_partition=product_partition,
        owner_partition=owner_partition,
        max_receipts=max_receipts,
        max_artifact_refs=max_artifact_refs,
        max_artifact_bytes=max_artifact_bytes,
    )
    _atomic_write_checkpoint(path, body=checkpoint, mac_key=mac_key)
    return load_and_verify_checkpoint(
        path,
        mac_key=mac_key,
        product_partition=product_partition,
        owner_partition=owner_partition,
        max_receipts=max_receipts,
        max_artifact_refs=max_artifact_refs,
        max_artifact_bytes=max_artifact_bytes,
    )


def retired_artifact_entries(checkpoint: dict[str, Any]) -> tuple[dict[str, Any], ...]:
    if checkpoint.get("schema_version") != SCHEMA_VERSION:
        return ()
    return tuple(
        entry
        for group in checkpoint["artifact_catalog"]
        for entry in group["artifacts"]
    )


def retired_history_complete(checkpoint: dict[str, Any]) -> bool:
    if checkpoint.get("schema_version") == SCHEMA_VERSION_V1:
        return int(checkpoint["retired_count"]) == 0
    if checkpoint.get("schema_version") == SCHEMA_VERSION:
        return int(checkpoint["legacy_unindexed_retired_count"]) == 0
    raise PartitionRetentionError("retention checkpoint schema is unsupported")


def _as_v2(checkpoint: dict[str, Any]) -> dict[str, Any]:
    if checkpoint["schema_version"] == SCHEMA_VERSION:
        return {**checkpoint, "receipts": list(checkpoint["receipts"]), "artifact_catalog": list(checkpoint["artifact_catalog"])}
    if checkpoint["schema_version"] != SCHEMA_VERSION_V1:
        raise PartitionRetentionError("retention checkpoint schema is unsupported")
    return {
        **checkpoint,
        "schema_version": SCHEMA_VERSION,
        "receipts": list(checkpoint["receipts"]),
        "legacy_unindexed_retired_count": int(checkpoint["retired_count"]),
        "artifact_ref_count": 0,
        "artifact_bytes": 0,
        "artifact_catalog_tip": GENESIS_HASH,
        "artifact_catalog": [],
        "pending_retirement": None,
    }


def _append_receipt(
    checkpoint: dict[str, Any],
    *,
    receipt: RetentionReceiptInput,
    max_receipts: int,
    allow_latest_reuse: bool,
) -> tuple[dict[str, Any], dict[str, Any]]:
    receipts = list(checkpoint["receipts"])
    if allow_latest_reuse and receipts:
        latest = receipts[-1]
        if (
            latest["session_partition"] == receipt.session_partition
            and latest["source_files_hash"] == receipt.source_files_hash
        ):
            return {**checkpoint, "receipts": receipts}, latest
    sequence = int(checkpoint["retired_count"]) + 1
    receipt_body = {
        "seq": sequence,
        "session_partition": receipt.session_partition,
        "source_files_hash": receipt.source_files_hash,
        "source_file_count": receipt.source_file_count,
        "source_total_bytes": receipt.source_total_bytes,
        "journal_record_count": receipt.journal_record_count,
        "journal_tip_hash": receipt.journal_tip_hash,
        "retired_at": receipt.retired_at,
        "prev_hash": checkpoint["tip"],
    }
    stored_receipt = {**receipt_body, "receipt_hash": stable_hash(receipt_body)}
    receipts.append(stored_receipt)
    compacted_count = int(checkpoint["compacted_count"])
    compacted_tip = str(checkpoint["compacted_tip"])
    if len(receipts) > max_receipts:
        removed = receipts[: len(receipts) - max_receipts]
        receipts = receipts[len(removed) :]
        compacted_count = int(removed[-1]["seq"])
        compacted_tip = str(removed[-1]["receipt_hash"])
    return (
        {
            **checkpoint,
            "retired_count": sequence,
            "compacted_count": compacted_count,
            "compacted_tip": compacted_tip,
            "tip": stored_receipt["receipt_hash"],
            "receipts": receipts,
        },
        stored_receipt,
    )


def _artifact_entries(
    receipts: tuple[RetiredArtifactReceiptInput, ...],
) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for receipt in receipts:
        if type(receipt) is not RetiredArtifactReceiptInput:
            raise TypeError("retired artifact receipts must use exact storage inputs")
        for ordinal, ref in enumerate(receipt.artifact_refs):
            if type(ref) is not ArtifactRefV1 or ArtifactRefV1.from_dict(ref.to_dict()) != ref:
                raise PartitionRetentionError("retired artifact ref is invalid")
            expected_mode = AppMode.WORK if receipt.product_id == "js-work" else AppMode.PERSONAL
            if receipt.product_id not in {"js-agent", "js-work"}:
                raise PartitionRetentionError("retired artifact product binding is invalid")
            if (
                ref.owner != receipt.tenant_id
                or ref.mode is not expected_mode
                or ref.workspace != receipt.workspace
                or ref.session != receipt.session_id
                or ref.created_by_run != receipt.run_id
            ):
                raise PartitionRetentionError("retired artifact receipt binding mismatch")
            entries.append(
                {
                    "receipt_id": receipt.receipt_id,
                    "effect_id": receipt.effect_id,
                    "tenant_id": receipt.tenant_id,
                    "run_id": receipt.run_id,
                    "binding": {
                        "tenant_id": receipt.tenant_id,
                        "product_id": receipt.product_id,
                        "workspace": receipt.workspace,
                        "session_id": receipt.session_id,
                        "run_id": receipt.run_id,
                    },
                    "ordinal": ordinal,
                    "artifact_ref": ref.to_dict(),
                }
            )
    return entries


def _verify_checkpoint_body(
    body: dict[str, Any],
    *,
    product_partition: str,
    owner_partition: str,
    max_receipts: int,
    max_artifact_refs: int,
    max_artifact_bytes: int,
) -> None:
    schema = body.get("schema_version")
    if schema == SCHEMA_VERSION_V1:
        _verify_common_checkpoint(
            body,
            expected_keys={
                "schema_version", "product_partition", "owner_partition",
                "retired_count", "compacted_count", "compacted_tip", "tip",
                "receipts",
            },
            product_partition=product_partition,
            owner_partition=owner_partition,
            max_receipts=max_receipts,
        )
        return
    if schema != SCHEMA_VERSION:
        raise PartitionRetentionError("retention checkpoint schema is unsupported")
    _verify_common_checkpoint(
        body,
        expected_keys={
            "schema_version", "product_partition", "owner_partition",
            "retired_count", "compacted_count", "compacted_tip", "tip", "receipts",
            "legacy_unindexed_retired_count", "artifact_ref_count", "artifact_bytes",
            "artifact_catalog_tip", "artifact_catalog", "pending_retirement",
        },
        product_partition=product_partition,
        owner_partition=owner_partition,
        max_receipts=max_receipts,
    )
    legacy_count = body["legacy_unindexed_retired_count"]
    ref_count = body["artifact_ref_count"]
    artifact_bytes = body["artifact_bytes"]
    catalog = body["artifact_catalog"]
    if (
        not _is_non_negative_int(legacy_count)
        or legacy_count > body["retired_count"]
        or not _is_non_negative_int(ref_count)
        or ref_count > max_artifact_refs
        or not _is_non_negative_int(artifact_bytes)
        or artifact_bytes > max_artifact_bytes
        or not isinstance(catalog, list)
    ):
        raise PartitionRetentionError("retired artifact catalog limits are invalid")
    expected_prev = GENESIS_HASH
    actual_count = 0
    actual_bytes = 0
    seen_groups: set[str] = set()
    seen_retirement_sequences: set[int] = set()
    seen_retirement_identities: set[tuple[str, str, str]] = set()
    for group in catalog:
        _verify_catalog_group(group, expected_prev=expected_prev, checkpoint=body)
        group_hash = group["group_hash"]
        if group_hash in seen_groups:
            raise PartitionRetentionError("retired artifact catalog group is duplicated")
        seen_groups.add(group_hash)
        retirement_sequence = group["retirement_seq"]
        if retirement_sequence in seen_retirement_sequences:
            raise PartitionRetentionError(
                "retired artifact retirement sequence is duplicated"
            )
        seen_retirement_sequences.add(retirement_sequence)
        retirement_identity = (
            group["retirement_receipt_hash"],
            group["session_partition"],
            group["source_files_hash"],
        )
        if retirement_identity in seen_retirement_identities:
            raise PartitionRetentionError(
                "retired artifact retirement identity is duplicated"
            )
        seen_retirement_identities.add(retirement_identity)
        expected_prev = group_hash
        actual_count += len(group["artifacts"])
        actual_bytes += _serialized_bytes(group)
    if body["artifact_catalog_tip"] != expected_prev:
        raise PartitionRetentionError("retired artifact catalog tip is invalid")
    if ref_count != actual_count or artifact_bytes != actual_bytes:
        raise PartitionRetentionError("retired artifact catalog accounting is invalid")
    _verify_pending(body)


def _verify_common_checkpoint(
    body: dict[str, Any],
    *,
    expected_keys: set[str],
    product_partition: str,
    owner_partition: str,
    max_receipts: int,
) -> None:
    if set(body) != expected_keys:
        raise PartitionRetentionError("retention checkpoint fields are invalid")
    if body["product_partition"] != product_partition:
        raise PartitionRetentionError("retention checkpoint product mismatch")
    if body["owner_partition"] != owner_partition:
        raise PartitionRetentionError("retention checkpoint owner mismatch")
    retired_count = body["retired_count"]
    compacted_count = body["compacted_count"]
    receipts = body["receipts"]
    if (
        not _is_non_negative_int(retired_count)
        or not _is_non_negative_int(compacted_count)
        or compacted_count > retired_count
        or not isinstance(receipts, list)
        or len(receipts) > max_receipts
        or retired_count != compacted_count + len(receipts)
    ):
        raise PartitionRetentionError("retention checkpoint counts are invalid")
    expected_prev = body["compacted_tip"]
    if not _is_sha256_ref(expected_prev):
        raise PartitionRetentionError("retention checkpoint compacted tip is invalid")
    expected_sequence = compacted_count + 1
    for stored in receipts:
        _verify_receipt(stored, expected_sequence=expected_sequence, expected_prev=expected_prev)
        expected_prev = stored["receipt_hash"]
        expected_sequence += 1
    if body["tip"] != expected_prev or not _is_sha256_ref(body["tip"]):
        raise PartitionRetentionError("retention checkpoint tip is invalid")


def _verify_receipt(stored: object, *, expected_sequence: int, expected_prev: str) -> None:
    if not isinstance(stored, dict):
        raise PartitionRetentionError("retention receipt is not an object")
    receipt_hash = stored.get("receipt_hash")
    receipt_body = {key: value for key, value in stored.items() if key != "receipt_hash"}
    if set(receipt_body) != {
        "seq", "session_partition", "source_files_hash", "source_file_count",
        "source_total_bytes", "journal_record_count", "journal_tip_hash",
        "retired_at", "prev_hash",
    }:
        raise PartitionRetentionError("retention receipt fields are invalid")
    if (
        receipt_body["seq"] != expected_sequence
        or receipt_body["prev_hash"] != expected_prev
        or not isinstance(receipt_body["session_partition"], str)
        or not receipt_body["session_partition"].startswith("session_")
        or not _is_sha256_ref(receipt_body["source_files_hash"])
        or not _is_non_negative_int(receipt_body["source_file_count"])
        or not _is_non_negative_int(receipt_body["source_total_bytes"])
        or not _is_non_negative_int(receipt_body["journal_record_count"])
        or not _is_sha256_ref(receipt_body["journal_tip_hash"])
        or not isinstance(receipt_body["retired_at"], str)
        or not receipt_body["retired_at"]
        or receipt_hash != stable_hash(receipt_body)
    ):
        raise PartitionRetentionError("retention receipt chain is invalid")


def _verify_catalog_group(
    group: object,
    *,
    expected_prev: str,
    checkpoint: dict[str, Any],
) -> None:
    if not isinstance(group, dict):
        raise PartitionRetentionError("retired artifact catalog group is not an object")
    group_hash = group.get("group_hash")
    group_body = {key: value for key, value in group.items() if key != "group_hash"}
    if set(group_body) != {
        "retirement_seq", "retirement_prev_hash", "retirement_receipt_hash",
        "session_partition", "source_files_hash", "source_file_count",
        "source_total_bytes", "journal_record_count", "journal_tip_hash",
        "retired_at", "artifacts", "prev_hash",
    }:
        raise PartitionRetentionError("retired artifact catalog fields are invalid")
    receipt_body = {
        "seq": group["retirement_seq"],
        "session_partition": group["session_partition"],
        "source_files_hash": group["source_files_hash"],
        "source_file_count": group["source_file_count"],
        "source_total_bytes": group["source_total_bytes"],
        "journal_record_count": group["journal_record_count"],
        "journal_tip_hash": group["journal_tip_hash"],
        "retired_at": group["retired_at"],
        "prev_hash": group["retirement_prev_hash"],
    }
    _verify_receipt(
        {**receipt_body, "receipt_hash": group["retirement_receipt_hash"]},
        expected_sequence=group["retirement_seq"],
        expected_prev=group["retirement_prev_hash"],
    )
    if (
        group["prev_hash"] != expected_prev
        or group_hash != stable_hash(group_body)
        or group["retirement_receipt_hash"] != stable_hash(receipt_body)
        or not _is_non_negative_int(group["retirement_seq"])
        or group["retirement_seq"] <= checkpoint["legacy_unindexed_retired_count"]
        or group["retirement_seq"] > checkpoint["retired_count"]
        or not isinstance(group["artifacts"], list)
        or not group["artifacts"]
    ):
        raise PartitionRetentionError("retired artifact catalog chain is invalid")
    stored = next(
        (
            receipt
            for receipt in checkpoint["receipts"]
            if receipt["seq"] == group["retirement_seq"]
        ),
        None,
    )
    if stored is not None and stored != {**receipt_body, "receipt_hash": group["retirement_receipt_hash"]}:
        raise PartitionRetentionError("retired artifact receipt evidence mismatch")
    ordinals: dict[str, list[int]] = {}
    for entry in group["artifacts"]:
        _verify_artifact_entry(entry)
        key = str(entry["receipt_id"])
        ordinals.setdefault(key, []).append(entry["ordinal"])
    if any(sorted(values) != list(range(len(values))) for values in ordinals.values()):
        raise PartitionRetentionError("retired artifact ordinals are invalid")


def _verify_artifact_entry(entry: object) -> None:
    if not isinstance(entry, dict) or set(entry) != {
        "receipt_id", "effect_id", "tenant_id", "run_id", "binding", "ordinal",
        "artifact_ref",
    }:
        raise PartitionRetentionError("retired artifact entry fields are invalid")
    binding = entry["binding"]
    if not isinstance(binding, dict) or set(binding) != {
        "tenant_id", "product_id", "workspace", "session_id", "run_id",
    }:
        raise PartitionRetentionError("retired artifact binding fields are invalid")
    try:
        ref = ArtifactRefV1.from_dict(entry["artifact_ref"])
    except Exception as exc:
        raise PartitionRetentionError("retired artifact R1 payload is invalid") from exc
    product_id = binding["product_id"]
    expected_mode = AppMode.WORK if product_id == "js-work" else AppMode.PERSONAL
    if product_id not in {"js-agent", "js-work"}:
        raise PartitionRetentionError("retired artifact product binding is invalid")
    if (
        not isinstance(entry["receipt_id"], str)
        or not entry["receipt_id"]
        or not isinstance(entry["effect_id"], str)
        or not entry["effect_id"]
        or entry["receipt_id"] != f"receipt:{entry['effect_id']}"
        or not _is_non_negative_int(entry["ordinal"])
        or entry["tenant_id"] != binding["tenant_id"]
        or entry["run_id"] != binding["run_id"]
        or ref.owner != binding["tenant_id"]
        or ref.mode is not expected_mode
        or ref.workspace != binding["workspace"]
        or ref.session != binding["session_id"]
        or ref.created_by_run != binding["run_id"]
    ):
        raise PartitionRetentionError("retired artifact receipt binding is invalid")


def _verify_pending(body: dict[str, Any]) -> None:
    pending = body["pending_retirement"]
    if pending is None:
        return
    if not isinstance(pending, dict) or set(pending) != {
        "session_partition", "source_files_hash", "retirement_receipt_hash",
        "artifact_group_hash",
    }:
        raise PartitionRetentionError("pending retirement fields are invalid")
    latest = body["receipts"][-1] if body["receipts"] else None
    if (
        latest is None
        or pending["session_partition"] != latest["session_partition"]
        or pending["source_files_hash"] != latest["source_files_hash"]
        or pending["retirement_receipt_hash"] != latest["receipt_hash"]
    ):
        raise PartitionRetentionError("pending retirement receipt is invalid")
    group_hash = pending["artifact_group_hash"]
    matching_groups = [
        group
        for group in body["artifact_catalog"]
        if group["retirement_receipt_hash"] == pending["retirement_receipt_hash"]
        and group["session_partition"] == pending["session_partition"]
        and group["source_files_hash"] == pending["source_files_hash"]
    ]
    if group_hash is None:
        if matching_groups:
            raise PartitionRetentionError(
                "pending retirement unexpectedly omits its catalog group"
            )
        return
    if len(matching_groups) != 1 or matching_groups[0]["group_hash"] != group_hash:
        raise PartitionRetentionError("pending retirement catalog group is invalid")


def _receipt_for_hash(checkpoint: dict[str, Any], receipt_hash: str) -> dict[str, Any] | None:
    return next(
        (receipt for receipt in checkpoint["receipts"] if receipt["receipt_hash"] == receipt_hash),
        None,
    )


def _serialized_bytes(value: object) -> int:
    return len(canonical_json(value).encode("utf-8"))


def _checkpoint_size_limit(*, max_receipts: int, max_artifact_bytes: int) -> int:
    bounded_receipts = min(max_receipts, _MAX_CHECKPOINT_RECEIPT_COUNT_FOR_SIZE)
    return (
        max_artifact_bytes
        + bounded_receipts * _MAX_CHECKPOINT_RECEIPT_BYTES
        + _MAX_CHECKPOINT_FIXED_BYTES
    )


def _atomic_write_checkpoint(path: Path, *, body: dict[str, Any], mac_key: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    row = {**body, "mac": stable_hmac(mac_key, body).hex()}
    payload = canonical_json(row)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            fd = -1
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
        _fsync_directory(path.parent)
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _is_sha256_ref(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 71
        and value.startswith("sha256:")
        and all(character in "0123456789abcdef" for character in value[7:])
    )


def _is_non_negative_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _fsync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
