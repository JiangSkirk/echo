from __future__ import annotations

import json
import os
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from js.echo.ledger._hashing import hmac_matches, stable_hash, stable_hmac

SCHEMA_VERSION = "echo-session-retention-v1"
GENESIS_HASH = "sha256:" + "0" * 64


class PartitionRetentionError(RuntimeError):
    """A bounded session-retention checkpoint is missing or invalid."""


@dataclass(frozen=True, slots=True)
class RetentionReceiptInput:
    session_partition: str
    source_files_hash: str
    source_file_count: int
    source_total_bytes: int
    journal_record_count: int
    journal_tip_hash: str
    retired_at: str


def empty_checkpoint(*, product_partition: str, owner_partition: str) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
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
) -> dict[str, Any]:
    if max_receipts < 1:
        raise ValueError("max_receipts must be positive")
    if not path.exists():
        return empty_checkpoint(
            product_partition=product_partition,
            owner_partition=owner_partition,
        )
    if path.is_symlink() or not path.is_file():
        raise PartitionRetentionError("retention checkpoint is not a regular file")
    try:
        row = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PartitionRetentionError("retention checkpoint is unreadable") from exc
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
    checkpoint = load_and_verify_checkpoint(
        path,
        mac_key=mac_key,
        product_partition=product_partition,
        owner_partition=owner_partition,
        max_receipts=max_receipts,
    )
    receipts = list(checkpoint["receipts"])
    if receipts:
        latest = receipts[-1]
        if (
            latest["session_partition"] == receipt.session_partition
            and latest["source_files_hash"] == receipt.source_files_hash
        ):
            return checkpoint, latest

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
    stored_receipt = {
        **receipt_body,
        "receipt_hash": stable_hash(receipt_body),
    }
    receipts.append(stored_receipt)
    compacted_count = int(checkpoint["compacted_count"])
    compacted_tip = str(checkpoint["compacted_tip"])
    if len(receipts) > max_receipts:
        removed = receipts[: len(receipts) - max_receipts]
        receipts = receipts[len(removed) :]
        compacted_count = int(removed[-1]["seq"])
        compacted_tip = str(removed[-1]["receipt_hash"])
    updated = {
        "schema_version": SCHEMA_VERSION,
        "product_partition": product_partition,
        "owner_partition": owner_partition,
        "retired_count": sequence,
        "compacted_count": compacted_count,
        "compacted_tip": compacted_tip,
        "tip": stored_receipt["receipt_hash"],
        "receipts": receipts,
    }
    _verify_checkpoint_body(
        updated,
        product_partition=product_partition,
        owner_partition=owner_partition,
        max_receipts=max_receipts,
    )
    _atomic_write_checkpoint(path, body=updated, mac_key=mac_key)
    return updated, stored_receipt


def _verify_checkpoint_body(
    body: dict[str, Any],
    *,
    product_partition: str,
    owner_partition: str,
    max_receipts: int,
) -> None:
    expected_keys = {
        "schema_version",
        "product_partition",
        "owner_partition",
        "retired_count",
        "compacted_count",
        "compacted_tip",
        "tip",
        "receipts",
    }
    if set(body) != expected_keys:
        raise PartitionRetentionError("retention checkpoint fields are invalid")
    if body["schema_version"] != SCHEMA_VERSION:
        raise PartitionRetentionError("retention checkpoint schema is unsupported")
    if body["product_partition"] != product_partition:
        raise PartitionRetentionError("retention checkpoint product mismatch")
    if body["owner_partition"] != owner_partition:
        raise PartitionRetentionError("retention checkpoint owner mismatch")
    retired_count = body["retired_count"]
    compacted_count = body["compacted_count"]
    receipts = body["receipts"]
    if (
        not isinstance(retired_count, int)
        or isinstance(retired_count, bool)
        or retired_count < 0
        or not isinstance(compacted_count, int)
        or isinstance(compacted_count, bool)
        or compacted_count < 0
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
        if not isinstance(stored, dict):
            raise PartitionRetentionError("retention receipt is not an object")
        receipt_hash = stored.get("receipt_hash")
        receipt_body = {key: value for key, value in stored.items() if key != "receipt_hash"}
        if set(receipt_body) != {
            "seq",
            "session_partition",
            "source_files_hash",
            "source_file_count",
            "source_total_bytes",
            "journal_record_count",
            "journal_tip_hash",
            "retired_at",
            "prev_hash",
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
        expected_prev = receipt_hash
        expected_sequence += 1
    if body["tip"] != expected_prev or not _is_sha256_ref(body["tip"]):
        raise PartitionRetentionError("retention checkpoint tip is invalid")


def _atomic_write_checkpoint(path: Path, *, body: dict[str, Any], mac_key: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    row = {**body, "mac": stable_hmac(mac_key, body).hex()}
    payload = json.dumps(
        row,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    )
    temporary = path.with_name(
        f".{path.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
    )
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
