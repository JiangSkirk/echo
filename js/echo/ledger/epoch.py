"""HMAC epoch ratchet bound to Merkle anchoring (P1-2).

Closing an epoch is the conjunction of: Merkle root anchored AND old key
destroyed. A missing root refuses destroy. ``tip_anchor.py`` is not used
as a Merkle tree; inclusion proofs live in ``js.echo.ledger.merkle``.

Legacy journals with no ``epoch.json`` keep the old ``verify_file`` path.
"""

from __future__ import annotations

import hmac
import json
import os
import stat
import threading
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from js.echo.ledger._hashing import stable_hash
from js.echo.ledger.journal import (
    CommitRecord,
    EchoJournal,
    VerificationReport,
    _journal_lock_path,
    _lock_file,
    _make_handle_private,
    _path_lock,
    _read_verified_file,
    _record_from_row,
    _record_to_json,
    _unlock_file,
    verify_file,
    verify_records,
)
from js.echo.ledger.merkle import (
    InclusionProof,
    decode_digest,
    encode_digest,
    inclusion_proof,
    merkle_tree_hash,
    verify_inclusion,
)
from js.echo.ledger.tip_seal import seal_path_for

EPOCH_STATE_NAME: Final[str] = "epoch.json"
MERKLE_ANCHORS_NAME: Final[str] = "merkle_anchors.jsonl"
EPOCH_DIR_NAME: Final[str] = "epochs"
PERMIT_EPOCH_PREFIX: Final[str] = "permit-epoch-"
_GENESIS_ANCHOR: Final[str] = "sha256:" + "0" * 64
_RATCHET_DOMAIN: Final[bytes] = b"echo-ledger-ratchet:"


class EpochCloseError(ValueError):
    """Epoch close was refused (missing root, open effects, or archive)."""


@dataclass(frozen=True, slots=True)
class ClosedEpochAnchor:
    epoch: int
    first_seq: int
    last_seq: int
    merkle_root: str
    leaf_count: int
    prev_anchor_hash: str
    archive_name: str
    record_hash: str


@dataclass(frozen=True, slots=True)
class EpochCloseResult:
    closed_epoch: int
    live_epoch: int
    merkle_root: str
    leaf_count: int
    inclusion_proofs: tuple[InclusionProof, ...]


def permit_epoch_name(epoch: int) -> str:
    if epoch < 1:
        raise EpochCloseError("epoch must be >= 1")
    return f"{PERMIT_EPOCH_PREFIX}{epoch}"


def derive_next_key(key: bytes, *, closed_epoch: int, purpose: str) -> bytes:
    if not isinstance(key, (bytes, bytearray)) or len(key) != 32:
        raise EpochCloseError("epoch key must be 32 bytes")
    if closed_epoch < 1:
        raise EpochCloseError("closed epoch must be >= 1")
    message = _RATCHET_DOMAIN + f"{purpose}:{closed_epoch}".encode("ascii")
    return hmac.new(bytes(key), message, digestmod="sha256").digest()


def load_live_epoch(root: Path) -> int:
    path = Path(root) / EPOCH_STATE_NAME
    if not path.exists():
        return 1
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise EpochCloseError("epoch state is not an object")
    live = raw.get("live_epoch", 1)
    if not isinstance(live, int) or isinstance(live, bool) or live < 1:
        raise EpochCloseError("live_epoch is invalid")
    return live


def load_closed_anchors(root: Path) -> tuple[ClosedEpochAnchor, ...]:
    path = Path(root) / MERKLE_ANCHORS_NAME
    if not path.exists():
        return ()
    anchors: list[ClosedEpochAnchor] = []
    expected_prev = _GENESIS_ANCHOR
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise EpochCloseError(f"merkle anchor line {line_number} is not JSON") from exc
        if not isinstance(row, dict):
            raise EpochCloseError(f"merkle anchor line {line_number} is not an object")
        anchor = _anchor_from_row(row)
        if anchor.prev_anchor_hash != expected_prev:
            raise EpochCloseError(f"merkle anchor line {line_number}: prev_hash_mismatch")
        recomputed = _anchor_record_hash(anchor)
        if anchor.record_hash != recomputed:
            raise EpochCloseError(f"merkle anchor line {line_number}: record_hash_mismatch")
        expected_prev = anchor.record_hash
        anchors.append(anchor)
    return tuple(anchors)


def leaf_payload(record: CommitRecord) -> bytes:
    return record.record_hash.encode("utf-8")


def destroy_key_file(path: Path, *, merkle_root_anchored: bool) -> None:
    """Overwrite then unlink. Missing Merkle root refuses destroy (R4)."""

    if not merkle_root_anchored:
        raise EpochCloseError("merkle root not anchored; refusing to destroy epoch key")
    if not path.exists():
        return
    metadata = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise EpochCloseError(f"invalid key file {path}")
    fd = os.open(path, os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        size = os.fstat(fd).st_size
        os.pwrite(fd, b"\x00" * max(size, 32), 0)
        os.fsync(fd)
    finally:
        os.close(fd)
    path.unlink()


@contextmanager
def _journal_exclusive(path: Path) -> Iterator[None]:
    lock_path = _journal_lock_path(path)
    lock_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with _path_lock(path), lock_path.open("a+b") as lock_handle:
        _make_handle_private(lock_handle)
        _lock_file(lock_handle)
        try:
            yield
        finally:
            _unlock_file(lock_handle)


def close_epoch(
    root: Path,
    *,
    records: Sequence[CommitRecord],
    journal_key: bytes,
    permit_key: bytes,
    journal_key_path: Path,
    permit_key_path: Path,
    journal_path: Path,
    tenant_id: str = "__system__",
) -> EpochCloseResult:
    """Anchor the on-disk journal, ratchet HMAC keys, rewrite the live chain.

    ``records`` is kept for callers that already hold a snapshot. Close always
    reloads ``journal_path`` under the flock so concurrent appends are not dropped.
    """

    del records
    with _journal_exclusive(journal_path):
        return _close_epoch_locked(
            root,
            journal_key=journal_key,
            permit_key=permit_key,
            journal_key_path=journal_key_path,
            permit_key_path=permit_key_path,
            journal_path=journal_path,
            tenant_id=tenant_id,
        )


def _close_epoch_locked(
    root: Path,
    *,
    journal_key: bytes,
    permit_key: bytes,
    journal_key_path: Path,
    permit_key_path: Path,
    journal_path: Path,
    tenant_id: str,
) -> EpochCloseResult:
    try:
        report, disk_records, _offset = _read_verified_file(journal_path, mac_key=journal_key)
    except OSError as exc:
        raise EpochCloseError(f"live journal unreadable: {exc}") from exc
    if not report.ok:
        raise EpochCloseError("live journal failed verification: " + ",".join(report.errors))
    records = tuple(disk_records)
    if not records:
        raise EpochCloseError("cannot close an empty epoch")
    if any(
        record.record_type == "snapshot_anchor" and bool(record.payload.get("archive_required"))
        for record in records
    ):
        raise EpochCloseError("cannot close epoch while sqlite archives require the live MAC key")
    closed_epoch = load_live_epoch(root)
    existing = load_closed_anchors(root)
    leaves = tuple(leaf_payload(record) for record in records)
    root_digest = merkle_tree_hash(leaves)
    merkle_root = encode_digest(root_digest)
    proofs = tuple(inclusion_proof(index, leaves) for index in range(len(leaves)))
    for index, record in enumerate(records):
        if not verify_inclusion(leaf_payload(record), proofs[index], merkle_root):
            raise EpochCloseError(f"seq:{index}:inclusion_proof_invalid")
    prev_hash = existing[-1].record_hash if existing else _GENESIS_ANCHOR
    archive_name = f"epoch-{closed_epoch}.json"
    draft = ClosedEpochAnchor(
        epoch=closed_epoch,
        first_seq=records[0].seq,
        last_seq=records[-1].seq,
        merkle_root=merkle_root,
        leaf_count=len(leaves),
        prev_anchor_hash=prev_hash,
        archive_name=archive_name,
        record_hash="",
    )
    anchored = ClosedEpochAnchor(
        epoch=draft.epoch,
        first_seq=draft.first_seq,
        last_seq=draft.last_seq,
        merkle_root=draft.merkle_root,
        leaf_count=draft.leaf_count,
        prev_anchor_hash=draft.prev_anchor_hash,
        archive_name=draft.archive_name,
        record_hash=_anchor_record_hash(draft),
    )
    _write_epoch_archive(root, anchored, records=records, proofs=proofs)
    archive_report = verify_closed_epoch_archive(root, anchored)
    if not archive_report.ok:
        raise EpochCloseError(
            "epoch archive failed verification: " + ",".join(archive_report.errors)
        )

    next_epoch = closed_epoch + 1
    next_journal_key = derive_next_key(journal_key, closed_epoch=closed_epoch, purpose="journal")
    next_permit_key = derive_next_key(permit_key, closed_epoch=closed_epoch, purpose="permit")
    live = EchoJournal(mac_key=next_journal_key)
    for record in records:
        live.append(
            record_type=record.record_type,
            tenant_id=record.tenant_id,
            run_id=record.run_id,
            payload=record.payload,
        )
    live.append(
        record_type="epoch_open",
        tenant_id=tenant_id,
        run_id="epoch-close",
        payload={
            "closed_epoch": closed_epoch,
            "live_epoch": next_epoch,
            "merkle_root": merkle_root,
            "leaf_count": len(records),
            "effect_tombstones": _completed_effect_ids(records),
        },
    )

    pending_journal = pending_key_path(journal_key_path)
    pending_permit = pending_key_path(permit_key_path)
    _replace_key_file(pending_journal, next_journal_key)
    _replace_key_file(pending_permit, next_permit_key)
    _write_journal_file(journal_path, live.records)
    seal_path = seal_path_for(journal_path)
    if seal_path.exists() and not seal_path.is_symlink():
        seal_path.unlink()
    _replace_key_file(journal_key_path, next_journal_key)
    _replace_key_file(permit_key_path, next_permit_key)
    _unlink_if_file(pending_journal)
    _unlink_if_file(pending_permit)
    _append_merkle_anchor(root, anchored)
    loaded = load_closed_anchors(root)
    if not loaded or loaded[-1].merkle_root != merkle_root:
        raise EpochCloseError("merkle root not anchored after key rotation")
    _write_epoch_state(root, live_epoch=next_epoch)
    return EpochCloseResult(
        closed_epoch=closed_epoch,
        live_epoch=next_epoch,
        merkle_root=merkle_root,
        leaf_count=len(leaves),
        inclusion_proofs=proofs,
    )


def verify_closed_epochs(root: Path) -> VerificationReport:
    """Verify every closed epoch against its anchored Merkle root."""

    try:
        anchors = load_closed_anchors(root)
    except EpochCloseError as exc:
        return VerificationReport(ok=False, errors=(str(exc),))
    errors: list[str] = []
    for anchor in anchors:
        report = verify_closed_epoch_archive(root, anchor)
        if not report.ok:
            errors.extend(report.errors)
    return VerificationReport(ok=not errors, errors=tuple(errors))


def pending_key_path(path: Path) -> Path:
    return path.with_name(path.name + ".next")


def recover_pending_key_rotation(
    journal_path: Path,
    *,
    journal_key_path: Path,
    permit_key_path: Path,
) -> None:
    """Promote ``*.key.next`` when the live journal already verifies with them."""

    pending_journal = pending_key_path(journal_key_path)
    pending_permit = pending_key_path(permit_key_path)
    if not pending_journal.exists() and not pending_permit.exists():
        return
    with _journal_exclusive(journal_path):
        _recover_pending_key_rotation_locked(
            journal_path,
            journal_key_path=journal_key_path,
            permit_key_path=permit_key_path,
            pending_journal=pending_journal,
            pending_permit=pending_permit,
        )


def _recover_pending_key_rotation_locked(
    journal_path: Path,
    *,
    journal_key_path: Path,
    permit_key_path: Path,
    pending_journal: Path,
    pending_permit: Path,
) -> None:
    if not pending_journal.exists() and not pending_permit.exists():
        return
    live_key = _try_read_key(journal_key_path)
    next_key = _try_read_key(pending_journal)
    live_ok = live_key is not None and verify_file(journal_path, mac_key=live_key).ok
    next_ok = next_key is not None and verify_file(journal_path, mac_key=next_key).ok
    if next_ok and not live_ok:
        if next_key is None:
            raise EpochCloseError("pending journal key unreadable")
        next_permit = _try_read_key(pending_permit)
        if next_permit is None:
            raise EpochCloseError("pending permit key missing after journal rotation")
        _replace_key_file(journal_key_path, next_key)
        _replace_key_file(permit_key_path, next_permit)
        _unlink_if_file(pending_journal)
        _unlink_if_file(pending_permit)
        return
    if live_ok:
        _unlink_if_file(pending_journal)
        _unlink_if_file(pending_permit)
        return
    raise EpochCloseError("pending epoch key rotation is inconsistent with the live journal")


def complete_pending_epoch_metadata(
    root: Path,
    *,
    journal_path: Path,
    journal_key_path: Path,
) -> int:
    """Finish Merkle chain + ``epoch.json`` after keys already match the live journal."""

    key = _try_read_key(journal_key_path)
    if key is None or not journal_path.is_file():
        return load_live_epoch(root)
    if not verify_file(journal_path, mac_key=key).ok:
        return load_live_epoch(root)
    _report, records, _offset = _read_verified_file(journal_path, mac_key=key)
    opens = [record for record in records if record.record_type == "epoch_open"]
    if not opens:
        return load_live_epoch(root)
    payload = opens[-1].payload
    closed_raw = payload.get("closed_epoch")
    live_raw = payload.get("live_epoch")
    merkle_root = payload.get("merkle_root")
    if not isinstance(closed_raw, int) or isinstance(closed_raw, bool):
        return load_live_epoch(root)
    if not isinstance(live_raw, int) or isinstance(live_raw, bool) or live_raw < 2:
        return load_live_epoch(root)
    if not isinstance(merkle_root, str) or not merkle_root:
        return load_live_epoch(root)
    try:
        anchors = load_closed_anchors(root)
    except EpochCloseError:
        return load_live_epoch(root)
    if not any(anchor.epoch == closed_raw for anchor in anchors):
        _append_anchor_from_archive(
            root,
            closed_epoch=closed_raw,
            merkle_root=merkle_root,
        )
        anchors = load_closed_anchors(root)
        if not anchors or anchors[-1].epoch != closed_raw:
            raise EpochCloseError("merkle root not anchored; refusing to complete epoch close")
    if load_live_epoch(root) != live_raw:
        _write_epoch_state(root, live_epoch=live_raw)
    return live_raw


def _append_anchor_from_archive(root: Path, *, closed_epoch: int, merkle_root: str) -> None:
    archive_name = f"epoch-{closed_epoch}.json"
    archive_path = Path(root) / EPOCH_DIR_NAME / archive_name
    if not archive_path.is_file():
        raise EpochCloseError("merkle root not anchored; refusing to complete epoch close")
    raw = json.loads(archive_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or raw.get("merkle_root") != merkle_root:
        raise EpochCloseError("epoch archive does not match epoch_open merkle root")
    existing = load_closed_anchors(root)
    prev_hash = existing[-1].record_hash if existing else _GENESIS_ANCHOR
    draft = ClosedEpochAnchor(
        epoch=closed_epoch,
        first_seq=int(raw["first_seq"]),
        last_seq=int(raw["last_seq"]),
        merkle_root=merkle_root,
        leaf_count=int(raw["leaf_count"]),
        prev_anchor_hash=prev_hash,
        archive_name=archive_name,
        record_hash="",
    )
    anchored = ClosedEpochAnchor(
        epoch=draft.epoch,
        first_seq=draft.first_seq,
        last_seq=draft.last_seq,
        merkle_root=draft.merkle_root,
        leaf_count=draft.leaf_count,
        prev_anchor_hash=draft.prev_anchor_hash,
        archive_name=draft.archive_name,
        record_hash=_anchor_record_hash(draft),
    )
    report = verify_closed_epoch_archive(root, anchored)
    if not report.ok:
        raise EpochCloseError("epoch archive failed verification: " + ",".join(report.errors))
    _append_merkle_anchor(root, anchored)


def verify_closed_epoch_archive(root: Path, anchor: ClosedEpochAnchor) -> VerificationReport:
    archive_path = Path(root) / EPOCH_DIR_NAME / anchor.archive_name
    if not archive_path.is_file():
        return VerificationReport(ok=False, errors=(f"epoch:{anchor.epoch}:archive_missing",))
    try:
        raw = json.loads(archive_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return VerificationReport(ok=False, errors=(f"epoch:{anchor.epoch}:archive_json",))
    if not isinstance(raw, dict):
        return VerificationReport(ok=False, errors=(f"epoch:{anchor.epoch}:archive_object",))
    records_raw = raw.get("records")
    if not isinstance(records_raw, list):
        return VerificationReport(ok=False, errors=(f"epoch:{anchor.epoch}:records_missing",))
    errors: list[str] = []
    leaves: list[bytes] = []
    proofs_raw = raw.get("proofs")
    for offset, row in enumerate(records_raw):
        seq = anchor.first_seq + offset
        if not isinstance(row, dict):
            errors.append(f"seq:{seq}:invalid_record")
            continue
        try:
            record = _record_from_row(row)
        except (KeyError, TypeError, ValueError):
            errors.append(f"seq:{seq}:invalid_record")
            continue
        recomputed = stable_hash(record.hash_payload())
        if record.record_hash != recomputed:
            errors.append(f"seq:{seq}:record_hash_mismatch")
            continue
        leaf = leaf_payload(record)
        leaves.append(leaf)
        if isinstance(proofs_raw, list) and offset < len(proofs_raw):
            try:
                proof = _proof_from_row(proofs_raw[offset])
            except (KeyError, TypeError, ValueError):
                errors.append(f"seq:{seq}:inclusion_proof_invalid")
                continue
            if not verify_inclusion(leaf, proof, anchor.merkle_root):
                errors.append(f"seq:{seq}:inclusion_proof_mismatch")
    if errors:
        return VerificationReport(ok=False, errors=tuple(errors))
    if len(leaves) != anchor.leaf_count:
        return VerificationReport(ok=False, errors=(f"epoch:{anchor.epoch}:leaf_count_mismatch",))
    computed_root = encode_digest(merkle_tree_hash(leaves))
    if computed_root != anchor.merkle_root:
        return VerificationReport(ok=False, errors=(f"epoch:{anchor.epoch}:merkle_root_mismatch",))
    decode_digest(anchor.merkle_root)
    return VerificationReport(ok=True, errors=())


def verify_journal_dual_read(
    records: Sequence[CommitRecord],
    *,
    live_mac_key: bytes,
    root: Path,
) -> VerificationReport:
    """Old verifier for live/legacy chains; Merkle for closed epochs."""

    closed = verify_closed_epochs(root)
    if not closed.ok:
        return closed
    return verify_records(tuple(records), mac_key=live_mac_key)


def _completed_effect_ids(records: Sequence[CommitRecord]) -> list[str]:
    found: set[str] = set()
    for record in records:
        if record.record_type in {"snapshot_anchor", "epoch_open"}:
            stored = record.payload.get("effect_tombstones", ())
            if isinstance(stored, list):
                found.update(item for item in stored if isinstance(item, str) and item)
            continue
        if record.record_type != "merge":
            continue
        effect_id = record.payload.get("effect_id")
        if isinstance(effect_id, str) and effect_id:
            found.add(effect_id)
    return sorted(found)


def _anchor_record_hash(anchor: ClosedEpochAnchor) -> str:
    return stable_hash(
        {
            "epoch": anchor.epoch,
            "first_seq": anchor.first_seq,
            "last_seq": anchor.last_seq,
            "merkle_root": anchor.merkle_root,
            "leaf_count": anchor.leaf_count,
            "prev_anchor_hash": anchor.prev_anchor_hash,
            "archive_name": anchor.archive_name,
        }
    )


def _anchor_from_row(row: dict[str, Any]) -> ClosedEpochAnchor:
    return ClosedEpochAnchor(
        epoch=int(row["epoch"]),
        first_seq=int(row["first_seq"]),
        last_seq=int(row["last_seq"]),
        merkle_root=str(row["merkle_root"]),
        leaf_count=int(row["leaf_count"]),
        prev_anchor_hash=str(row["prev_anchor_hash"]),
        archive_name=str(row["archive_name"]),
        record_hash=str(row["record_hash"]),
    )


def _anchor_to_row(anchor: ClosedEpochAnchor) -> dict[str, Any]:
    return {
        "epoch": anchor.epoch,
        "first_seq": anchor.first_seq,
        "last_seq": anchor.last_seq,
        "merkle_root": anchor.merkle_root,
        "leaf_count": anchor.leaf_count,
        "prev_anchor_hash": anchor.prev_anchor_hash,
        "archive_name": anchor.archive_name,
        "record_hash": anchor.record_hash,
    }


def _proof_from_row(row: Any) -> InclusionProof:
    if not isinstance(row, dict):
        raise TypeError("proof is not an object")
    siblings = row.get("siblings")
    if not isinstance(siblings, list):
        raise TypeError("proof siblings missing")
    return InclusionProof(
        leaf_index=int(row["leaf_index"]),
        tree_size=int(row["tree_size"]),
        leaf_hash=str(row["leaf_hash"]),
        siblings=tuple(str(item) for item in siblings),
    )


def _proof_to_row(proof: InclusionProof) -> dict[str, Any]:
    return {
        "leaf_index": proof.leaf_index,
        "tree_size": proof.tree_size,
        "leaf_hash": proof.leaf_hash,
        "siblings": list(proof.siblings),
    }


def _write_epoch_archive(
    root: Path,
    anchor: ClosedEpochAnchor,
    *,
    records: Sequence[CommitRecord],
    proofs: Sequence[InclusionProof],
) -> None:
    directory = Path(root) / EPOCH_DIR_NAME
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(directory, 0o700)
    payload = {
        "epoch": anchor.epoch,
        "merkle_root": anchor.merkle_root,
        "first_seq": anchor.first_seq,
        "last_seq": anchor.last_seq,
        "leaf_count": anchor.leaf_count,
        "records": [json.loads(_record_to_json(record)) for record in records],
        "proofs": [_proof_to_row(proof) for proof in proofs],
    }
    path = directory / anchor.archive_name
    _atomic_json(path, payload)


def _append_merkle_anchor(root: Path, anchor: ClosedEpochAnchor) -> None:
    path = Path(root) / MERKLE_ANCHORS_NAME
    line = json.dumps(_anchor_to_row(anchor), sort_keys=True, separators=(",", ":"))
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as handle:
            fd = -1
            handle.write(line + "\n")
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        if fd >= 0:
            os.close(fd)


def _write_epoch_state(root: Path, *, live_epoch: int) -> None:
    _atomic_json(Path(root) / EPOCH_STATE_NAME, {"live_epoch": live_epoch})


def _write_journal_file(path: Path, records: Sequence[CommitRecord]) -> None:
    encoded = "".join(_record_to_json(record) + "\n" for record in records)
    _atomic_text(path, encoded)


def _replace_key_file(path: Path, key: bytes) -> None:
    if len(key) != 32:
        raise EpochCloseError("epoch key must be 32 bytes")
    _atomic_text(path, key.hex())


def _try_read_key(path: Path) -> bytes | None:
    if not path.is_file():
        return None
    try:
        key = bytes.fromhex(path.read_text(encoding="utf-8").strip())
    except ValueError:
        return None
    if len(key) != 32:
        return None
    return key


def _unlink_if_file(path: Path) -> None:
    if path.exists() and not path.is_symlink() and path.is_file():
        path.unlink()


def _atomic_json(path: Path, payload: dict[str, Any]) -> None:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    _atomic_text(path, encoded + "\n")


def _atomic_text(path: Path, encoded: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp_path = path.with_name(f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
    fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            fd = -1
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, path)
        os.chmod(path, 0o600)
    finally:
        if fd >= 0:
            os.close(fd)
        if tmp_path.exists():
            tmp_path.unlink()


__all__ = [
    "ClosedEpochAnchor",
    "EPOCH_DIR_NAME",
    "EPOCH_STATE_NAME",
    "EpochCloseError",
    "EpochCloseResult",
    "MERKLE_ANCHORS_NAME",
    "close_epoch",
    "complete_pending_epoch_metadata",
    "derive_next_key",
    "destroy_key_file",
    "leaf_payload",
    "load_closed_anchors",
    "load_live_epoch",
    "pending_key_path",
    "permit_epoch_name",
    "recover_pending_key_rotation",
    "verify_closed_epoch_archive",
    "verify_closed_epochs",
    "verify_journal_dual_read",
]
