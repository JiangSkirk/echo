"""Strict File Cell for staged, handle-scoped owner-root commits (WP9).

The File Cell receives the complete :class:`~js.orin.draft.CellPackage` on
the authenticated ``cells.sock`` connection.  It never reads Orind's WAL or
an Orind-owned shared execution package:

* preflight validates a sealed ``DirectoryHandle``, snapshots every source,
  and writes exact proposed bytes plus a canonical machine report into a
  private cell-owned staging directory;
* commit re-reads that stage, binds it to the supplied ``StateWitness``,
  rechecks root/source identities, then uses same-directory temporary files
  and atomic replacement.

WP9 intentionally has no durable commit state machine.  Crash ambiguity and
``UNKNOWN_COMMIT`` reconciliation belong to the single WP10 membrane.
"""

from __future__ import annotations

import difflib
import hashlib
import hmac
import json
import os
import secrets
import stat
import time
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from js.orin.draft import (
    CellPackage,
    CommitPermit,
    FileCommitPreviewV1,
    Impact,
    StateWitness,
    cell_package_from_dict,
    permit_from_dict,
)
from js.orin.handles import OriginHandle
from js.orin.protocol import ProtocolError, canonical_json
from js.orind.cells.base import CellBase

_STAGE_SCHEMA: Final[str] = "orin-file-stage/v1"
_REPORT_NAME: Final[str] = "report.json"
_WITNESS_TTL_MS: Final[int] = 60_000
_MAX_CHANGES: Final[int] = 128
_MAX_PATH_BYTES: Final[int] = 1_024
_MAX_COMPONENT_BYTES: Final[int] = 255
_MAX_EXISTING_BYTES: Final[int] = 8 * 1024 * 1024
_MAX_CONTENT_BYTES: Final[int] = 8 * 1024 * 1024
_DIR_FLAGS: Final[int] = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
_READ_FLAGS: Final[int] = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)


def _now_ms() -> int:
    return time.time_ns() // 1_000_000


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _write_all(fd: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise ProtocolError("short write while preparing file commit")
        view = view[written:]


def _read_all(fd: int, *, limit: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(fd, min(64 * 1024, limit + 1 - total))
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        total += len(chunk)
        if total > limit:
            raise ProtocolError("file exceeds the File Cell read bound")


def _reject_control_text(value: str, *, field: str) -> None:
    if not value:
        raise ProtocolError(f"{field} must not be empty")
    if any(unicodedata.category(char).startswith("C") for char in value):
        raise ProtocolError(f"{field} contains a control or invisible character")


@dataclass(frozen=True, slots=True)
class _Change:
    path: str
    parts: tuple[str, ...]
    content: bytes


@dataclass(frozen=True, slots=True)
class _Root:
    path: Path
    fd: int
    device: int
    inode: int


@dataclass(frozen=True, slots=True)
class _Source:
    exists: bool
    digest: str | None
    fingerprint: dict[str, int] | None
    content: bytes


@dataclass(slots=True)
class _PreparedReplace:
    parent_fd: int
    parent_path: Path
    temp_name: str
    target_name: str
    expected_source: _Source
    expected_digest: str


def _normalize_relative_path(raw: Any) -> tuple[str, tuple[str, ...]]:
    if not isinstance(raw, str):
        raise ProtocolError("change path must be a string")
    _reject_control_text(raw, field="change path")
    if raw.startswith("/") or raw.startswith("\\") or "\\" in raw:
        raise ProtocolError("change path must be a portable relative path")
    raw_parts = raw.split("/")
    if any(part in {"", ".", ".."} for part in raw_parts):
        raise ProtocolError("change path contains an empty, dot, or parent component")
    normalized_parts = tuple(unicodedata.normalize("NFC", part) for part in raw_parts)
    if normalized_parts != tuple(raw_parts):
        raise ProtocolError("change path must already be NFC normalized")
    parts = normalized_parts
    for part in parts:
        _reject_control_text(part, field="path component")
        if len(part.encode("utf-8")) > _MAX_COMPONENT_BYTES:
            raise ProtocolError("change path component exceeds 255 UTF-8 bytes")
        if part.casefold() == ".git":
            raise ProtocolError("File Cell never writes Git metadata")
    normalized = "/".join(parts)
    if len(normalized.encode("utf-8")) > _MAX_PATH_BYTES:
        raise ProtocolError("change path exceeds the File Cell path bound")
    return normalized, parts


def _parse_changes(package: CellPackage) -> tuple[_Change, ...]:
    draft = package.draft
    if draft.effect_type != "file.commit":
        raise ProtocolError("File Cell accepts only file.commit drafts")
    if set(draft.arguments) != {"directory_handle", "changes"}:
        raise ProtocolError("file.commit arguments must be exactly directory_handle and changes")
    raw_changes = draft.arguments.get("changes")
    if not isinstance(raw_changes, list) or not 1 <= len(raw_changes) <= _MAX_CHANGES:
        raise ProtocolError("file.commit changes must contain 1..128 entries")

    changes: list[_Change] = []
    folded_paths: set[str] = set()
    total_bytes = 0
    for raw_change in raw_changes:
        if not isinstance(raw_change, dict) or set(raw_change) != {"path", "content"}:
            raise ProtocolError("each file change must contain exactly path and content")
        path, parts = _normalize_relative_path(raw_change.get("path"))
        content = raw_change.get("content")
        if not isinstance(content, str):
            raise ProtocolError("file change content must be a UTF-8 string")
        encoded = content.encode("utf-8")
        total_bytes += len(encoded)
        if total_bytes > _MAX_CONTENT_BYTES:
            raise ProtocolError("file.commit content exceeds the File Cell bound")
        folded = path.casefold()
        if folded in folded_paths:
            raise ProtocolError("file.commit paths collide after NFC/casefold normalization")
        folded_paths.add(folded)
        changes.append(_Change(path=path, parts=parts, content=encoded))

    changes.sort(key=lambda change: change.path)
    folded_parts = [tuple(part.casefold() for part in change.parts) for change in changes]
    for index, parts in enumerate(folded_parts):
        for other in folded_parts[index + 1 :]:
            shortest = min(len(parts), len(other))
            if parts[:shortest] == other[:shortest] and len(parts) != len(other):
                raise ProtocolError("a file target cannot also be another target's directory")
    return tuple(changes)


def _open_absolute_directory(path: Path) -> _Root:
    if not path.is_absolute():
        raise ProtocolError("DirectoryHandle root must be absolute")
    text = str(path)
    _reject_control_text(text, field="DirectoryHandle root")
    if any(part in {".", ".."} for part in path.parts):
        raise ProtocolError("DirectoryHandle root contains a dot component")

    fd = os.open(os.sep, _DIR_FLAGS)
    try:
        for part in path.parts[1:]:
            _reject_control_text(part, field="DirectoryHandle root component")
            try:
                next_fd = os.open(part, _DIR_FLAGS, dir_fd=fd)
            except OSError as exc:
                raise ProtocolError("DirectoryHandle root is not a no-symlink directory") from exc
            os.close(fd)
            fd = next_fd
        metadata = os.fstat(fd)
        if not stat.S_ISDIR(metadata.st_mode):
            raise ProtocolError("DirectoryHandle root is not a directory")
        return _Root(path=path, fd=fd, device=metadata.st_dev, inode=metadata.st_ino)
    except Exception:
        os.close(fd)
        raise


def _matching_name(parent_fd: int, requested: str) -> str | None:
    folded = unicodedata.normalize("NFC", requested).casefold()
    matches = [
        name
        for name in os.listdir(parent_fd)
        if unicodedata.normalize("NFC", name).casefold() == folded
    ]
    if len(matches) > 1:
        raise ProtocolError("owner directory contains an ambiguous NFC/casefold collision")
    if not matches:
        return None
    if matches[0] != requested:
        raise ProtocolError("target aliases an existing NFC/casefold name")
    return requested


def _open_existing_parent(
    root: _Root,
    parent_parts: tuple[str, ...],
) -> tuple[int | None, Path]:
    fd = os.dup(root.fd)
    current_path = root.path
    try:
        for part in parent_parts:
            if _matching_name(fd, part) is None:
                os.close(fd)
                return None, current_path / part
            try:
                next_fd = os.open(part, _DIR_FLAGS, dir_fd=fd)
            except OSError as exc:
                raise ProtocolError("target parent is not a no-symlink directory") from exc
            metadata = os.fstat(next_fd)
            if not stat.S_ISDIR(metadata.st_mode) or metadata.st_dev != root.device:
                os.close(next_fd)
                raise ProtocolError("target parent crosses the owner-root device")
            os.close(fd)
            fd = next_fd
            current_path /= part
        return fd, current_path
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        raise


def _source_at(parent_fd: int, name: str, *, root_device: int) -> _Source:
    if _matching_name(parent_fd, name) is None:
        return _Source(False, None, None, b"")
    try:
        fd = os.open(name, _READ_FLAGS, dir_fd=parent_fd)
    except OSError as exc:
        raise ProtocolError("target must be a no-symlink regular file") from exc
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise ProtocolError("target must be a regular file")
        if metadata.st_dev != root_device:
            raise ProtocolError("target crosses the owner-root device")
        if metadata.st_nlink != 1:
            raise ProtocolError("hardlinked targets are forbidden")
        if metadata.st_size > _MAX_EXISTING_BYTES:
            raise ProtocolError("existing target exceeds the File Cell read bound")
        content = _read_all(fd, limit=_MAX_EXISTING_BYTES)
        after = os.fstat(fd)
        if (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
            after.st_nlink,
        ) != (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
            metadata.st_nlink,
        ):
            raise ProtocolError("target changed while File Cell inspected it")
        fingerprint = {
            "device": metadata.st_dev,
            "inode": metadata.st_ino,
            "mode": stat.S_IMODE(metadata.st_mode),
            "size": metadata.st_size,
            "mtime_ns": metadata.st_mtime_ns,
            "ctime_ns": metadata.st_ctime_ns,
            "nlink": metadata.st_nlink,
        }
        return _Source(True, _sha256(content), fingerprint, content)
    finally:
        os.close(fd)


def _inspect_source(root: _Root, change: _Change) -> _Source:
    parent_fd, _parent_path = _open_existing_parent(root, change.parts[:-1])
    if parent_fd is None:
        return _Source(False, None, None, b"")
    try:
        return _source_at(parent_fd, change.parts[-1], root_device=root.device)
    finally:
        os.close(parent_fd)


def _same_source(left: _Source, right: _Source) -> bool:
    return (
        left.exists == right.exists
        and left.digest == right.digest
        and left.fingerprint == right.fingerprint
    )


def _normalized_diff(change: _Change, source: _Source) -> str:
    before = source.content.decode("utf-8", errors="replace").splitlines(keepends=True)
    after = change.content.decode("utf-8", errors="strict").splitlines(keepends=True)
    return "".join(
        difflib.unified_diff(
            before,
            after,
            fromfile=f"a/{change.path}",
            tofile=f"b/{change.path}",
            lineterm="\n",
        )
    )


def _stage_key(package: CellPackage) -> str:
    material = f"{package.draft.draft_id}\x00{package.canonical_effect_hash}".encode()
    return hashlib.sha256(material).hexdigest()


def _desired_digest(payload: bytes) -> str:
    """Return the exact content identity used for commit reconciliation."""

    return _sha256(payload)


def _regular_file_bytes_at(
    parent_fd: int,
    name: str,
    *,
    limit: int,
    expected_device: int | None = None,
) -> bytes:
    try:
        fd = os.open(name, _READ_FLAGS, dir_fd=parent_fd)
    except OSError as exc:
        raise ProtocolError("staged artifact is missing or unsafe") from exc
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ProtocolError("staged artifact must be a single-link regular file")
        if expected_device is not None and metadata.st_dev != expected_device:
            raise ProtocolError("staged artifact crosses its staging device")
        if metadata.st_size > limit:
            raise ProtocolError("staged artifact exceeds its bound")
        return _read_all(fd, limit=limit)
    finally:
        os.close(fd)


class FileCell(CellBase):
    """``cell.file`` strict package executor."""

    def __init__(
        self,
        *,
        socket_path: Path,
        state_dir: Path,
        mac_key: bytes,
    ) -> None:
        self._mac_key = mac_key
        self._stage_root = state_dir / "orin" / "file-staging"
        super().__init__(
            cap="cell.file",
            socket_path=socket_path,
            state_dir=state_dir,
            handler=self._commit_package,
            preflight_handler=self._preflight_package,
            reconcile_handler=self._reconcile_effect,
            strict_effect_protocol=True,
        )

    def _authority(
        self,
        package: CellPackage,
        *,
        require_write: bool,
        require_fresh: bool = True,
    ) -> tuple[OriginHandle, _Root]:
        package.validate_binding(require_witness=require_write)
        changes = _parse_changes(package)
        _ = changes
        raw_handle_id = package.draft.arguments.get("directory_handle")
        if not isinstance(raw_handle_id, str):
            raise ProtocolError("file.commit directory_handle must be a handle id")
        if len(package.resolved_handles) != 1:
            raise ProtocolError("File Cell requires exactly one resolved DirectoryHandle")
        handle = package.resolved_handles[0]
        if handle.handle_id != raw_handle_id or handle.kind != "DirectoryHandle":
            raise ProtocolError("file.commit DirectoryHandle binding is invalid")
        if handle.issuer != "orind:broker" or not handle.verify_seal(self._mac_key):
            raise ProtocolError("DirectoryHandle seal or issuer is invalid")
        now = _now_ms()
        if handle.created_at_ms > now + 5_000 or (require_fresh and handle.expires_at_ms <= now):
            raise ProtocolError("DirectoryHandle is outside its validity window")
        required_caps = {"read", "stage"}
        if require_write:
            required_caps.add("write")
        if not required_caps.issubset(handle.capabilities):
            raise ProtocolError("DirectoryHandle lacks required File Cell capabilities")
        root = _open_absolute_directory(Path(handle.object_digest))
        return handle, root

    @staticmethod
    def _fd_device(fd: int) -> int:
        """Small mount-boundary seam used at every opened directory layer."""

        return os.fstat(fd).st_dev

    def _validate_device_layers(
        self,
        root: _Root,
        changes: tuple[_Change, ...],
    ) -> None:
        if self._fd_device(root.fd) != root.device:
            raise ProtocolError("owner-root device identity changed")
        checked: set[tuple[str, ...]] = set()
        for change in changes:
            for depth in range(1, len(change.parts)):
                prefix = change.parts[:depth]
                if prefix in checked:
                    continue
                checked.add(prefix)
                fd = os.dup(root.fd)
                try:
                    for part in prefix:
                        if _matching_name(fd, part) is None:
                            break
                        try:
                            next_fd = os.open(part, _DIR_FLAGS, dir_fd=fd)
                        except OSError as exc:
                            raise ProtocolError(
                                "target parent is not a no-symlink directory"
                            ) from exc
                        os.close(fd)
                        fd = next_fd
                        if self._fd_device(fd) != root.device:
                            raise ProtocolError("target parent crosses the owner-root device")
                finally:
                    os.close(fd)

    def _ensure_stage_directory(self, package: CellPackage) -> tuple[Path, int]:
        self._stage_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self._stage_root, 0o700)
        stage_dir = self._stage_root / _stage_key(package)
        try:
            stage_dir.mkdir(mode=0o700)
        except FileExistsError:
            pass
        try:
            fd = os.open(stage_dir, _DIR_FLAGS)
        except OSError as exc:
            raise ProtocolError("File Cell staging directory is unsafe") from exc
        metadata = os.fstat(fd)
        if not stat.S_ISDIR(metadata.st_mode):
            os.close(fd)
            raise ProtocolError("File Cell staging path is not a directory")
        if stat.S_IMODE(metadata.st_mode) != 0o700:
            os.close(fd)
            raise ProtocolError("File Cell staging directory must remain mode 0700")
        return stage_dir, fd

    @staticmethod
    def _write_stage_file(stage_fd: int, name: str, payload: bytes) -> None:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(name, flags, 0o600, dir_fd=stage_fd)
        except FileExistsError:
            existing = _regular_file_bytes_at(stage_fd, name, limit=len(payload))
            if existing != payload:
                raise ProtocolError("existing File Cell stage conflicts with the draft") from None
            return
        except OSError as exc:
            raise ProtocolError("unable to create private File Cell stage") from exc
        try:
            _write_all(fd, payload)
            os.fsync(fd)
        finally:
            os.close(fd)

    def _preflight_package(self, package: CellPackage) -> StateWitness:
        handle, root = self._authority(package, require_write=False)
        try:
            changes = _parse_changes(package)
            self._validate_device_layers(root, changes)
            sources = {change.path: _inspect_source(root, change) for change in changes}
            stage_files = {
                change.path: {
                    "name": f"content-{index:04d}-{hashlib.sha256(change.path.encode()).hexdigest()}",
                    "sha256": _sha256(change.content),
                    "bytes": len(change.content),
                }
                for index, change in enumerate(changes)
            }
            normalized_diff = "".join(
                _normalized_diff(change, sources[change.path]) for change in changes
            )
            overwrites = [change.path for change in changes if sources[change.path].exists]
            bytes_written = sum(len(change.content) for change in changes)
            report: dict[str, Any] = {
                "schema": _STAGE_SCHEMA,
                "draft_id": package.draft.draft_id,
                "task_id": package.draft.task_id,
                "canonical_effect_hash": package.canonical_effect_hash,
                "directory_handle_id": handle.handle_id,
                "owner_root": str(root.path),
                "owner_root_identity": {"device": root.device, "inode": root.inode},
                "files": [change.path for change in changes],
                "file_count": len(changes),
                "bytes_written": bytes_written,
                "overwrites": overwrites,
                "source_hashes": {change.path: sources[change.path].digest for change in changes},
                "source_fingerprints": {
                    change.path: sources[change.path].fingerprint for change in changes
                },
                "stage_files": stage_files,
                "normalized_diff": normalized_diff,
            }
            witness_material = canonical_json(report).encode("utf-8")
            witness_id = (
                "state:"
                + hmac.new(
                    self._mac_key,
                    witness_material,
                    hashlib.sha256,
                ).hexdigest()
            )
            report["witness_id"] = witness_id
            report_payload = canonical_json(report).encode("utf-8")
            stage_dir, stage_fd = self._ensure_stage_directory(package)
            try:
                for change in changes:
                    stage_name = str(stage_files[change.path]["name"])
                    self._write_stage_file(stage_fd, stage_name, change.content)
                self._write_stage_file(stage_fd, _REPORT_NAME, report_payload)
                os.fsync(stage_fd)
            finally:
                os.close(stage_fd)
            # Keep a concrete path only for later private reads; no stage path
            # or owner-root locator crosses the authenticated Cell ack.
            _ = stage_dir
            now = _now_ms()
            return StateWitness(
                witness_id=witness_id,
                draft_id=package.draft.draft_id,
                executor_id=package.executor_id,
                target_version="file-stage:" + hashlib.sha256(report_payload).hexdigest(),
                canonical_effect_hash=package.canonical_effect_hash,
                impact=Impact(writes=len(changes)),
                reversibility="reversible_until_stage",
                idempotency_support="client_key",
                created_at_ms=now,
                expires_at_ms=now + _WITNESS_TTL_MS,
                file_commit_preview=FileCommitPreviewV1(
                    file_count=len(changes),
                    bytes=bytes_written,
                    overwrites=tuple(overwrites),
                    diff_hash=_sha256(normalized_diff.encode("utf-8")),
                ),
            )
        finally:
            os.close(root.fd)

    def _load_bound_stage(
        self,
        package: CellPackage,
        changes: tuple[_Change, ...],
        handle: OriginHandle,
        root: _Root,
    ) -> tuple[dict[str, Any], dict[str, bytes]]:
        witness = package.state_witness
        if witness is None:
            raise ProtocolError("file commit package requires a StateWitness")
        stage_dir = self._stage_root / _stage_key(package)
        try:
            stage_fd = os.open(stage_dir, _DIR_FLAGS)
        except OSError as exc:
            raise ProtocolError("File Cell stage is missing or unsafe") from exc
        try:
            stage_meta = os.fstat(stage_fd)
            if not stat.S_ISDIR(stage_meta.st_mode) or stat.S_IMODE(stage_meta.st_mode) != 0o700:
                raise ProtocolError("File Cell stage permissions changed")
            report_payload = _regular_file_bytes_at(
                stage_fd,
                _REPORT_NAME,
                limit=_MAX_EXISTING_BYTES,
                expected_device=stage_meta.st_dev,
            )
            try:
                report = json.loads(report_payload)
            except (UnicodeError, json.JSONDecodeError) as exc:
                raise ProtocolError("File Cell stage report is not canonical JSON") from exc
            if not isinstance(report, dict) or canonical_json(report).encode() != report_payload:
                raise ProtocolError("File Cell stage report is not canonical")
            target_version = "file-stage:" + hashlib.sha256(report_payload).hexdigest()
            if witness.target_version != target_version:
                raise ProtocolError("StateWitness does not bind the current File Cell stage")
            expected_keys = {
                "schema",
                "draft_id",
                "task_id",
                "canonical_effect_hash",
                "directory_handle_id",
                "owner_root",
                "owner_root_identity",
                "files",
                "file_count",
                "bytes_written",
                "overwrites",
                "source_hashes",
                "source_fingerprints",
                "stage_files",
                "normalized_diff",
                "witness_id",
            }
            if set(report) != expected_keys or report.get("schema") != _STAGE_SCHEMA:
                raise ProtocolError("File Cell stage report shape is invalid")
            raw_witness_id = report.get("witness_id")
            if not isinstance(raw_witness_id, str):
                raise ProtocolError("File Cell stage witness is invalid")
            signed_report = dict(report)
            signed_report.pop("witness_id")
            expected_witness_id = (
                "state:"
                + hmac.new(
                    self._mac_key,
                    canonical_json(signed_report).encode("utf-8"),
                    hashlib.sha256,
                ).hexdigest()
            )
            if not hmac.compare_digest(raw_witness_id, expected_witness_id):
                raise ProtocolError("File Cell stage witness authentication failed")
            expected_static = {
                "draft_id": package.draft.draft_id,
                "task_id": package.draft.task_id,
                "canonical_effect_hash": package.canonical_effect_hash,
                "directory_handle_id": handle.handle_id,
                "owner_root": str(root.path),
                "owner_root_identity": {"device": root.device, "inode": root.inode},
                "files": [change.path for change in changes],
                "file_count": len(changes),
                "bytes_written": sum(len(change.content) for change in changes),
                "witness_id": witness.witness_id,
            }
            if any(report.get(key) != value for key, value in expected_static.items()):
                raise ProtocolError("File Cell stage does not match the commit package")
            if witness.impact.writes != len(changes):
                raise ProtocolError("File Cell witness impact does not match the staged report")
            preview = witness.file_commit_preview
            normalized_diff = report.get("normalized_diff")
            overwrites = report.get("overwrites")
            if (
                preview is None
                or not isinstance(normalized_diff, str)
                or not isinstance(overwrites, list)
                or preview.file_count != len(changes)
                or preview.bytes != sum(len(change.content) for change in changes)
                or preview.overwrites != tuple(overwrites)
                or preview.diff_hash != _sha256(normalized_diff.encode("utf-8"))
            ):
                raise ProtocolError("File Cell approval preview does not match the staged report")

            raw_stage_files = report.get("stage_files")
            if not isinstance(raw_stage_files, dict) or set(raw_stage_files) != {
                change.path for change in changes
            }:
                raise ProtocolError("File Cell staged file map is invalid")
            staged: dict[str, bytes] = {}
            for change in changes:
                raw_entry = raw_stage_files.get(change.path)
                if not isinstance(raw_entry, dict) or set(raw_entry) != {
                    "name",
                    "sha256",
                    "bytes",
                }:
                    raise ProtocolError("File Cell staged file entry is invalid")
                name = raw_entry.get("name")
                if (
                    not isinstance(name, str)
                    or "/" in name
                    or name in {"", ".", "..", _REPORT_NAME}
                ):
                    raise ProtocolError("File Cell staged file name is invalid")
                payload = _regular_file_bytes_at(
                    stage_fd,
                    name,
                    limit=_MAX_CONTENT_BYTES,
                    expected_device=stage_meta.st_dev,
                )
                if (
                    raw_entry.get("bytes") != len(payload)
                    or raw_entry.get("sha256") != _sha256(payload)
                    or payload != change.content
                ):
                    raise ProtocolError("File Cell staged bytes do not match the draft")
                staged[change.path] = payload
            return report, staged
        finally:
            os.close(stage_fd)

    @staticmethod
    def _expected_sources(
        report: dict[str, Any], changes: tuple[_Change, ...]
    ) -> dict[str, _Source]:
        raw_hashes = report.get("source_hashes")
        raw_fingerprints = report.get("source_fingerprints")
        raw_overwrites = report.get("overwrites")
        paths = {change.path for change in changes}
        if (
            not isinstance(raw_hashes, dict)
            or set(raw_hashes) != paths
            or not isinstance(raw_fingerprints, dict)
            or set(raw_fingerprints) != paths
            or not isinstance(raw_overwrites, list)
        ):
            raise ProtocolError("File Cell source snapshot shape is invalid")
        overwrite_set = set(raw_overwrites)
        if len(overwrite_set) != len(raw_overwrites) or not overwrite_set.issubset(paths):
            raise ProtocolError("File Cell overwrite set is invalid")
        expected: dict[str, _Source] = {}
        for change in changes:
            digest = raw_hashes.get(change.path)
            fingerprint = raw_fingerprints.get(change.path)
            exists = change.path in overwrite_set
            if exists:
                if (
                    not isinstance(digest, str)
                    or len(digest) != 71
                    or not digest.startswith("sha256:")
                    or any(char not in "0123456789abcdef" for char in digest[7:])
                    or not isinstance(fingerprint, dict)
                ):
                    raise ProtocolError("File Cell source fingerprint is invalid")
                parsed_fingerprint: dict[str, int] = {}
                expected_fields = {
                    "device",
                    "inode",
                    "mode",
                    "size",
                    "mtime_ns",
                    "ctime_ns",
                    "nlink",
                }
                if set(fingerprint) != expected_fields:
                    raise ProtocolError("File Cell source fingerprint fields are invalid")
                for key in expected_fields:
                    value = fingerprint.get(key)
                    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                        raise ProtocolError("File Cell source fingerprint value is invalid")
                    parsed_fingerprint[key] = value
                expected[change.path] = _Source(True, digest, parsed_fingerprint, b"")
            else:
                if digest is not None or fingerprint is not None:
                    raise ProtocolError("missing File Cell source has a fingerprint")
                expected[change.path] = _Source(False, None, None, b"")
        return expected

    @staticmethod
    def _target_state(
        current: _Source,
        expected_source: _Source,
        desired_payload: bytes,
    ) -> str:
        """Classify one target without changing owner-root state.

        Desired content is checked before the preflight source identity so a
        no-op draft, or a target already published before a crash, is treated
        as complete.  Anything other than the exact desired bytes or the
        exact preflight CAS snapshot is ambiguous and must never be retried.
        """

        if current.exists and current.digest == _desired_digest(desired_payload):
            return "desired"
        if _same_source(current, expected_source):
            return "source"
        return "conflict"

    def _classify_targets(
        self,
        *,
        root: _Root,
        changes: tuple[_Change, ...],
        expected_sources: dict[str, _Source],
        staged: dict[str, bytes],
    ) -> dict[str, str]:
        return {
            change.path: self._target_state(
                _inspect_source(root, change),
                expected_sources[change.path],
                staged[change.path],
            )
            for change in changes
        }

    def _reconcile_effect(
        self,
        effect_id: str,
        probe: dict[str, Any],
    ) -> dict[str, str]:
        """Read-only WP10 reconciliation over an authenticated Cell probe.

        The probe carries the same strict, parallel permit/package pair as a
        commit.  It is parsed independently inside the Cell and is never
        replaced by a path to Orind state.  Every malformed, stale-stage, or
        authority-conflicting observation remains ``UNKNOWN_COMMIT``.
        """

        try:
            if not isinstance(effect_id, str) or not 1 <= len(effect_id) <= 256:
                raise ProtocolError("file reconcile effect_id is invalid")
            if not isinstance(probe, dict) or set(probe) != {"permit", "package"}:
                raise ProtocolError("file reconcile probe shape is invalid")
            raw_permit = probe.get("permit")
            raw_package = probe.get("package")
            if not isinstance(raw_permit, dict) or not isinstance(raw_package, dict):
                raise ProtocolError("file reconcile requires permit and package objects")
            permit = permit_from_dict(raw_permit)
            package = cell_package_from_dict(
                raw_package,
                require_witness=True,
                permit=permit,
            )
            if package.executor_id != self.cap:
                raise ProtocolError("file reconcile package executor mismatch")

            # Expiry prevents a new effect, but must not prevent observation
            # of a previously authorised, cryptographically bound attempt.
            handle, root = self._authority(
                package,
                require_write=True,
                require_fresh=False,
            )
            try:
                changes = _parse_changes(package)
                self._validate_device_layers(root, changes)
                report, staged = self._load_bound_stage(package, changes, handle, root)
                expected_sources = self._expected_sources(report, changes)
                states = self._classify_targets(
                    root=root,
                    changes=changes,
                    expected_sources=expected_sources,
                    staged=staged,
                )
                if "conflict" in states.values():
                    return {"state": "UNKNOWN_COMMIT"}
                if all(state == "desired" for state in states.values()):
                    return {"state": "COMMITTED"}
                return {"state": "PREPARED"}
            finally:
                os.close(root.fd)
        except Exception:  # noqa: BLE001 - reconciliation is fail-closed and non-reflective
            return {"state": "UNKNOWN_COMMIT"}

    @staticmethod
    def _open_or_create_parent(root: _Root, parts: tuple[str, ...]) -> tuple[int, Path]:
        fd = os.dup(root.fd)
        current_path = root.path
        try:
            for part in parts:
                matched = _matching_name(fd, part)
                if matched is None:
                    try:
                        os.mkdir(part, mode=0o700, dir_fd=fd)
                        os.fsync(fd)
                    except FileExistsError:
                        pass
                try:
                    next_fd = os.open(part, _DIR_FLAGS, dir_fd=fd)
                except OSError as exc:
                    raise ProtocolError("commit parent is not a no-symlink directory") from exc
                metadata = os.fstat(next_fd)
                if not stat.S_ISDIR(metadata.st_mode) or metadata.st_dev != root.device:
                    os.close(next_fd)
                    raise ProtocolError("commit parent crosses the owner-root device")
                os.close(fd)
                fd = next_fd
                current_path /= part
            return fd, current_path
        except Exception:
            try:
                os.close(fd)
            except OSError:
                pass
            raise

    @staticmethod
    def _prepare_replacement(
        *,
        root: _Root,
        change: _Change,
        payload: bytes,
        expected_source: _Source,
        permit: CommitPermit,
    ) -> _PreparedReplace:
        parent_fd, parent_path = FileCell._open_or_create_parent(root, change.parts[:-1])
        current = _source_at(parent_fd, change.parts[-1], root_device=root.device)
        if not _same_source(current, expected_source):
            os.close(parent_fd)
            raise ProtocolError("source changed after File Cell preflight")
        token = hashlib.sha256(
            f"{permit.idempotency_key}\x00{change.path}\x00{secrets.token_hex(8)}".encode()
        ).hexdigest()[:32]
        temp_name = f".orin-{token}.tmp"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        try:
            temp_fd = os.open(temp_name, flags, 0o600, dir_fd=parent_fd)
        except OSError as exc:
            os.close(parent_fd)
            raise ProtocolError("unable to create same-directory commit temporary") from exc
        try:
            _write_all(temp_fd, payload)
            os.fsync(temp_fd)
        except Exception:
            os.close(temp_fd)
            try:
                os.unlink(temp_name, dir_fd=parent_fd)
            except OSError:
                pass
            os.close(parent_fd)
            raise
        os.close(temp_fd)
        return _PreparedReplace(
            parent_fd=parent_fd,
            parent_path=parent_path,
            temp_name=temp_name,
            target_name=change.parts[-1],
            expected_source=expected_source,
            expected_digest=_sha256(payload),
        )

    @staticmethod
    def _cleanup_prepared(prepared: list[_PreparedReplace]) -> None:
        for item in prepared:
            try:
                os.unlink(item.temp_name, dir_fd=item.parent_fd)
            except OSError:
                pass
            try:
                os.close(item.parent_fd)
            except OSError:
                pass

    def _commit_package(
        self,
        permit: CommitPermit,
        package: CellPackage,
    ) -> dict[str, Any]:
        package.validate_binding(permit, require_witness=True)
        handle, root = self._authority(package, require_write=True)
        prepared: list[_PreparedReplace] = []
        try:
            changes = _parse_changes(package)
            self._validate_device_layers(root, changes)
            report, staged = self._load_bound_stage(package, changes, handle, root)
            expected_sources = self._expected_sources(report, changes)
            target_states = self._classify_targets(
                root=root,
                changes=changes,
                expected_sources=expected_sources,
                staged=staged,
            )

            # Complete the entire CAS validation before creating any temporary
            # or replacing any owner-root target.  A target that already has
            # the staged digest is the durable evidence of an earlier rename
            # and is deliberately skipped.  Only the exact original source
            # snapshot is eligible for another atomic publish.
            if "conflict" in target_states.values():
                raise ProtocolError("file target is neither preflight source nor desired output")

            for change in changes:
                if target_states[change.path] == "desired":
                    continue
                prepared.append(
                    self._prepare_replacement(
                        root=root,
                        change=change,
                        payload=staged[change.path],
                        expected_source=expected_sources[change.path],
                        permit=permit,
                    )
                )

            # Recheck through the pinned parent descriptors immediately before
            # the irreversible rename sequence.
            for item in prepared:
                current = _source_at(
                    item.parent_fd,
                    item.target_name,
                    root_device=root.device,
                )
                if not _same_source(current, item.expected_source):
                    raise ProtocolError("source raced the File Cell commit")

            # Skipped targets are not held by a writable descriptor.  Observe
            # them again immediately before the remaining rename sequence so
            # an intervening writer cannot be mistaken for a completed effect.
            for change in changes:
                if target_states[change.path] != "desired":
                    continue
                current = _inspect_source(root, change)
                if not current.exists or current.digest != _desired_digest(staged[change.path]):
                    raise ProtocolError("completed File Cell target changed before retry")

            for index, item in enumerate(prepared):
                try:
                    os.replace(
                        item.temp_name,
                        item.target_name,
                        src_dir_fd=item.parent_fd,
                        dst_dir_fd=item.parent_fd,
                    )
                    os.fsync(item.parent_fd)
                    committed = _source_at(
                        item.parent_fd,
                        item.target_name,
                        root_device=root.device,
                    )
                    if committed.digest != item.expected_digest:
                        raise ProtocolError("atomic file commit verification failed")
                finally:
                    # Once replace succeeds the old temp name is absent; on a
                    # failed replace this removes only our private basename.
                    try:
                        os.unlink(item.temp_name, dir_fd=item.parent_fd)
                    except OSError:
                        pass
                    os.close(item.parent_fd)
                prepared[index].parent_fd = -1

            # A concurrent writer can race any skipped or newly replaced
            # target.  Returning COMMITTED requires the complete desired set
            # to be observable after the final publish.
            for change in changes:
                committed = _inspect_source(root, change)
                if not committed.exists or committed.digest != _desired_digest(staged[change.path]):
                    raise ProtocolError("File Cell target set is not fully committed")

            diff_text = report.get("normalized_diff")
            if not isinstance(diff_text, str):
                raise ProtocolError("File Cell normalized diff is invalid")
            diff_hash = _sha256(diff_text.encode("utf-8"))
            public = {
                "status": "COMMITTED",
                "files": [change.path for change in changes],
                "bytes_written": sum(len(staged[change.path]) for change in changes),
                "diff_hash": diff_hash,
            }
            return self.attach_signed_receipt(
                public,
                permit_id=permit.permit_id,
                executor_id="cell.file",
                effect_hash=package.canonical_effect_hash,
                receipt_id="receipt:" + diff_hash.removeprefix("sha256:"),
            )
        finally:
            self._cleanup_prepared([item for item in prepared if item.parent_fd >= 0])
            os.close(root.fd)


def main() -> None:  # pragma: no cover - subprocess entry
    socket_path = os.environ.get("ORIN_CELLS_SOCKET")
    state_dir_env = os.environ.get("ORIN_STATE_DIR")
    if not socket_path or not state_dir_env:
        raise SystemExit("ORIN_CELLS_SOCKET and ORIN_STATE_DIR are required")
    from js.orin.container_vm import read_host_broker_mac
    from js.orind.keybox import KeyBox

    state_dir = Path(state_dir_env)
    host_mac = read_host_broker_mac()
    if host_mac is not None:
        cell = FileCell(socket_path=Path(socket_path), state_dir=state_dir, mac_key=host_mac)
    else:
        strict_paths = os.environ.get("ORIN_CELL_IDENTITY_ENFORCE") == "1"
        keybox_tier = os.environ.get("ORIN_KEYBOX_TIER")
        if strict_paths and keybox_tier not in {"dev", "production"}:
            raise SystemExit("ORIN_KEYBOX_TIER must be explicit in Cell identity enforce mode")
        keybox = KeyBox(
            state_dir,
            tier=keybox_tier or "dev",
            strict_paths=strict_paths,
        )
        cell = FileCell(socket_path=Path(socket_path), state_dir=state_dir, mac_key=keybox.key)
    cell.start()
    try:
        while True:
            time.sleep(1)
            if not cell.healthy():
                raise SystemExit("File Cell became unhealthy")
    except KeyboardInterrupt:
        pass
    finally:
        cell.stop()


if __name__ == "__main__":  # pragma: no cover
    main()


__all__ = ["FileCell"]
