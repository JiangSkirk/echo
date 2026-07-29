"""Echo attachment scope checks shared by web and agent paths."""

from __future__ import annotations

import hashlib
import mimetypes
import os
import secrets
import stat
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path, PurePath
from typing import Any, BinaryIO

from js.echo.ledger.security_controls import FileScope

_PENDING_SESSION = "_pending"
_MAX_ATTACHMENT_COUNT = 32
_MAX_ATTACHMENT_BYTES = 100 * 1024 * 1024
_MAX_UPLOAD_SCAN_ENTRIES = 4096
_MAX_LISTED_UPLOADS = 1000
_MAX_UPLOAD_NAME_ATTEMPTS = 10_000


class AttachmentGateError(PermissionError):
    """Attachment scope failure with an HTTP-compatible status code."""

    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


@dataclass(frozen=True)
class AttachmentSnapshot:
    """One attachment read through a no-follow descriptor chain."""

    relative_path: str
    name: str
    suffix: str
    size: int
    sha256: str
    media_type: str
    data: bytes = field(repr=False)


@dataclass(frozen=True)
class OwnedUploadEntry:
    """Metadata captured from an already-open owner/session directory."""

    relative_path: str
    name: str
    size: int
    modified: float


def owner_slug(owner_key_hash: str | None) -> str:
    owner = owner_key_hash or "local"
    digest = hashlib.sha256(owner.encode("utf-8")).hexdigest()
    return f"o_{digest[:24]}"


def session_slug(session_id: str | None) -> str:
    if not session_id:
        return _PENDING_SESSION
    digest = hashlib.sha256(session_id.encode("utf-8")).hexdigest()
    return f"s_{digest[:24]}"


def safe_upload_filename(filename: str | None) -> str:
    logical_name = unicodedata.normalize("NFC", filename or "unnamed").replace("\\", "/")
    safe_name = PurePath(logical_name).name.strip()
    safe_name = "".join(
        "_" if unicodedata.category(character).startswith("C") else character
        for character in safe_name
    )
    if not safe_name or safe_name in {".", ".."} or safe_name.startswith("."):
        return "unnamed"
    encoded = safe_name.encode("utf-8")
    if len(encoded) <= 240:
        return safe_name
    suffix = PurePath(safe_name).suffix
    suffix_bytes = suffix.encode("utf-8")
    if len(suffix_bytes) > 32:
        suffix = ""
        suffix_bytes = b""
    stem = safe_name[: -len(suffix)] if suffix else safe_name
    budget = 240 - len(suffix_bytes)
    truncated = stem.encode("utf-8")[:budget].decode("utf-8", errors="ignore")
    return (truncated or "unnamed") + suffix


def upload_dir(workspace: Path, owner_key_hash: str | None, session_id: str | None) -> Path:
    return workspace / "uploads" / owner_slug(owner_key_hash) / session_slug(session_id)


class SecureUploadWriter:
    """Stage and atomically publish one owner/session-scoped upload.

    Every path component is opened relative to a directory descriptor with
    ``O_NOFOLLOW``.  The final name is claimed with a same-directory hard link,
    which provides portable no-replace semantics without a path check/open race.
    """

    # Test-only one-shot fault injection. Production never sets these.
    _test_fault_after_publish_fsync: str | None = None
    _test_fault_rollback_unlink: str | None = None

    def __init__(
        self,
        workspace: Path,
        owner_key_hash: str | None,
        session_id: str | None,
        filename: str | None,
        *,
        max_bytes: int = _MAX_ATTACHMENT_BYTES,
        quota_limits: Any | None = None,
    ) -> None:
        if not (session_id or "").strip():
            raise AttachmentGateError(400, "session_id is required")
        if max_bytes <= 0:
            raise AttachmentGateError(500, "Invalid upload size limit")
        self._workspace = workspace
        self._owner_key_hash = owner_key_hash
        self._session_id = session_id
        self._logical_dir = upload_dir(workspace, owner_key_hash, session_id)
        self._safe_name = safe_upload_filename(filename)
        self._max_bytes = max_bytes
        self._bytes_written = 0
        self._committed = False
        self._closed = False
        self._dir_fd = -1
        self._temp_name = f".upload-{secrets.token_hex(16)}.tmp"
        self._file: BinaryIO | None = None
        self._reservation_id = secrets.token_hex(16)
        self._quota_reserved = False
        self._publish_intent = False

        from js.echo.upload_quota import UploadQuotaLedger, UploadQuotaLimits

        limits = (
            quota_limits if isinstance(quota_limits, UploadQuotaLimits) else UploadQuotaLimits()
        )
        self._quota = UploadQuotaLedger(workspace, owner_key_hash, limits=limits)
        self._quota.reserve(
            session_id=str(session_id),
            bytes_needed=max_bytes,
            files_needed=1,
            reservation_id=self._reservation_id,
        )
        self._quota_reserved = True

        try:
            self._dir_fd = _open_secure_upload_dir(workspace, owner_key_hash, session_id)
        except Exception:
            if self._quota_reserved:
                self._quota.release(reservation_id=self._reservation_id)
                self._quota_reserved = False
            raise
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
        try:
            file_fd = os.open(self._temp_name, flags, 0o600, dir_fd=self._dir_fd)
            os.fchmod(file_fd, 0o600)
            metadata = os.fstat(file_fd)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                os.close(file_fd)
                raise AttachmentGateError(409, "Unsafe upload staging file")
            self._file = os.fdopen(file_fd, "wb")
        except Exception:
            os.close(self._dir_fd)
            self._dir_fd = -1
            if self._quota_reserved:
                self._quota.release(reservation_id=self._reservation_id)
                self._quota_reserved = False
            raise

    @property
    def bytes_written(self) -> int:
        return self._bytes_written

    def write(self, chunk: bytes | bytearray | memoryview) -> int:
        if self._closed or self._file is None:
            raise AttachmentGateError(409, "Upload writer is closed")
        payload = bytes(chunk)
        if self._bytes_written + len(payload) > self._max_bytes:
            raise AttachmentGateError(413, "File too large (max 100MB)")
        written = self._file.write(payload)
        if written != len(payload):
            raise AttachmentGateError(500, "Short upload write")
        self._bytes_written += written
        return written

    def commit(self) -> Path:
        if self._closed or self._file is None:
            raise AttachmentGateError(409, "Upload writer is closed")
        if self._committed:
            raise AttachmentGateError(409, "Upload is already committed")
        self._file.flush()
        os.fsync(self._file.fileno())

        stem = Path(self._safe_name).stem
        suffix = Path(self._safe_name).suffix
        for counter in range(_MAX_UPLOAD_NAME_ATTEMPTS):
            candidate = self._safe_name if counter == 0 else f"{stem}_{counter}{suffix}"
            # Persist publishing intent (final name/size) BEFORE publishing the file.
            if self._quota_reserved:
                try:
                    self._quota.mark_published(
                        session_id=self._session_id or "",
                        reservation_id=self._reservation_id,
                        filename=candidate,
                        actual_bytes=self._bytes_written,
                    )
                    self._publish_intent = True
                except AttachmentGateError as exc:
                    if "already published differently" in str(exc.detail):
                        continue
                    raise
            try:
                os.link(
                    self._temp_name,
                    candidate,
                    src_dir_fd=self._dir_fd,
                    dst_dir_fd=self._dir_fd,
                    follow_symlinks=False,
                )
            except FileExistsError:
                continue
            except OSError as exc:
                if self._quota_reserved:
                    try:
                        self._quota.release(
                            reservation_id=self._reservation_id,
                            abandon_published=True,
                        )
                    except Exception:
                        pass
                    self._quota_reserved = False
                raise AttachmentGateError(409, "Could not publish upload safely") from exc
            os.unlink(self._temp_name, dir_fd=self._dir_fd)
            os.fsync(self._dir_fd)
            # Test hook: crash after file is durable, before quota commit.
            fault = getattr(type(self), "_test_fault_after_publish_fsync", None)
            if fault == "os_exit":
                type(self)._test_fault_after_publish_fsync = None
                os._exit(97)
            published = self._logical_dir / candidate
            try:
                if self._quota_reserved:
                    self._quota.commit(
                        session_id=self._session_id or "",
                        reservation_id=self._reservation_id,
                        actual_bytes=self._bytes_written,
                        filename=candidate,
                    )
                    self._quota_reserved = False
            except Exception:
                unlinked = False
                try:
                    if type(self)._test_fault_rollback_unlink == "raise":
                        type(self)._test_fault_rollback_unlink = None
                        raise OSError("simulated rollback unlink failure")
                    os.unlink(candidate, dir_fd=self._dir_fd)
                    os.fsync(self._dir_fd)
                    unlinked = True
                except OSError:
                    # Unlink failed: leave published intent for recover to bill.
                    pass
                if self._quota_reserved and unlinked:
                    try:
                        self._quota.release(
                            reservation_id=self._reservation_id,
                            abandon_published=True,
                        )
                    except Exception:
                        pass
                    self._quota_reserved = False
                # If unlink failed, keep published reservation (fail-closed).
                raise
            self._committed = True
            return published
        raise AttachmentGateError(409, "Too many files with the same upload name")

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._file is not None:
            self._file.close()
            self._file = None
        if not self._committed and self._dir_fd >= 0:
            try:
                os.unlink(self._temp_name, dir_fd=self._dir_fd)
            except FileNotFoundError:
                pass
            except OSError:
                pass
        if self._dir_fd >= 0:
            os.close(self._dir_fd)
            self._dir_fd = -1
        if self._quota_reserved:
            if self._publish_intent and not self._committed:
                # Published intent may still have a visible file; do not abandon.
                # Bounded recover will bill or drop based on descriptor-relative existence.
                self._quota_reserved = False
            else:
                try:
                    self._quota.release(reservation_id=self._reservation_id)
                except Exception:
                    pass
                self._quota_reserved = False

    def __enter__(self) -> SecureUploadWriter:
        return self

    def __exit__(self, _exc_type: object, _exc: object, _tb: object) -> None:
        self.close()


_DIR_FD_UPLOAD_OK = (
    hasattr(os, "O_NOFOLLOW")
    and hasattr(os, "O_DIRECTORY")
    and hasattr(os, "O_CLOEXEC")
    and all(
        function in getattr(os, "supports_dir_fd", set())
        for function in (os.open, os.mkdir, os.link, os.unlink, os.stat)
    )
)


def _open_secure_upload_dir(
    workspace: Path,
    owner_key_hash: str | None,
    session_id: str | None,
) -> int:
    if not _DIR_FD_UPLOAD_OK:
        raise AttachmentGateError(503, "Secure upload primitives are unavailable")

    try:
        workspace.mkdir(parents=True, exist_ok=True)
        root = workspace.resolve(strict=True)
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
        current_fd = os.open(root, flags)
    except OSError as exc:
        raise AttachmentGateError(409, "Unsafe upload workspace") from exc

    components = ("uploads", owner_slug(owner_key_hash), session_slug(session_id))
    try:
        for component in components:
            try:
                os.mkdir(component, 0o700, dir_fd=current_fd)
            except FileExistsError:
                pass
            next_fd = os.open(component, flags, dir_fd=current_fd)
            metadata = os.fstat(next_fd)
            if not stat.S_ISDIR(metadata.st_mode):
                os.close(next_fd)
                raise AttachmentGateError(409, "Unsafe upload directory")
            os.fchmod(next_fd, 0o700)
            os.close(current_fd)
            current_fd = next_fd
        return current_fd
    except AttachmentGateError:
        os.close(current_fd)
        raise
    except OSError as exc:
        os.close(current_fd)
        raise AttachmentGateError(409, "Unsafe upload directory") from exc


def _open_existing_upload_dir(
    workspace: Path,
    owner_key_hash: str | None,
    session_id: str | None,
) -> int | None:
    """Open an existing owner/session partition without creating path components."""
    required_dir_fd = (os.open, os.stat, os.unlink)
    if (
        not hasattr(os, "O_NOFOLLOW")
        or not hasattr(os, "O_DIRECTORY")
        or not hasattr(os, "O_CLOEXEC")
        or any(function not in os.supports_dir_fd for function in required_dir_fd)
    ):
        raise AttachmentGateError(503, "Secure upload primitives are unavailable")

    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        root = workspace.resolve(strict=True)
        current_fd = os.open(root, flags)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise AttachmentGateError(409, "Unsafe upload workspace") from exc

    components = ("uploads", owner_slug(owner_key_hash), session_slug(session_id))
    try:
        for component in components:
            try:
                next_fd = os.open(component, flags, dir_fd=current_fd)
            except FileNotFoundError:
                os.close(current_fd)
                return None
            metadata = os.fstat(next_fd)
            if not stat.S_ISDIR(metadata.st_mode):
                os.close(next_fd)
                raise AttachmentGateError(409, "Unsafe upload directory")
            if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
                os.close(next_fd)
                raise AttachmentGateError(409, "Unsafe upload directory owner")
            os.close(current_fd)
            current_fd = next_fd
        return current_fd
    except AttachmentGateError:
        os.close(current_fd)
        raise
    except OSError as exc:
        os.close(current_fd)
        raise AttachmentGateError(409, "Unsafe upload directory") from exc


def resolve_owned_upload_path(
    *,
    workspace: Path,
    path: str,
    owner_key_hash: str | None,
    session_id: str | None = None,
    allow_pending: bool = False,
) -> Path:
    try:
        resolved = FileScope(root=workspace).resolve(path)
    except PermissionError as exc:
        raise AttachmentGateError(400, "Invalid upload path") from exc

    owner_root = (workspace / "uploads" / owner_slug(owner_key_hash)).resolve()
    if not _is_relative_to(resolved, owner_root):
        raise AttachmentGateError(403, "Upload access denied")

    if session_id:
        allowed_roots = [(owner_root / session_slug(session_id)).resolve()]
        if allow_pending:
            allowed_roots.append((owner_root / _PENDING_SESSION).resolve())
        if not any(_is_relative_to(resolved, root) for root in allowed_roots):
            raise AttachmentGateError(403, "Upload session access denied")

    return resolved


def echo_attachment_scope_enabled() -> bool:
    """Return the invariant Echo-only attachment gate state."""

    return True


def validate_agent_attachment_path(
    *,
    workspace: Path,
    path: str,
    owner_key_hash: str | None = None,
    session_id: str | None = None,
) -> Path:
    relative = _validated_attachment_relative_path(
        path,
        owner_key_hash=owner_key_hash,
        session_id=session_id,
    )
    return workspace.resolve() / relative


def _validated_attachment_relative_path(
    path: str,
    *,
    owner_key_hash: str | None,
    session_id: str | None,
) -> Path:
    if not isinstance(path, str) or not path or "\x00" in path:
        raise AttachmentGateError(400, "Invalid attachment path")
    logical = PurePath(path)
    if logical.is_absolute() or path.startswith("~") or ".." in logical.parts:
        raise AttachmentGateError(
            400,
            "Attachment path must be a safe root-relative handle",
        )
    parts = tuple(part for part in logical.parts if part not in ("", "."))
    if not parts:
        raise AttachmentGateError(400, "Invalid attachment path")
    relative = Path(*parts)
    _validate_owned_upload_parts(
        relative,
        owner_key_hash=owner_key_hash,
        session_id=session_id,
    )
    return relative


def _validate_owned_upload_parts(
    relative: Path,
    *,
    owner_key_hash: str | None,
    session_id: str | None,
) -> None:
    parts = relative.parts
    if not parts or parts[0] != "uploads":
        raise AttachmentGateError(
            403,
            "plain workspace attachment access denied in Echo; use an owner/session upload",
        )
    if len(parts) < 2 or parts[1] != owner_slug(owner_key_hash):
        raise AttachmentGateError(403, "Upload access denied")
    if not (session_id or "").strip():
        raise AttachmentGateError(400, "session_id is required for attachments")
    if len(parts) < 3 or parts[2] != session_slug(session_id):
        raise AttachmentGateError(403, "Upload session access denied")
    if len(parts) != 4 or safe_upload_filename(parts[3]) != parts[3]:
        raise AttachmentGateError(400, "Invalid owned upload handle")


def _open_attachment_file(workspace: Path, relative: Path) -> int:
    required_dir_fd = (os.open,)
    if (
        not hasattr(os, "O_NOFOLLOW")
        or not hasattr(os, "O_DIRECTORY")
        or not hasattr(os, "O_CLOEXEC")
        or any(function not in os.supports_dir_fd for function in required_dir_fd)
    ):
        raise AttachmentGateError(503, "Secure attachment primitives are unavailable")

    directory_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        current_fd = os.open(workspace.resolve(strict=True), directory_flags)
    except OSError as exc:
        raise AttachmentGateError(400, "Attachment workspace is unavailable") from exc
    try:
        for component in relative.parts[:-1]:
            next_fd = os.open(component, directory_flags, dir_fd=current_fd)
            os.close(current_fd)
            current_fd = next_fd
        return os.open(
            relative.name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=current_fd,
        )
    except OSError as exc:
        raise AttachmentGateError(400, "Attachment is unavailable") from exc
    finally:
        os.close(current_fd)


def read_agent_attachment(
    *,
    workspace: Path,
    path: str,
    owner_key_hash: str | None,
    session_id: str | None,
    max_bytes: int = _MAX_ATTACHMENT_BYTES,
) -> AttachmentSnapshot:
    """Read exact authorized bytes without reopening an attacker-controlled path."""
    if max_bytes < 0:
        raise AttachmentGateError(413, "Attachments exceed 100 MiB")
    relative = _validated_attachment_relative_path(
        path,
        owner_key_hash=owner_key_hash,
        session_id=session_id,
    )
    file_fd = _open_attachment_file(workspace, relative)
    try:
        before = os.fstat(file_fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise AttachmentGateError(400, "Attachment is not a private regular file")
        if before.st_size > max_bytes:
            raise AttachmentGateError(413, "Attachments exceed 100 MiB")
        chunks: list[bytes] = []
        bytes_read = 0
        while True:
            chunk = os.read(file_fd, min(1024 * 1024, max_bytes + 1 - bytes_read))
            if not chunk:
                break
            chunks.append(chunk)
            bytes_read += len(chunk)
            if bytes_read > max_bytes:
                raise AttachmentGateError(413, "Attachments exceed 100 MiB")
        after = os.fstat(file_fd)
    finally:
        os.close(file_fd)

    fingerprint_before = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    fingerprint_after = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    if fingerprint_before != fingerprint_after or bytes_read != before.st_size:
        raise AttachmentGateError(409, "Attachment changed while being read")

    data = b"".join(chunks)
    media_type = mimetypes.guess_type(relative.name)[0] or "application/octet-stream"
    return AttachmentSnapshot(
        relative_path=relative.as_posix(),
        name=relative.name,
        suffix=relative.suffix.lower(),
        size=before.st_size,
        sha256="sha256:" + hashlib.sha256(data).hexdigest(),
        media_type=media_type,
        data=data,
    )


def validate_chat_attachments(
    *,
    workspace: Path,
    attachments: list[str],
    owner_key_hash: str | None,
    session_id: str | None,
) -> None:
    if not isinstance(attachments, list):
        raise AttachmentGateError(400, "attachments must be a list")
    if attachments and not (session_id or "").strip():
        raise AttachmentGateError(400, "session_id is required for attachments")

    for attachment in attachments:
        validate_agent_attachment_path(
            workspace=workspace,
            path=attachment,
            owner_key_hash=owner_key_hash,
            session_id=session_id,
        )


def build_attachment_manifest(
    *,
    workspace: Path,
    attachments: list[str],
    owner_key_hash: str | None,
    session_id: str | None,
) -> tuple[dict[str, Any], ...]:
    """Hash the exact owned attachment files for provider-bound authorization.

    The manifest contains no paths or file contents. Files are opened only after
    the owner/session gate succeeds, and metadata is checked again after hashing
    so a concurrent replacement fails closed.
    """
    if len(attachments) > _MAX_ATTACHMENT_COUNT:
        raise AttachmentGateError(400, "Too many attachments")
    manifest: list[dict[str, Any]] = []
    total_bytes = 0
    for attachment in attachments:
        snapshot = read_agent_attachment(
            workspace=workspace,
            path=attachment,
            owner_key_hash=owner_key_hash,
            session_id=session_id,
            max_bytes=_MAX_ATTACHMENT_BYTES - total_bytes,
        )
        total_bytes += snapshot.size
        manifest.append(
            {
                "name": snapshot.name,
                "size": snapshot.size,
                "sha256": snapshot.sha256,
                "media_type": snapshot.media_type,
            }
        )
    return tuple(manifest)


def list_owned_uploads(
    workspace: Path,
    owner_key_hash: str | None,
    session_id: str | None = None,
) -> list[Path]:
    return [
        workspace / entry.relative_path
        for entry in list_owned_upload_entries(workspace, owner_key_hash, session_id)
    ]


def list_owned_upload_entries(
    workspace: Path,
    owner_key_hash: str | None,
    session_id: str | None = None,
) -> list[OwnedUploadEntry]:
    if not (session_id or "").strip():
        raise AttachmentGateError(400, "session_id is required")
    directory_fd = _open_existing_upload_dir(workspace, owner_key_hash, session_id)
    if directory_fd is None:
        return []

    relative_root = Path("uploads") / owner_slug(owner_key_hash) / session_slug(session_id)
    candidates: list[tuple[int, str, OwnedUploadEntry]] = []
    try:
        with os.scandir(directory_fd) as entries:
            for index, entry in enumerate(entries):
                if index >= _MAX_UPLOAD_SCAN_ENTRIES:
                    break
                if entry.name.startswith(".upload-"):
                    continue
                try:
                    metadata = entry.stat(follow_symlinks=False)
                except OSError:
                    continue
                if not stat.S_ISREG(metadata.st_mode):
                    continue
                candidates.append(
                    (
                        metadata.st_mtime_ns,
                        entry.name,
                        OwnedUploadEntry(
                            relative_path=(relative_root / entry.name).as_posix(),
                            name=entry.name,
                            size=metadata.st_size,
                            modified=metadata.st_mtime,
                        ),
                    )
                )
    except OSError:
        return []
    finally:
        os.close(directory_fd)
    candidates.sort(key=lambda item: (item[0], item[1]), reverse=True)
    return [entry for _mtime, _name, entry in candidates[:_MAX_LISTED_UPLOADS]]


def find_owned_upload_by_name(
    workspace: Path,
    owner_key_hash: str | None,
    filename: str,
    session_id: str | None = None,
) -> Path | None:
    safe_name = safe_upload_filename(filename)
    for path in list_owned_uploads(workspace, owner_key_hash, session_id):
        if path.name == safe_name:
            return path
    return None


# Test-only one-shot fault injection for delete crash windows. Production: None.
_test_fault_after_delete_unlink: str | None = None


def delete_owned_upload_by_name(
    workspace: Path,
    owner_key_hash: str | None,
    filename: str,
    session_id: str | None = None,
) -> bool:
    """Delete one owned upload through its already-open session directory.

    Order: persist deleting intent → unlink+fsync → mark_deleted → finalize.
    """
    if not (session_id or "").strip():
        raise AttachmentGateError(400, "session_id is required")
    from js.echo.upload_quota import UploadQuotaLedger

    name = safe_upload_filename(filename)
    directory_fd = _open_existing_upload_dir(workspace, owner_key_hash, session_id)
    if directory_fd is None:
        # Session partition missing — still recover outstanding delete intents.
        UploadQuotaLedger(workspace, owner_key_hash).recover()
        return False

    try:
        try:
            metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            # File already gone — finish any deleting intents via recover.
            UploadQuotaLedger(workspace, owner_key_hash).recover()
            return False
        if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            return False
        size = int(metadata.st_size)

        ledger = UploadQuotaLedger(workspace, owner_key_hash)
        delete_id = secrets.token_hex(16)
        ledger.begin_delete(
            session_id=str(session_id),
            bytes_freed=size,
            delete_id=delete_id,
            filename=name,
        )
        try:
            os.unlink(name, dir_fd=directory_fd)
            os.fsync(directory_fd)
        except FileNotFoundError:
            # Already gone — still finish accounting from deleting intent.
            ledger.mark_deleted(delete_id=delete_id)
            ledger.finalize_delete(delete_id=delete_id)
            return True
        except OSError as exc:
            raise AttachmentGateError(409, "Could not delete upload safely") from exc
        fault = _test_fault_after_delete_unlink
        if fault == "os_exit":
            # Module-level clear is best-effort; child exits immediately.
            globals()["_test_fault_after_delete_unlink"] = None
            os._exit(91)
        if fault == "raise":
            globals()["_test_fault_after_delete_unlink"] = None
            raise OSError("simulated delete accounting failure")
        ledger.mark_deleted(delete_id=delete_id)
        ledger.finalize_delete(delete_id=delete_id)
        return True
    finally:
        os.close(directory_fd)


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True
