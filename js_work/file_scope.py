"""Owner-aware file scope for JS Agent Work."""

from __future__ import annotations

import os
import secrets
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path

from js.echo.attachment_gate import owner_slug, session_slug
from js.echo.turn_context import current_runtime_context

LOCAL_WORK_OWNER = "js-work-local"
_WORKSPACE_ROOT_NAMES = {"local", "owners", "uploads"}
_MAX_WORK_INPUT_BYTES = 100 * 1024 * 1024


class WorkFileScopeError(PermissionError):
    """File-scope failure with an HTTP-compatible status and detail."""

    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


@dataclass(frozen=True)
class WorkFileSnapshot:
    """Authorized Work file bytes captured through a no-follow descriptor chain."""

    relative_path: str
    name: str
    suffix: str
    size: int
    sha256: str
    data: bytes = field(repr=False)

    def verified_data(self) -> bytes:
        """Return bytes only when immutable snapshot metadata still matches them."""
        relative = Path(self.relative_path)
        if (
            relative.is_absolute()
            or ".." in relative.parts
            or relative.name != self.name
            or relative.suffix.lower() != self.suffix
            or self.size != len(self.data)
            or self.sha256 != sha256(self.data).hexdigest()
        ):
            raise WorkFileScopeError(409, "Work file snapshot integrity conflict")
        return self.data


class MaterializedSnapshotPath(type(Path())):  # type: ignore[misc]
    """Visible snapshot name whose filesystem opens are bound to its read fd."""

    _snapshot_fd: int

    def __fspath__(self) -> str:
        if self._snapshot_fd < 0:
            raise OSError("Work file snapshot descriptor is closed")
        return f"/dev/fd/{self._snapshot_fd}"

    def read(self, size: int = -1) -> bytes:
        if self._snapshot_fd < 0:
            raise OSError("Work file snapshot descriptor is closed")
        if size < 0:
            current = os.lseek(self._snapshot_fd, 0, os.SEEK_CUR)
            size = max(0, os.fstat(self._snapshot_fd).st_size - current)
        return os.read(self._snapshot_fd, size)

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        if self._snapshot_fd < 0:
            raise OSError("Work file snapshot descriptor is closed")
        return os.lseek(self._snapshot_fd, offset, whence)

    def tell(self) -> int:
        return self.seek(0, os.SEEK_CUR)

    def fileno(self) -> int:
        if self._snapshot_fd < 0:
            raise OSError("Work file snapshot descriptor is closed")
        return self._snapshot_fd

    @staticmethod
    def seekable() -> bool:
        return True


class WorkOwnerFileScope:
    """Resolve Work paths within one owner's private and upload roots."""

    def __init__(
        self,
        workspace: Path,
        *,
        owner: str,
        session_id: str,
    ) -> None:
        if not isinstance(owner, str) or not owner:
            raise WorkFileScopeError(400, "Invalid work owner")
        if not isinstance(session_id, str) or not session_id:
            raise WorkFileScopeError(400, "Invalid work session")

        self.workspace = self._resolve_path(Path(workspace))
        self.owner = owner
        self.session_id = session_id
        self.uploads_root = self._resolve_root(self.workspace / "uploads", "uploads")
        if owner == LOCAL_WORK_OWNER:
            self.private_root = self._resolve_root(
                self.workspace / "local" / session_slug(session_id),
                "local private",
            )
        else:
            self.private_root = self._resolve_root(
                self.workspace
                / "owners"
                / owner_slug(owner)
                / session_slug(session_id),
                "owner private",
            )
        self.owned_upload_root = self._resolve_root(
            self.workspace
            / "uploads"
            / owner_slug(owner)
            / session_slug(session_id),
            "owned upload",
        )

    def resolve_private_read(self, path: str | Path) -> Path:
        """Resolve a read path that must remain in the owner's private root."""
        self._reject_logical_symlinks(path)
        resolved = self._resolve_logical(path)
        if self._is_relative_to(resolved, self.uploads_root):
            raise WorkFileScopeError(403, "Private reads cannot target uploads")
        if not self._is_relative_to(resolved, self.private_root):
            raise WorkFileScopeError(403, "Private file access denied")
        return resolved

    def resolve_routine_input(self, path: str | Path) -> Path:
        """Resolve routine input from the private root or the owner's uploads."""
        self._reject_logical_symlinks(path)
        resolved = self._resolve_logical(path)
        if self._is_relative_to(resolved, self.uploads_root):
            if self._is_relative_to(resolved, self.owned_upload_root):
                return resolved
            raise WorkFileScopeError(403, "Owned upload access denied")
        if self._is_relative_to(resolved, self.private_root):
            return resolved
        raise WorkFileScopeError(403, "Routine input access denied")

    def read_routine_input(
        self,
        path: str | Path,
        *,
        max_bytes: int = _MAX_WORK_INPUT_BYTES,
    ) -> WorkFileSnapshot:
        """Read authorized input bytes without reopening a validated pathname."""
        if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes < 0:
            raise WorkFileScopeError(500, "Invalid Work file size limit")
        relative = self._authorized_routine_relative(path)
        file_fd = self._open_routine_file(relative)
        try:
            before = os.fstat(file_fd)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise WorkFileScopeError(403, "Work input must be a private regular file")
            if before.st_size > max_bytes:
                raise WorkFileScopeError(413, "Work input exceeds the size limit")

            chunks: list[bytes] = []
            bytes_read = 0
            while True:
                chunk = os.read(
                    file_fd,
                    min(1024 * 1024, max_bytes + 1 - bytes_read),
                )
                if not chunk:
                    break
                chunks.append(chunk)
                bytes_read += len(chunk)
                if bytes_read > max_bytes:
                    raise WorkFileScopeError(413, "Work input exceeds the size limit")
            after = os.fstat(file_fd)
        except WorkFileScopeError:
            raise
        except OSError as exc:
            raise WorkFileScopeError(409, "Work input could not be read safely") from exc
        finally:
            os.close(file_fd)

        before_fingerprint = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        after_fingerprint = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if before_fingerprint != after_fingerprint or bytes_read != before.st_size:
            raise WorkFileScopeError(409, "Work input changed while being read")

        payload = b"".join(chunks)
        return WorkFileSnapshot(
            relative_path=relative.as_posix(),
            name=relative.name,
            suffix=relative.suffix.lower(),
            size=before.st_size,
            sha256=sha256(payload).hexdigest(),
            data=payload,
        )

    @contextmanager
    def materialize_snapshot(
        self,
        snapshot: WorkFileSnapshot,
    ) -> Iterator[MaterializedSnapshotPath]:
        """Expose snapshot bytes through a held fd while retaining its visible name."""
        if not isinstance(snapshot, WorkFileSnapshot):
            raise WorkFileScopeError(500, "Invalid Work file snapshot")
        relative = Path(snapshot.relative_path)
        authorized_roots = (
            self.private_root.relative_to(self.workspace),
            self.owned_upload_root.relative_to(self.workspace),
        )
        if (
            relative.is_absolute()
            or ".." in relative.parts
            or not any(
                self._is_relative_to(relative, root) and relative != root
                for root in authorized_roots
            )
        ):
            raise WorkFileScopeError(403, "Work file snapshot scope conflict")
        payload = snapshot.verified_data()
        if (
            relative.as_posix() != snapshot.relative_path
            or relative.name != snapshot.name
            or relative.suffix.lower() != snapshot.suffix
        ):
            raise WorkFileScopeError(409, "Work file snapshot integrity conflict")

        private_relative = self.private_root.relative_to(self.workspace)
        private_fd = self._open_directory(private_relative, label="Work private root")
        snapshot_dir_fd = -1
        snapshot_fd = -1
        snapshot_dir_name = f".work-input-snapshot-{secrets.token_hex(16)}"
        snapshot_dir_created = False
        staged = MaterializedSnapshotPath(
            self.private_root / snapshot_dir_name / snapshot.name
        )
        staged._snapshot_fd = -1
        body_failed = False
        conflict = False
        cleanup_failed = False
        try:
            try:
                os.mkdir(snapshot_dir_name, 0o700, dir_fd=private_fd)
                snapshot_dir_created = True
                snapshot_dir_fd = os.open(
                    snapshot_dir_name,
                    os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=private_fd,
                )
                descriptor = os.open(
                    snapshot.name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                    0o600,
                    dir_fd=snapshot_dir_fd,
                )
                try:
                    remaining = memoryview(payload)
                    while remaining:
                        written = os.write(descriptor, remaining)
                        if written <= 0:
                            raise OSError("short Work snapshot write")
                        remaining = remaining[written:]
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                snapshot_fd = os.open(
                    snapshot.name,
                    os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=snapshot_dir_fd,
                )
                staged._snapshot_fd = snapshot_fd
                expected = os.fstat(snapshot_fd)
                anchored = os.stat(
                    snapshot.name,
                    dir_fd=snapshot_dir_fd,
                    follow_symlinks=False,
                )
                pathname = os.lstat(str(staged))
                expected_fingerprint = self._snapshot_fingerprint(expected)
                if (
                    not stat.S_ISREG(expected.st_mode)
                    or expected.st_nlink != 1
                    or expected.st_size != snapshot.size
                    or self._snapshot_fingerprint(anchored) != expected_fingerprint
                    or self._snapshot_fingerprint(pathname) != expected_fingerprint
                ):
                    raise WorkFileScopeError(409, "Work file snapshot staging conflict")
            except WorkFileScopeError:
                raise
            except (OSError, ValueError) as exc:
                raise WorkFileScopeError(
                    409,
                    "Work file snapshot could not be staged safely",
                ) from exc

            try:
                yield staged
            except BaseException:
                body_failed = True
                raise
            finally:
                try:
                    current = os.fstat(snapshot_fd)
                    anchored = os.stat(
                        snapshot.name,
                        dir_fd=snapshot_dir_fd,
                        follow_symlinks=False,
                    )
                    pathname = os.lstat(str(staged))
                    conflict = any(
                        self._snapshot_fingerprint(item) != expected_fingerprint
                        for item in (current, anchored, pathname)
                    )
                except OSError:
                    conflict = True
        finally:
            if snapshot_fd >= 0:
                os.close(snapshot_fd)
                staged._snapshot_fd = -1
            if snapshot_dir_fd >= 0:
                try:
                    os.unlink(snapshot.name, dir_fd=snapshot_dir_fd)
                except FileNotFoundError:
                    conflict = True
                except OSError:
                    cleanup_failed = True
                os.close(snapshot_dir_fd)
            if snapshot_dir_created:
                try:
                    os.rmdir(snapshot_dir_name, dir_fd=private_fd)
                except FileNotFoundError:
                    conflict = True
                except OSError:
                    cleanup_failed = True
            os.close(private_fd)
            if not body_failed and (conflict or cleanup_failed):
                raise WorkFileScopeError(409, "Work file snapshot staging conflict")

    def resolve_output(self, path: str | Path) -> Path:
        """Resolve output in the private root while always rejecting uploads."""
        self._reject_logical_symlinks(path)
        resolved = self._resolve_logical(path)
        if self._is_relative_to(resolved, self.uploads_root):
            raise WorkFileScopeError(403, "Work outputs cannot target uploads")
        if not self._is_relative_to(resolved, self.private_root):
            raise WorkFileScopeError(403, "Output access denied")
        return resolved

    def to_registry_path(self, path: str | Path) -> str:
        """Return an allowed workspace-relative registry path."""
        if Path(path).is_absolute():
            resolved = self._resolve_path(Path(path))
            self._validate_routine_input(resolved)
        else:
            resolved = self.resolve_routine_input(path)
        return resolved.relative_to(self.workspace).as_posix()

    def to_public_handle(self, path: str | Path) -> str:
        """Convert an authorized path to a non-absolute handle safe for model output."""
        try:
            raw = Path(path)
        except (OSError, TypeError, ValueError) as exc:
            raise WorkFileScopeError(500, "Invalid Work result path") from exc
        if raw.is_absolute():
            resolved = self._resolve_path(raw)
        else:
            resolved = self._resolve_logical(raw)
        if self._is_relative_to(resolved, self.private_root):
            return resolved.relative_to(self.private_root).as_posix()
        if self._is_relative_to(resolved, self.owned_upload_root):
            return resolved.relative_to(self.workspace).as_posix()
        raise WorkFileScopeError(500, "Work result path is outside the active scope")

    def _resolve_logical(self, path: str | Path) -> Path:
        if not isinstance(path, str | Path):
            raise WorkFileScopeError(400, "Invalid work file path")
        logical = Path(path)
        if ".." in logical.parts:
            raise WorkFileScopeError(400, "Parent path segments are not allowed")
        if logical.is_absolute():
            raise WorkFileScopeError(400, "Absolute Work paths are not allowed")
        if (
            logical.parts
            and logical.parts[0] in _WORKSPACE_ROOT_NAMES
            and not (
                logical.parts[0] == "local"
                and self.owner == LOCAL_WORK_OWNER
            )
        ):
            candidate = self.workspace / logical
        else:
            candidate = self.private_root / logical
        resolved = self._resolve_path(candidate)
        if not self._is_relative_to(resolved, self.workspace):
            raise WorkFileScopeError(400, "Path escapes the workspace")
        return resolved

    def _reject_logical_symlinks(self, path: str | Path) -> None:
        if not isinstance(path, (str, Path)):
            raise WorkFileScopeError(400, "Invalid work file path")
        logical = Path(path)
        if logical.is_absolute() or ".." in logical.parts:
            return
        if logical.parts and logical.parts[0] in _WORKSPACE_ROOT_NAMES:
            candidate = self.workspace / logical
        else:
            candidate = self.private_root / logical
        self._reject_symlink_components(candidate, "Work path")

    def _authorized_routine_relative(self, path: str | Path) -> Path:
        if not isinstance(path, (str, Path)):
            raise WorkFileScopeError(400, "Invalid work file path")
        try:
            logical = Path(path)
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            raise WorkFileScopeError(400, "Invalid work file path") from exc
        if logical.is_absolute():
            raise WorkFileScopeError(400, "Absolute Work paths are not allowed")
        if ".." in logical.parts:
            raise WorkFileScopeError(400, "Parent path segments are not allowed")
        logical_parts = tuple(part for part in logical.parts if part not in ("", "."))
        if not logical_parts:
            raise WorkFileScopeError(400, "Invalid work file path")

        private_parts = (
            ("local", session_slug(self.session_id))
            if self.owner == LOCAL_WORK_OWNER
            else (
                "owners",
                owner_slug(self.owner),
                session_slug(self.session_id),
            )
        )
        upload_parts = (
            "uploads",
            owner_slug(self.owner),
            session_slug(self.session_id),
        )
        if logical_parts[0] in _WORKSPACE_ROOT_NAMES and not (
            logical_parts[0] == "local" and self.owner == LOCAL_WORK_OWNER
        ):
            relative_parts = logical_parts
        else:
            relative_parts = private_parts + logical_parts

        authorized_root: tuple[str, ...] | None = None
        for root_parts in (private_parts, upload_parts):
            if relative_parts[: len(root_parts)] == root_parts:
                authorized_root = root_parts
                break
        if authorized_root is None:
            raise WorkFileScopeError(403, "Routine input access denied")
        if len(relative_parts) <= len(authorized_root):
            raise WorkFileScopeError(400, "Work input must name a file")
        return Path(*relative_parts)

    def _open_routine_file(self, relative: Path) -> int:
        required_dir_fd = (os.open,)
        if (
            not hasattr(os, "O_NOFOLLOW")
            or not hasattr(os, "O_DIRECTORY")
            or not hasattr(os, "O_CLOEXEC")
            or any(function not in os.supports_dir_fd for function in required_dir_fd)
        ):
            raise WorkFileScopeError(503, "Secure Work file primitives are unavailable")

        directory_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
        try:
            current_fd = os.open(self.workspace.resolve(strict=True), directory_flags)
        except FileNotFoundError as exc:
            raise WorkFileScopeError(404, "Work file not found") from exc
        except (OSError, RuntimeError, ValueError) as exc:
            raise WorkFileScopeError(409, "Unsafe Work workspace") from exc

        try:
            for component in relative.parts[:-1]:
                next_fd = os.open(component, directory_flags, dir_fd=current_fd)
                metadata = os.fstat(next_fd)
                if not stat.S_ISDIR(metadata.st_mode):
                    os.close(next_fd)
                    raise WorkFileScopeError(403, "Unsafe Work input directory")
                os.close(current_fd)
                current_fd = next_fd
            return os.open(
                relative.name,
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=current_fd,
            )
        except FileNotFoundError as exc:
            raise WorkFileScopeError(404, "Work file not found") from exc
        except WorkFileScopeError:
            raise
        except (OSError, ValueError) as exc:
            raise WorkFileScopeError(403, "Work file is unavailable") from exc
        finally:
            os.close(current_fd)

    def _open_directory(self, relative: Path, *, label: str) -> int:
        required_dir_fd = (os.open, os.mkdir, os.rmdir, os.stat, os.unlink)
        if (
            not hasattr(os, "O_NOFOLLOW")
            or not hasattr(os, "O_DIRECTORY")
            or not hasattr(os, "O_CLOEXEC")
            or any(function not in os.supports_dir_fd for function in required_dir_fd)
        ):
            raise WorkFileScopeError(503, "Secure Work file primitives are unavailable")
        directory_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
        try:
            current_fd = os.open(self.workspace.resolve(strict=True), directory_flags)
        except (OSError, RuntimeError, ValueError) as exc:
            raise WorkFileScopeError(409, f"Unsafe {label}") from exc
        try:
            for component in relative.parts:
                next_fd = os.open(component, directory_flags, dir_fd=current_fd)
                metadata = os.fstat(next_fd)
                if not stat.S_ISDIR(metadata.st_mode):
                    os.close(next_fd)
                    raise WorkFileScopeError(403, f"Unsafe {label}")
                os.close(current_fd)
                current_fd = next_fd
            return current_fd
        except WorkFileScopeError:
            os.close(current_fd)
            raise
        except (OSError, ValueError) as exc:
            os.close(current_fd)
            raise WorkFileScopeError(409, f"Unsafe {label}") from exc

    @staticmethod
    def _snapshot_fingerprint(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
        return (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        )

    def _validate_routine_input(self, resolved: Path) -> None:
        if self._is_relative_to(resolved, self.uploads_root):
            if self._is_relative_to(resolved, self.owned_upload_root):
                return
            raise WorkFileScopeError(403, "Owned upload access denied")
        if self._is_relative_to(resolved, self.private_root):
            return
        raise WorkFileScopeError(403, "Routine input access denied")

    def _resolve_root(self, root: Path, label: str) -> Path:
        self._reject_symlink_components(root, f"{label.capitalize()} root")
        resolved = self._resolve_path(root)
        if not self._is_relative_to(resolved, self.workspace):
            raise WorkFileScopeError(400, f"{label.capitalize()} root escapes the workspace")
        return resolved

    def _reject_symlink_components(self, candidate: Path, label: str) -> None:
        try:
            relative = candidate.relative_to(self.workspace)
        except ValueError as exc:
            raise WorkFileScopeError(400, f"{label} escapes the workspace") from exc
        current = self.workspace
        for component in relative.parts:
            current = current / component
            try:
                if os.path.lexists(current) and current.is_symlink():
                    raise WorkFileScopeError(403, f"{label} contains a symlink")
            except WorkFileScopeError:
                raise
            except OSError as exc:
                raise WorkFileScopeError(409, f"{label} could not be inspected safely") from exc

    @staticmethod
    def _resolve_path(path: Path) -> Path:
        try:
            return path.expanduser().resolve()
        except (OSError, RuntimeError, ValueError) as exc:
            raise WorkFileScopeError(400, "Invalid work file path") from exc

    @staticmethod
    def _is_relative_to(path: Path, root: Path) -> bool:
        try:
            path.relative_to(root)
        except ValueError:
            return False
        return True


def current_work_owner() -> str:
    """Return the active Work owner or fail closed outside Echo's Work turn."""
    context = current_runtime_context()
    if (
        context is None
        or context.product_id != "js-work"
        or not isinstance(context.owner_key_hash, str)
        or not context.owner_key_hash
    ):
        raise WorkFileScopeError(403, "Work runtime context required")
    return context.owner_key_hash


def current_work_session_id() -> str:
    """Return the active Work session or fail closed outside a complete turn."""
    context = current_runtime_context()
    if (
        context is None
        or context.product_id != "js-work"
        or not isinstance(context.session_id, str)
        or not context.session_id
    ):
        raise WorkFileScopeError(403, "Work runtime session required")
    return context.session_id


def current_work_identity() -> tuple[str, str]:
    """Return the complete owner/session identity for the active Work turn."""
    return current_work_owner(), current_work_session_id()
