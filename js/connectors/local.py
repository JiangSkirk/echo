"""Local connector declarations for the sealed production composition.

R4-B implements descriptor-relative read import and atomic no-clobber
publish through the :class:`ConnectorArtifactStore`.  All file operations
use ``O_NOFOLLOW|O_CLOEXEC`` and ``dir_fd``-relative walks to prevent
symlink and TOCTOU attacks.
"""

from __future__ import annotations

import hashlib
import os
import stat
import unicodedata
from typing import Any

from js.connectors.base import ConnectorBase, ConnectorResult
from js.connectors.contracts import ConnectorEffect, DirectoryGrantV1
from js.echo.mode_contract import ArtifactRefV1, ConnectorManifestV1

_MAX_IMPORT_FILE_BYTES = 8 * 1024 * 1024
_MAX_PUBLISH_BYTES = 8 * 1024 * 1024
_CHUNK_BYTES = 64 * 1024


def _normalize_nfc(text: str) -> str:
    return unicodedata.normalize("NFC", text)


def _validate_basename(filename: str) -> str:
    """Validate and normalize a publish filename."""
    name = _normalize_nfc(filename)
    if not name or name in (".", ".."):
        raise ValueError("invalid filename")
    if "/" in name or "\\" in name or "\x00" in name:
        raise ValueError("filename contains path separator or NUL")
    if len(name.encode("utf-8")) > 255:
        raise ValueError("filename too long")
    for ch in name:
        if unicodedata.category(ch).startswith("C") and ch != "\t":
            raise ValueError("filename contains control character")
    return name


def _validate_relative_path(path: str) -> str:
    """Validate a relative import path (NFC, no separators in components)."""
    name = _normalize_nfc(path)
    if not name or name.startswith("/"):
        raise ValueError("path must be relative")
    if "\x00" in name:
        raise ValueError("path contains NUL")
    parts = name.split("/")
    for part in parts:
        if not part or part in (".", ".."):
            raise ValueError("path contains empty or traversal component")
        if len(part.encode("utf-8")) > 255:
            raise ValueError("path component too long")
    return name


class ReadOnlyImportConnector(ConnectorBase):
    def __init__(self, artifact_store: Any = None) -> None:
        super().__init__(
            ConnectorManifestV1(
                connector_type="local_import",
                capabilities=("read",),
                read_scopes=("files",),
                write_scopes=(),
                approval_policy="read_only",
            )
        )
        self._store = artifact_store

    async def _read_authorized(
        self,
        scope: str,
        *,
        params: dict[str, Any],
        directory_grant: DirectoryGrantV1 | None,
        context_binding: dict[str, Any] | None = None,
    ) -> ConnectorResult:
        if directory_grant is None:
            return ConnectorResult(
                connector_type=self.connector_type,
                success=False,
                error="connector_directory_grant_required",
            )
        if self._store is None:
            return ConnectorResult(
                connector_type=self.connector_type,
                success=False,
                error="connector_artifact_store_unavailable",
            )

        path_param = params.get("path", "")
        try:
            rel_path = _validate_relative_path(str(path_param))
        except ValueError as exc:
            return ConnectorResult(
                connector_type=self.connector_type,
                success=False,
                error="connector_invalid_path",
                data={"reason": str(exc)},
            )

        grant_root = directory_grant.root
        if grant_root == "/":
            return ConnectorResult(
                connector_type=self.connector_type,
                success=False,
                error="connector_grant_root_forbidden",
            )

        try:
            root_fd = _open_dir_no_follow(grant_root)
        except OSError as exc:
            return ConnectorResult(
                connector_type=self.connector_type,
                success=False,
                error="connector_grant_root_unavailable",
                data={"reason": str(exc)},
            )

        try:
            source_fd = _walk_open_file(root_fd, rel_path)
        except (OSError, ValueError) as exc:
            os.close(root_fd)
            return ConnectorResult(
                connector_type=self.connector_type,
                success=False,
                error="connector_source_unavailable",
                data={"reason": str(exc)},
            )

        binding = context_binding or {}
        try:
            owner = binding.get("owner", "unknown")
            mode = binding.get("mode", directory_grant.mode.value if hasattr(directory_grant.mode, "value") else str(directory_grant.mode))
            workspace = binding.get("workspace", directory_grant.workspace)
            session = binding.get("session", "unknown")
            run = binding.get("run", "unknown")
            digest, size, ref = self._store.stage_import(
                source_fd=source_fd,
                byte_limit=_MAX_IMPORT_FILE_BYTES,
                owner=owner,
                mode=mode,
                workspace=workspace,
                session=session,
                run=run,
            )
        except (ValueError, OSError, RuntimeError) as exc:
            return ConnectorResult(
                connector_type=self.connector_type,
                success=False,
                error="connector_import_failed",
                data={"reason": str(exc)},
            )
        finally:
            try:
                os.close(source_fd)
            except OSError:
                pass
            try:
                os.close(root_fd)
            except OSError:
                pass

        effect = ConnectorEffect(
            effect_type="read",
            target=rel_path,
            digest=digest,
            bytes_processed=size,
        )
        return ConnectorResult(
            connector_type=self.connector_type,
            success=True,
            effects=(effect,),
            artifact_refs=(ref,),
        )


class LimitedWritePublishConnector(ConnectorBase):
    def __init__(self, artifact_store: Any = None) -> None:
        super().__init__(
            ConnectorManifestV1(
                connector_type="local_publish",
                capabilities=("read", "write"),
                read_scopes=("artifacts",),
                write_scopes=("publish",),
                approval_policy="explicit",
            )
        )
        self._store = artifact_store

    async def _write_authorized(
        self,
        scope: str,
        *,
        params: dict[str, Any],
        directory_grant: DirectoryGrantV1 | None,
        context_binding: dict[str, Any] | None = None,
    ) -> ConnectorResult:
        if directory_grant is None:
            return ConnectorResult(
                connector_type=self.connector_type,
                success=False,
                error="connector_directory_grant_required",
            )
        if self._store is None:
            return ConnectorResult(
                connector_type=self.connector_type,
                success=False,
                error="connector_artifact_store_unavailable",
            )

        artifact_ref_dict = params.get("artifact_ref")
        filename_raw = params.get("filename", "")
        if not artifact_ref_dict or not filename_raw:
            return ConnectorResult(
                connector_type=self.connector_type,
                success=False,
                error="connector_invalid_publish_params",
            )

        try:
            filename = _validate_basename(str(filename_raw))
        except ValueError as exc:
            return ConnectorResult(
                connector_type=self.connector_type,
                success=False,
                error="connector_invalid_filename",
                data={"reason": str(exc)},
            )

        # Parse the artifact ref
        try:
            ref = ArtifactRefV1.from_dict(artifact_ref_dict)  # type: ignore[arg-type]
        except Exception as exc:
            return ConnectorResult(
                connector_type=self.connector_type,
                success=False,
                error="connector_invalid_artifact_ref",
                data={"reason": str(exc)},
            )

        binding = context_binding or {}
        # Open verified source from store
        try:
            source_fd = self._store.open_verified(
                ref=ref,
                owner=binding.get("owner", "unknown"),
                mode=binding.get("mode", directory_grant.mode.value if hasattr(directory_grant.mode, "value") else str(directory_grant.mode)),
                workspace=binding.get("workspace", directory_grant.workspace),
                session=binding.get("session", "unknown"),
                run=binding.get("run", "unknown"),
            )
        except PermissionError as exc:
            return ConnectorResult(
                connector_type=self.connector_type,
                success=False,
                error="connector_artifact_content_unavailable",
                data={"reason": str(exc)},
            )

        # Open target directory and publish with no-clobber link
        grant_root = directory_grant.root
        if grant_root == "/":
            os.close(source_fd)
            return ConnectorResult(
                connector_type=self.connector_type,
                success=False,
                error="connector_grant_root_forbidden",
            )

        try:
            target_dir_fd = _open_dir_no_follow(grant_root)
        except OSError as exc:
            os.close(source_fd)
            return ConnectorResult(
                connector_type=self.connector_type,
                success=False,
                error="connector_target_dir_unavailable",
                data={"reason": str(exc)},
            )

        try:
            # Check target doesn't exist
            try:
                os.stat(filename, dir_fd=target_dir_fd, follow_symlinks=False)
                return ConnectorResult(
                    connector_type=self.connector_type,
                    success=False,
                    error="connector_target_already_exists",
                )
            except FileNotFoundError:
                pass

            # Create temp file, copy, link
            temp_name = f".tmp-{os.getpid()}-{filename}"
            temp_fd = os.open(
                temp_name,
                os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
                dir_fd=target_dir_fd,
            )
            try:
                os.fchmod(temp_fd, 0o600)
                copied = 0
                hasher = hashlib.sha256()
                while True:
                    chunk = os.read(source_fd, _CHUNK_BYTES)
                    if not chunk:
                        break
                    copied += len(chunk)
                    if copied > _MAX_PUBLISH_BYTES:
                        raise ValueError("publish exceeds byte limit")
                    hasher.update(chunk)
                    written = 0
                    while written < len(chunk):
                        written += os.write(temp_fd, chunk[written:])
                os.fsync(temp_fd)
                # Atomic no-clobber link
                os.link(
                    temp_name,
                    filename,
                    src_dir_fd=target_dir_fd,
                    dst_dir_fd=target_dir_fd,
                    follow_symlinks=False,
                )
                # fsync target and directory
                os.fsync(target_dir_fd)
            finally:
                try:
                    os.unlink(temp_name, dir_fd=target_dir_fd)
                except FileNotFoundError:
                    pass
                os.close(temp_fd)

            # Verify published file
            verify_fd = os.open(
                filename,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=target_dir_fd,
            )
            try:
                st = os.fstat(verify_fd)
                if not stat.S_ISREG(st.st_mode):
                    raise RuntimeError("published file is not regular")
                verify_hasher = hashlib.sha256()
                while True:
                    chunk = os.read(verify_fd, _CHUNK_BYTES)
                    if not chunk:
                        break
                    verify_hasher.update(chunk)
                actual_digest = "sha256:" + verify_hasher.hexdigest()
                import hmac as _hmac

                if not _hmac.compare_digest(actual_digest, ref.digest):
                    raise RuntimeError("published file digest mismatch")
            finally:
                os.close(verify_fd)

        except (OSError, ValueError, RuntimeError) as exc:
            return ConnectorResult(
                connector_type=self.connector_type,
                success=False,
                error="connector_publish_failed",
                data={"reason": str(exc)},
            )
        finally:
            os.close(source_fd)
            os.close(target_dir_fd)

        effect = ConnectorEffect(
            effect_type="publish",
            target=filename,
            digest=ref.digest,
            bytes_processed=copied if "copied" in dir() else 0,
        )
        return ConnectorResult(
            connector_type=self.connector_type,
            success=True,
            effects=(effect,),
        )


def _open_dir_no_follow(path: str) -> int:
    """Open a directory with O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC."""
    return os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)


def _walk_open_file(root_fd: int, rel_path: str) -> int:
    """Walk from ``root_fd`` through relative path components to open a file.

    Each intermediate component is opened with ``O_DIRECTORY|O_NOFOLLOW``.
    The final component is opened with ``O_RDONLY|O_NOFOLLOW``.
    """
    parts = rel_path.split("/")
    current_fd = root_fd
    owned_fds: list[int] = []
    try:
        for i, part in enumerate(parts):
            is_last = i == len(parts) - 1
            if is_last:
                # Open the file
                fd = os.open(
                    part,
                    os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=current_fd,
                )
                st = os.fstat(fd)
                if not stat.S_ISREG(st.st_mode):
                    raise ValueError(f"source is not a regular file: {part}")
                if st.st_nlink != 1:
                    raise ValueError(f"source has multiple hard links: {part}")
                return fd
            else:
                # Open intermediate directory
                fd = os.open(
                    part,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=current_fd,
                )
                owned_fds.append(fd)
                current_fd = fd
        raise ValueError("empty path")
    except Exception:
        for fd in owned_fds:
            try:
                os.close(fd)
            except OSError:
                pass
        raise


__all__ = ["LimitedWritePublishConnector", "ReadOnlyImportConnector"]
