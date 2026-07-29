"""Crash-aware, no-clobber publication helpers for JS Agent Work artifacts.

Security model (P0-2 fix): staging creation, publishing, fsync and cleanup
are bound to ONE verified parent directory file descriptor.  After the
parent fd is opened (O_NOFOLLOW), no pathname re-resolution can redirect
the staging file or the published link:

- the staging file is created with ``os.open(..., dir_fd=parent_fd)``;
- publishing uses ``os.link(..., src_dir_fd=parent_fd, dst_dir_fd=parent_fd)``
  (atomic no-clobber) after verifying the staged inode identity both through
  the directory fd and through the pathname the caller wrote to;
- any parent swap / inode substitution makes the publish fail closed instead
  of silently escaping the authorized root;
- fsync happens on the opened descriptors, and a failed publish rolls back
  the just-created link.

Callers may write to the staged artifact through its pathname (third-party
libraries like openpyxl require a real path).  The publish step verifies the
pathname still resolves to the exact inode created through the directory fd,
so a redirected write is detected and rejected instead of published.

Recovery: staging names are hidden dotfiles; ``sweep_staging`` removes
orphaned staging files left behind by a SIGKILLed process.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import stat as _stat
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, BinaryIO, cast

_STAGING_NAME_RE = re.compile(r"^\.[^.]+\.[0-9a-f]{16}(?:\.[^.]+)?$")


def ensure_absent(path: Path, message: str) -> None:
    """Reject files, directories, symlinks, and dangling symlinks at a destination."""
    if os.path.lexists(path):
        raise ValueError(message)


def reject_symlink_components(workspace: Path, candidate: Path) -> None:
    """Reject paths containing symlink components within the workspace (fail-closed)."""
    try:
        relative = candidate.relative_to(workspace)
    except ValueError as exc:
        raise ValueError(f"Path escapes workspace: {candidate}") from exc
    current = workspace
    for component in relative.parts:
        current = current / component
        try:
            if os.path.lexists(current) and current.is_symlink():
                raise ValueError(f"Path contains a symlink: {candidate}")
        except OSError as exc:
            raise ValueError(f"Path component could not be inspected: {candidate}") from exc


class StagedArtifact(type(Path())):  # type: ignore[misc]
    """A staged file path bound to its verified parent directory fd."""

    _parent_fd: int
    _staged_name: str
    _identity: tuple[int, int]


def _fd_identity(fd: int) -> tuple[int, int]:
    stat_result = os.fstat(fd)
    return (stat_result.st_dev, stat_result.st_ino)


def _path_identity(path: Path) -> tuple[int, int]:
    stat_result = os.stat(path)
    return (stat_result.st_dev, stat_result.st_ino)


def _open_parent_no_follow(parent: Path) -> int:
    """Open the parent directory with O_NOFOLLOW so a symlink swap cannot redirect staging.

    Raises if the parent (or any component) is a symlink.  The returned
    descriptor anchors every subsequent staging/publish/fsync/cleanup
    operation to this exact directory (descriptor-relative), closing the
    TOCTOU window between pathname checks and use.
    """
    parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(parent, flags)
    parent_stat = os.fstat(descriptor)
    if not _stat.S_ISDIR(parent_stat.st_mode):
        os.close(descriptor)
        raise ValueError(f"staging parent is not a directory: {parent}")
    if hasattr(os, "O_NOFOLLOW") and parent_stat.st_nlink == 0:
        os.close(descriptor)
        raise ValueError(f"staging parent was deleted: {parent}")
    return descriptor


def _unlink_at(parent_fd: int, name: str) -> None:
    try:
        os.unlink(name, dir_fd=parent_fd)
    except FileNotFoundError:
        pass


def create_staged(
    target: Path,
    *,
    anchor: StagedArtifact | None = None,
) -> StagedArtifact:
    """Create a descriptor-relative staged artifact for manual management.

    Pair with :func:`discard_staged` (idempotent) in a ``finally`` block.
    Prefer :func:`staged_path` unless the caller needs manual control.
    """
    if anchor is None:
        parent_fd = _open_parent_no_follow(target.parent)
    else:
        if anchor._parent_fd < 0:
            raise RuntimeError("staging anchor is already closed")
        if Path(anchor).parent != target.parent:
            raise ValueError(f"staging anchor and target live in different directories: {target}")
        parent_fd = os.dup(anchor._parent_fd)
    try:
        name = f".{target.stem}.{secrets.token_hex(8)}{target.suffix}"
        descriptor = os.open(
            name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=parent_fd,
        )
        identity = _fd_identity(descriptor)
        os.close(descriptor)
    except Exception:
        os.close(parent_fd)
        raise
    staged = StagedArtifact(target.parent / name)
    staged._parent_fd = parent_fd
    staged._staged_name = name
    staged._identity = identity
    return staged


@contextmanager
def open_artifact(path: Path, mode: str = "rb") -> Iterator[BinaryIO]:
    """Open an artifact through its anchored parent fd, never its mutable pathname."""
    if mode not in {"rb", "w+b"}:
        raise ValueError(f"unsupported descriptor-bound artifact mode: {mode}")
    snapshot_fd = getattr(path, "_snapshot_fd", -1)
    if snapshot_fd >= 0:
        if mode != "rb":
            raise ValueError("Work input snapshots are read-only")
        descriptor = os.open(
            os.fspath(path),
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0),
        )
        opened = os.fstat(descriptor)
        expected = os.fstat(snapshot_fd)
        if opened.st_ino != expected.st_ino or opened.st_size != expected.st_size:
            os.close(descriptor)
            raise ValueError("Work input snapshot descriptor identity changed")
        snapshot_handle = os.fdopen(descriptor, "rb")
        try:
            snapshot_handle.seek(0)
            yield snapshot_handle
        finally:
            snapshot_handle.close()
        return
    owns_parent_fd = not isinstance(path, StagedArtifact)
    parent_fd = path._parent_fd if isinstance(path, StagedArtifact) else _open_parent_no_follow(path.parent)
    name = path._staged_name if isinstance(path, StagedArtifact) else path.name
    flags = os.O_RDONLY if mode == "rb" else os.O_RDWR | os.O_TRUNC
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(name, flags, dir_fd=parent_fd)
        identity = _fd_identity(descriptor)
        if isinstance(path, StagedArtifact):
            if identity != path._identity:
                os.close(descriptor)
                raise ValueError(f"staged artifact identity changed: {path}")
        else:
            try:
                pathname_identity = _path_identity(path)
            except OSError as exc:
                os.close(descriptor)
                raise ValueError(f"artifact pathname is unavailable: {path}") from exc
            if pathname_identity != identity:
                os.close(descriptor)
                raise ValueError(f"artifact pathname was redirected: {path}")
        artifact_handle = os.fdopen(descriptor, mode)
        try:
            yield cast("BinaryIO", artifact_handle)
            if mode != "rb":
                artifact_handle.flush()
                os.fsync(artifact_handle.fileno())
        finally:
            artifact_handle.close()
    finally:
        if owns_parent_fd:
            os.close(parent_fd)


@contextmanager
def rewrite_artifact(path: Path) -> Iterator[tuple[BinaryIO, BinaryIO]]:
    """Rewrite one file atomically through a single verified parent directory fd."""
    owns_parent_fd = not isinstance(path, StagedArtifact)
    parent_fd = path._parent_fd if isinstance(path, StagedArtifact) else _open_parent_no_follow(path.parent)
    name = path._staged_name if isinstance(path, StagedArtifact) else path.name
    temporary_name = f".{Path(name).stem}.{secrets.token_hex(8)}{Path(name).suffix}"
    source_fd = -1
    temporary_fd = -1
    replaced = False
    try:
        source_fd = os.open(
            name,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent_fd,
        )
        source_identity = _fd_identity(source_fd)
        if isinstance(path, StagedArtifact):
            if source_identity != path._identity:
                raise ValueError(f"staged artifact identity changed: {path}")
        elif _path_identity(path) != source_identity:
            raise ValueError(f"artifact pathname was redirected: {path}")
        temporary_fd = os.open(
            temporary_name,
            os.O_RDWR
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=parent_fd,
        )
        with os.fdopen(source_fd, "rb") as source, os.fdopen(temporary_fd, "w+b") as temporary:
            source_fd = -1
            temporary_fd = -1
            yield source, temporary
            temporary.flush()
            os.fsync(temporary.fileno())
        current_fd = os.open(
            name,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent_fd,
        )
        try:
            if _fd_identity(current_fd) != source_identity:
                raise ValueError(f"artifact was replaced concurrently: {path}")
        finally:
            os.close(current_fd)
        if not isinstance(path, StagedArtifact) and _path_identity(path) != source_identity:
            raise ValueError(f"artifact pathname was redirected: {path}")
        os.replace(
            temporary_name,
            name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
        )
        replaced = True
        replacement_fd = os.open(
            name,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent_fd,
        )
        try:
            replacement_identity = _fd_identity(replacement_fd)
            os.fsync(replacement_fd)
        finally:
            os.close(replacement_fd)
        os.fsync(parent_fd)
        if isinstance(path, StagedArtifact):
            path._identity = replacement_identity
    finally:
        if source_fd >= 0:
            os.close(source_fd)
        if temporary_fd >= 0:
            os.close(temporary_fd)
        if not replaced:
            _unlink_at(parent_fd, temporary_name)
        if owns_parent_fd:
            os.close(parent_fd)


def discard_staged(staged: Path) -> None:
    """Remove a staged artifact (through its verified fd) and close the fd."""
    if not isinstance(staged, StagedArtifact):
        Path(staged).unlink(missing_ok=True)
        return
    parent_fd = staged._parent_fd
    staged._parent_fd = -1
    try:
        _unlink_at(parent_fd, staged._staged_name)
    finally:
        os.close(parent_fd)


@contextmanager
def staged_path(
    target: Path,
    *,
    anchor: StagedArtifact | None = None,
) -> Iterator[StagedArtifact]:
    """Yield a descriptor-relative staged artifact and always clean it up.

    The staging file is created through the verified parent directory fd
    (``O_CREAT | O_EXCL``), so a parent swap after the fd was opened cannot
    redirect where the staging inode lives.  The staged name is always
    removed on exit (through the same fd).
    """
    staged = create_staged(target, anchor=anchor)
    try:
        yield staged
    finally:
        parent_fd = staged._parent_fd
        if parent_fd >= 0:
            staged._parent_fd = -1
            try:
                _unlink_at(parent_fd, staged._staged_name)
            finally:
                os.close(parent_fd)


def _verify_staged_identity(staged: StagedArtifact) -> tuple[int, int]:
    """Verify the staged file through BOTH the dir fd and the caller pathname.

    Legitimate writers (openpyxl, LibreOffice) may replace the staged inode
    in place via atomic rename *inside* the verified directory, so the inode
    may change between creation and publish.  What must hold at publish time
    is that the pathname view and the verified-directory-fd view name the
    same inode: a parent swap, symlink, or missing file fails closed.
    Returns the staged inode identity.
    """
    parent_fd = staged._parent_fd
    try:
        descriptor = os.open(
            staged._staged_name,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
            dir_fd=parent_fd,
        )
    except FileNotFoundError as exc:
        raise ValueError(
            f"staged file missing from verified directory: {staged._staged_name}"
        ) from exc
    except OSError as exc:
        raise ValueError(f"staged file is not a regular file: {staged}") from exc
    identity = _fd_identity(descriptor)
    os.close(descriptor)
    try:
        pathname_identity = _path_identity(Path(staged))
    except OSError as exc:
        raise ValueError(
            f"staged pathname no longer resolves inside the verified directory: {staged}"
        ) from exc
    if pathname_identity != identity:
        raise ValueError(
            f"staged pathname was redirected outside the verified directory: {staged}"
        )
    return identity


def publish_no_clobber(source: Path, target: Path, message: str) -> None:
    """Atomically publish a staged artifact without replacing any destination.

    The hard link is created descriptor-relative to the verified parent fd
    (atomic no-clobber), then fsynced; any fsync failure rolls the link back.
    """
    if isinstance(source, StagedArtifact):
        _publish_staged(source, target, message)
        return
    _publish_plain(source, target, message)


def _publish_staged(staged: StagedArtifact, target: Path, message: str) -> None:
    parent_fd = staged._parent_fd
    if Path(staged).parent != target.parent:
        raise ValueError(f"staged artifact and target live in different directories: {target}")
    identity = _verify_staged_identity(staged)
    staged._identity = identity
    _link_at(parent_fd, staged._staged_name, target.name, identity, message)


def _publish_plain(source: Path, target: Path, message: str) -> None:
    """Fallback for non-staged plain paths, still bound to a verified dir fd."""
    if source.parent != target.parent:
        raise ValueError(f"source and target live in different directories: {target}")
    parent_fd = _open_parent_no_follow(target.parent)
    try:
        try:
            descriptor = os.open(
                source.name,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
                dir_fd=parent_fd,
            )
        except FileNotFoundError as exc:
            raise ValueError(f"source missing from verified directory: {source}") from exc
        identity = _fd_identity(descriptor)
        os.close(descriptor)
        if _path_identity(source) != identity:
            raise ValueError(f"source pathname was redirected: {source}")
        _link_at(parent_fd, source.name, target.name, identity, message)
    finally:
        os.close(parent_fd)


def _link_at(
    parent_fd: int,
    source_name: str,
    target_name: str,
    source_identity: tuple[int, int],
    message: str,
) -> None:
    try:
        os.link(
            source_name,
            target_name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
            follow_symlinks=False,
        )
    except FileExistsError as exc:
        raise ValueError(message) from exc
    published = False
    try:
        descriptor = os.open(
            target_name,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0),
            dir_fd=parent_fd,
        )
        try:
            if _fd_identity(descriptor) != source_identity:
                raise ValueError(f"published link does not name the staged inode: {target_name}")
            os.fsync(descriptor)
            published = True
        finally:
            os.close(descriptor)
        os.fsync(parent_fd)
    except Exception:
        if not published:
            _unlink_at(parent_fd, target_name)
        else:
            # Parent-dir fsync failed after the file itself was synced; the
            # link is not durable, so roll it back as well.
            _unlink_at(parent_fd, target_name)
        raise


def write_json_no_clobber(
    path: Path,
    payload: dict[str, Any],
    message: str,
    *,
    anchor: StagedArtifact | None = None,
) -> None:
    """Durably publish JSON while preserving every pre-existing path."""
    ensure_absent(path, message)
    with staged_path(path, anchor=anchor) as temporary:
        rendered = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        with open_artifact(temporary, "w+b") as handle:
            handle.write(rendered.encode("utf-8"))
        publish_no_clobber(temporary, path, message)


def remove_published_link(source: Path, target: Path) -> None:
    """Roll back only a destination that still names the caller's staged inode."""
    parent_fd = (
        source._parent_fd
        if isinstance(source, StagedArtifact)
        else _open_parent_no_follow(target.parent)
    )
    owns_parent_fd = not isinstance(source, StagedArtifact)
    try:
        try:
            if isinstance(source, StagedArtifact):
                source_identity = source._identity
                target_metadata = os.stat(target.name, dir_fd=parent_fd, follow_symlinks=False)
                target_identity = (target_metadata.st_dev, target_metadata.st_ino)
            else:
                source_identity = _path_identity(source)
                target_identity = _path_identity(target)
        except FileNotFoundError:
            os.fsync(parent_fd)
            return
        except OSError as exc:
            raise RuntimeError("published artifact rollback could not be confirmed") from exc
        if source_identity != target_identity:
            raise RuntimeError("published artifact rollback could not be confirmed")
        try:
            os.unlink(target.name, dir_fd=parent_fd)
            os.fsync(parent_fd)
        except FileNotFoundError:
            os.fsync(parent_fd)
        except OSError as exc:
            raise RuntimeError("published artifact rollback could not be confirmed") from exc
    finally:
        if owns_parent_fd:
            os.close(parent_fd)


def sweep_staging(directory: Path, *, min_age_seconds: float = 3600.0) -> int:
    """Remove orphaned staging files left by a crashed process.

    Only names matching the staging pattern older than ``min_age_seconds``
    are removed, and only through a verified directory fd (a symlinked
    directory fails closed).  Returns the number of files removed.
    """
    if not directory.is_dir() or directory.is_symlink():
        return 0
    parent_fd = _open_parent_no_follow(directory)
    removed = 0
    try:
        now = time.time()
        for entry in directory.iterdir():
            if _STAGING_NAME_RE.fullmatch(entry.name) is None:
                continue
            try:
                stat_result = os.stat(entry.name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            if not _stat.S_ISREG(stat_result.st_mode):
                continue
            if now - stat_result.st_mtime < min_age_seconds:
                continue
            _unlink_at(parent_fd, entry.name)
            removed += 1
        if removed:
            os.fsync(parent_fd)
    finally:
        os.close(parent_fd)
    return removed


def fsync_file(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
