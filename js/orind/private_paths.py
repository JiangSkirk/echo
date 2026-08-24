"""Fail-closed private-path primitives for the Stage-C C1 test harness.

These helpers are deliberately opt-in.  Stage A/B callers retain their frozen
path behaviour unless their owner passes ``strict_paths=True``.  Strict mode
never repairs an existing object: a wrong owner, mode, type, link count, or
inode identity is an authority-boundary failure.
"""

from __future__ import annotations

import fcntl
import os
import secrets
import stat
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

_PRIVATE_DIR_MODE: Final = 0o700
_PRIVATE_FILE_MODE: Final = 0o600
_SQLITE_STABLE_SUFFIXES: Final = ("-wal", "-shm")
_MACOS_TRUSTED_PRIVATE_ALIASES: Final[dict[str, Path]] = {
    "tmp": Path("/private/tmp"),
    "var": Path("/private/var"),
}


class PrivatePathError(RuntimeError):
    """A private authority path violated its frozen filesystem contract."""


@dataclass(frozen=True, slots=True)
class PathIdentity:
    """Filesystem identity pinned after a strict open."""

    dev: int
    ino: int
    uid: int
    mode: int

    @classmethod
    def from_stat(cls, metadata: os.stat_result) -> PathIdentity:
        return cls(
            dev=int(metadata.st_dev),
            ino=int(metadata.st_ino),
            uid=int(metadata.st_uid),
            mode=stat.S_IMODE(metadata.st_mode),
        )


def _effective_uid() -> int:
    getuid = getattr(os, "geteuid", None)
    if getuid is None:
        raise PrivatePathError("strict private paths require a POSIX effective uid")
    return int(getuid())


def _absolute_without_resolving(path: Path) -> Path:
    """Lexically absolutize while permitting only verified macOS root aliases."""

    absolute = Path(os.path.abspath(os.fspath(Path(path).expanduser())))
    if sys.platform != "darwin" or len(absolute.parts) < 3:
        return absolute
    alias_name = absolute.parts[1]
    expected = _MACOS_TRUSTED_PRIVATE_ALIASES.get(alias_name)
    if expected is None:
        return absolute
    alias = Path(absolute.anchor) / alias_name
    try:
        metadata = alias.lstat()
        if (
            not alias.is_symlink()
            or metadata.st_uid != 0
            or Path(os.path.realpath(alias)) != expected
            or not expected.is_dir()
        ):
            return absolute
    except OSError:
        return absolute
    return expected.joinpath(*absolute.parts[2:])


def _open_parent(path: Path) -> tuple[int, str]:
    path = _absolute_without_resolving(Path(path))
    name = path.name
    if name in {"", ".", ".."}:
        raise PrivatePathError(f"invalid private path leaf: {path}")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    parent = path.parent
    components = parent.parts
    if parent.is_absolute():
        start = parent.anchor
        components = components[1:]
    else:
        start = "."
    try:
        fd = os.open(start, flags)
    except OSError as exc:
        raise PrivatePathError(f"private path anchor is unavailable: {start}") from exc
    try:
        for component in components:
            if component in {"", "."}:
                continue
            if component == "..":
                raise PrivatePathError(f"private path parent must not traverse '..': {parent}")
            next_fd = os.open(component, flags, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        metadata = os.fstat(fd)
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != _effective_uid():
            raise PrivatePathError(f"private path parent has the wrong type or owner: {parent}")
        return fd, name
    except OSError as exc:
        os.close(fd)
        raise PrivatePathError(
            f"private path parent contains an unavailable or symlink component: {parent}"
        ) from exc
    except BaseException:
        os.close(fd)
        raise


def ensure_private_dir(path: Path, *, mode: int = _PRIVATE_DIR_MODE) -> PathIdentity:
    """Create or verify an owner-only directory without following its leaf."""

    path = Path(path)
    parent_fd, name = _open_parent(path)
    try:
        try:
            metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            try:
                os.mkdir(name, mode, dir_fd=parent_fd)
            except FileExistsError:
                # A racing publisher must still pass the same checks below.
                pass
            metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            os.fsync(parent_fd)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != _effective_uid()
            or stat.S_IMODE(metadata.st_mode) != mode
        ):
            raise PrivatePathError(
                f"private directory must be owner-owned mode {mode:04o} without symlinks: {path}"
            )
        flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        opened_fd = os.open(name, flags, dir_fd=parent_fd)
        try:
            opened = os.fstat(opened_fd)
        finally:
            os.close(opened_fd)
        if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise PrivatePathError(f"private directory changed while opening: {path}")
        return PathIdentity.from_stat(opened)
    except OSError as exc:
        if isinstance(exc, PrivatePathError):
            raise
        raise PrivatePathError(f"private directory validation failed: {path}") from exc
    finally:
        os.close(parent_fd)


def _check_private_file_metadata(
    metadata: os.stat_result,
    path: Path,
    *,
    mode: int,
) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != _effective_uid()
        or stat.S_IMODE(metadata.st_mode) != mode
    ):
        raise PrivatePathError(
            f"private file must be owner-owned regular nlink=1 mode {mode:04o}: {path}"
        )


def open_private_file(
    path: Path,
    flags: int = os.O_RDONLY,
    *,
    mode: int = _PRIVATE_FILE_MODE,
    expected: PathIdentity | None = None,
) -> tuple[int, PathIdentity]:
    """Open and pin an existing private file; the caller owns the returned fd."""

    path = Path(path)
    parent_fd, name = _open_parent(path)
    try:
        metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        _check_private_file_metadata(metadata, path, mode=mode)
        identity = PathIdentity.from_stat(metadata)
        if expected is not None and identity != expected:
            raise PrivatePathError(f"private file identity changed: {path}")
        safe_flags = flags | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(name, safe_flags, dir_fd=parent_fd)
        try:
            opened = os.fstat(fd)
            _check_private_file_metadata(opened, path, mode=mode)
            opened_identity = PathIdentity.from_stat(opened)
            if opened_identity != identity:
                raise PrivatePathError(f"private file changed while opening: {path}")
        except BaseException:
            os.close(fd)
            raise
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        _check_private_file_metadata(current, path, mode=mode)
        if PathIdentity.from_stat(current) != opened_identity:
            os.close(fd)
            raise PrivatePathError(f"private file changed while opening: {path}")
        return fd, opened_identity
    except FileNotFoundError as exc:
        raise PrivatePathError(f"private file does not exist: {path}") from exc
    except OSError as exc:
        if isinstance(exc, PrivatePathError):
            raise
        raise PrivatePathError(f"private file validation failed: {path}") from exc
    finally:
        os.close(parent_fd)


def verify_private_file(
    path: Path,
    *,
    mode: int = _PRIVATE_FILE_MODE,
    expected: PathIdentity | None = None,
) -> PathIdentity:
    """Verify a private file and close the validation descriptor."""

    fd, identity = open_private_file(path, mode=mode, expected=expected)
    os.close(fd)
    return identity


def _check_private_socket_metadata(metadata: os.stat_result, path: Path) -> None:
    if (
        not stat.S_ISSOCK(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != _effective_uid()
        or stat.S_IMODE(metadata.st_mode) != _PRIVATE_FILE_MODE
    ):
        raise PrivatePathError(
            f"private socket must be owner-owned nlink=1 mode 0600: {path}"
        )


def verify_private_socket(
    path: Path,
    *,
    expected: PathIdentity | None = None,
) -> PathIdentity:
    """Verify a private socket through a no-symlink parent descriptor."""

    path = Path(path)
    parent_fd, name = _open_parent(path)
    try:
        metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        _check_private_socket_metadata(metadata, path)
        identity = PathIdentity.from_stat(metadata)
        if expected is not None and identity != expected:
            raise PrivatePathError(f"private socket identity changed: {path}")
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        _check_private_socket_metadata(current, path)
        if PathIdentity.from_stat(current) != identity:
            raise PrivatePathError(f"private socket changed while verifying: {path}")
        return identity
    except FileNotFoundError as exc:
        raise PrivatePathError(f"private socket does not exist: {path}") from exc
    except OSError as exc:
        if isinstance(exc, PrivatePathError):
            raise
        raise PrivatePathError(f"private socket validation failed: {path}") from exc
    finally:
        os.close(parent_fd)


def safe_unlink_socket_if_same(path: Path, expected: PathIdentity) -> None:
    """Unlink only a socket reached through its no-symlink parent chain."""

    path = Path(path)
    parent_fd, name = _open_parent(path)
    try:
        metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        _check_private_socket_metadata(metadata, path)
        if PathIdentity.from_stat(metadata) != expected:
            raise PrivatePathError(f"refusing to unlink replaced private socket: {path}")
        os.unlink(name, dir_fd=parent_fd)
        os.fsync(parent_fd)
    except FileNotFoundError as exc:
        raise PrivatePathError(f"private socket disappeared before unlink: {path}") from exc
    finally:
        os.close(parent_fd)


def write_private_file_exclusive(
    path: Path,
    data: bytes,
    *,
    mode: int = _PRIVATE_FILE_MODE,
) -> PathIdentity:
    """Atomically publish a new private file without replacing any leaf.

    A fully written and fsynced temporary inode is linked into the final name
    with no-overwrite semantics.  Removing the temporary name leaves the
    published file with the required single hardlink.
    """

    if not isinstance(data, bytes):
        raise TypeError("private file data must be bytes")
    path = Path(path)
    parent_fd, name = _open_parent(path)
    temp_name = f".{name}.{os.getpid()}.{secrets.token_hex(12)}.tmp"
    temp_identity: PathIdentity | None = None
    published = False
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(temp_name, flags, mode, dir_fd=parent_fd)
        try:
            opened = os.fstat(fd)
            _check_private_file_metadata(opened, path.with_name(temp_name), mode=mode)
            temp_identity = PathIdentity.from_stat(opened)
            view = memoryview(data)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise PrivatePathError(f"short write while publishing private file: {path}")
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
        os.link(
            temp_name,
            name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
            follow_symlinks=False,
        )
        published = True
        os.unlink(temp_name, dir_fd=parent_fd)
        temp_identity = None
        os.fsync(parent_fd)
    except FileExistsError as exc:
        raise PrivatePathError(f"private file already exists: {path}") from exc
    except OSError as exc:
        raise PrivatePathError(f"private file publication failed: {path}") from exc
    finally:
        if temp_identity is not None:
            try:
                current = os.stat(temp_name, dir_fd=parent_fd, follow_symlinks=False)
                if (current.st_dev, current.st_ino) == (temp_identity.dev, temp_identity.ino):
                    os.unlink(temp_name, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
        os.close(parent_fd)
    if not published:
        raise PrivatePathError(f"private file was not published: {path}")
    return verify_private_file(path, mode=mode)


def read_private_file(
    path: Path,
    *,
    expected: PathIdentity | None = None,
    max_bytes: int = 1024 * 1024,
) -> bytes:
    """Read a bounded private file while pinning its inode identity."""

    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 0:
        raise ValueError("max_bytes must be a non-negative integer")
    fd, identity = open_private_file(path, expected=expected)
    try:
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining:
            chunk = os.read(fd, min(remaining, 64 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > max_bytes:
            raise PrivatePathError(f"private file exceeds read limit: {path}")
        opened = os.fstat(fd)
        if PathIdentity.from_stat(opened) != identity:
            raise PrivatePathError(f"private file changed while reading: {path}")
    finally:
        os.close(fd)
    verify_private_file(path, expected=identity)
    return data


def safe_unlink_if_same(path: Path, expected: PathIdentity) -> None:
    """Unlink only the exact private inode previously pinned by the caller."""

    path = Path(path)
    parent_fd, name = _open_parent(path)
    try:
        metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        _check_private_file_metadata(metadata, path, mode=expected.mode)
        if PathIdentity.from_stat(metadata) != expected:
            raise PrivatePathError(f"refusing to unlink replaced private file: {path}")
        os.unlink(name, dir_fd=parent_fd)
        os.fsync(parent_fd)
    except FileNotFoundError as exc:
        raise PrivatePathError(f"private file disappeared before unlink: {path}") from exc
    finally:
        os.close(parent_fd)


def read_once_private_file(path: Path, *, max_bytes: int = 1024 * 1024) -> bytes:
    """Exclusively lock, read, and consume one private file by inode identity."""

    fd, identity = open_private_file(path)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        data = os.read(fd, max_bytes + 1)
        if len(data) > max_bytes:
            raise PrivatePathError(f"private file exceeds read limit: {path}")
        opened = os.fstat(fd)
        if PathIdentity.from_stat(opened) != identity:
            raise PrivatePathError(f"private file changed while consuming: {path}")
        safe_unlink_if_same(path, identity)
    finally:
        os.close(fd)
    return data


@dataclass(slots=True)
class PrivateSQLiteGuard:
    """Pins a SQLite database and its stable WAL sidecars in strict mode."""

    path: Path
    database: PathIdentity
    sidecars: dict[str, PathIdentity | None] = field(
        default_factory=lambda: dict.fromkeys(_SQLITE_STABLE_SUFFIXES)
    )
    violation: PrivatePathError | None = None

    def verify(self) -> None:
        verify_private_file(self.path, expected=self.database)
        for suffix in _SQLITE_STABLE_SUFFIXES:
            sidecar = Path(f"{self.path}{suffix}")
            previous = self.sidecars[suffix]
            try:
                current = verify_private_file(sidecar, expected=previous)
            except PrivatePathError as exc:
                try:
                    sidecar.lstat()
                except FileNotFoundError:
                    if previous is None:
                        continue
                raise exc
            if previous is None:
                self.sidecars[suffix] = current

    def progress(self) -> int:
        if self.violation is not None:
            return 1
        try:
            self.verify()
        except PrivatePathError as exc:
            self.violation = exc
            return 1
        return 0

    def raise_if_violated(self) -> None:
        if self.violation is not None:
            raise self.violation


def prepare_private_sqlite(path: Path) -> PrivateSQLiteGuard:
    """Create/verify a private SQLite authority database and pin its inode."""

    path = Path(path)
    ensure_private_dir(path.parent)
    try:
        identity = verify_private_file(path)
    except PrivatePathError:
        try:
            path.lstat()
        except FileNotFoundError:
            identity = write_private_file_exclusive(path, b"")
        else:
            raise
    guard = PrivateSQLiteGuard(path=path, database=identity)
    guard.verify()
    return guard


def install_sqlite_guard(connection: object, guard: PrivateSQLiteGuard) -> None:
    """Install a per-statement path check on a ``sqlite3.Connection``."""

    setter = getattr(connection, "set_progress_handler", None)
    if setter is None:
        raise TypeError("connection does not support SQLite progress handlers")
    setter(guard.progress, 1)


__all__ = [
    "PathIdentity",
    "PrivatePathError",
    "PrivateSQLiteGuard",
    "ensure_private_dir",
    "install_sqlite_guard",
    "open_private_file",
    "prepare_private_sqlite",
    "read_once_private_file",
    "read_private_file",
    "safe_unlink_if_same",
    "safe_unlink_socket_if_same",
    "verify_private_file",
    "verify_private_socket",
    "write_private_file_exclusive",
]
