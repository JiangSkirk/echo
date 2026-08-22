"""Compute the source digest embedded in the native desktop executable."""

from __future__ import annotations

import os
import stat
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def desktop_source_digest(repo_root: Path = REPO_ROOT) -> str:
    from js.echo.ledger.release_gates import release_source_digest

    return release_source_digest(repo_root)


_EMBEDDED_DIGEST_FILE = Path(__file__).resolve().parent / ".embedded_source_digest"


class EmbeddedProvenanceError(ValueError):
    """The sidecar cannot prove a valid embedded release-source identity."""


def load_embedded_sidecar_digest() -> str:
    """Return the validated digest baked into the sidecar at build time.

    Missing, unreadable, non-ASCII, or malformed resources are provenance
    failures. Callers must not continue startup without this value.
    """
    parent_fd = -1
    file_fd = -1
    parent = _EMBEDDED_DIGEST_FILE.parent
    try:
        parent_flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        parent_fd = os.open(parent, parent_flags)
        parent_before = os.fstat(parent_fd)
        parent_path_before = os.stat(parent, follow_symlinks=False)
        if (
            not stat.S_ISDIR(parent_before.st_mode)
            or not stat.S_ISDIR(parent_path_before.st_mode)
            or (parent_before.st_dev, parent_before.st_ino)
            != (parent_path_before.st_dev, parent_path_before.st_ino)
        ):
            raise EmbeddedProvenanceError("embedded source parent is not stable")

        file_flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
        )
        file_fd = os.open(
            _EMBEDDED_DIGEST_FILE.name,
            file_flags,
            dir_fd=parent_fd,
        )
        file_before = os.fstat(file_fd)
        file_path_before = os.stat(
            _EMBEDDED_DIGEST_FILE.name,
            dir_fd=parent_fd,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(file_before.st_mode)
            or not stat.S_ISREG(file_path_before.st_mode)
            or file_before.st_size != 64
            or (file_before.st_dev, file_before.st_ino)
            != (file_path_before.st_dev, file_path_before.st_ino)
        ):
            raise EmbeddedProvenanceError("embedded source digest is not a regular file")

        chunks: list[bytes] = []
        remaining = 64
        while remaining:
            chunk = os.read(file_fd, remaining)
            if not chunk:
                raise EmbeddedProvenanceError("embedded source digest is truncated")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(file_fd, 1):
            raise EmbeddedProvenanceError("embedded source digest is oversized")
        payload = b"".join(chunks)

        file_after = os.fstat(file_fd)
        file_path_after = os.stat(
            _EMBEDDED_DIGEST_FILE.name,
            dir_fd=parent_fd,
            follow_symlinks=False,
        )
        parent_after = os.fstat(parent_fd)
        parent_path_after = os.stat(parent, follow_symlinks=False)
        if (
            (file_before.st_dev, file_before.st_ino, file_before.st_size)
            != (file_after.st_dev, file_after.st_ino, file_after.st_size)
            or (file_before.st_dev, file_before.st_ino)
            != (file_path_after.st_dev, file_path_after.st_ino)
            or (parent_before.st_dev, parent_before.st_ino)
            != (parent_after.st_dev, parent_after.st_ino)
            or (parent_before.st_dev, parent_before.st_ino)
            != (parent_path_after.st_dev, parent_path_after.st_ino)
        ):
            raise EmbeddedProvenanceError("embedded source digest identity changed")
    except OSError as exc:
        raise EmbeddedProvenanceError("embedded source digest is unavailable") from exc
    finally:
        if file_fd >= 0:
            os.close(file_fd)
        if parent_fd >= 0:
            os.close(parent_fd)

    try:
        value = payload.decode("ascii")
    except UnicodeDecodeError as exc:
        raise EmbeddedProvenanceError("embedded source digest is malformed") from exc
    if len(value) != 64 or any(byte not in "0123456789abcdef" for byte in value):
        raise EmbeddedProvenanceError("embedded source digest is malformed")
    return value


def main() -> int:
    print(desktop_source_digest())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
