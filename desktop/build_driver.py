"""Closed, offline build driver for the unsigned JS Agent desktop bundle.

Every build runs in a newly-created external directory owned by this process.
Generated inputs never touch the repository and ambient build configuration is
not inherited. Failed non-pristine runs are retained intact and marked for
manual cleanup instead of being recursively deleted.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import importlib.metadata
import io
import json
import os
import plistlib
import re
import secrets
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import unicodedata
import zipfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path, PurePosixPath

REPO_ROOT = Path(__file__).resolve().parent.parent
TARGET_TRIPLE = "aarch64-apple-darwin"
SIDECAR_NAME = f"js-agent-host-{TARGET_TRIPLE}"
PRODUCT_VERSION = "0.1.0"
MANIFEST_SCHEMA = "JSAgentDesktopProvenanceV4"
BUILD_ENVIRONMENT_SCHEMA = "JSAgentDesktopBuildEnvironmentV1"
OWNER_MARKER_NAME = ".js-agent-build-owner"
INVALID_RUN_MARKER_NAME = ".js-agent-build-invalid-manual-cleanup"
_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_BUILD_NUMBER = re.compile(r"(?P<day>[0-9]{8})(?P<sequence>[0-9]{2})\Z")
_PIN = re.compile(r"([A-Za-z0-9_.-]+)==([^\s=]+)\Z")
TREE_DIGEST_SCHEMA = "JSAgentTreeDigestV2"
_TREE_DIGEST_DOMAIN = (TREE_DIGEST_SCHEMA + "\0").encode("ascii")
_THIN_MACH_O_MAGICS = {
    bytes.fromhex("feedface"): (">", 28),
    bytes.fromhex("feedfacf"): (">", 32),
    bytes.fromhex("cefaedfe"): ("<", 28),
    bytes.fromhex("cffaedfe"): ("<", 32),
}
_FAT_MACH_O_MAGICS = {
    bytes.fromhex("cafebabe"): (">", 20, False),
    bytes.fromhex("bebafeca"): ("<", 20, False),
    bytes.fromhex("cafebabf"): (">", 32, True),
    bytes.fromhex("bfbafeca"): ("<", 32, True),
}
_NON_EXECUTABLE_RESOURCE_SUFFIXES = frozenset({".class", ".jar", ".zip"})
_PYTHON_BUILD_REQUIREMENTS = frozenset({"pyinstaller", "pyinstaller-hooks-contrib"})
_ARTIFACT_KEYS = frozenset(
    {"rust_main", "sidecar", "sidecar_standalone", "app_tree", "zip"}
)
_BUILD_INPUT_PATHS = {
    "cargo_lock": "desktop/src-tauri/Cargo.lock",
    "pnpm_lock": "desktop/pnpm-lock.yaml",
    "python_build_reqs": "desktop/requirements-build.txt",
    "build_driver": "desktop/build_driver.py",
}
_ENVIRONMENT_FILE_KEYS = ("python", "pnpm", "cargo", "node", "ditto")
_ENVIRONMENT_TREE_KEYS = ("cargo_home", "pnpm_store")
_CARGO_MUTABLE_CACHE_NAMES = (
    ".global-cache",
    ".package-cache",
    ".package-cache-mutate",
)

Runner = Callable[..., tuple[int, str, str]]


@dataclass(frozen=True)
class BuildRun:
    root: Path
    _owner_secret: bytes = field(repr=False)
    _root_device: int = field(repr=False)
    _root_inode: int = field(repr=False)
    _marker_device: int = field(repr=False)
    _marker_inode: int = field(repr=False)
    _root_ctime_ns: int = field(repr=False)
    _root_mtime_ns: int = field(repr=False)
    _marker_ctime_ns: int = field(repr=False)
    _marker_mtime_ns: int = field(repr=False)


@dataclass(frozen=True)
class OfflineBuildInputs:
    pnpm_executable: Path
    cargo_executable: Path
    node_executable: Path
    ditto_executable: Path
    cargo_home: Path
    pnpm_store: Path


@dataclass(frozen=True)
class TreeEntry:
    entry_type: str
    mode: int
    content: bytes = b""


def _run(
    cmd: list[str],
    *,
    cwd: Path,
    env: dict[str, str] | None = None,
    timeout: int = 600,
) -> tuple[int, str, str]:
    result = subprocess.run(
        cmd,
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return result.returncode, result.stdout, result.stderr


def _absolute_lexical(path: Path) -> Path:
    expanded = path.expanduser()
    if not expanded.is_absolute():
        expanded = Path.cwd() / expanded
    return expanded


def _has_symlink_component(path: Path) -> bool:
    absolute = _absolute_lexical(path)
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        try:
            mode = current.lstat().st_mode
        except FileNotFoundError:
            return False
        except OSError as exc:
            raise RuntimeError(f"path component is unreadable: {current}") from exc
        if stat.S_ISLNK(mode):
            return True
    return False


def _single_link_file_stat(path: Path, label: str) -> os.stat_result:
    if _has_symlink_component(path):
        raise RuntimeError(f"{label} contains a symlink component")
    try:
        info = path.lstat()
    except OSError as exc:
        raise RuntimeError(f"{label} is unavailable") from exc
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise RuntimeError(f"{label} must be a single-link regular file")
    return info


def _read_single_link_file(path: Path, label: str) -> bytes:
    before = _single_link_file_stat(path, label)
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino, opened.st_size)
            != (before.st_dev, before.st_ino, before.st_size)
        ):
            raise RuntimeError(f"{label} identity changed before read")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(descriptor)
        path_after = _single_link_file_stat(path, label)
        expected = (before.st_dev, before.st_ino, before.st_size)
        if (
            (after.st_dev, after.st_ino, after.st_size) != expected
            or (path_after.st_dev, path_after.st_ino, path_after.st_size) != expected
        ):
            raise RuntimeError(f"{label} identity changed during read")
        return b"".join(chunks)
    except OSError as exc:
        raise RuntimeError(f"{label} is unreadable") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _replace_single_link_file(path: Path, payload: bytes, label: str) -> None:
    """Replace a build-owned file without following a swapped path."""
    before = _single_link_file_stat(path, label)
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
        ):
            raise RuntimeError(f"{label} identity changed before write")
        os.ftruncate(descriptor, 0)
        view = memoryview(payload)
        written = 0
        while written < len(view):
            written += os.write(descriptor, view[written:])
        os.fsync(descriptor)
        after = os.fstat(descriptor)
        path_after = _single_link_file_stat(path, label)
        if (
            (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino)
            or (path_after.st_dev, path_after.st_ino)
            != (before.st_dev, before.st_ino)
            or after.st_size != len(payload)
            or path_after.st_size != len(payload)
        ):
            raise RuntimeError(f"{label} identity changed during write")
    except OSError as exc:
        raise RuntimeError(f"{label} is not writable") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _sha256_file(path: Path, label: str | None = None) -> str:
    return hashlib.sha256(_read_single_link_file(path, label or path.name)).hexdigest()


def _safe_directory(path: Path, label: str) -> Path:
    if _has_symlink_component(path):
        raise RuntimeError(f"{label} contains a symlink component")
    try:
        info = path.lstat()
    except OSError as exc:
        raise RuntimeError(f"{label} is unavailable") from exc
    if not stat.S_ISDIR(info.st_mode):
        raise RuntimeError(f"{label} must be a directory")
    return path.resolve(strict=True)


def _resolved_executable(path: Path, label: str) -> Path:
    _single_link_file_stat(path, f"{label} executable")
    resolved = path.resolve(strict=True)
    if not os.access(resolved, os.X_OK):
        raise RuntimeError(f"{label} executable is not executable")
    return resolved


def _owner_marker_digest(secret: bytes) -> bytes:
    return hashlib.sha256(secret).hexdigest().encode("ascii")


def _run_is_owned(run: BuildRun) -> bool:
    try:
        root = _safe_directory(run.root, "build run")
        root_info = root.stat()
        if (
            root != run.root
            or root_info.st_uid != os.getuid()
            or (root_info.st_dev, root_info.st_ino)
            != (run._root_device, run._root_inode)
        ):
            return False
        marker_path = root / OWNER_MARKER_NAME
        marker_info = _single_link_file_stat(marker_path, "build owner marker")
        if (marker_info.st_dev, marker_info.st_ino) != (
            run._marker_device,
            run._marker_inode,
        ) or (marker_info.st_ctime_ns, marker_info.st_mtime_ns) != (
            run._marker_ctime_ns,
            run._marker_mtime_ns,
        ):
            return False
        marker = _read_single_link_file(marker_path, "build owner marker")
    except RuntimeError:
        return False
    return hmac.compare_digest(marker, _owner_marker_digest(run._owner_secret))


def _canonical_parent_snapshot(
    parent: Path,
    label: str,
) -> tuple[Path, Path, os.stat_result]:
    lexical = _absolute_lexical(parent)
    try:
        canonical = lexical.resolve(strict=True)
        info = canonical.lstat()
    except (OSError, RuntimeError) as exc:
        raise RuntimeError(f"{label} is unavailable") from exc
    if not stat.S_ISDIR(info.st_mode):
        raise RuntimeError(f"{label} must be a directory")
    return lexical, canonical, info


def _parent_matches_snapshot(
    lexical: Path,
    canonical: Path,
    expected: os.stat_result,
) -> bool:
    try:
        current = lexical.resolve(strict=True)
        info = current.lstat()
    except (OSError, RuntimeError):
        return False
    return (
        current == canonical
        and stat.S_ISDIR(info.st_mode)
        and (info.st_dev, info.st_ino) == (expected.st_dev, expected.st_ino)
    )


def _directory_open_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )


def _write_invalid_marker_fd(root_descriptor: int) -> None:
    descriptor = -1
    try:
        descriptor = os.open(
            INVALID_RUN_MARKER_NAME,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=root_descriptor,
        )
        payload = b"invalid=true\nmanual_cleanup=true\n"
        if os.write(descriptor, payload) == len(payload):
            os.fsync(descriptor)
    except OSError:
        return
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def prepare_build_run(
    *,
    output_dir: Path | None,
    repo_root: Path = REPO_ROOT,
    temporary_parent: Path | None = None,
) -> BuildRun:
    """Create one external run through a canonical parent directory descriptor."""
    resolved_repo = repo_root.resolve(strict=False)
    if output_dir is None:
        requested_parent = (
            temporary_parent
            if temporary_parent is not None
            else Path(tempfile.gettempdir())
        )
        lexical_parent, resolved_parent, parent_info = _canonical_parent_snapshot(
            requested_parent,
            "temporary build parent",
        )
        output_name = f"js-agent-desktop-{secrets.token_hex(16)}"
    else:
        lexical = _absolute_lexical(output_dir)
        normalized_lexical = Path(os.path.abspath(lexical))
        if normalized_lexical.is_relative_to(resolved_repo):
            raise RuntimeError("build output must be outside the repository")
        lexical_parent, resolved_parent, parent_info = _canonical_parent_snapshot(
            lexical.parent,
            "build output parent",
        )
        output_name = lexical.name

    if output_name in {"", ".", ".."}:
        raise RuntimeError("build output basename is invalid")
    root = resolved_parent / output_name
    if root.resolve(strict=False).is_relative_to(resolved_repo):
        raise RuntimeError("build output must be outside the repository")

    secret = secrets.token_bytes(32)
    parent_descriptor = -1
    root_descriptor = -1
    created = False
    descriptor = -1
    try:
        parent_descriptor = os.open(resolved_parent, _directory_open_flags())
        opened_parent = os.fstat(parent_descriptor)
        if (
            (opened_parent.st_dev, opened_parent.st_ino)
            != (parent_info.st_dev, parent_info.st_ino)
            or not _parent_matches_snapshot(
                lexical_parent,
                resolved_parent,
                parent_info,
            )
        ):
            raise RuntimeError("build output parent identity changed before creation")
        try:
            os.stat(output_name, dir_fd=parent_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise RuntimeError(
                "explicit build output already exists and is not owned by this run"
            )
        os.mkdir(output_name, mode=0o700, dir_fd=parent_descriptor)
        created = True
        root_descriptor = os.open(
            output_name,
            _directory_open_flags(),
            dir_fd=parent_descriptor,
        )
        created_root_info = os.fstat(root_descriptor)
        parent_entry = os.stat(
            output_name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISDIR(parent_entry.st_mode)
            or (parent_entry.st_dev, parent_entry.st_ino)
            != (created_root_info.st_dev, created_root_info.st_ino)
            or not _parent_matches_snapshot(
                lexical_parent,
                resolved_parent,
                parent_info,
            )
        ):
            raise RuntimeError("build output parent identity changed during creation")
        descriptor = os.open(
            OWNER_MARKER_NAME,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=root_descriptor,
        )
        payload = _owner_marker_digest(secret)
        if os.write(descriptor, payload) != len(payload):
            raise RuntimeError("build owner marker write was incomplete")
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        if not _parent_matches_snapshot(
            lexical_parent,
            resolved_parent,
            parent_info,
        ):
            raise RuntimeError("build output parent identity changed after creation")
        final_entry = os.stat(
            output_name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        root_info = os.fstat(root_descriptor)
        marker_info = os.stat(
            OWNER_MARKER_NAME,
            dir_fd=root_descriptor,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISDIR(final_entry.st_mode)
            or (final_entry.st_dev, final_entry.st_ino)
            != (root_info.st_dev, root_info.st_ino)
            or not stat.S_ISREG(marker_info.st_mode)
            or marker_info.st_nlink != 1
        ):
            raise RuntimeError("new build run identity is invalid")
    except Exception:
        if descriptor >= 0:
            os.close(descriptor)
            descriptor = -1
        if created and root_descriptor >= 0:
            _write_invalid_marker_fd(root_descriptor)
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if root_descriptor >= 0:
            os.close(root_descriptor)
        if parent_descriptor >= 0:
            os.close(parent_descriptor)

    owned_root = root
    run = BuildRun(
        root=owned_root,
        _owner_secret=secret,
        _root_device=root_info.st_dev,
        _root_inode=root_info.st_ino,
        _marker_device=marker_info.st_dev,
        _marker_inode=marker_info.st_ino,
        _root_ctime_ns=root_info.st_ctime_ns,
        _root_mtime_ns=root_info.st_mtime_ns,
        _marker_ctime_ns=marker_info.st_ctime_ns,
        _marker_mtime_ns=marker_info.st_mtime_ns,
    )
    if not _run_is_owned(run):
        raise RuntimeError("new build run owner marker could not be verified")
    return run


def _mark_run_invalid(run: BuildRun) -> None:
    descriptor = -1
    try:
        descriptor = os.open(run.root, _directory_open_flags())
        info = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(info.st_mode)
            or (info.st_dev, info.st_ino) != (run._root_device, run._root_inode)
        ):
            return
        _write_invalid_marker_fd(descriptor)
    except OSError:
        return
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _run_is_marked_invalid(root: Path) -> bool:
    try:
        (root / INVALID_RUN_MARKER_NAME).lstat()
    except FileNotFoundError:
        return False
    except OSError:
        return True
    return True


def _pristine_run_can_be_removed(run: BuildRun) -> bool:
    if not _run_is_owned(run):
        return False
    parent_descriptor = -1
    root_descriptor = -1
    marker_descriptor = -1
    try:
        parent_descriptor = os.open(run.root.parent, _directory_open_flags())
        parent_entry = os.stat(
            run.root.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISDIR(parent_entry.st_mode)
            or (parent_entry.st_dev, parent_entry.st_ino)
            != (run._root_device, run._root_inode)
            or (parent_entry.st_ctime_ns, parent_entry.st_mtime_ns)
            != (run._root_ctime_ns, run._root_mtime_ns)
        ):
            return False
        root_descriptor = os.open(
            run.root.name,
            _directory_open_flags(),
            dir_fd=parent_descriptor,
        )
        root_info = os.fstat(root_descriptor)
        if (
            (root_info.st_dev, root_info.st_ino)
            != (run._root_device, run._root_inode)
            or (root_info.st_ctime_ns, root_info.st_mtime_ns)
            != (run._root_ctime_ns, run._root_mtime_ns)
            or os.listdir(root_descriptor) != [OWNER_MARKER_NAME]
        ):
            return False
        marker_info = os.stat(
            OWNER_MARKER_NAME,
            dir_fd=root_descriptor,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(marker_info.st_mode)
            or marker_info.st_nlink != 1
            or (marker_info.st_dev, marker_info.st_ino)
            != (run._marker_device, run._marker_inode)
            or (marker_info.st_ctime_ns, marker_info.st_mtime_ns)
            != (run._marker_ctime_ns, run._marker_mtime_ns)
        ):
            return False
        marker_descriptor = os.open(
            OWNER_MARKER_NAME,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=root_descriptor,
        )
        marker_payload = os.read(marker_descriptor, 65)
        if not hmac.compare_digest(
            marker_payload,
            _owner_marker_digest(run._owner_secret),
        ):
            return False
        marker_after = os.fstat(marker_descriptor)
        root_after = os.fstat(root_descriptor)
        if (
            (marker_after.st_dev, marker_after.st_ino)
            != (run._marker_device, run._marker_inode)
            or (marker_after.st_ctime_ns, marker_after.st_mtime_ns)
            != (run._marker_ctime_ns, run._marker_mtime_ns)
            or (root_after.st_dev, root_after.st_ino)
            != (run._root_device, run._root_inode)
            or (root_after.st_ctime_ns, root_after.st_mtime_ns)
            != (run._root_ctime_ns, run._root_mtime_ns)
            or os.listdir(root_descriptor) != [OWNER_MARKER_NAME]
        ):
            return False
        os.unlink(OWNER_MARKER_NAME, dir_fd=root_descriptor)
        if os.listdir(root_descriptor):
            return False
        final_entry = os.stat(
            run.root.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (final_entry.st_dev, final_entry.st_ino) != (
            run._root_device,
            run._root_inode,
        ):
            return False
        os.rmdir(run.root.name, dir_fd=parent_descriptor)
        return True
    except OSError:
        return False
    finally:
        if marker_descriptor >= 0:
            os.close(marker_descriptor)
        if root_descriptor >= 0:
            os.close(root_descriptor)
        if parent_descriptor >= 0:
            os.close(parent_descriptor)


def cleanup_build_run(run: BuildRun) -> bool:
    """Remove only an untouched marker-only run; retain every other run intact."""
    if _pristine_run_can_be_removed(run):
        return True
    _mark_run_invalid(run)
    return False


def _validated_offline_inputs(inputs: OfflineBuildInputs) -> OfflineBuildInputs:
    return OfflineBuildInputs(
        pnpm_executable=_resolved_executable(inputs.pnpm_executable, "pnpm"),
        cargo_executable=_resolved_executable(inputs.cargo_executable, "Cargo"),
        node_executable=_resolved_executable(inputs.node_executable, "Node"),
        ditto_executable=_resolved_executable(inputs.ditto_executable, "ditto"),
        cargo_home=_safe_directory(inputs.cargo_home, "Cargo home"),
        pnpm_store=_safe_directory(inputs.pnpm_store, "pnpm store"),
    )


def controlled_build_environment(
    run: BuildRun,
    offline_inputs: OfflineBuildInputs,
) -> dict[str, str]:
    """Construct a strict allowlist; never copy the ambient process environment."""
    if not _run_is_owned(run):
        raise RuntimeError("build run owner marker is invalid")
    inputs = _validated_offline_inputs(offline_inputs)
    home = run.root / "home"
    temporary = run.root / "tmp"
    cache = run.root / "cache"
    pyinstaller_cache = cache / "pyinstaller"
    for directory in (home, temporary, cache, pyinstaller_cache):
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    path_parts = [
        str(inputs.node_executable.parent),
        str(inputs.cargo_executable.parent),
        str(inputs.pnpm_executable.parent),
        "/usr/bin",
        "/bin",
    ]
    return {
        "PATH": os.pathsep.join(dict.fromkeys(path_parts)),
        "HOME": str(home),
        "TMPDIR": str(temporary),
        "XDG_CACHE_HOME": str(cache),
        "PYINSTALLER_CONFIG_DIR": str(pyinstaller_cache),
        "PIP_NO_INDEX": "1",
        "UV_OFFLINE": "1",
        "CARGO_HOME": str(inputs.cargo_home),
        "CARGO_NET_OFFLINE": "true",
        "LANG": "C",
        "LC_ALL": "C",
        "TZ": "UTC",
        "NO_COLOR": "1",
    }


def compute_source_digest(repo_root: Path = REPO_ROOT) -> str:
    from desktop.source_digest import desktop_source_digest

    return desktop_source_digest(repo_root)


def stage_release_sources(
    source_digest: str,
    *,
    run: BuildRun,
    repo_root: Path = REPO_ROOT,
) -> Path:
    """Copy the exact release-source closure and stage the embedded digest."""
    from js.echo.ledger.release_gates import _iter_release_source_files, release_source_digest

    if not _run_is_owned(run):
        raise RuntimeError("build run owner marker is invalid")
    if _LOWER_SHA256.fullmatch(source_digest) is None:
        raise RuntimeError("source digest must be lowercase 64-hex")
    resolved_repo = repo_root.resolve()
    stage_root = run.root / "stage/source"
    if stage_root.exists():
        raise RuntimeError("owned build stage already exists")
    for source in _iter_release_source_files(resolved_repo):
        relative = source.relative_to(resolved_repo)
        destination = stage_root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination, follow_symlinks=False)

    embedded = stage_root / "desktop/.embedded_source_digest"
    embedded.parent.mkdir(parents=True, exist_ok=True)
    embedded.write_bytes(source_digest.encode("ascii"))
    staged_digest = release_source_digest(stage_root)
    if not hmac.compare_digest(staged_digest, source_digest):
        raise RuntimeError("staged release sources do not reproduce the source digest")
    return stage_root


def verify_python_build_requirements(
    requirements_path: Path,
    *,
    version_resolver: Callable[[str], str] = importlib.metadata.version,
) -> None:
    try:
        lines = _read_single_link_file(
            requirements_path, "Python build requirements"
        ).decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise RuntimeError("Python build requirements are not UTF-8") from exc
    pins: dict[str, str] = {}
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = _PIN.fullmatch(line)
        if match is None:
            raise RuntimeError("Python build requirements must use exact pins")
        name = match.group(1).lower().replace("_", "-")
        if name in pins:
            raise RuntimeError("Python build requirements contain duplicate pins")
        pins[name] = match.group(2)
    if set(pins) != _PYTHON_BUILD_REQUIREMENTS:
        raise RuntimeError("Python build requirements have an unexpected package set")
    for name, expected in pins.items():
        try:
            actual = version_resolver(name)
        except importlib.metadata.PackageNotFoundError as exc:
            raise RuntimeError(f"Python build requirement missing: {name}") from exc
        if actual != expected:
            raise RuntimeError(
                f"Python build requirement mismatch: {name} expected {expected}, got {actual}"
            )


def install_desktop_dependencies(
    stage_root: Path,
    *,
    run: BuildRun,
    offline_inputs: OfflineBuildInputs,
    runner: Runner = _run,
) -> None:
    inputs = _validated_offline_inputs(offline_inputs)
    command = [
        str(inputs.pnpm_executable),
        "install",
        "--frozen-lockfile",
        "--offline",
        "--ignore-scripts",
        "--store-dir",
        str(inputs.pnpm_store),
    ]
    code, _stdout, stderr = runner(
        command,
        cwd=stage_root / "desktop",
        env=controlled_build_environment(run, inputs),
        timeout=600,
    )
    if code != 0:
        raise RuntimeError(f"offline pnpm install failed: {stderr}")
    _cleanup_pnpm_store_project_links(inputs.pnpm_store)


def _cleanup_pnpm_store_project_links(store: Path) -> None:
    """Remove project symlink entries that pnpm creates in the store during install.

    pnpm records project metadata as symlinks under ``v11/projects/``.  These
    symlinks point back to the source tree and break the single-link-file
    invariant required by ``_tree_entries``.  Removing them keeps the store
    reproducible without affecting offline resolution.
    """
    projects = store / "v11" / "projects"
    if not projects.is_dir():
        return
    for child in projects.iterdir():
        if child.is_symlink():
            child.unlink()


def build_sidecar(
    source_digest: str,
    *,
    run: BuildRun,
    stage_root: Path,
    offline_inputs: OfflineBuildInputs,
    runner: Runner = _run,
) -> Path:
    embedded = stage_root / "desktop/.embedded_source_digest"
    try:
        embedded_value = _read_single_link_file(
            embedded, "staged embedded source digest"
        ).decode("ascii")
    except UnicodeDecodeError as exc:
        raise RuntimeError("staged embedded source digest is not ASCII") from exc
    if embedded_value != source_digest or _LOWER_SHA256.fullmatch(source_digest) is None:
        raise RuntimeError("staged embedded source digest mismatch")

    artifacts = run.root / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    work_dir = run.root / "stage/pyinstaller-work"
    spec_dir = run.root / "stage/pyinstaller-spec"
    python = _resolved_executable(Path(sys.executable).resolve(strict=True), "Python")
    command = [
        str(python),
        "-m",
        "PyInstaller",
        "--onefile",
        "--name",
        SIDECAR_NAME,
        "--distpath",
        str(artifacts),
        "--workpath",
        str(work_dir),
        "--specpath",
        str(spec_dir),
        "--noconfirm",
        "--clean",
        "--add-data",
        f"{embedded}:desktop",
        # Web UI assets must live beside the frozen js.web package path.
        "--add-data",
        f"{stage_root / 'js' / 'web' / 'static'}:js/web/static",
        "--add-data",
        f"{stage_root / 'js' / 'web' / 'templates'}:js/web/templates",
        # Tiktoken BPE cache: Path(__file__).parents[2]/resources/tokenizer in freeze.
        "--add-data",
        f"{stage_root / 'resources' / 'tokenizer'}:resources/tokenizer",
        "--hidden-import",
        "js.web",
        "--hidden-import",
        "js_work.web",
        "--hidden-import",
        "js.appshell.server",
        "--hidden-import",
        "uvicorn",
        # Work Office stack is imported via appshell → js_work.cli on cold start.
        # Missing these causes sidecar exit before the ready sentinel.
        "--hidden-import",
        "xlrd",
        "--hidden-import",
        "xlrd.book",
        "--hidden-import",
        "xlrd.sheet",
        "--hidden-import",
        "openpyxl",
        "--hidden-import",
        "openpyxl.workbook",
        "--hidden-import",
        "openpyxl.reader.excel",
        "--collect-submodules",
        "xlrd",
        "--collect-submodules",
        "openpyxl",
        # tiktoken discovers encodings via the tiktoken_ext namespace package.
        "--hidden-import",
        "tiktoken",
        "--hidden-import",
        "tiktoken_ext",
        "--hidden-import",
        "tiktoken_ext.openai_public",
        "--collect-submodules",
        "tiktoken",
        "--collect-submodules",
        "tiktoken_ext",
        "-p",
        str(stage_root),
        str(stage_root / "desktop/sidecar/host.py"),
    ]
    env = controlled_build_environment(run, offline_inputs)
    env["PYTHONPATH"] = str(stage_root)
    code, _stdout, stderr = runner(command, cwd=stage_root, env=env, timeout=900)
    if code != 0:
        raise RuntimeError(f"PyInstaller failed: {stderr}")
    binary = artifacts / SIDECAR_NAME
    _single_link_file_stat(binary, "PyInstaller sidecar")
    return binary


def validate_build_number(value: object) -> str:
    """Validate the caller-supplied deterministic ``YYYYMMDDNN`` build number."""
    if not isinstance(value, str):
        raise RuntimeError("build number must use YYYYMMDDNN")
    match = _BUILD_NUMBER.fullmatch(value)
    if match is None or match.group("sequence") == "00":
        raise RuntimeError("build number must use YYYYMMDDNN with sequence 01-99")
    day = match.group("day")
    try:
        date.fromisoformat(f"{day[:4]}-{day[4:6]}-{day[6:8]}")
    except ValueError as exc:
        raise RuntimeError("build number contains an invalid calendar date") from exc
    return value


def _bundle_info(app_path: Path) -> tuple[Path, dict[str, object]]:
    info_path = _safe_directory(app_path, "app bundle") / "Contents/Info.plist"
    try:
        value = plistlib.loads(_read_single_link_file(info_path, "app Info.plist"))
    except (plistlib.InvalidFileException, ValueError, TypeError) as exc:
        raise RuntimeError("app Info.plist is invalid") from exc
    if not isinstance(value, dict):
        raise RuntimeError("app Info.plist root must be a dictionary")
    return info_path, value


def _bind_bundle_versions(app_path: Path, build_number: str) -> None:
    validated = validate_build_number(build_number)
    info_path, info = _bundle_info(app_path)
    info["CFBundleShortVersionString"] = PRODUCT_VERSION
    info["CFBundleVersion"] = validated
    payload = plistlib.dumps(info, fmt=plistlib.FMT_XML, sort_keys=True)
    _replace_single_link_file(info_path, payload, "app Info.plist")


def _verify_bundle_versions(app_path: Path, build_number: str) -> None:
    validated = validate_build_number(build_number)
    _info_path, info = _bundle_info(app_path)
    if info.get("CFBundleShortVersionString") != PRODUCT_VERSION:
        raise RuntimeError(
            f"app CFBundleShortVersionString must equal {PRODUCT_VERSION}"
        )
    if info.get("CFBundleVersion") != validated:
        raise RuntimeError("app CFBundleVersion does not match manifest build number")


def _is_thin_mach_o(payload: bytes) -> bool:
    layout = _THIN_MACH_O_MAGICS.get(payload[:4])
    if layout is None:
        return False
    endian, header_size = layout
    if len(payload) < header_size:
        return False
    try:
        cpu_type, _cpu_subtype, file_type, commands, commands_size, _flags = (
            struct.unpack_from(f"{endian}IIIIII", payload, 4)
        )
    except struct.error:
        return False
    return bool(
        cpu_type != 0
        and 1 <= file_type <= 0x20
        and commands <= 100_000
        and commands_size <= len(payload) - header_size
    )


def _is_fat_mach_o(payload: bytes) -> bool:
    layout = _FAT_MACH_O_MAGICS.get(payload[:4])
    if layout is None or len(payload) < 8:
        return False
    endian, record_size, uses_64_bit_offsets = layout
    try:
        architectures = struct.unpack_from(f"{endian}I", payload, 4)[0]
    except struct.error:
        return False
    if not 1 <= architectures <= 64 or 8 + architectures * record_size > len(payload):
        return False
    for index in range(architectures):
        offset = 8 + index * record_size
        try:
            if uses_64_bit_offsets:
                _cpu_type, _cpu_subtype, slice_offset, slice_size, _align, _reserved = (
                    struct.unpack_from(f"{endian}IIQQII", payload, offset)
                )
            else:
                _cpu_type, _cpu_subtype, slice_offset, slice_size, _align = (
                    struct.unpack_from(f"{endian}IIIII", payload, offset)
                )
        except struct.error:
            return False
        if (
            slice_size == 0
            or slice_offset < 8 + architectures * record_size
            or slice_offset + slice_size > len(payload)
            or not _is_thin_mach_o(payload[slice_offset : slice_offset + slice_size])
        ):
            return False
    return True


def _is_mach_o(payload: bytes) -> bool:
    return _is_thin_mach_o(payload) or _is_fat_mach_o(payload)


def _app_file_expected_mode(relative: PurePosixPath, payload: bytes) -> int:
    parts = relative.parts
    in_macos_directory = any(
        parts[index : index + 2] == ("Contents", "MacOS")
        for index in range(max(0, len(parts) - 1))
    )
    if in_macos_directory or payload.startswith(b"#!"):
        return 0o755
    if relative.suffix.casefold() in _NON_EXECUTABLE_RESOURCE_SUFFIXES:
        return 0o644
    if _is_mach_o(payload):
        return 0o755
    return 0o644


def _set_regular_file_mode(path: Path, mode: int, label: str) -> None:
    before = _single_link_file_stat(path, label)
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
        ):
            raise RuntimeError(f"{label} identity changed before chmod")
        os.fchmod(descriptor, mode)
        after = os.fstat(descriptor)
        if (
            (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino)
            or stat.S_IMODE(after.st_mode) != mode
        ):
            raise RuntimeError(f"{label} identity changed during chmod")
    except OSError as exc:
        raise RuntimeError(f"{label} permissions could not be normalized") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _set_directory_mode(path: Path, mode: int, label: str) -> None:
    descriptor = -1
    try:
        descriptor = os.open(path, _directory_open_flags())
        before = os.fstat(descriptor)
        if not stat.S_ISDIR(before.st_mode):
            raise RuntimeError(f"{label} must be a directory")
        os.fchmod(descriptor, mode)
        after = os.fstat(descriptor)
        if (
            (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino)
            or stat.S_IMODE(after.st_mode) != mode
        ):
            raise RuntimeError(f"{label} identity changed during chmod")
    except OSError as exc:
        raise RuntimeError(f"{label} permissions could not be normalized") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _walk_app_bundle(app_path: Path) -> Iterator[tuple[Path, PurePosixPath, int]]:
    root = _safe_directory(app_path, "app bundle")

    def walk(current: Path) -> Iterator[tuple[Path, PurePosixPath, int]]:
        try:
            children = sorted(os.scandir(current), key=lambda entry: entry.name)
        except OSError as exc:
            raise RuntimeError("app bundle is unreadable") from exc
        for child in children:
            path = Path(child.path)
            try:
                mode = child.stat(follow_symlinks=False).st_mode
            except OSError as exc:
                raise RuntimeError("app bundle entry is unreadable") from exc
            relative = PurePosixPath(path.relative_to(root).as_posix())
            if stat.S_ISLNK(mode):
                raise RuntimeError(f"app bundle contains a symlink: {relative}")
            if not stat.S_ISDIR(mode) and not stat.S_ISREG(mode):
                raise RuntimeError(f"app bundle contains a special file: {relative}")
            yield path, relative, mode
            if stat.S_ISDIR(mode):
                yield from walk(path)

    yield from walk(root)


def normalize_app_bundle_permissions(app_path: Path) -> None:
    """Normalize an unsigned bundle without trusting inherited execute bits."""
    root = _safe_directory(app_path, "app bundle")
    _set_directory_mode(root, 0o755, "app bundle root")
    for path, relative, mode in _walk_app_bundle(root):
        label = f"app bundle entry {relative}"
        if stat.S_ISDIR(mode):
            _set_directory_mode(path, 0o755, label)
            continue
        payload = _read_single_link_file(path, label)
        _set_regular_file_mode(path, _app_file_expected_mode(relative, payload), label)


def _verify_app_bundle_permissions(app_path: Path) -> None:
    root = _safe_directory(app_path, "app bundle")
    if stat.S_IMODE(root.stat().st_mode) != 0o755:
        raise RuntimeError("app bundle root permission must be 0755")
    for path, relative, mode in _walk_app_bundle(root):
        actual = stat.S_IMODE(mode)
        if stat.S_ISDIR(mode):
            expected = 0o755
        else:
            payload = _read_single_link_file(path, f"app bundle entry {relative}")
            expected = _app_file_expected_mode(relative, payload)
        if actual != expected:
            raise RuntimeError(
                f"app bundle permission mismatch: {relative} is {actual:04o}, "
                f"expected {expected:04o}"
            )


def build_tauri_app(
    source_digest: str,
    *,
    build_number: str,
    run: BuildRun,
    stage_root: Path,
    offline_inputs: OfflineBuildInputs,
    runner: Runner = _run,
) -> Path:
    if _LOWER_SHA256.fullmatch(source_digest) is None:
        raise RuntimeError("source digest must be lowercase 64-hex")
    validated_build_number = validate_build_number(build_number)
    inputs = _validated_offline_inputs(offline_inputs)
    tauri = _resolved_executable(
        stage_root / "desktop/node_modules/.bin/tauri", "Tauri"
    )
    target_dir = run.root / "stage/cargo-target"
    env = controlled_build_environment(run, inputs)
    env.update(
        {
            "CARGO_TARGET_DIR": str(target_dir),
            "JS_AGENT_DESKTOP_SOURCE_DIGEST": source_digest,
        }
    )
    command = [
        str(tauri),
        "build",
        "--runner",
        str(inputs.cargo_executable),
        "--target",
        TARGET_TRIPLE,
        "--no-sign",
        "--bundles",
        "app",
        "--",
        "--locked",
        "--offline",
    ]
    code, _stdout, stderr = runner(
        command,
        cwd=stage_root / "desktop/src-tauri",
        env=env,
        timeout=1200,
    )
    if code != 0:
        raise RuntimeError(f"offline Tauri build failed: {stderr}")
    app_path = target_dir / TARGET_TRIPLE / "release/bundle/macos/JS Agent.app"
    _safe_directory(app_path, "Tauri app bundle")
    _bind_bundle_versions(app_path, validated_build_number)
    return app_path


def _cargo_home_cache_snapshot(cargo_home: Path) -> dict[str, bytes | None]:
    """Capture exact mutable Cargo cache bytes and original existence."""
    _safe_directory(cargo_home, "Cargo home")
    snapshot: dict[str, bytes | None] = {}
    for name in _CARGO_MUTABLE_CACHE_NAMES:
        path = cargo_home / name
        try:
            path.lstat()
        except FileNotFoundError:
            snapshot[name] = None
        except OSError as exc:
            raise RuntimeError(f"Cargo cache state is unreadable: {name}") from exc
        else:
            snapshot[name] = _read_single_link_file(path, f"Cargo cache {name}")
    return snapshot


def _restore_cargo_home_caches(
    cargo_home: Path,
    snapshot: dict[str, bytes | None],
) -> None:
    """Restore the exact pre-build bytes without guessing that caches were empty."""
    _safe_directory(cargo_home, "Cargo home")
    if set(snapshot) != set(_CARGO_MUTABLE_CACHE_NAMES):
        raise RuntimeError("Cargo cache snapshot schema is invalid")
    for name in _CARGO_MUTABLE_CACHE_NAMES:
        path = cargo_home / name
        payload = snapshot[name]
        try:
            path.lstat()
        except FileNotFoundError:
            exists = False
        except OSError as exc:
            raise RuntimeError(f"Cargo cache state is unreadable: {name}") from exc
        else:
            exists = True
            _single_link_file_stat(path, f"Cargo cache {name}")

        if payload is None:
            if exists:
                path.unlink()
            continue

        flags = os.O_WRONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        flags |= os.O_TRUNC if exists else os.O_CREAT | os.O_EXCL
        descriptor = -1
        try:
            descriptor = os.open(path, flags, 0o600)
            view = memoryview(payload)
            written = 0
            while written < len(view):
                written += os.write(descriptor, view[written:])
            os.fsync(descriptor)
        except OSError as exc:
            raise RuntimeError(f"Cargo cache state could not be restored: {name}") from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)


@contextmanager
def _preserve_cargo_home_caches(cargo_home: Path) -> Iterator[None]:
    snapshot = _cargo_home_cache_snapshot(cargo_home)
    try:
        yield
    finally:
        _restore_cargo_home_caches(cargo_home, snapshot)


def _adhoc_sign_app(app_path: Path, *, runner: Runner = _run) -> None:
    """Ad-hoc sign the .app bundle for local testing.

    This is NOT a Developer ID signature and the bundle is NOT notarized.
    It allows ``codesign --verify --deep --strict`` to pass on the local
    machine so the process-smoke and WebView harness can launch the app
    without Gatekeeper blocking it.
    """
    code, _stdout, stderr = runner(
        ["/usr/bin/codesign", "-s", "-", "--force", "--deep", str(app_path)],
        cwd=app_path.parent,
        timeout=120,
    )
    if code != 0:
        raise RuntimeError(f"ad-hoc codesign failed (exit {code}): {stderr}")
    verify_code, _verify_stdout, verify_stderr = runner(
        ["/usr/bin/codesign", "--verify", "--deep", "--strict", str(app_path)],
        cwd=app_path.parent,
        timeout=60,
    )
    if verify_code != 0:
        raise RuntimeError(
            f"codesign verify failed after ad-hoc signing (exit {verify_code}): "
            f"{verify_stderr}"
        )


def _zip_artifact_name(digest_short: str) -> str:
    return f"JS-Agent-{PRODUCT_VERSION}-macos-arm64-unsigned-{digest_short}.zip"


def create_zip(
    app_path: Path,
    *,
    run: BuildRun,
    digest_short: str,
    offline_inputs: OfflineBuildInputs,
    runner: Runner = _run,
) -> Path:
    """Create a ZIP of the .app without AppleDouble / resource-fork noise.

    Uses ditto with ``--norsrc --noextattr --noqtn`` so members like ``._*``,
    ``__MACOSX``, and ``.DS_Store`` are never archived. The resulting archive is
    re-scanned and rejected if any such member appears.
    """
    inputs = _validated_offline_inputs(offline_inputs)
    artifacts = run.root / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    zip_path = artifacts / _zip_artifact_name(digest_short)
    if zip_path.exists():
        zip_path.unlink()
    code, _stdout, stderr = runner(
        [
            str(inputs.ditto_executable),
            "-c",
            "-k",
            "--keepParent",
            "--norsrc",
            "--noextattr",
            "--noqtn",
            str(app_path),
            str(zip_path),
        ],
        cwd=run.root,
        env=controlled_build_environment(run, inputs),
        timeout=120,
    )
    if code != 0:
        raise RuntimeError(f"zip creation failed: {stderr}")
    _single_link_file_stat(zip_path, "zip artifact")
    forbidden = _zip_forbidden_members(zip_path)
    if forbidden:
        raise RuntimeError(
            "zip contains AppleDouble/resource-fork/junk members: "
            + ", ".join(forbidden[:12])
        )
    return zip_path


def _zip_forbidden_members(zip_path: Path) -> list[str]:
    """Return ZIP member names that must never appear in a release archive."""
    payload = _read_single_link_file(zip_path, "zip artifact")
    bad: list[str] = []
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            for member in archive.infolist():
                name = member.filename or ""
                pure = PurePosixPath(name)
                parts = pure.parts
                if not parts:
                    continue
                if any(part == "__MACOSX" for part in parts):
                    bad.append(name)
                    continue
                if any(part == ".DS_Store" for part in parts):
                    bad.append(name)
                    continue
                if any(part.startswith("._") for part in parts):
                    bad.append(name)
                    continue
    except zipfile.BadZipFile as exc:
        raise RuntimeError("zip artifact is invalid") from exc
    return bad


def _tree_entries(directory: Path, label: str = "artifact tree") -> dict[str, TreeEntry]:
    root = _safe_directory(directory, label)
    entries: dict[str, TreeEntry] = {
        "": TreeEntry("directory", stat.S_IMODE(root.stat().st_mode))
    }

    def walk(current: Path) -> None:
        try:
            children = sorted(os.scandir(current), key=lambda entry: entry.name)
        except OSError as exc:
            raise RuntimeError(f"{label} is unreadable") from exc
        for child in children:
            path = Path(child.path)
            try:
                mode = child.stat(follow_symlinks=False).st_mode
            except OSError as exc:
                raise RuntimeError(f"{label} entry is unreadable") from exc
            if stat.S_ISLNK(mode):
                raise RuntimeError(f"{label} contains a symlink")
            relative = path.relative_to(root).as_posix()
            if stat.S_ISDIR(mode):
                entries[relative] = TreeEntry("directory", stat.S_IMODE(mode))
                walk(path)
            elif stat.S_ISREG(mode):
                entries[relative] = TreeEntry(
                    "file",
                    stat.S_IMODE(mode),
                    _read_single_link_file(path, f"{label} file"),
                )
            else:
                raise RuntimeError(f"{label} contains a special file")

    walk(root)
    if not any(entry.entry_type == "file" for entry in entries.values()):
        raise RuntimeError(f"{label} is empty")
    return entries


def _entries_digest(entries: dict[str, TreeEntry]) -> str:
    digest = hashlib.sha256()
    digest.update(_TREE_DIGEST_DOMAIN)
    for relative, entry in sorted(entries.items()):
        if entry.entry_type not in {"directory", "file"}:
            raise RuntimeError("tree entry type is not closed")
        if (
            entry.entry_type == "directory"
            and entry.mode != 0o755
            or entry.entry_type == "file"
            and entry.mode not in {0o644, 0o755}
        ):
            raise RuntimeError("tree entry permission is not normalized")
        if entry.entry_type == "directory" and entry.content:
            raise RuntimeError("directory tree entry contains data")
        entry_type = entry.entry_type.encode("ascii")
        encoded = relative.encode("utf-8")
        digest.update(len(entry_type).to_bytes(8, "big"))
        digest.update(entry_type)
        digest.update(entry.mode.to_bytes(8, "big"))
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
        digest.update(len(entry.content).to_bytes(8, "big"))
        digest.update(entry.content)
    return digest.hexdigest()


def _sha256_tree(directory: Path, label: str = "artifact tree") -> str:
    return _entries_digest(_tree_entries(directory, label))


def _sha256_content_tree(directory: Path, label: str) -> str:
    entries = _tree_entries(directory, label)
    digest = hashlib.sha256()
    for relative, entry in sorted(entries.items()):
        if entry.entry_type != "file":
            continue
        encoded = relative.encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
        digest.update(len(entry.content).to_bytes(8, "big"))
        digest.update(entry.content)
    return digest.hexdigest()


def _zip_app_entries(zip_path: Path, app_name: str) -> dict[str, TreeEntry]:
    entries: dict[str, TreeEntry] = {}
    seen: set[str] = set()
    macos_seen: set[str] = set()
    payload = _read_single_link_file(zip_path, "zip artifact")
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            if archive.testzip() is not None:
                raise RuntimeError("zip member checksum mismatch")
            for member in archive.infolist():
                name = member.filename
                if not name or "\\" in name or "\x00" in name:
                    raise RuntimeError("zip contains an unsafe member path")
                canonical_name = name[:-1] if member.is_dir() and name.endswith("/") else name
                raw_parts = canonical_name.split("/")
                pure = PurePosixPath(canonical_name)
                if (
                    pure.is_absolute()
                    or any(part in {"", ".", ".."} for part in raw_parts)
                    or pure.as_posix() != canonical_name
                ):
                    raise RuntimeError("zip contains an unsafe member path")
                if any(part.startswith("._") for part in raw_parts):
                    raise RuntimeError(f"zip contains AppleDouble member: {canonical_name}")
                if any(part == "__MACOSX" for part in raw_parts):
                    raise RuntimeError(f"zip contains __MACOSX member: {canonical_name}")
                if any(part == ".DS_Store" for part in raw_parts):
                    raise RuntimeError(f"zip contains .DS_Store member: {canonical_name}")
                if canonical_name in seen:
                    raise RuntimeError("zip contains duplicate members")
                seen.add(canonical_name)
                macos_key = unicodedata.normalize("NFC", canonical_name).casefold()
                if macos_key in macos_seen:
                    raise RuntimeError("zip contains a macOS path collision")
                macos_seen.add(macos_key)
                unix_mode = member.external_attr >> 16
                file_type = stat.S_IFMT(unix_mode)
                if stat.S_ISLNK(unix_mode):
                    raise RuntimeError("zip contains a symlink")
                if member.create_system != 3:
                    raise RuntimeError("zip member type metadata is not Unix")
                is_directory = member.is_dir()
                if is_directory and file_type != stat.S_IFDIR:
                    raise RuntimeError("zip directory contains special type metadata")
                if not is_directory and file_type != stat.S_IFREG:
                    raise RuntimeError("zip contains a special file")
                if not pure.parts or pure.parts[0] != app_name:
                    raise RuntimeError("zip contains an unexpected top-level entry")
                if len(pure.parts) == 1:
                    if not is_directory:
                        raise RuntimeError("zip declared app root is not a directory")
                    relative = ""
                else:
                    relative = PurePosixPath(*pure.parts[1:]).as_posix()
                permissions = stat.S_IMODE(unix_mode)
                if is_directory:
                    if member.file_size != 0:
                        raise RuntimeError("zip directory contains data")
                    if permissions != 0o755:
                        raise RuntimeError(
                            f"zip directory permission mismatch: {canonical_name}"
                        )
                    entries[relative] = TreeEntry("directory", permissions)
                    continue
                content = archive.read(member)
                expected = _app_file_expected_mode(PurePosixPath(relative), content)
                if permissions != expected:
                    raise RuntimeError(
                        f"zip app file permission mismatch: {relative} is "
                        f"{permissions:04o}, expected {expected:04o}"
                    )
                entries[relative] = TreeEntry("file", permissions, content)
    except zipfile.BadZipFile as exc:
        raise RuntimeError("zip artifact is invalid") from exc
    if entries.get("") != TreeEntry("directory", 0o755):
        raise RuntimeError("zip does not contain the declared app root directory")
    if not any(entry.entry_type == "file" for entry in entries.values()):
        raise RuntimeError("zip app tree is empty")
    return entries


def _artifact_paths(source_digest: str) -> dict[str, str]:
    zip_name = _zip_artifact_name(source_digest[:16])
    return {
        "rust_main": "artifacts/JS Agent.app/Contents/MacOS/js-agent-desktop",
        "sidecar": "artifacts/JS Agent.app/Contents/MacOS/js-agent-host",
        "sidecar_standalone": f"artifacts/{SIDECAR_NAME}",
        "app_tree": "artifacts/JS Agent.app",
        "zip": f"artifacts/{zip_name}",
    }


def _file_binding(path: Path, label: str) -> dict[str, str]:
    resolved = _resolved_executable(path, label) if label in {
        "Python", "pnpm", "Cargo", "Node", "ditto"
    } else path.resolve(strict=True)
    return {"path": str(resolved), "sha256": _sha256_file(resolved, label)}


def build_environment_binding(
    run: BuildRun,
    offline_inputs: OfflineBuildInputs,
) -> dict[str, object]:
    if not _run_is_owned(run):
        raise RuntimeError("build run owner marker is invalid")
    inputs = _validated_offline_inputs(offline_inputs)
    return {
        "schema": BUILD_ENVIRONMENT_SCHEMA,
        "run_owner_marker_sha256": _sha256_file(
            run.root / OWNER_MARKER_NAME, "build owner marker"
        ),
        "python": _file_binding(Path(sys.executable).resolve(strict=True), "Python"),
        "pnpm": _file_binding(inputs.pnpm_executable, "pnpm"),
        "cargo": _file_binding(inputs.cargo_executable, "Cargo"),
        "node": _file_binding(inputs.node_executable, "Node"),
        "ditto": _file_binding(inputs.ditto_executable, "ditto"),
        "cargo_home": {
            "path": str(inputs.cargo_home),
            "tree_sha256": _sha256_content_tree(inputs.cargo_home, "Cargo home"),
        },
        "pnpm_store": {
            "path": str(inputs.pnpm_store),
            "tree_sha256": _sha256_content_tree(inputs.pnpm_store, "pnpm store"),
        },
    }


def _collect_build_inputs(repo_root: Path) -> dict[str, dict[str, str]]:
    return {
        name: {
            "path": relative,
            "sha256": _sha256_file(repo_root.resolve() / relative, f"build input {name}"),
        }
        for name, relative in _BUILD_INPUT_PATHS.items()
    }


def generate_manifest(
    *,
    source_digest: str,
    build_number: str,
    sidecar_path: Path,
    app_path: Path,
    zip_path: Path,
    run: BuildRun,
    repo_root: Path = REPO_ROOT,
    offline_inputs: OfflineBuildInputs,
) -> Path:
    if not _run_is_owned(run):
        raise RuntimeError("build run owner marker is invalid")
    if _run_is_marked_invalid(run.root):
        raise RuntimeError("build run is invalid and requires manual cleanup")
    if _LOWER_SHA256.fullmatch(source_digest) is None:
        raise RuntimeError("source digest must be lowercase 64-hex")
    validated_build_number = validate_build_number(build_number)
    expected_paths = _artifact_paths(source_digest)
    supplied = {
        "sidecar_standalone": sidecar_path.absolute(),
        "app_tree": app_path.absolute(),
        "zip": zip_path.absolute(),
    }
    for name, path in supplied.items():
        if path != (run.root / expected_paths[name]).absolute():
            raise RuntimeError(f"{name} is not at its fixed output path")

    rust_main = run.root / expected_paths["rust_main"]
    bundled_sidecar = run.root / expected_paths["sidecar"]
    _verify_bundle_versions(app_path, validated_build_number)
    _verify_app_bundle_permissions(app_path)
    artifacts = {
        "rust_main": {"path": expected_paths["rust_main"], "sha256": _sha256_file(rust_main)},
        "sidecar": {"path": expected_paths["sidecar"], "sha256": _sha256_file(bundled_sidecar)},
        "sidecar_standalone": {
            "path": expected_paths["sidecar_standalone"],
            "sha256": _sha256_file(sidecar_path),
        },
        "app_tree": {
            "path": expected_paths["app_tree"],
            "sha256": _sha256_tree(app_path),
        },
        "zip": {"path": expected_paths["zip"], "sha256": _sha256_file(zip_path)},
    }
    manifest = {
        "schema": MANIFEST_SCHEMA,
        "source_digest": source_digest,
        "arch": TARGET_TRIPLE,
        "product_version": PRODUCT_VERSION,
        "build_number": validated_build_number,
        "artifacts": artifacts,
        "build_inputs": _collect_build_inputs(repo_root),
        "build_environment": build_environment_binding(run, offline_inputs),
    }
    manifest_path = run.root / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return manifest_path


def _closed_hash_entry(value: object, *, expected_path: str) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == {"path", "sha256"}
        and value.get("path") == expected_path
        and isinstance(value.get("sha256"), str)
        and _LOWER_SHA256.fullmatch(value["sha256"]) is not None
    )


def _contained_path(root: Path, relative: str) -> Path | None:
    pure = PurePosixPath(relative)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        return None
    resolved_root = root.resolve()
    candidate = resolved_root
    for part in pure.parts:
        candidate /= part
        if candidate.is_symlink():
            return None
    if not candidate.resolve(strict=False).is_relative_to(resolved_root):
        return None
    return candidate


def _verify_build_environment(output_root: Path, value: object) -> list[str]:
    errors: list[str] = []
    expected_keys = {
        "schema",
        "run_owner_marker_sha256",
        *_ENVIRONMENT_FILE_KEYS,
        *_ENVIRONMENT_TREE_KEYS,
    }
    if not isinstance(value, dict) or set(value) != expected_keys:
        return ["manifest build environment schema is not closed"]
    marker_digest = value.get("run_owner_marker_sha256")
    if value.get("schema") != BUILD_ENVIRONMENT_SCHEMA or not isinstance(
        marker_digest, str
    ) or _LOWER_SHA256.fullmatch(marker_digest) is None:
        return ["manifest build environment identity is invalid"]
    try:
        actual_marker = _sha256_file(
            output_root / OWNER_MARKER_NAME, "build owner marker"
        )
        if not hmac.compare_digest(actual_marker, marker_digest):
            errors.append("build owner marker digest mismatch")
    except RuntimeError as exc:
        errors.append(str(exc))

    for name in _ENVIRONMENT_FILE_KEYS:
        entry = value.get(name)
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256"}:
            errors.append(f"build environment file entry is invalid: {name}")
            continue
        path_value = entry.get("path")
        digest_value = entry.get("sha256")
        if (
            not isinstance(path_value, str)
            or not Path(path_value).is_absolute()
            or not isinstance(digest_value, str)
            or _LOWER_SHA256.fullmatch(digest_value) is None
        ):
            errors.append(f"build environment file entry is invalid: {name}")
            continue
        try:
            actual = _sha256_file(Path(path_value), f"build environment {name}")
            if not hmac.compare_digest(actual, digest_value):
                errors.append(f"build environment digest mismatch: {name}")
        except RuntimeError as exc:
            errors.append(str(exc))

    for name in _ENVIRONMENT_TREE_KEYS:
        entry = value.get(name)
        if not isinstance(entry, dict) or set(entry) != {"path", "tree_sha256"}:
            errors.append(f"build environment tree entry is invalid: {name}")
            continue
        path_value = entry.get("path")
        digest_value = entry.get("tree_sha256")
        if (
            not isinstance(path_value, str)
            or not Path(path_value).is_absolute()
            or not isinstance(digest_value, str)
            or _LOWER_SHA256.fullmatch(digest_value) is None
        ):
            errors.append(f"build environment tree entry is invalid: {name}")
            continue
        try:
            actual = _sha256_content_tree(
                Path(path_value), f"build environment {name}"
            )
            if not hmac.compare_digest(actual, digest_value):
                errors.append(f"build environment tree digest mismatch: {name}")
        except RuntimeError as exc:
            errors.append(str(exc))
    return errors


def verify_manifest(
    manifest_path: Path,
    app_path: Path | None = None,
    *,
    repo_root: Path = REPO_ROOT,
) -> list[str]:
    del app_path
    if _run_is_marked_invalid(manifest_path.parent):
        return ["desktop build run is invalid and requires manual cleanup"]
    try:
        raw_manifest = _read_single_link_file(manifest_path, "desktop manifest")
        manifest = json.loads(raw_manifest.decode("utf-8"))
    except (RuntimeError, UnicodeError, json.JSONDecodeError) as exc:
        return [str(exc) or "manifest is unreadable or invalid JSON"]
    if not isinstance(manifest, dict) or set(manifest) != {
        "schema",
        "source_digest",
        "arch",
        "product_version",
        "build_number",
        "artifacts",
        "build_inputs",
        "build_environment",
    }:
        return ["manifest top-level schema is not closed"]
    errors = _verify_build_environment(manifest_path.parent.resolve(), manifest["build_environment"])
    source_digest = manifest.get("source_digest")
    build_number = manifest.get("build_number")
    try:
        validated_build_number = validate_build_number(build_number)
    except RuntimeError as exc:
        return [*errors, str(exc)]
    if (
        manifest.get("schema") != MANIFEST_SCHEMA
        or manifest.get("arch") != TARGET_TRIPLE
        or manifest.get("product_version") != PRODUCT_VERSION
        or not isinstance(source_digest, str)
        or _LOWER_SHA256.fullmatch(source_digest) is None
    ):
        return [*errors, "manifest identity fields are invalid"]
    try:
        current_digest = compute_source_digest(repo_root)
    except (OSError, RuntimeError, ValueError):
        return [*errors, "current release source digest is unavailable"]
    if not hmac.compare_digest(source_digest, current_digest):
        errors.append("manifest source digest does not match current release sources")

    expected_artifact_paths = _artifact_paths(source_digest)
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, dict) or set(artifacts) != _ARTIFACT_KEYS:
        return [*errors, "manifest artifact set is not exact"]
    for name, expected_path in expected_artifact_paths.items():
        if not _closed_hash_entry(artifacts.get(name), expected_path=expected_path):
            return [*errors, f"manifest artifact entry is invalid: {name}"]

    build_inputs = manifest.get("build_inputs")
    if not isinstance(build_inputs, dict) or set(build_inputs) != set(_BUILD_INPUT_PATHS):
        return [*errors, "manifest build input set is not exact"]
    for name, expected_path in _BUILD_INPUT_PATHS.items():
        if not _closed_hash_entry(build_inputs.get(name), expected_path=expected_path):
            return [*errors, f"manifest build input entry is invalid: {name}"]

    output_root = manifest_path.resolve().parent
    artifact_files: dict[str, Path] = {}
    for name, expected_path in expected_artifact_paths.items():
        full_path = _contained_path(output_root, expected_path)
        if full_path is None:
            errors.append(f"artifact path escapes output root or contains a link: {name}")
            continue
        artifact_files[name] = full_path
        if name == "app_tree":
            continue
        try:
            actual = _sha256_file(full_path, f"artifact {name}")
            if not hmac.compare_digest(actual, artifacts[name]["sha256"]):
                errors.append(f"artifact digest mismatch: {name}")
        except RuntimeError as exc:
            errors.append(str(exc))

    for name, expected_path in _BUILD_INPUT_PATHS.items():
        full_path = _contained_path(repo_root.resolve(), expected_path)
        if full_path is None:
            errors.append(f"build input path escapes repository or contains a link: {name}")
            continue
        try:
            actual = _sha256_file(full_path, f"build input {name}")
            if not hmac.compare_digest(actual, build_inputs[name]["sha256"]):
                errors.append(f"build input digest mismatch: {name}")
        except RuntimeError as exc:
            errors.append(str(exc))

    app = artifact_files.get("app_tree")
    app_entries: dict[str, TreeEntry] | None = None
    if app is not None:
        try:
            app_entries = _tree_entries(app)
            if not hmac.compare_digest(
                _entries_digest(app_entries), artifacts["app_tree"]["sha256"]
            ):
                errors.append("app tree digest mismatch")
        except RuntimeError as exc:
            errors.append(str(exc))
        try:
            _verify_bundle_versions(app, validated_build_number)
            _verify_app_bundle_permissions(app)
        except RuntimeError as exc:
            errors.append(str(exc))

    bundled = artifact_files.get("sidecar")
    standalone = artifact_files.get("sidecar_standalone")
    if bundled is not None and standalone is not None:
        try:
            if not hmac.compare_digest(
                _read_single_link_file(bundled, "bundled sidecar"),
                _read_single_link_file(standalone, "standalone sidecar"),
            ):
                errors.append("bundled and standalone sidecars differ")
        except RuntimeError as exc:
            errors.append(str(exc))

    zip_path = artifact_files.get("zip")
    if zip_path is not None and app is not None and app_entries is not None:
        try:
            if _zip_app_entries(zip_path, app.name) != app_entries:
                errors.append("zip app tree does not reproduce the declared app tree")
        except RuntimeError as exc:
            errors.append(str(exc))
    return errors


def build_desktop(
    *,
    build_number: str,
    output_dir: Path | None = None,
    repo_root: Path = REPO_ROOT,
    runner: Runner = _run,
    offline_inputs: OfflineBuildInputs,
    temporary_parent: Path | None = None,
) -> Path:
    from js.echo.ledger.release_gates import validate_release_source_integrity

    validated_build_number = validate_build_number(build_number)
    run = prepare_build_run(
        output_dir=output_dir,
        repo_root=repo_root,
        temporary_parent=temporary_parent,
    )
    try:
        inputs = _validated_offline_inputs(offline_inputs)
        source_digest = compute_source_digest(repo_root)
        if repo_root.resolve() == REPO_ROOT.resolve():
            validate_release_source_integrity(repo_root)
        stage_root = stage_release_sources(
            source_digest, run=run, repo_root=repo_root
        )
        verify_python_build_requirements(stage_root / "desktop/requirements-build.txt")
        install_desktop_dependencies(
            stage_root,
            run=run,
            offline_inputs=inputs,
            runner=runner,
        )
        environment_before = build_environment_binding(run, inputs)
        build_inputs_before = _collect_build_inputs(repo_root)
        with _preserve_cargo_home_caches(inputs.cargo_home):
            sidecar_path = build_sidecar(
                source_digest,
                run=run,
                stage_root=stage_root,
                offline_inputs=inputs,
                runner=runner,
            )
            staged_binary = stage_root / f"desktop/src-tauri/binaries/{SIDECAR_NAME}"
            staged_binary.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(sidecar_path, staged_binary)
            staged_app = build_tauri_app(
                source_digest,
                build_number=validated_build_number,
                run=run,
                stage_root=stage_root,
                offline_inputs=inputs,
                runner=runner,
            )
            app_path = run.root / "artifacts/JS Agent.app"
            shutil.copytree(staged_app, app_path, symlinks=True)
            normalize_app_bundle_permissions(app_path)
            zip_path = create_zip(
                app_path,
                run=run,
                digest_short=source_digest[:16],
                offline_inputs=inputs,
                runner=runner,
            )
        # Verify no drift before ad-hoc signing (signing modifies the .app).
        if not hmac.compare_digest(compute_source_digest(repo_root), source_digest):
            raise RuntimeError("source digest drift during desktop build")
        if _collect_build_inputs(repo_root) != build_inputs_before:
            raise RuntimeError("build input drift during desktop build")
        if build_environment_binding(run, inputs) != environment_before:
            raise RuntimeError("offline tool or cache drift during desktop build")
        # Ad-hoc sign the .app for local testing (not a Developer ID signature).
        _adhoc_sign_app(app_path, runner=runner)
        # Copy the signed bundled sidecar back to standalone so they match.
        # Tauri renames the sidecar to "js-agent-host" inside the bundle.
        bundled_sidecar = app_path / "Contents/MacOS" / "js-agent-host"
        if bundled_sidecar.is_file():
            shutil.copy2(bundled_sidecar, sidecar_path)
        # Re-create ZIP after signing so the archive matches the signed bundle.
        zip_path = create_zip(
            app_path,
            run=run,
            digest_short=source_digest[:16],
            offline_inputs=inputs,
            runner=runner,
        )
        manifest_path = generate_manifest(
            source_digest=source_digest,
            build_number=validated_build_number,
            sidecar_path=sidecar_path,
            app_path=app_path,
            zip_path=zip_path,
            run=run,
            repo_root=repo_root,
            offline_inputs=inputs,
        )
        errors = verify_manifest(manifest_path, repo_root=repo_root)
        if errors:
            raise RuntimeError("desktop manifest verification failed: " + "; ".join(errors))
        return manifest_path
    except Exception:
        cleanup_build_run(run)
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build JS Agent desktop shell offline")
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--build-number", required=True)
    parser.add_argument("--pnpm-executable", type=Path, required=True)
    parser.add_argument("--cargo-executable", type=Path, required=True)
    parser.add_argument("--node-executable", type=Path, required=True)
    parser.add_argument("--ditto-executable", type=Path, required=True)
    parser.add_argument("--cargo-home", type=Path, required=True)
    parser.add_argument("--pnpm-store", type=Path, required=True)
    args = parser.parse_args(argv)
    inputs = OfflineBuildInputs(
        pnpm_executable=args.pnpm_executable,
        cargo_executable=args.cargo_executable,
        node_executable=args.node_executable,
        ditto_executable=args.ditto_executable,
        cargo_home=args.cargo_home,
        pnpm_store=args.pnpm_store,
    )
    try:
        manifest = build_desktop(
            output_dir=args.output_dir,
            build_number=args.build_number,
            offline_inputs=inputs,
        )
    except RuntimeError as exc:
        print(f"desktop build failed: {exc}", file=sys.stderr)
        return 1
    print(f"desktop manifest: {manifest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
