"""Ephemeral Ed25519 ledger signing helpers for isolated E2E.

Private keys live only in a system temporary directory outside the repository
and evidence trees. Path is passed exclusively via
``JS_ISO_E2E_LEDGER_PRIVATE_KEY_PATH`` for the lifetime of the parent process
tree — never persisted as a repo/evidence sidecar.

Destroy requires an ``EphemeralKeyHandle`` that retains the creation-time
parent directory descriptor and inode identity. Overwrite-before-unlink is
best-effort lifecycle hygiene — not a claim of cryptographic secure erase on
APFS/SSD.
"""

from __future__ import annotations

import base64
import errno
import hashlib
import json
import os
import stat
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import NoReturn

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

E2E_LEDGER_PUBKEY_RELATIVE = Path("docs/security/ECHO_E2E_LEDGER_PUBKEY.json")
E2E_LEDGER_PUBKEY_SCHEMA = "echo-e2e-ledger-pubkey-v1"
E2E_PRIVATE_ENV = "JS_ISO_E2E_LEDGER_PRIVATE_KEY_PATH"
E2E_PARENT_OWNS_CLEANUP_ENV = "JS_ISO_E2E_LEDGER_PARENT_OWNS_CLEANUP"
E2E_PROVENANCE_SCHEMA = "echo-e2e-ledger-key-provenance-v1"
_PRIVATE_BASENAME = "ledger.ed25519.private"
_PRIVATE_SIZE = 32


def _fingerprint(public_raw: bytes) -> str:
    return hashlib.sha256(public_raw).hexdigest()


def write_frozen_pubkey(root: Path, public_raw: bytes) -> dict[str, object]:
    payload = {
        "schema_version": E2E_LEDGER_PUBKEY_SCHEMA,
        "algorithm": "Ed25519",
        "public_key_b64": base64.b64encode(public_raw).decode("ascii"),
        "fingerprint_sha256": _fingerprint(public_raw),
        "purpose": "ephemeral-e2e-ledger-consistency-v1",
        "not_a_third_party_signature": True,
        "notes": (
            "Public half of a per-freeze ephemeral keypair. Private key is stored "
            "in an external system temp directory and destroyed after signing. "
            "Anyone with the private key during the run can forge the same "
            "signatures; this is not a third-party attestation."
        ),
    }
    path = root.resolve() / E2E_LEDGER_PUBKEY_RELATIVE
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return payload


def _path_is_under(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def _dir_open_flags() -> int:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return flags


def _open_flags_nofollow_read() -> int:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return flags


def _open_flags_nofollow_rdwr() -> int:
    flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return flags


@dataclass
class EphemeralKeyHandle:
    """Creation-bound identity for a single E2E private key.

    Destroy must use this handle. A bare Path is rejected.
    """

    _dir_fd: int
    _parent_dev: int
    _parent_ino: int
    _parent_uid: int
    _parent_mode: int
    _basename: str
    _key_dev: int
    _key_ino: int
    _key_uid: int
    _key_mode: int
    _key_size: int
    _key_nlink: int
    _path_str: str
    _owns_dir_fd: bool = False
    _closed: bool = False
    _close_state: str = "unowned"

    @property
    def path(self) -> Path:
        return Path(self._path_str)

    def close(self) -> None:
        """Close the retained parent directory FD.

        Success is idempotent. Any close syscall error propagates and moves the
        handle to terminal ``unknown`` state; no code may touch that numeric FD
        again because it may already have been released and reused.
        """
        if self._close_state == "closed":
            return
        if self._close_state == "unknown":
            raise RuntimeError("E2E key handle close state is unknown; refusing numeric FD reuse")
        if self._close_state != "open" or not self._owns_dir_fd:
            raise RuntimeError("E2E key handle no longer owns its directory descriptor")
        fd = self._dir_fd
        try:
            os.close(fd)
        except BaseException as exc:
            self._close_state = "unknown"
            self._owns_dir_fd = False
            self._closed = False
            raise exc from None
        self._owns_dir_fd = False
        self._closed = True
        self._close_state = "closed"

    def __del__(self) -> None:  # noqa: D105
        if getattr(self, "_close_state", "closed") != "open" or not getattr(
            self, "_owns_dir_fd", False
        ):
            return
        try:
            self.close()
        except BaseException:
            pass


def _pwrite_private_key(fd: int, data: bytes) -> None:
    """Write the 32-byte private key in a single write; fail on any short write.

    A 32-byte write to a fresh regular file must complete atomically on local
    filesystems; a short count indicates a real I/O problem and we abort rather
    than silently persisting a partial key.
    """
    written = os.write(fd, data)
    if written != len(data):
        raise OSError(f"E2E private key short write: {written}/{len(data)}")


def _safe_rmdir(
    path: Path,
    expected_dev: int,
    expected_ino: int,
    *,
    strict: bool = False,
) -> None:
    """Remove an empty temp dir only if its lstat identity still matches creation.

    If the path was swapped to a different directory, refuse to delete it (not
    an error). When ``strict=True``, I/O failures after a positive identity match
    propagate so prepare/destroy cleanup cannot silently leave residue.
    """
    try:
        st = path.lstat()
    except OSError:
        if strict:
            raise
        return
    if not stat.S_ISDIR(st.st_mode):
        if strict:
            raise RuntimeError("E2E key parent path is not a directory during cleanup")
        return
    if int(st.st_dev) != expected_dev or int(st.st_ino) != expected_ino:
        return
    try:
        if any(path.iterdir()):
            if strict:
                raise RuntimeError(
                    "E2E key parent not empty during cleanup; residual private key may remain"
                )
            return
        path.rmdir()
    except OSError:
        if strict:
            raise


def _unlink_via_fd(basename: str, dir_fd: int) -> None:
    """Descriptor-relative unlink. FileNotFoundError is success; other OSError raise."""
    try:
        os.unlink(basename, dir_fd=dir_fd)
    except FileNotFoundError:
        return


def _exception_contains_private_path(
    exc: BaseException,
    private_paths: tuple[Path, ...],
) -> bool:
    rendered = f"{exc!s}\n{exc!r}"
    if isinstance(exc, OSError) and exc.filename is not None:
        return True
    return any(str(path) and str(path) in rendered for path in private_paths)


def _sanitize_lifecycle_exception(
    exc: BaseException,
    *,
    phase: str,
    private_paths: tuple[Path, ...],
) -> BaseException:
    """Remove private paths and all ambient cause/context chains."""
    if isinstance(exc, BaseExceptionGroup):
        children = [
            _sanitize_lifecycle_exception(child, phase=phase, private_paths=private_paths)
            for child in exc.exceptions
        ]
        message = str(exc)
        if any(str(path) and str(path) in message for path in private_paths):
            message = f"E2E key {phase} failed"
        sanitized: BaseException = BaseExceptionGroup(message, children)
    elif _exception_contains_private_path(exc, private_paths):
        if isinstance(exc, OSError):
            code = exc.errno if exc.errno is not None else errno.EIO
            sanitized = OSError(code, f"E2E key {phase} filesystem operation failed")
        elif isinstance(exc, KeyboardInterrupt):
            sanitized = KeyboardInterrupt(f"E2E key {phase} interrupted")
        elif isinstance(exc, SystemExit):
            sanitized = SystemExit(f"E2E key {phase} interrupted")
        else:
            sanitized = RuntimeError(f"E2E key {phase} failed")
    else:
        sanitized = exc
    sanitized.__cause__ = None
    sanitized.__context__ = None
    sanitized.__suppress_context__ = True
    return sanitized


def _raise_sanitized_exception(
    exc: BaseException,
    *,
    phase: str,
    private_paths: tuple[Path, ...],
) -> NoReturn:
    raise _sanitize_lifecycle_exception(
        exc,
        phase=phase,
        private_paths=private_paths,
    ) from None


def _close_fd_once(fd: int) -> None:
    """Attempt one close; an error makes numeric-FD state unknowable."""
    os.close(fd)


def _close_handle_fully(handle: EphemeralKeyHandle) -> list[BaseException]:
    """Attempt handle close once; unknown state is terminal and never retried."""
    try:
        handle.close()
    except BaseException as exc:
        return [exc]
    return []


def _raise_lifecycle_with_cleanup(
    primary: BaseException,
    cleanup_errors: list[BaseException],
    *,
    phase: str,
    residual_possible: bool,
    private_paths: tuple[Path, ...] = (),
) -> NoReturn:
    """Re-raise primary, or the correct exception group when cleanup failed.

    Messages must not include private-key bytes or absolute paths.
    """
    safe_primary = _sanitize_lifecycle_exception(
        primary,
        phase=phase,
        private_paths=private_paths,
    )
    safe_cleanup = [
        _sanitize_lifecycle_exception(exc, phase=phase, private_paths=private_paths)
        for exc in cleanup_errors
    ]
    if not safe_cleanup:
        raise safe_primary from None
    suffix = "; residual private key may remain" if residual_possible else ""
    group = BaseExceptionGroup(
        f"E2E key {phase} failed with cleanup errors{suffix}",
        [safe_primary, *safe_cleanup],
    )
    group.__cause__ = None
    group.__context__ = None
    group.__suppress_context__ = True
    raise group from None


def _raise_cleanup_errors(
    cleanup_errors: list[BaseException],
    *,
    phase: str,
    residual_possible: bool,
    private_paths: tuple[Path, ...] = (),
) -> NoReturn:
    """Raise one cleanup failure directly, or a correctly typed group."""
    safe_cleanup = [
        _sanitize_lifecycle_exception(exc, phase=phase, private_paths=private_paths)
        for exc in cleanup_errors
    ]
    if len(safe_cleanup) == 1 and not residual_possible:
        raise safe_cleanup[0] from None
    suffix = "; residual private key may remain" if residual_possible else ""
    group = BaseExceptionGroup(
        f"E2E key {phase} failed with cleanup errors{suffix}",
        safe_cleanup,
    )
    group.__cause__ = None
    group.__context__ = None
    group.__suppress_context__ = True
    raise group from None


def prepare_ephemeral_keypair(
    root: Path,
    *,
    evidence_root: Path | None = None,
    keys_parent: Path | None = None,
) -> tuple[EphemeralKeyHandle, dict[str, object], dict[str, object]]:
    """Generate a fresh keypair; pubkey on digest surface; private in system temp.

    Owns its own complete rollback: any failure after the private key file is
    created (short write, fchmod/fsync failure, metadata validation failure,
    pubkey write failure, or a post-handle pre-return failure) unlinks the
    private key via the retained directory descriptor, closes all FDs, removes
    the empty temp dir, and re-raises the original error. No ``destroyed=true``
    provenance is produced on this path.
    """
    setup_primary: BaseException | None = None
    setup_cleanup_errors: list[BaseException] = []
    key_dir: Path | None = None
    resolved_root = root
    evidence: Path | None = None
    try:
        resolved_root = root.resolve()
        evidence = evidence_root.resolve() if evidence_root is not None else None

        if keys_parent is not None:
            parent = keys_parent.resolve()
            if _path_is_under(parent, resolved_root) or (
                evidence is not None and _path_is_under(parent, evidence)
            ):
                raise RuntimeError("keys_parent must be outside repo and evidence")
            parent.mkdir(parents=True, exist_ok=True)
            os.chmod(parent, 0o700)
            key_dir = Path(tempfile.mkdtemp(prefix="js-e2e-ledger-", dir=str(parent)))
        else:
            key_dir = Path(tempfile.mkdtemp(prefix="js-e2e-ledger-"))
        os.chmod(key_dir, 0o700)
    except BaseException as exc:
        setup_primary = exc

    if setup_primary is not None:
        if key_dir is not None:
            try:
                if key_dir.is_dir() and not any(key_dir.iterdir()):
                    key_dir.rmdir()
            except BaseException as exc:
                setup_cleanup_errors.append(exc)
        private_paths = tuple(path for path in (keys_parent, key_dir) if path is not None)
        _raise_lifecycle_with_cleanup(
            setup_primary,
            setup_cleanup_errors,
            phase="prepare",
            residual_possible=bool(setup_cleanup_errors),
            private_paths=private_paths,
        )

    assert key_dir is not None

    if _path_is_under(key_dir, resolved_root) or (
        evidence is not None and _path_is_under(key_dir, evidence)
    ):
        try:
            key_dir.rmdir()
        except OSError:
            pass
        raise RuntimeError("refusing E2E private key location under controlled trees")

    dir_fd = -1
    parent_dev: int = -1
    parent_ino: int = -1
    handle: EphemeralKeyHandle | None = None
    prepare_primary: BaseException | None = None
    cleanup_errors: list[BaseException] = []
    residual_possible = False
    try:
        dir_fd = os.open(str(key_dir), _dir_open_flags())
        parent_st = os.fstat(dir_fd)
        if not stat.S_ISDIR(parent_st.st_mode):
            raise PermissionError("E2E key parent must be a directory")
        if parent_st.st_uid != os.getuid():
            raise PermissionError("E2E key parent uid mismatch")
        if stat.S_IMODE(parent_st.st_mode) != 0o700:
            raise PermissionError("E2E key parent must be mode 0700")
        parent_dev = int(parent_st.st_dev)
        parent_ino = int(parent_st.st_ino)

        private_key = Ed25519PrivateKey.generate()
        private_raw = private_key.private_bytes_raw()
        public_raw = private_key.public_key().public_bytes_raw()
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(_PRIVATE_BASENAME, flags, 0o600, dir_fd=dir_fd)
        write_primary: BaseException | None = None
        try:
            os.fstat(fd)
            _pwrite_private_key(fd, private_raw)
            os.fchmod(fd, 0o600)
            os.fsync(fd)
            key_st = os.fstat(fd)
        except BaseException as exc:
            write_primary = exc
        write_cleanup_errors: list[BaseException] = []
        try:
            _close_fd_once(fd)
        except BaseException as exc:
            write_cleanup_errors.append(exc)
        if write_primary is not None:
            _raise_lifecycle_with_cleanup(
                write_primary,
                write_cleanup_errors,
                phase="prepare",
                residual_possible=bool(write_cleanup_errors),
                private_paths=(key_dir, key_dir / _PRIVATE_BASENAME),
            )
        if write_cleanup_errors:
            _raise_cleanup_errors(
                write_cleanup_errors,
                phase="prepare",
                residual_possible=True,
                private_paths=(key_dir, key_dir / _PRIVATE_BASENAME),
            )
        del private_raw

        if not stat.S_ISREG(key_st.st_mode):
            raise PermissionError("E2E private key must be a regular file")
        if key_st.st_uid != os.getuid():
            raise PermissionError("E2E private key uid mismatch")
        if stat.S_IMODE(key_st.st_mode) != 0o600:
            raise PermissionError("E2E private key must be mode 0600")
        if key_st.st_size != _PRIVATE_SIZE:
            raise ValueError("E2E ledger private key must be 32 raw Ed25519 bytes")
        if key_st.st_nlink != 1:
            raise PermissionError("E2E private key must have nlink==1 at creation")

        private_path = key_dir / _PRIVATE_BASENAME
        handle = EphemeralKeyHandle(
            _dir_fd=dir_fd,
            _parent_dev=parent_dev,
            _parent_ino=parent_ino,
            _parent_uid=int(parent_st.st_uid),
            _parent_mode=stat.S_IMODE(parent_st.st_mode),
            _basename=_PRIVATE_BASENAME,
            _key_dev=int(key_st.st_dev),
            _key_ino=int(key_st.st_ino),
            _key_uid=int(key_st.st_uid),
            _key_mode=stat.S_IMODE(key_st.st_mode),
            _key_size=int(key_st.st_size),
            _key_nlink=int(key_st.st_nlink),
            _path_str=str(private_path),
            _owns_dir_fd=False,
            _close_state="open",
        )
        # The non-owning handle is already close-capable. This assignment is the
        # single ownership transfer; raw ownership is cleared only afterward.
        handle._owns_dir_fd = True
        dir_fd = -1
    except BaseException as exc:
        prepare_primary = exc
        if handle is not None and handle._owns_dir_fd:
            try:
                _unlink_via_fd(_PRIVATE_BASENAME, handle._dir_fd)
            except BaseException as exc:
                cleanup_errors.append(exc)
                residual_possible = True
            cleanup_errors.extend(_close_handle_fully(handle))
        elif dir_fd >= 0:
            try:
                _unlink_via_fd(_PRIVATE_BASENAME, dir_fd)
            except BaseException as exc:
                cleanup_errors.append(exc)
                residual_possible = True
            try:
                _close_fd_once(dir_fd)
            except BaseException as exc:
                cleanup_errors.append(exc)
        if parent_dev < 0:
            try:
                if key_dir.is_dir() and not any(key_dir.iterdir()):
                    key_dir.rmdir()
            except BaseException as exc:
                cleanup_errors.append(exc)
        else:
            try:
                _safe_rmdir(key_dir, parent_dev, parent_ino, strict=True)
            except BaseException as exc:
                cleanup_errors.append(exc)
                residual_possible = True

    if prepare_primary is not None:
        _raise_lifecycle_with_cleanup(
            prepare_primary,
            cleanup_errors,
            phase="prepare",
            residual_possible=residual_possible,
            private_paths=tuple(
                path
                for path in (keys_parent, key_dir, key_dir / _PRIVATE_BASENAME)
                if path is not None
            ),
        )

    assert handle is not None
    post_prepare_primary: BaseException | None = None
    post_cleanup_errors: list[BaseException] = []
    post_residual_possible = False
    try:
        pubkey_payload = write_frozen_pubkey(resolved_root, public_raw)
        provenance: dict[str, object] = {
            "schema_version": E2E_PROVENANCE_SCHEMA,
            "public_fingerprint": pubkey_payload["fingerprint_sha256"],
            "generation_method": "random",
            "location_class": "external_temp",
            "private_mode": "0600",
            "public_key_digest_binding": str(E2E_LEDGER_PUBKEY_RELATIVE.as_posix()),
            "destroyed": False,
            "not_a_third_party_signature": True,
            "erase_notes": (
                "Private key unlink is lifecycle control only; overwrite-after-unlink "
                "is best-effort and is not claimed to be cryptographically secure erase "
                "on APFS/SSD."
            ),
        }
        return handle, pubkey_payload, provenance
    except BaseException as exc:
        post_prepare_primary = exc
        try:
            _unlink_via_fd(_PRIVATE_BASENAME, handle._dir_fd)
        except BaseException as exc:
            post_cleanup_errors.append(exc)
            post_residual_possible = True
        post_cleanup_errors.extend(_close_handle_fully(handle))
        try:
            _safe_rmdir(key_dir, parent_dev, parent_ino, strict=True)
        except BaseException as exc:
            post_cleanup_errors.append(exc)
            post_residual_possible = True

    assert post_prepare_primary is not None
    _raise_lifecycle_with_cleanup(
        post_prepare_primary,
        post_cleanup_errors,
        phase="prepare",
        residual_possible=post_residual_possible,
        private_paths=tuple(
            path for path in (keys_parent, key_dir, key_dir / _PRIVATE_BASENAME) if path is not None
        ),
    )


def write_provenance_receipt(path: Path, provenance: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(dict(provenance), indent=2, sort_keys=True) + "\n", encoding="utf-8")


def mark_destroyed(provenance: Mapping[str, object]) -> dict[str, object]:
    updated = dict(provenance)
    updated["destroyed"] = True
    return updated


def open_private_key_bytes(path: Path) -> tuple[bytes, tuple[int, int]]:
    """Open private key with O_NOFOLLOW; return (raw, (dev, ino))."""
    if path.name != _PRIVATE_BASENAME:
        raise ValueError(f"E2E private key basename must be {_PRIVATE_BASENAME}")
    parent = path.parent
    dir_fd: int | None = None
    fd: int | None = None
    result: tuple[bytes, tuple[int, int]] | None = None
    primary: BaseException | None = None
    try:
        dir_fd = os.open(str(parent), _dir_open_flags())
        parent_st = os.fstat(dir_fd)
        if not stat.S_ISDIR(parent_st.st_mode):
            raise PermissionError("E2E key parent must be a directory")
        if parent_st.st_uid != os.getuid():
            raise PermissionError("E2E key parent uid mismatch")
        if stat.S_IMODE(parent_st.st_mode) != 0o700:
            raise PermissionError("E2E key parent must be mode 0700")
        try:
            fd = os.open(_PRIVATE_BASENAME, _open_flags_nofollow_read(), dir_fd=dir_fd)
        except OSError as exc:
            if getattr(exc, "errno", None) in {getattr(os, "ELOOP", 62), 62}:
                raise PermissionError("E2E private key path must not be a symlink") from exc
            raise
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise PermissionError("E2E private key must be a regular file")
        if st.st_uid != os.getuid():
            raise PermissionError("E2E private key uid mismatch")
        if stat.S_IMODE(st.st_mode) != 0o600:
            raise PermissionError("E2E private key must be mode 0600")
        if st.st_size != _PRIVATE_SIZE:
            raise ValueError("E2E ledger private key must be 32 raw Ed25519 bytes")
        if st.st_nlink != 1:
            raise PermissionError("E2E private key must have nlink==1")
        raw = os.read(fd, _PRIVATE_SIZE + 1)
        if len(raw) != _PRIVATE_SIZE:
            raise ValueError("E2E ledger private key must be 32 raw Ed25519 bytes")
        result = raw, (int(st.st_dev), int(st.st_ino))
    except BaseException as exc:
        primary = exc

    cleanup_errors: list[BaseException] = []
    if fd is not None:
        try:
            _close_fd_once(fd)
        except BaseException as exc:
            cleanup_errors.append(exc)
    if dir_fd is not None:
        try:
            _close_fd_once(dir_fd)
        except BaseException as exc:
            cleanup_errors.append(exc)
    if primary is not None:
        _raise_lifecycle_with_cleanup(
            primary,
            cleanup_errors,
            phase="validation",
            residual_possible=bool(cleanup_errors),
            private_paths=(parent, path),
        )
    if cleanup_errors:
        _raise_cleanup_errors(
            cleanup_errors,
            phase="validation",
            residual_possible=True,
            private_paths=(parent, path),
        )
    assert result is not None
    return result


def resolve_private_key_path(root: Path | None = None) -> Path:
    """Resolve private key path from env only (no in-repo pointer / sidecar)."""
    _ = root
    env = os.environ.get(E2E_PRIVATE_ENV, "").strip()
    if not env:
        raise RuntimeError(f"{E2E_PRIVATE_ENV} is unset")
    path = Path(env)
    if path.name != _PRIVATE_BASENAME:
        raise ValueError(f"E2E private key basename must be {_PRIVATE_BASENAME}")
    raw, _inode = open_private_key_bytes(path)
    del raw
    return path


def load_private_key(path: Path) -> Ed25519PrivateKey:
    raw, _inode = open_private_key_bytes(path)
    try:
        return Ed25519PrivateKey.from_private_bytes(raw)
    finally:
        del raw


def destroy_private_key(handle: EphemeralKeyHandle) -> None:
    """Destroy private key via creation-bound dir_fd + basename + inode checks.

    Rejects a bare Path. Does not Path.resolve() then delete.

    Order (race-safe): validate parent+file identity and nlink==1 -> UNLINK
    the trusted directory entry first (atomic) while keeping the private key FD
    open -> re-fstat the still-open FD -> only if st_nlink==0 (no external
    hardlink stole the inode) perform best-effort overwrite -> close FD + handle
    -> guarded empty-parent removal. If an external hardlink survived unlink,
    overwrite is refused and the gate fails closed; the caller must NOT mark
    provenance ``destroyed=true``.

    Parent fstat, identity validation, open/unlink/overwrite/fsync, and parent
    cleanup all run inside one outer try/finally so every success and failure
    path closes the handle. Close errors are observable (not swallowed).
    """
    if not isinstance(handle, EphemeralKeyHandle):
        raise TypeError("destroy_private_key requires EphemeralKeyHandle, not a bare Path")
    if handle._closed:
        raise RuntimeError("E2E key handle already closed")
    if handle._close_state == "unknown":
        raise RuntimeError("E2E key handle close state is unknown; refusing destroy retry")
    if handle._close_state != "open" or not handle._owns_dir_fd:
        raise RuntimeError("E2E key handle does not own its directory descriptor")

    fd: int | None = None
    fd_close_unknown = False
    primary: BaseException | None = None
    cleanup_errors: list[BaseException] = []
    try:
        if handle._basename != _PRIVATE_BASENAME:
            raise ValueError(f"E2E private key basename must be {_PRIVATE_BASENAME}")
        dir_fd = handle._dir_fd
        # Re-validate parent identity via fstat on the retained descriptor.
        parent_st = os.fstat(dir_fd)
        if (
            int(parent_st.st_dev) != handle._parent_dev
            or int(parent_st.st_ino) != handle._parent_ino
            or int(parent_st.st_uid) != handle._parent_uid
            or stat.S_IMODE(parent_st.st_mode) != handle._parent_mode
            or not stat.S_ISDIR(parent_st.st_mode)
        ):
            raise RuntimeError("E2E key parent identity drifted; refusing destroy")

        try:
            fd = os.open(handle._basename, _open_flags_nofollow_rdwr(), dir_fd=dir_fd)
        except FileNotFoundError as exc:
            raise RuntimeError("E2E private key missing at destroy") from exc
        except OSError as exc:
            if getattr(exc, "errno", None) in {getattr(os, "ELOOP", 62), 62}:
                raise PermissionError("refusing to destroy symlink private key path") from exc
            raise

        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise PermissionError("refusing to destroy non-regular E2E key path")
        if (
            int(st.st_dev) != handle._key_dev
            or int(st.st_ino) != handle._key_ino
            or int(st.st_uid) != handle._key_uid
            or stat.S_IMODE(st.st_mode) != handle._key_mode
            or int(st.st_size) != handle._key_size
        ):
            raise RuntimeError("E2E private key identity drifted; refusing destroy")
        if int(st.st_nlink) != 1:
            raise PermissionError("refusing to destroy E2E key with nlink!=1")

        # UNLINK FIRST (atomic removal of the trusted directory entry), keeping
        # the private key FD open so we can re-check nlink on the same inode.
        os.unlink(handle._basename, dir_fd=dir_fd)

        # After unlink, re-fstat the still-open FD. Only st_nlink==0 means no
        # external hardlink stole the inode; only then is overwrite safe.
        st2 = os.fstat(fd)
        if int(st2.st_nlink) != 0:
            raise PermissionError("refusing to overwrite E2E key: external link survived unlink")

        # Best-effort overwrite now that the inode is unreachable by path.
        os.lseek(fd, 0, os.SEEK_SET)
        os.write(fd, os.urandom(max(int(st.st_size), _PRIVATE_SIZE)))
        os.fsync(fd)

        # Close private-key FD before parent rmdir; handle.close() is in finally.
        try:
            os.close(fd)
        except BaseException:
            fd_close_unknown = True
            cleanup_errors.append(
                RuntimeError("E2E key descriptor close state unknown; residual may remain")
            )
            raise
        fd = None

        # Guarded empty-parent removal: verify creation-time parent dev/ino.
        parent_path = Path(handle._path_str).parent
        _safe_rmdir(parent_path, handle._parent_dev, handle._parent_ino)
    except BaseException as destroy_exc:
        primary = destroy_exc
    finally:
        if fd is not None and not fd_close_unknown:
            try:
                _close_fd_once(fd)
            except BaseException as close_fd_exc:
                cleanup_errors.append(close_fd_exc)
        cleanup_errors.extend(_close_handle_fully(handle))

    private_path = Path(handle._path_str)
    if primary is not None:
        _raise_lifecycle_with_cleanup(
            primary,
            cleanup_errors,
            phase="destroy",
            residual_possible=True,
            private_paths=(private_path.parent, private_path),
        )
    if cleanup_errors:
        _raise_cleanup_errors(
            cleanup_errors,
            phase="destroy",
            residual_possible=True,
            private_paths=(private_path.parent, private_path),
        )


def assert_no_private_key_under(evidence_root: Path) -> None:
    hits = [
        path
        for path in evidence_root.resolve().rglob("*")
        if path.is_file()
        and (
            path.name.endswith(".private")
            or path.name.endswith("_private.pem")
            or "ed25519.private" in path.name
            or path.name == ".private_key_env_path"
        )
    ]
    if hits:
        raise RuntimeError("private key material leaked into evidence")


def assert_provenance_destroyed(provenance: Mapping[str, object]) -> None:
    if provenance.get("schema_version") != E2E_PROVENANCE_SCHEMA:
        raise RuntimeError("E2E provenance schema mismatch")
    if provenance.get("generation_method") != "random":
        raise RuntimeError("E2E provenance generation_method must be random")
    if provenance.get("location_class") != "external_temp":
        raise RuntimeError("E2E provenance location_class must be external_temp")
    if provenance.get("destroyed") is not True:
        raise RuntimeError("E2E provenance destroyed must be true")
    if "private_path" in provenance or "absolute_path" in provenance:
        raise RuntimeError("E2E provenance must not record absolute private paths")
