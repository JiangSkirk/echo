"""Ed25519 digital signature system for skills, plugins, and Hermes bridge.

Provides cryptographic proof of authorship and integrity that replaces
the current trust model based on self-declared YAML fields and unsigned
JSON lock files.

Key management:
- The signing key is generated once and stored at ``state_dir/.signing_key``
  with ``0o600`` permissions.
- The public key is embedded in signed manifests for verification.
- Built-in skills use a hardcoded public-key whitelist.
- Private+public publish uses temp files, fsync, atomic replace, parent-dir
  fsync, and a recoverable keypair journal so crash windows can resume or
  fail closed without leaving an unpublished orphan private key.
"""

from __future__ import annotations

import base64
import hashlib
import importlib
import json
import os
import re
import secrets
import stat
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

# Whitelist of public keys for built-in skills shipped with JS Agent.
# These keys are trusted to sign BUILTIN-level manifests.
_BUILTIN_PUBLIC_KEYS: frozenset[str] = frozenset()

_KEYPAIR_JOURNAL_NAME = ".signing_keypair.journal"
_KEYPAIR_LOCK_NAME = ".signing_keypair.lock"
_KEYPAIR_JOURNAL_VERSION = 1
_PRIVATE_KEY_BYTES = 32
_PUBLIC_KEY_BYTES = 32
_JOURNAL_REQUIRED_KEYS = frozenset({"version", "phase", "pub_sha256", "priv_tmp", "pub_tmp"})
_JOURNAL_PHASES = frozenset(
    {
        "after_journal",
        "after_private_write",
        "after_public_write",
        "after_private_publish",
        "after_public_publish",
    }
)
_PRIVATE_TEMP_NAME_RE = re.compile(r"^\.signing_key\.tmp-[0-9]+-[0-9a-f]{16}$")
_PUBLIC_TEMP_NAME_RE = re.compile(r"^\.signing_key\.pub\.tmp-[0-9]+-[0-9a-f]{16}$")
_JOURNAL_TEMP_NAME_RE = re.compile(r"^\.signing_keypair\.journal\.tmp-[0-9]+-[0-9a-f]{16}$")
_TEMP_NAME_KIND_RES = {
    "private": _PRIVATE_TEMP_NAME_RE,
    "public": _PUBLIC_TEMP_NAME_RE,
    "journal": _JOURNAL_TEMP_NAME_RE,
}
_PHASE_TEMP_RULES: dict[str, tuple[bool, bool]] = {
    # (priv_tmp required non-null, pub_tmp required non-null)
    "after_journal": (False, False),
    "after_private_write": (True, False),
    "after_public_write": (True, True),
    "after_private_publish": (False, True),
    "after_public_publish": (False, False),
}
_PUB_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

# Test/fault injection: set to a phase name to raise, or use env
# ``JS_SIGNING_KEYPAIR_FAULT`` to ``os._exit`` in a real subprocess.
_keypair_fault_point: str | None = None


def _key_path(state_dir: Path) -> Path:
    return state_dir / ".signing_key"


def _pubkey_path(state_dir: Path) -> Path:
    return state_dir / ".signing_key.pub"


def _journal_path(state_dir: Path) -> Path:
    return state_dir / _KEYPAIR_JOURNAL_NAME


def _lock_path(state_dir: Path) -> Path:
    return state_dir / _KEYPAIR_LOCK_NAME


def _acquire_file_lock(lock_fd: int) -> None:
    if os.name == "nt":
        msvcrt: Any = importlib.import_module("msvcrt")
        if os.fstat(lock_fd).st_size == 0:
            os.write(lock_fd, b"\0")
        os.lseek(lock_fd, 0, os.SEEK_SET)
        msvcrt.locking(lock_fd, msvcrt.LK_LOCK, 1)
        return
    fcntl: Any = importlib.import_module("fcntl")
    fcntl.flock(lock_fd, fcntl.LOCK_EX)


def _release_file_lock(lock_fd: int) -> None:
    if os.name == "nt":
        msvcrt: Any = importlib.import_module("msvcrt")
        os.lseek(lock_fd, 0, os.SEEK_SET)
        msvcrt.locking(lock_fd, msvcrt.LK_UNLCK, 1)
        return
    fcntl: Any = importlib.import_module("fcntl")
    fcntl.flock(lock_fd, fcntl.LOCK_UN)


@dataclass(frozen=True)
class TrustedStateDir:
    """Verified real directory handle for signer state operations."""

    path: Path
    dir_fd: int
    st_dev: int
    st_ino: int


def _open_trusted_state_dir(
    state_dir: Path,
    *,
    expected: TrustedStateDir | None = None,
    create: bool = True,
) -> TrustedStateDir:
    """Open ``state_dir`` as a real directory (reject symlinks / non-dirs)."""
    if state_dir.is_symlink():
        raise ValueError("signing state directory must not be a symlink")
    if create and not state_dir.exists():
        state_dir.mkdir(parents=True, exist_ok=True)
    if state_dir.is_symlink():
        raise ValueError("signing state directory must not be a symlink")
    if not state_dir.exists():
        raise ValueError("signing state directory does not exist")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        dir_fd = os.open(str(state_dir), flags)
    except OSError as exc:
        raise ValueError("signing state directory must be a real directory") from exc
    try:
        metadata = os.fstat(dir_fd)
        if not stat.S_ISDIR(metadata.st_mode):
            raise ValueError("signing state directory must be a real directory")
        if expected is not None and (
            metadata.st_dev != expected.st_dev or metadata.st_ino != expected.st_ino
        ):
            raise ValueError("signing state directory inode changed")
        return TrustedStateDir(
            path=state_dir,
            dir_fd=dir_fd,
            st_dev=metadata.st_dev,
            st_ino=metadata.st_ino,
        )
    except Exception:
        os.close(dir_fd)
        raise


def _close_trusted_state_dir(trusted: TrustedStateDir) -> None:
    os.close(trusted.dir_fd)


@contextmanager
def _keypair_lock(state_dir: Path) -> Iterator[None]:
    """Cross-process lock for keypair recover/generate/publish transactions."""
    trusted = _open_trusted_state_dir(state_dir, create=True)
    try:
        # macOS openat(O_CREAT|O_NOFOLLOW) can return ENOENT for a missing
        # final component; create first, then verify the opened inode.
        create_flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_CLOEXEC", 0)
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        try:
            lock_fd = os.open(
                _KEYPAIR_LOCK_NAME,
                create_flags | nofollow,
                0o600,
                dir_fd=trusted.dir_fd,
            )
        except FileNotFoundError:
            lock_fd = os.open(
                _KEYPAIR_LOCK_NAME,
                create_flags,
                0o600,
                dir_fd=trusted.dir_fd,
            )
        try:
            metadata = os.fstat(lock_fd)
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError(
                    f"signing keypair lock must be a regular file: {_KEYPAIR_LOCK_NAME}"
                )
            mode = metadata.st_mode & 0o777
            if mode & 0o077:
                raise PermissionError(
                    f"signing keypair lock permissions too open: {oct(mode)}; expected 0o600"
                )
            os.fchmod(lock_fd, 0o600)
            _acquire_file_lock(lock_fd)
            try:
                yield
            finally:
                _release_file_lock(lock_fd)
        finally:
            os.close(lock_fd)
    finally:
        _close_trusted_state_dir(trusted)


def _public_bytes_from_private(private_key: ed25519.Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _maybe_keypair_fault(point: str) -> None:
    """Inject a crash at ``point`` for durability tests."""
    global _keypair_fault_point
    env_point = os.environ.get("JS_SIGNING_KEYPAIR_FAULT")
    if env_point == point:
        # Real subprocess exit — do not raise (would be catchable).
        os._exit(91)
    if _keypair_fault_point == point:
        _keypair_fault_point = None
        raise RuntimeError(f"injected signing keypair fault: {point}")


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    fd = os.open(str(path), flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _read_regular_file(path: Path, *, max_bytes: int = 64) -> bytes:
    """Read a regular file with O_NOFOLLOW + fstat."""
    if path.is_symlink():
        raise ValueError(f"must not be a symlink: {path}")
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(str(path), os.O_RDONLY | nofollow)
    except OSError as exc:
        raise ValueError(f"must be a regular file: {path}") from exc
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"must be a regular file: {path}")
        return os.read(fd, max_bytes)
    finally:
        os.close(fd)


def _write_temp_bytes(state_dir: Path, *, prefix: str, payload: bytes, mode: int) -> Path:
    """Write ``payload`` to an O_EXCL temp file, fsync, and return its path."""
    # ``prefix`` is already a hidden basename (e.g. ``.signing_key``).
    tmp_name = f"{prefix}.tmp-{os.getpid()}-{secrets.token_hex(8)}"
    tmp_path = state_dir / tmp_name
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(str(tmp_path), os.O_CREAT | os.O_WRONLY | os.O_EXCL | nofollow, mode)
    try:
        os.fchmod(fd, mode)
        os.write(fd, payload)
        os.fsync(fd)
    finally:
        os.close(fd)
    return tmp_path


def _atomic_publish(tmp_path: Path, final_path: Path, *, clobber: bool) -> None:
    """Publish ``tmp_path`` to ``final_path``.

    When ``clobber`` is False (initial public key), use ``link`` so an
    existing attacker-controlled final path cannot be overwritten.
    """
    if clobber:
        os.replace(str(tmp_path), str(final_path))
        return
    try:
        os.link(str(tmp_path), str(final_path))
    except FileExistsError:
        tmp_path.unlink(missing_ok=True)
        raise
    tmp_path.unlink(missing_ok=True)


def _write_journal(state_dir: Path, payload: dict[str, Any]) -> None:
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    journal = _journal_path(state_dir)
    tmp = _write_temp_bytes(
        state_dir,
        prefix=_KEYPAIR_JOURNAL_NAME,
        payload=raw,
        mode=0o600,
    )
    try:
        os.replace(str(tmp), str(journal))
    except Exception:
        _cleanup_temp_names(state_dir, tmp.name, kind="journal")
        raise
    _fsync_directory(state_dir)


def _validate_temp_basename(name: str, *, kind: Literal["private", "public", "journal"]) -> str:
    """Accept only fixed-prefix basenames that cannot escape ``state_dir``."""
    if not isinstance(name, str) or not name:
        raise ValueError("invalid signing keypair journal temp name")
    if "\x00" in name or "/" in name or "\\" in name or name != os.path.basename(name):
        raise ValueError("signing keypair journal temp name must be a safe basename")
    if name.startswith("..") or ".." in name:
        raise ValueError("signing keypair journal temp name must not contain '..'")
    if _TEMP_NAME_KIND_RES[kind].fullmatch(name) is None:
        raise ValueError("signing keypair journal temp name has unexpected shape")
    return name


def _validate_temp_metadata(
    metadata: os.stat_result, *, kind: Literal["private", "public", "journal"]
) -> None:
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError("signing keypair temp must be a regular file")
    if stat.S_ISLNK(metadata.st_mode):
        raise ValueError("signing keypair temp must not be a symlink")
    if metadata.st_uid != os.getuid():
        raise PermissionError("signing keypair temp owner mismatch")
    mode = metadata.st_mode & 0o777
    if kind in {"private", "journal"}:
        if mode != 0o600:
            raise PermissionError(
                f"signing keypair {kind} temp permissions too open: {oct(mode)}; expected 0o600"
            )
        return
    if mode & 0o022:
        raise PermissionError(
            f"signing keypair public temp permissions too open: {oct(mode)}; "
            "group/other write not allowed"
        )


def _validate_journal_payload(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("unsupported signing keypair journal")
    if set(payload.keys()) != _JOURNAL_REQUIRED_KEYS:
        raise ValueError("unsupported signing keypair journal schema")
    version = payload["version"]
    if type(version) is not int or version != _KEYPAIR_JOURNAL_VERSION:
        raise ValueError("unsupported signing keypair journal")
    phase = payload.get("phase")
    if not isinstance(phase, str) or phase not in _JOURNAL_PHASES:
        raise ValueError("unsupported signing keypair journal phase")
    pub_sha = payload.get("pub_sha256")
    if not isinstance(pub_sha, str) or _PUB_SHA256_RE.fullmatch(pub_sha) is None:
        raise ValueError("unsupported signing keypair journal digest")
    priv_rule, pub_rule = _PHASE_TEMP_RULES[phase]
    priv_tmp = payload.get("priv_tmp")
    pub_tmp = payload.get("pub_tmp")
    if priv_rule:
        if not isinstance(priv_tmp, str):
            raise ValueError("invalid signing keypair journal temp name")
        _validate_temp_basename(priv_tmp, kind="private")
    elif priv_tmp is not None:
        raise ValueError("invalid signing keypair journal temp name")
    if pub_rule:
        if not isinstance(pub_tmp, str):
            raise ValueError("invalid signing keypair journal temp name")
        _validate_temp_basename(pub_tmp, kind="public")
    elif pub_tmp is not None:
        raise ValueError("invalid signing keypair journal temp name")
    return payload


def _read_journal(state_dir: Path) -> dict[str, Any] | None:
    """Read journal only after trusted state-dir + owner/mode/regular-file checks."""
    trusted = _open_trusted_state_dir(state_dir, create=False)
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        try:
            fd = os.open(_KEYPAIR_JOURNAL_NAME, flags, dir_fd=trusted.dir_fd)
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise ValueError("signing keypair journal must be a regular file") from exc
        try:
            metadata = os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError("signing keypair journal must be a regular file")
            if metadata.st_uid != os.getuid():
                raise PermissionError("signing keypair journal owner mismatch")
            mode = metadata.st_mode & 0o777
            if mode != 0o600:
                raise PermissionError(
                    f"signing keypair journal permissions too open: {oct(mode)}; expected 0o600"
                )
            raw = os.read(fd, 4096)
        finally:
            os.close(fd)
    finally:
        _close_trusted_state_dir(trusted)
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("corrupt signing keypair journal") from exc
    return _validate_journal_payload(payload)


def _clear_journal(state_dir: Path) -> None:
    trusted = _open_trusted_state_dir(state_dir, create=False)
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        try:
            fd = os.open(_KEYPAIR_JOURNAL_NAME, flags, dir_fd=trusted.dir_fd)
        except FileNotFoundError:
            return
        try:
            metadata = os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError("signing keypair journal must be a regular file")
            if metadata.st_uid != os.getuid():
                raise PermissionError("signing keypair journal owner mismatch")
            mode = metadata.st_mode & 0o777
            if mode != 0o600:
                raise PermissionError(
                    f"signing keypair journal permissions too open: {oct(mode)}; expected 0o600"
                )
        finally:
            os.close(fd)
        os.unlink(_KEYPAIR_JOURNAL_NAME, dir_fd=trusted.dir_fd)
    finally:
        _close_trusted_state_dir(trusted)
    _fsync_directory(state_dir)


def _cleanup_temp_names(
    state_dir: Path,
    *names: str | None,
    kind: Literal["private", "public", "journal"],
) -> None:
    """Unlink validated temp basenames inside ``state_dir`` using dir_fd + O_NOFOLLOW."""
    trusted = _open_trusted_state_dir(state_dir, create=False)
    try:
        for name in names:
            if name is None:
                continue
            safe_name = _validate_temp_basename(name, kind=kind)
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
            try:
                fd = os.open(safe_name, flags, dir_fd=trusted.dir_fd)
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise ValueError(
                    f"signing keypair temp must be a regular file: {safe_name}"
                ) from exc
            try:
                metadata = os.fstat(fd)
                _validate_temp_metadata(metadata, kind=kind)
            finally:
                os.close(fd)
            try:
                os.unlink(safe_name, dir_fd=trusted.dir_fd)
            except FileNotFoundError:
                continue
    finally:
        _close_trusted_state_dir(trusted)
    _fsync_directory(state_dir)


def _sweep_orphan_journal_temps(state_dir: Path) -> None:
    """Remove signer-namespaced orphan journal temps after successful init."""
    trusted = _open_trusted_state_dir(state_dir, create=False)
    try:
        names = os.listdir(trusted.dir_fd)
        for name in names:
            if _JOURNAL_TEMP_NAME_RE.fullmatch(name) is None:
                continue
            try:
                _cleanup_temp_names(state_dir, name, kind="journal")
            except (ValueError, PermissionError, OSError):
                # Never delete objects that fail fixed-prefix/owner/mode/regular checks.
                continue
    finally:
        _close_trusted_state_dir(trusted)


def _isolate_invalid_private(key_path: Path) -> Path:
    """Move an invalid private key aside and fsync the parent directory."""
    quarantine = key_path.with_name(f"{key_path.name}.corrupt-{time.time_ns()}")
    os.replace(str(key_path), str(quarantine))
    try:
        os.chmod(quarantine, 0o600)
    except OSError:
        pass
    pub = key_path.with_name(key_path.name + ".pub")
    if pub.exists() or pub.is_symlink():
        pub_q = pub.with_name(f"{pub.name}.corrupt-{time.time_ns()}")
        try:
            os.replace(str(pub), str(pub_q))
        except OSError:
            pass
    _fsync_directory(key_path.parent)
    return quarantine


def _load_private_bytes(key_path: Path) -> bytes:
    """Load exactly 32 private key bytes; isolate and fail closed if invalid."""
    if key_path.is_symlink():
        raise ValueError("signing key must not be a symlink")
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(str(key_path), os.O_RDONLY | nofollow)
    except OSError as exc:
        raise ValueError("signing key must be a regular file") from exc
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("signing key must be a regular file")
        mode = metadata.st_mode & 0o777
        if mode & 0o077:
            raise PermissionError(f"signing key permissions too open: {oct(mode)}; expected 0o600")
        priv_bytes = os.read(fd, _PRIVATE_KEY_BYTES + 1)
    finally:
        os.close(fd)
    if len(priv_bytes) != _PRIVATE_KEY_BYTES:
        _isolate_invalid_private(key_path)
        raise ValueError("signing private key is truncated or invalid")
    try:
        ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)
    except Exception:
        _isolate_invalid_private(key_path)
        raise ValueError("signing private key is truncated or invalid") from None
    return priv_bytes


def _publish_public_key(state_dir: Path, pub_bytes: bytes, *, clobber: bool) -> None:
    """Atomically publish the public key from a temp file."""
    pub_path = _pubkey_path(state_dir)
    if not clobber and (pub_path.exists() or pub_path.is_symlink()):
        raise FileExistsError(str(pub_path))
    tmp = _write_temp_bytes(
        state_dir,
        prefix=".signing_key.pub",
        payload=pub_bytes,
        mode=0o644,
    )
    try:
        _atomic_publish(tmp, pub_path, clobber=clobber)
    finally:
        tmp.unlink(missing_ok=True)
    _fsync_directory(state_dir)


def _ensure_matching_public(state_dir: Path, private_key: ed25519.Ed25519PrivateKey) -> bytes:
    """Ensure on-disk public matches private; rebuild when missing."""
    expected = _public_bytes_from_private(private_key)
    pub_path = _pubkey_path(state_dir)
    if pub_path.exists() or pub_path.is_symlink():
        on_disk = _read_regular_file(pub_path, max_bytes=_PUBLIC_KEY_BYTES + 1)
        if on_disk != expected:
            raise ValueError("signing public key does not match private key")
        return on_disk
    _publish_public_key(state_dir, expected, clobber=False)
    on_disk = _read_regular_file(pub_path, max_bytes=_PUBLIC_KEY_BYTES + 1)
    if on_disk != expected:
        raise ValueError("rebuilt signing public key does not match private key")
    return on_disk


def _recover_keypair(state_dir: Path) -> ed25519.Ed25519PrivateKey | None:
    """Replay or clean a keypair journal; return loaded key if durable private exists."""
    # Trust-check state_dir before interpreting journal or cleaning temps.
    trusted = _open_trusted_state_dir(state_dir, create=True)
    _close_trusted_state_dir(trusted)
    journal = _read_journal(state_dir)
    key_path = _key_path(state_dir)
    pub_path = _pubkey_path(state_dir)

    private_key: ed25519.Ed25519PrivateKey | None = None
    if key_path.exists() or key_path.is_symlink():
        priv_bytes = _load_private_bytes(key_path)
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)
        _ensure_matching_public(state_dir, private_key)

    if journal is not None:
        # Payload already fully validated (schema/version/phase/prefix/owner/mode).
        priv_tmp = journal.get("priv_tmp")
        pub_tmp = journal.get("pub_tmp")
        if isinstance(priv_tmp, str):
            _cleanup_temp_names(state_dir, priv_tmp, kind="private")
        if isinstance(pub_tmp, str):
            _cleanup_temp_names(state_dir, pub_tmp, kind="public")
        # If private was never published, drop any orphan public from a partial run.
        if private_key is None and (pub_path.exists() or pub_path.is_symlink()):
            # Only remove a public we ourselves staged in this journal window.
            phase = str(journal.get("phase", ""))
            if phase in {"after_public_write", "after_private_write", "after_journal"}:
                try:
                    pub_path.unlink(missing_ok=True)
                except OSError:
                    pass
        _clear_journal(state_dir)

    return private_key


# ---------------------------------------------------------------------------
# Key management
# ---------------------------------------------------------------------------


def _load_existing_signing_key(state_dir: Path) -> ed25519.Ed25519PrivateKey:
    """Load an existing signing key after re-checking under the keypair lock."""
    key_path = _key_path(state_dir)
    if key_path.is_symlink():
        raise ValueError("signing key must not be a symlink")
    if not key_path.exists():
        raise ValueError("signing key path missing after race")
    priv_bytes = _load_private_bytes(key_path)
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)
    _ensure_matching_public(state_dir, private_key)
    return private_key


def _cleanup_keypair_attempt(
    state_dir: Path,
    *,
    priv_tmp: Path | None,
    pub_tmp: Path | None,
) -> None:
    if priv_tmp is not None:
        try:
            _cleanup_temp_names(state_dir, priv_tmp.name, kind="private")
        except (ValueError, PermissionError, OSError):
            pass
    if pub_tmp is not None:
        try:
            _cleanup_temp_names(state_dir, pub_tmp.name, kind="public")
        except (ValueError, PermissionError, OSError):
            pass
    try:
        _clear_journal(state_dir)
    except (ValueError, PermissionError, OSError):
        pass


def _init_signing_keypair(state_dir: Path) -> ed25519.Ed25519PrivateKey:
    """Generate and publish a new keypair; caller must hold ``_keypair_lock``."""
    key_path = _key_path(state_dir)
    pub_path = _pubkey_path(state_dir)
    if key_path.exists() or key_path.is_symlink():
        return _load_existing_signing_key(state_dir)

    if pub_path.exists() or pub_path.is_symlink():
        # Attacker-controlled public without a matching private — refuse.
        raise FileExistsError(str(pub_path))

    private_key = ed25519.Ed25519PrivateKey.generate()
    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = _public_bytes_from_private(private_key)
    roundtrip = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)
    if _public_bytes_from_private(roundtrip) != pub_bytes:
        raise ValueError("signing keypair self-check failed")

    priv_tmp: Path | None = None
    pub_tmp: Path | None = None
    journal_payload: dict[str, Any] = {
        "version": _KEYPAIR_JOURNAL_VERSION,
        "phase": "after_journal",
        "pub_sha256": hashlib.sha256(pub_bytes).hexdigest(),
        "priv_tmp": None,
        "pub_tmp": None,
    }
    try:
        _write_journal(state_dir, journal_payload)
        _maybe_keypair_fault("after_journal")

        priv_tmp = _write_temp_bytes(
            state_dir,
            prefix=".signing_key",
            payload=priv_bytes,
            mode=0o600,
        )
        journal_payload = {
            **journal_payload,
            "phase": "after_private_write",
            "priv_tmp": priv_tmp.name,
        }
        _write_journal(state_dir, journal_payload)
        _maybe_keypair_fault("after_private_write")

        pub_tmp = _write_temp_bytes(
            state_dir,
            prefix=".signing_key.pub",
            payload=pub_bytes,
            mode=0o644,
        )
        journal_payload = {
            **journal_payload,
            "phase": "after_public_write",
            "pub_tmp": pub_tmp.name,
        }
        _write_journal(state_dir, journal_payload)
        _maybe_keypair_fault("after_public_write")

        try:
            _atomic_publish(priv_tmp, key_path, clobber=False)
        except FileExistsError:
            _cleanup_keypair_attempt(state_dir, priv_tmp=priv_tmp, pub_tmp=pub_tmp)
            return _load_existing_signing_key(state_dir)
        priv_tmp = None
        journal_payload = {**journal_payload, "phase": "after_private_publish", "priv_tmp": None}
        _write_journal(state_dir, journal_payload)
        _fsync_directory(state_dir)
        _maybe_keypair_fault("after_private_publish")

        try:
            _atomic_publish(pub_tmp, pub_path, clobber=False)
        except FileExistsError:
            _cleanup_keypair_attempt(state_dir, priv_tmp=None, pub_tmp=pub_tmp)
            return _load_existing_signing_key(state_dir)
        pub_tmp = None
        journal_payload = {**journal_payload, "phase": "after_public_publish", "pub_tmp": None}
        _write_journal(state_dir, journal_payload)
        _fsync_directory(state_dir)
        _maybe_keypair_fault("after_public_publish")

        _maybe_keypair_fault("before_cleanup")
        _clear_journal(state_dir)
        _sweep_orphan_journal_temps(state_dir)
    except FileExistsError:
        _cleanup_keypair_attempt(state_dir, priv_tmp=priv_tmp, pub_tmp=pub_tmp)
        return _load_existing_signing_key(state_dir)
    except Exception:
        _cleanup_keypair_attempt(state_dir, priv_tmp=priv_tmp, pub_tmp=pub_tmp)
        if key_path.exists() and not (pub_path.exists() or pub_path.is_symlink()):
            # Durable private without public is recoverable — keep it.
            pass
        raise

    on_disk_pub = _read_regular_file(pub_path, max_bytes=_PUBLIC_KEY_BYTES + 1)
    if on_disk_pub != pub_bytes:
        try:
            key_path.unlink(missing_ok=True)
        except OSError:
            pass
        try:
            pub_path.unlink(missing_ok=True)
        except OSError:
            pass
        _clear_journal(state_dir)
        raise ValueError("published signing public key does not match private key")

    return private_key


def generate_signing_key(state_dir: Path) -> ed25519.Ed25519PrivateKey:
    """Generate a new Ed25519 signing key and persist it to disk.

    The key file is created with ``0o600`` permissions.
    If a key already exists, it is NOT overwritten.
    The public key is published without clobbering an existing ``.pub`` file.

    Private and public keys are published as a matching pair via temp files,
    fsync, atomic publish, parent-dir fsync, and a recoverable journal.
    """
    # Reject symlink state_dir before any key material is written.
    trusted = _open_trusted_state_dir(state_dir, create=True)
    _close_trusted_state_dir(trusted)
    with _keypair_lock(state_dir):
        recovered = _recover_keypair(state_dir)
        if recovered is not None:
            _sweep_orphan_journal_temps(state_dir)
            return recovered

        key_path = _key_path(state_dir)
        if key_path.exists() or key_path.is_symlink():
            return _load_existing_signing_key(state_dir)

        return _init_signing_keypair(state_dir)


def load_signing_key(state_dir: Path) -> ed25519.Ed25519PrivateKey | None:
    """Load the signing key from disk, or None if not found.

    Rejects symlinks and world/group-readable private key files.
    Replays any keypair journal and rebuilds a missing public key when the
    private key is valid. Truncated/invalid private keys are isolated and
    fail closed.
    """
    with _keypair_lock(state_dir):
        _recover_keypair(state_dir)
        key_path = _key_path(state_dir)
        if key_path.is_symlink():
            raise ValueError("signing key must not be a symlink")
        if not key_path.exists():
            return None
        priv_bytes = _load_private_bytes(key_path)
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)
        _ensure_matching_public(state_dir, private_key)
        return private_key


def get_public_key(state_dir: Path) -> str:
    """Return the public key as a base64-encoded string.

    Never trusts an unverified on-disk public key. When a ``.pub`` file is
    present it is opened with ``O_NOFOLLOW`` + ``fstat`` and compared to the
    public key derived from the private key. Symlinks and mismatches fail
    closed. If no public file exists, it is safely rebuilt from the private key.
    """
    private_key = load_signing_key(state_dir)
    if private_key is None:
        return ""
    on_disk = _ensure_matching_public(state_dir, private_key)
    return base64.b64encode(on_disk).decode("ascii")


# ---------------------------------------------------------------------------
# Signing and verification
# ---------------------------------------------------------------------------


def sign_content(content: str, state_dir: Path) -> str:
    """Sign a string payload with the local signing key.

    Returns the base64-encoded Ed25519 signature.
    Raises ``RuntimeError`` if no signing key exists.
    """
    key = load_signing_key(state_dir)
    if key is None:
        raise RuntimeError("No signing key found.  Run generate_signing_key() first.")
    signature = key.sign(content.encode("utf-8"))
    return base64.b64encode(signature).decode("ascii")


def verify_signature(
    content: str,
    signature_b64: str,
    public_key_b64: str,
) -> bool:
    """Verify an Ed25519 signature for a content string.

    Returns ``True`` if the signature is valid, ``False`` otherwise.
    Also accepts built-in public keys from the whitelist.
    """
    try:
        signature = base64.b64decode(signature_b64)
        public_key_bytes = base64.b64decode(public_key_b64)
    except Exception:
        return False

    try:
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
        public_key.verify(signature, content.encode("utf-8"))
        return True
    except Exception:
        # Also check against the built-in whitelist
        if public_key_b64 in _BUILTIN_PUBLIC_KEYS:
            # Re-try with each whitelisted key as a fallback
            for pk_b64 in _BUILTIN_PUBLIC_KEYS:
                try:
                    pk = ed25519.Ed25519PublicKey.from_public_bytes(
                        base64.b64decode(pk_b64),
                    )
                    pk.verify(signature, content.encode("utf-8"))
                    return True
                except Exception:
                    continue
        return False


# ---------------------------------------------------------------------------
# Skill / Plugin manifest signing helpers
# ---------------------------------------------------------------------------


def sign_skill_manifest(manifest_path: Path, state_dir: Path) -> tuple[str, str]:
    """Sign a SKILL.md manifest file.

    Returns ``(signature, public_key)`` as base64 strings.
    The content being signed is the SHA-256 hash of the manifest file
    and all code files in the skill directory (same scope as
    ``SkillSpec.compute_hash()``).

    This MUST be called after ``generate_signing_key()``.
    """
    content_hash = _compute_skill_content_hash(manifest_path)
    signature = sign_content(content_hash, state_dir)
    public_key = get_public_key(state_dir)
    return signature, public_key


def verify_skill_manifest(
    manifest_path: Path,
    signature: str,
    public_key: str,
) -> bool:
    """Verify a skill manifest signature.

    Returns ``True`` if the signature is valid for the current content
    of the skill directory.
    """
    if not signature or not public_key:
        return False
    content_hash = _compute_skill_content_hash(manifest_path)
    return verify_signature(content_hash, signature, public_key)


def _compute_skill_content_hash(manifest_path: Path) -> str:
    """Compute a SHA-256 hash of the skill manifest + all code files."""
    h = hashlib.sha256()
    skill_dir = manifest_path.parent

    # Hash manifest
    if manifest_path.exists():
        h.update(manifest_path.read_bytes())

    # Hash code files
    for pattern in (
        "*.py",
        "*.sh",
        "*.bash",
        "*.js",
        "*.json",
        "*.yaml",
        "*.yml",
        "*.toml",
        "requirements.txt",
    ):
        for f in sorted(skill_dir.glob(pattern)):
            if not f.is_symlink() and f.is_file():
                h.update(f.read_bytes())

    # Hash scripts/ directory
    scripts_dir = skill_dir / "scripts"
    if scripts_dir.exists():
        for f in sorted(scripts_dir.rglob("*")):
            if f.is_file() and not f.is_symlink():
                h.update(f.read_bytes())

    return h.hexdigest()


def is_builtin_public_key(public_key_b64: str) -> bool:
    """Check whether a public key belongs to the built-in whitelist."""
    return public_key_b64 in _BUILTIN_PUBLIC_KEYS
