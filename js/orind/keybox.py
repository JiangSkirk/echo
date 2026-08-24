"""orind KeyBox: lease HMAC key custody with legacy adoption.

Decision (Stage A, frozen): the first orind start *adopts without rotating*.

- KeyBox empty + legacy ``<state_dir>/echo_tool_lease.key`` exists →
  import that same 32-byte HMAC via the existing strict-read discipline
  (the same hardening as ``js.agent.tool_executor._read_tool_lease_key_strict``:
  lstat/fstat identity, no symlinks, single hardlink, mandatory 0600 mode).
  The legacy JSONL ledger is then replayed as-is by the gatekeeper — no
  re-signing, no pre-image changes to ``authority-hmac-sha256:`` records.
- No legacy file → a fresh key may be generated.
- KeyBox key disagrees with an existing legacy file → refuse to start.
- Adoption records a key fingerprint for idempotency; the legacy key file
  is NEVER deleted in Stage A so ``orin_enabled=false`` rollback still works.
- Tiers: ``dev`` = 0600 key file. ``production`` = macOS Keychain controlled
  extraction via the ``security`` CLI (spike); any Keychain failure falls
  back to the dev tier with a logged warning. Secure Enclave HMAC is not
  supported and is not pretended to be.
"""

from __future__ import annotations

import hashlib
import os
import secrets
import stat
import subprocess
from pathlib import Path

from js.orind.private_paths import (
    PrivatePathError,
    ensure_private_dir,
    read_private_file,
    verify_private_file,
    write_private_file_exclusive,
)

KEYBOX_DIR_NAME = "orin"
KEYBOX_FILE_NAME = "keybox.key"
KEYBOX_FINGERPRINT_NAME = "keybox.fp"
LEGACY_KEY_NAME = "echo_tool_lease.key"
KEYCHAIN_SERVICE = "com.js-agent.orin.lease-key"
KEYCHAIN_ACCOUNT = "orind"
KEY_BYTES = 32


class KeyBoxError(Exception):
    """KeyBox cannot be initialized; orind must refuse to start."""


def _read_key_strict(path: Path, *, strict_paths: bool = False) -> bytes:
    """Read a 32-byte hex key file with full hardening.

    Mirrors ``js.agent.tool_executor._read_tool_lease_key_strict`` (kept as a
    local copy so orind never imports the heavy agent module).
    """

    if strict_paths:
        try:
            encoded = read_private_file(path, max_bytes=128).decode("utf-8").strip()
        except (OSError, UnicodeError, PrivatePathError) as exc:
            raise KeyBoxError(f"invalid key file {path}: expected a private 32-byte key file") from exc
        return _decode_key(path, encoded)

    try:
        metadata = path.lstat()
    except OSError as exc:
        raise KeyBoxError(f"invalid key file {path}: expected a 32-byte key file") from exc
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise KeyBoxError(f"invalid key file {path}: expected a 32-byte regular file")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(fd)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino)
        ):
            raise KeyBoxError(f"invalid key file {path}: key file changed while opening")
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "r", encoding="utf-8") as handle:
            fd = -1
            encoded = handle.read().strip()
        current = path.lstat()
        if (
            stat.S_ISLNK(current.st_mode)
            or current.st_nlink != 1
            or (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino)
        ):
            raise KeyBoxError(f"invalid key file {path}: key file changed while reading")
    finally:
        if fd >= 0:
            os.close(fd)
    if stat.S_IMODE(current.st_mode) != 0o600:
        raise KeyBoxError(f"invalid key file {path}: expected mode 0600")
    return _decode_key(path, encoded)


def _decode_key(path: Path, encoded: str) -> bytes:
    try:
        key = bytes.fromhex(encoded)
    except ValueError as exc:
        raise KeyBoxError(f"invalid key file {path}: expected 32-byte hexadecimal data") from exc
    if len(encoded) != 64 or len(key) != KEY_BYTES:
        raise KeyBoxError(f"invalid key file {path}: expected 32-byte hexadecimal data")
    return key


def _write_key_atomic(path: Path, key: bytes, *, strict_paths: bool = False) -> None:
    """Write a key file 0600 atomically (temp file + fsync + rename)."""

    if strict_paths:
        try:
            write_private_file_exclusive(path, key.hex().encode("ascii"))
        except PrivatePathError as exc:
            raise KeyBoxError(f"cannot publish private key file {path}") from exc
        return

    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp")
    published = False
    try:
        fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(key.hex())
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, path)
        published = True
        os.chmod(path, 0o600)
        dir_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        if not published:
            try:
                tmp_path.unlink()
            except FileNotFoundError:
                pass


def _fingerprint(key: bytes) -> str:
    return hashlib.sha256(b"orin-keybox-fingerprint-v1:" + key).hexdigest()


def _keychain_read(*, security_binary: str = "security") -> bytes | None:
    """Read the lease key from the macOS Keychain via ``security``.

    Returns ``None`` when the item does not exist. Any other failure raises
    so the caller can fall back to the dev tier.
    """

    completed = subprocess.run(
        [
            security_binary,
            "find-generic-password",
            "-a",
            KEYCHAIN_ACCOUNT,
            "-s",
            KEYCHAIN_SERVICE,
            "-w",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        message = (completed.stderr or "").strip()
        if "could not be found" in message.lower():
            return None
        raise KeyBoxError(f"keychain read failed: {message}")
    try:
        key = bytes.fromhex(completed.stdout.strip())
    except ValueError as exc:
        raise KeyBoxError("keychain item is not 32-byte hex data") from exc
    if len(key) != KEY_BYTES:
        raise KeyBoxError("keychain item is not 32-byte hex data")
    return key


def _keychain_write(key: bytes, *, security_binary: str = "security") -> None:
    completed = subprocess.run(
        [
            security_binary,
            "add-generic-password",
            "-a",
            KEYCHAIN_ACCOUNT,
            "-s",
            KEYCHAIN_SERVICE,
            "-w",
            key.hex(),
            "-U",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise KeyBoxError(f"keychain write failed: {(completed.stderr or '').strip()}")


class KeyBox:
    """Custodian of the lease HMAC key. Exactly one tier is active."""

    def __init__(
        self,
        state_dir: Path,
        *,
        tier: str = "dev",
        strict_paths: bool = False,
    ) -> None:
        self._state_dir = state_dir
        self._orin_dir = state_dir / KEYBOX_DIR_NAME
        self._strict_paths = bool(strict_paths)
        if self._strict_paths:
            try:
                ensure_private_dir(self._state_dir)
                ensure_private_dir(self._orin_dir)
            except PrivatePathError as exc:
                raise KeyBoxError(f"invalid private KeyBox directory: {self._orin_dir}") from exc
        else:
            self._orin_dir.mkdir(parents=True, exist_ok=True)
            os.chmod(self._orin_dir, 0o700)
        self._tier = tier
        self._active_tier: str | None = None
        self.adopted_legacy = False
        self._key = self._load_or_create()

    @property
    def active_tier(self) -> str:
        assert self._active_tier is not None
        return self._active_tier

    @property
    def key(self) -> bytes:
        return self._key

    def _load_or_create(self) -> bytes:
        if self._tier == "production" and os.uname().sysname == "Darwin":
            try:
                return self._load_production()
            except KeyBoxError:
                # Spike fallback: honest dev-tier degradation, documented in
                # the daemon log; never pretend the Keychain succeeded.
                self._active_tier = "dev"
                return self._load_dev()
        self._active_tier = "dev"
        return self._load_dev()

    def _load_dev(self) -> bytes:
        key_path = self._orin_dir / KEYBOX_FILE_NAME
        legacy_path = self._state_dir / LEGACY_KEY_NAME
        legacy_key: bytes | None = None
        if legacy_path.exists() or legacy_path.is_symlink():
            legacy_key = _read_key_strict(legacy_path, strict_paths=self._strict_paths)

        if key_path.exists() or key_path.is_symlink():
            key = _read_key_strict(key_path, strict_paths=self._strict_paths)
            if legacy_key is not None and not secrets.compare_digest(key, legacy_key):
                raise KeyBoxError(
                    "keybox key disagrees with legacy echo_tool_lease.key; refusing to start"
                )
            self._verify_fingerprint(key)
            return key

        if legacy_key is not None:
            self.adopted_legacy = True
            _write_key_atomic(key_path, legacy_key, strict_paths=self._strict_paths)
            self._write_fingerprint(legacy_key)
            return legacy_key

        fresh = secrets.token_bytes(KEY_BYTES)
        _write_key_atomic(key_path, fresh, strict_paths=self._strict_paths)
        self._write_fingerprint(fresh)
        # Mirror the fresh key to the legacy location so there is exactly
        # one key per state dir: an ``orin_enabled=false`` rollback must
        # read the same key or the shared JSONL ledger fails MAC replay
        # (fail-closed crash, but a broken rollback nonetheless).
        _write_key_atomic(legacy_path, fresh, strict_paths=self._strict_paths)
        return fresh

    def _load_production(self) -> bytes:
        legacy_path = self._state_dir / LEGACY_KEY_NAME
        legacy_key: bytes | None = None
        if legacy_path.exists() or legacy_path.is_symlink():
            legacy_key = _read_key_strict(legacy_path, strict_paths=self._strict_paths)

        security_binary = "/usr/bin/security" if self._strict_paths else "security"
        keychain_key = _keychain_read(security_binary=security_binary)
        if keychain_key is not None:
            if legacy_key is not None and not secrets.compare_digest(keychain_key, legacy_key):
                raise KeyBoxError(
                    "keychain key disagrees with legacy echo_tool_lease.key; refusing to start"
                )
            self._active_tier = "production"
            return keychain_key
        if legacy_key is not None:
            _keychain_write(legacy_key, security_binary=security_binary)
            self.adopted_legacy = True
            self._active_tier = "production"
            return legacy_key
        fresh = secrets.token_bytes(KEY_BYTES)
        _keychain_write(fresh, security_binary=security_binary)
        # Mirror to the legacy location for the same rollback guarantee as
        # the dev tier (see _load_dev).
        _write_key_atomic(legacy_path, fresh, strict_paths=self._strict_paths)
        self._active_tier = "production"
        return fresh

    def _fingerprint_path(self) -> Path:
        return self._orin_dir / KEYBOX_FINGERPRINT_NAME

    def _write_fingerprint(self, key: bytes) -> None:
        fp_path = self._fingerprint_path()
        if self._strict_paths:
            try:
                write_private_file_exclusive(
                    fp_path,
                    (_fingerprint(key) + "\n").encode("ascii"),
                )
            except PrivatePathError as exc:
                raise KeyBoxError("cannot publish keybox fingerprint") from exc
            return
        fp_path.write_text(_fingerprint(key) + "\n", encoding="utf-8")
        os.chmod(fp_path, 0o600)

    def _verify_fingerprint(self, key: bytes) -> None:
        fp_path = self._fingerprint_path()
        missing = not fp_path.exists()
        if self._strict_paths:
            missing = missing and not fp_path.is_symlink()
        if missing:
            self._write_fingerprint(key)
            return
        if self._strict_paths:
            try:
                identity = verify_private_file(fp_path)
                recorded = read_private_file(
                    fp_path,
                    expected=identity,
                    max_bytes=128,
                ).decode("ascii").strip()
            except (PrivatePathError, UnicodeError) as exc:
                raise KeyBoxError("invalid keybox fingerprint file") from exc
        else:
            recorded = fp_path.read_text(encoding="utf-8").strip()
        if recorded != _fingerprint(key):
            raise KeyBoxError("keybox fingerprint mismatch; refusing to start")


__all__ = ["KEYBOX_DIR_NAME", "KeyBox", "KeyBoxError"]
