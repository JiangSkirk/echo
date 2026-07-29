"""Secret detection, redaction, and encrypted storage."""

from __future__ import annotations

import base64
import hashlib
import hmac
import importlib
import json
import os
import re
import stat
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, ClassVar

from cryptography.fernet import Fernet, InvalidToken

from js.utils.db import db_connection


class SecretManager:
    """Manages secret detection, redaction, and encrypted storage."""

    # Patterns for common secrets
    PATTERNS = {
        "openai_key": re.compile(r"sk-[a-zA-Z0-9]{20,60}"),
        "anthropic_key": re.compile(r"sk-ant-[a-zA-Z0-9_-]{20,100}"),
        "generic_api_key": re.compile(
            r"[a-zA-Z0-9_-]*[aA][pP][iI][_-]?[kK][eE][yY]\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{16,})['\"]?"
        ),
        "aws_key": re.compile(r"AKIA[0-9A-Z]{16}"),
        "github_token": re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,}"),
        "jwt": re.compile(r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*"),
        "password": re.compile(
            r"[pP][aA][sS][sS][wW][oO][rR][dD]\s*[:=]\s*['\"]?([^'\"\s]{8,})['\"]?"
        ),
        "token": re.compile(r"[tT][oO][kK][eE][nN]\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{16,})['\"]?"),
    }

    _init_lock = threading.RLock()
    _KDF_HEADER = b"JSS1"
    _KDF_ITERATIONS = 600_000
    _LEGACY_KDF_ITERATIONS = 100_000
    _KDF_JOURNAL_NAME = ".secret_kdf_migrate.journal"
    # Test-only one-shot fault injection. Production never sets this.
    _migration_fault_point: ClassVar[str | None] = None

    def __init__(
        self,
        state_dir: Path,
        master_key: str | None = None,
        *,
        require_encryption: bool = True,
    ) -> None:
        self.state_dir = state_dir
        self.db_path = state_dir / "secrets.db"
        self._require_encryption = bool(require_encryption)
        self._init_db()
        self._fernet, self._key_material = self._init_fernet(master_key)
        self._redaction_cache: set[str] = set()

    def _init_db(self) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.state_dir, 0o700)
        with db_connection(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS secrets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    value_encrypted BLOB NOT NULL,
                    category TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS detected_leaks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source TEXT,
                    secret_hash TEXT,
                    secret_type TEXT,
                    redacted_preview TEXT,
                    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()

    def _init_fernet(self, master_key: str | None) -> tuple[Fernet, bytes]:
        key_path = self.state_dir / ".secret_key"
        salt_path = self.state_dir / ".secret_salt"
        if master_key:
            with self._init_lock, self._secret_material_lock():
                recovered = self._recover_kdf_migration(master_key=master_key, salt_path=salt_path)
                if recovered is not None:
                    return recovered
                encoded_salt = self._load_or_create_kdf_salt(salt_path)
            if len(encoded_salt) == 16:
                salt = encoded_salt
                iterations = self._LEGACY_KDF_ITERATIONS
                legacy = True
            elif len(encoded_salt) == 24 and encoded_salt.startswith(self._KDF_HEADER):
                iterations = int.from_bytes(encoded_salt[4:8], "big")
                if iterations < self._LEGACY_KDF_ITERATIONS:
                    raise ValueError("secret KDF iteration count is below the supported minimum")
                salt = encoded_salt[8:]
                legacy = iterations < self._KDF_ITERATIONS
            else:
                raise ValueError("invalid secret KDF salt metadata")
            key = hashlib.pbkdf2_hmac(
                "sha256",
                master_key.encode(),
                salt,
                iterations,
                dklen=32,
            )
            fernet_key = base64.urlsafe_b64encode(key)
            fernet = Fernet(fernet_key)
            if legacy:
                fernet, key = self._migrate_legacy_kdf(
                    master_key=master_key,
                    salt_path=salt_path,
                    old_fernet=fernet,
                    old_encoded=encoded_salt,
                )
            return fernet, key

        with self._init_lock, self._secret_material_lock():
            if key_path.exists() or key_path.is_symlink():
                key = self._read_private_file(key_path)
                return Fernet(key), key

            key = Fernet.generate_key()
            fd = os.open(str(key_path), os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o600)
            try:
                os.fchmod(fd, 0o600)
                with os.fdopen(fd, "wb") as handle:
                    fd = -1
                    handle.write(key)
                    handle.flush()
                    os.fsync(handle.fileno())
            finally:
                if fd >= 0:
                    os.close(fd)
            self._fsync_state_directory()
            return Fernet(key), key

    def derive_mac_key(self, purpose: str) -> bytes:
        """Derive a purpose-scoped MAC key from the master secret material.

        The derived key never exposes the Fernet master key itself, and each
        purpose label produces an independent key domain so MAC keys cannot be
        confused across subsystems.  The key is stable across restarts for the
        same installation, which is required for verifying persisted chains.
        """
        if not purpose.strip():
            raise ValueError("MAC key purpose must not be empty")
        return hmac.new(
            self._key_material,
            f"js-secret-manager-mac-v1:{purpose}".encode(),
            hashlib.sha256,
        ).digest()

    def _load_or_create_kdf_salt(self, path: Path) -> bytes:
        if path.exists() or path.is_symlink():
            return self._read_private_file(path)
        salt = os.urandom(16)
        encoded = self._KDF_HEADER + self._KDF_ITERATIONS.to_bytes(4, "big") + salt
        fd = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o600)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as handle:
                fd = -1
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
        finally:
            if fd >= 0:
                os.close(fd)
        self._fsync_state_directory()
        return encoded

    @contextmanager
    def _secret_material_lock(self) -> Iterator[None]:
        lock_path = self.state_dir / ".secret_material.lock"
        flags = os.O_CREAT | os.O_RDWR
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        lock_fd = os.open(lock_path, flags, 0o600)
        try:
            metadata = os.fstat(lock_fd)
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError(f"secret material lock must be a regular file: {lock_path}")
            os.fchmod(lock_fd, 0o600)
            self._acquire_file_lock(lock_fd)
            try:
                yield
            finally:
                self._release_file_lock(lock_fd)
        finally:
            os.close(lock_fd)

    @staticmethod
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

    @staticmethod
    def _release_file_lock(lock_fd: int) -> None:
        if os.name == "nt":
            msvcrt: Any = importlib.import_module("msvcrt")
            os.lseek(lock_fd, 0, os.SEEK_SET)
            msvcrt.locking(lock_fd, msvcrt.LK_UNLCK, 1)
            return
        fcntl: Any = importlib.import_module("fcntl")
        fcntl.flock(lock_fd, fcntl.LOCK_UN)

    def _fsync_state_directory(self) -> None:
        directory_fd = os.open(self.state_dir, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)

    @staticmethod
    def _read_private_file(path: Path) -> bytes:
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(path, flags)
        except OSError as exc:
            raise ValueError(f"secret key material must be a regular file: {path}") from exc
        try:
            metadata = os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError(f"secret key material must be a regular file: {path}")
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "rb") as handle:
                fd = -1
                return handle.read()
        finally:
            if fd >= 0:
                os.close(fd)

    def store(self, name: str, value: str, category: str = "general") -> None:
        """Store a secret securely."""
        encrypted = self._fernet.encrypt(value.encode())
        with db_connection(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO secrets (name, value_encrypted, category)
                VALUES (?, ?, ?)
                ON CONFLICT(name) DO UPDATE SET
                    value_encrypted=excluded.value_encrypted,
                    category=excluded.category,
                    updated_at=CURRENT_TIMESTAMP
                """,
                (name, encrypted, category),
            )
            conn.commit()

    def retrieve(self, name: str) -> str | None:
        """Retrieve a secret by name."""
        with db_connection(self.db_path) as conn:
            row = conn.execute(
                "SELECT value_encrypted FROM secrets WHERE name = ?", (name,)
            ).fetchone()
        if row:
            return self._fernet.decrypt(row[0]).decode()
        return None

    def delete(self, name: str) -> bool:
        """Delete one stored secret and report whether it existed."""
        with db_connection(self.db_path) as conn:
            cursor = conn.execute("DELETE FROM secrets WHERE name = ?", (name,))
            conn.commit()
            return cursor.rowcount > 0

    _BLOB_PREFIX: bytes = b"ENC:v1:"  # Version tag for encrypted blobs

    def encrypt_blob(self, data: bytes) -> bytes:
        """Encrypt arbitrary binary data with the Fernet key.

        Prepends a version tag so that ``decrypt_blob`` can distinguish
        encrypted payloads from pre-upgrade plaintext data.
        """
        return self._BLOB_PREFIX + self._fernet.encrypt(data)

    def decrypt_blob(self, data: bytes) -> bytes:
        """Decrypt data previously encrypted with ``encrypt_blob``.

        Legacy plaintext blobs are rejected by default. Callers that must
        accept pre-encryption data must construct the manager with
        ``require_encryption=False``.
        """
        if not data.startswith(self._BLOB_PREFIX):
            if self._require_encryption:
                raise ValueError("legacy plaintext blob rejected; encryption required")
            return data  # Explicit opt-out for migration tooling
        return self._fernet.decrypt(data[len(self._BLOB_PREFIX) :])

    def _kdf_journal_path(self) -> Path:
        return self.state_dir / self._KDF_JOURNAL_NAME

    @classmethod
    def _maybe_migration_fault(cls, point: str) -> None:
        """Raise once when tests inject a crash at ``point``."""
        if cls._migration_fault_point == point:
            cls._migration_fault_point = None
            raise RuntimeError(f"injected kdf migration fault: {point}")

    @classmethod
    def _fernet_from_encoded_salt(
        cls, master_key: str, encoded: bytes
    ) -> tuple[Fernet, bytes, bytes]:
        """Derive Fernet + raw key material from a salt file blob.

        Returns ``(fernet, key_material, salt_bytes)``.
        """
        if len(encoded) == 16:
            salt = encoded
            iterations = cls._LEGACY_KDF_ITERATIONS
        elif len(encoded) == 24 and encoded.startswith(cls._KDF_HEADER):
            iterations = int.from_bytes(encoded[4:8], "big")
            if iterations < cls._LEGACY_KDF_ITERATIONS:
                raise ValueError("secret KDF iteration count is below the supported minimum")
            salt = encoded[8:]
        else:
            raise ValueError("invalid secret KDF salt metadata")
        key = hashlib.pbkdf2_hmac(
            "sha256",
            master_key.encode(),
            salt,
            iterations,
            dklen=32,
        )
        return Fernet(base64.urlsafe_b64encode(key)), key, salt

    def _write_kdf_journal(
        self,
        *,
        old_encoded: bytes,
        new_encoded: bytes,
        phase: str,
    ) -> None:
        payload = {
            "version": 1,
            "phase": phase,
            "old_salt": base64.b64encode(old_encoded).decode("ascii"),
            "new_salt": base64.b64encode(new_encoded).decode("ascii"),
        }
        raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        journal_path = self._kdf_journal_path()
        tmp_path = journal_path.with_name(
            f".{journal_path.name}.tmp-{os.getpid()}-{os.urandom(4).hex()}"
        )
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(str(tmp_path), os.O_CREAT | os.O_WRONLY | os.O_EXCL | nofollow, 0o600)
        try:
            os.fchmod(fd, 0o600)
            os.write(fd, raw)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp_path, journal_path)
        self._fsync_state_directory()

    def _read_kdf_journal(self) -> dict[str, Any] | None:
        journal_path = self._kdf_journal_path()
        if not (journal_path.exists() or journal_path.is_symlink()):
            return None
        raw = self._read_private_file(journal_path)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("corrupt secret KDF migration journal") from exc
        if not isinstance(payload, dict) or int(payload.get("version", 0)) != 1:
            raise ValueError("unsupported secret KDF migration journal")
        for field in ("phase", "old_salt", "new_salt"):
            if field not in payload or not isinstance(payload[field], str):
                raise ValueError("invalid secret KDF migration journal")
        return payload

    def _clear_kdf_journal(self) -> None:
        journal_path = self._kdf_journal_path()
        try:
            journal_path.unlink(missing_ok=True)
        except OSError:
            pass
        self._fsync_state_directory()

    def _publish_kdf_salt(self, salt_path: Path, encoded: bytes) -> None:
        tmp_path = salt_path.with_name(
            f".{salt_path.name}.migrate-{os.getpid()}-{os.urandom(4).hex()}"
        )
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(str(tmp_path), os.O_CREAT | os.O_WRONLY | os.O_EXCL | nofollow, 0o600)
        try:
            os.fchmod(fd, 0o600)
            os.write(fd, encoded)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp_path, salt_path)
        self._fsync_state_directory()

    def _secrets_decryptable(self, fernet: Fernet) -> bool:
        with db_connection(self.db_path) as conn:
            rows = conn.execute("SELECT value_encrypted FROM secrets").fetchall()
        if not rows:
            return True
        for (blob,) in rows:
            try:
                fernet.decrypt(blob)
            except InvalidToken:
                return False
        return True

    def _recover_kdf_migration(
        self,
        *,
        master_key: str,
        salt_path: Path,
    ) -> tuple[Fernet, bytes] | None:
        """Replay an interrupted KDF migration journal (dual-key window).

        Crash after re-encrypt but before salt publish leaves old salt on disk
        and new ciphertext in SQLite; the journal carries the new salt so
        restart can finish the swap. Crash after salt publish leaves the
        journal for cleanup. In all recoverable states plaintext remains
        readable.
        """
        journal = self._read_kdf_journal()
        if journal is None:
            return None

        old_encoded = base64.b64decode(journal["old_salt"])
        new_encoded = base64.b64decode(journal["new_salt"])
        old_fernet, _old_key, _ = self._fernet_from_encoded_salt(master_key, old_encoded)
        new_fernet, new_key, _ = self._fernet_from_encoded_salt(master_key, new_encoded)

        published = (
            self._read_private_file(salt_path)
            if (salt_path.exists() or salt_path.is_symlink())
            else None
        )

        if published == new_encoded:
            if not self._secrets_decryptable(new_fernet):
                raise ValueError("KDF migration journal/salt mismatch after salt publish")
            self._clear_kdf_journal()
            return new_fernet, new_key

        if published is not None and published != old_encoded:
            raise ValueError("KDF migration journal does not match published salt")

        if self._secrets_decryptable(new_fernet):
            self._write_kdf_journal(
                old_encoded=old_encoded,
                new_encoded=new_encoded,
                phase="reencrypted",
            )
            self._publish_kdf_salt(salt_path, new_encoded)
            self._maybe_migration_fault("after_salt_publish")
            self._clear_kdf_journal()
            return new_fernet, new_key

        if self._secrets_decryptable(old_fernet):
            # Intent only — ciphertext still under the old key; drop journal so
            # legacy migration can run again cleanly.
            self._clear_kdf_journal()
            return None

        raise ValueError("KDF migration journal is not recoverable")

    def _migrate_legacy_kdf(
        self,
        *,
        master_key: str,
        salt_path: Path,
        old_fernet: Fernet,
        old_encoded: bytes,
    ) -> tuple[Fernet, bytes]:
        """Upgrade a 100K (or otherwise below-target) salt to JSS1/600K and re-encrypt.

        Crash-safe via a replayable migration journal:

        1. Write intent journal (old + new salt metadata).
        2. Re-encrypt ciphertext under the new key while the published salt
           remains the old one (dual-key window).
        3. Atomically publish the new salt.
        4. Clear the journal.

        A crash at any step leaves secrets decryptable after restart by
        replaying the journal or continuing under the old salt.
        """
        with self._init_lock, self._secret_material_lock():
            recovered = self._recover_kdf_migration(master_key=master_key, salt_path=salt_path)
            if recovered is not None:
                return recovered

            current = (
                self._read_private_file(salt_path)
                if (salt_path.exists() or salt_path.is_symlink())
                else old_encoded
            )
            if (
                len(current) == 24
                and current.startswith(self._KDF_HEADER)
                and int.from_bytes(current[4:8], "big") >= self._KDF_ITERATIONS
            ):
                fernet, key, _ = self._fernet_from_encoded_salt(master_key, current)
                return fernet, key

            rows: list[tuple[str, bytes, str | None]] = []
            with db_connection(self.db_path) as conn:
                for name, value_encrypted, category in conn.execute(
                    "SELECT name, value_encrypted, category FROM secrets"
                ):
                    plaintext = old_fernet.decrypt(value_encrypted)
                    rows.append((name, plaintext, category))

            new_salt = os.urandom(16)
            new_encoded = self._KDF_HEADER + self._KDF_ITERATIONS.to_bytes(4, "big") + new_salt
            new_fernet, new_key, _ = self._fernet_from_encoded_salt(master_key, new_encoded)
            journal_old = current if len(current) in {16, 24} else old_encoded

            # 1) Durable intent: both salts known before any ciphertext change.
            self._write_kdf_journal(
                old_encoded=journal_old,
                new_encoded=new_encoded,
                phase="intent",
            )
            self._maybe_migration_fault("after_journal")

            # 2) Encrypt-then-salt-swap: re-encrypt under dual-key window.
            updates = [
                (new_fernet.encrypt(plaintext), category, name)
                for name, plaintext, category in rows
            ]
            with db_connection(self.db_path) as conn:
                for encrypted, category, name in updates:
                    conn.execute(
                        """
                        UPDATE secrets
                        SET value_encrypted = ?, category = COALESCE(?, category),
                            updated_at = CURRENT_TIMESTAMP
                        WHERE name = ?
                        """,
                        (encrypted, category, name),
                    )
                self._maybe_migration_fault("after_ciphertext_update")
                self._maybe_migration_fault("before_commit")
                conn.commit()

            self._write_kdf_journal(
                old_encoded=journal_old,
                new_encoded=new_encoded,
                phase="reencrypted",
            )

            # 3) Publish new salt only after ciphertext is durable.
            self._maybe_migration_fault("before_salt_publish")
            self._publish_kdf_salt(salt_path, new_encoded)
            self._maybe_migration_fault("after_salt_publish")

            # 4) Drop journal — migration complete.
            self._clear_kdf_journal()
            return new_fernet, new_key

    def detect_and_redact(self, text: str, source: str = "unknown") -> str:
        """Detect secrets in text and replace with [REDACTED]."""
        result = text
        for secret_type, pattern in self.PATTERNS.items():
            for match in pattern.finditer(text):
                secret_value = match.group(0)
                secret_hash = hashlib.sha256(secret_value.encode()).hexdigest()[:16]

                if secret_hash not in self._redaction_cache:
                    self._redaction_cache.add(secret_hash)
                    # Limit cache size to prevent unbounded growth
                    if len(self._redaction_cache) > 10_000:
                        self._redaction_cache.clear()
                    self._log_detection(source, secret_hash, secret_type, secret_value)

                result = result.replace(secret_value, f"[REDACTED:{secret_type}]")
        return result

    def _log_detection(self, source: str, secret_hash: str, secret_type: str, value: str) -> None:
        # Never store partial secret values — only the type and hash.
        preview = f"[{secret_type}]"
        with db_connection(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO detected_leaks (source, secret_hash, secret_type, redacted_preview)
                VALUES (?, ?, ?, ?)
                """,
                (source, secret_hash, secret_type, preview),
            )
            conn.commit()

    def get_stats(self) -> dict[str, int]:
        """Return statistics about stored secrets and detections."""
        with db_connection(self.db_path) as conn:
            secret_count = conn.execute("SELECT COUNT(*) FROM secrets").fetchone()[0]
            leak_count = conn.execute("SELECT COUNT(*) FROM detected_leaks").fetchone()[0]
        return {"stored_secrets": secret_count, "detected_leaks": leak_count}


def redact_known_secrets(text: str) -> str:
    """Redact built-in secret shapes without requiring a stateful manager."""
    redacted = text
    for secret_type, pattern in SecretManager.PATTERNS.items():
        redacted = pattern.sub(f"[REDACTED:{secret_type}]", redacted)
    return redacted


class StreamingSecretRedactor:
    """Incrementally redact secrets without leaking cross-chunk matches.

    Normal text is emitted immediately. Only suffixes that can still become a
    supported secret are retained, keeping first-token latency unchanged for
    ordinary output while preventing provider chunk boundaries from bypassing
    :class:`SecretManager` patterns.
    """

    _MAX_PENDING = 4096
    _LITERAL_CANDIDATES: tuple[tuple[str, str], ...] = (
        ("sk-ant-", r"[A-Za-z0-9_-]"),
        ("sk-", r"[A-Za-z0-9_-]"),
        ("AKIA", r"[0-9A-Z]"),
        ("ghp_", r"[A-Za-z0-9_]"),
        ("gho_", r"[A-Za-z0-9_]"),
        ("ghu_", r"[A-Za-z0-9_]"),
        ("ghs_", r"[A-Za-z0-9_]"),
        ("ghr_", r"[A-Za-z0-9_]"),
        ("eyJ", r"[A-Za-z0-9_.-]"),
    )
    _LABEL_PREFIXES = ("api_key", "api-key", "apikey", "password", "token")
    _LABEL_CANDIDATE = re.compile(
        r"(?i)(?:[A-Za-z0-9_-]*api[_-]?key|password|token)"
        r"\s*[:=]\s*['\"]?[^\s'\"]*$"
    )
    _CONTINUATION_PATTERNS = {
        "openai_key": re.compile(r"[A-Za-z0-9]"),
        "anthropic_key": re.compile(r"[A-Za-z0-9_-]"),
        "generic_api_key": re.compile(r"[A-Za-z0-9_-]"),
        "aws_key": re.compile(r"[0-9A-Z]"),
        "github_token": re.compile(r"[A-Za-z0-9_]"),
        "jwt": re.compile(r"[A-Za-z0-9_.-]"),
        "password": re.compile(r"[^\s'\"]"),
        "token": re.compile(r"[A-Za-z0-9_-]"),
        "possible_secret": re.compile(r"[^\s'\"]"),
    }

    def __init__(self, manager: Any, source: str) -> None:
        self._manager = manager
        self._source = source
        self._pending = ""
        self._suppress_type: str | None = None

    def feed(self, text: str) -> str:
        if not text:
            return ""
        self._pending += text
        return self._drain(final=False)

    def flush(self) -> str:
        return self._drain(final=True)

    def discard(self) -> None:
        self._pending = ""
        self._suppress_type = None

    def _drain(self, *, final: bool) -> str:
        emitted: list[str] = []
        while self._pending:
            if self._suppress_type is not None:
                boundary = self._suppression_boundary(self._pending, self._suppress_type)
                if boundary is None:
                    self._pending = ""
                    break
                self._pending = self._pending[boundary:]
                self._suppress_type = None
                continue

            first_match = self._first_match(self._pending)
            if first_match is not None:
                secret_type, match = first_match
                if match.start() > 0:
                    emitted.append(
                        self._manager.detect_and_redact(
                            self._pending[: match.start()], self._source
                        )
                    )
                matched = self._pending[match.start() : match.end()]
                marker = self._manager.detect_and_redact(matched, self._source)
                if marker == matched:
                    marker = f"[REDACTED:{secret_type}]"
                emitted.append(marker)

                end = match.end()
                continuation = self._CONTINUATION_PATTERNS[secret_type]
                while end < len(self._pending) and continuation.fullmatch(self._pending[end]):
                    end += 1
                reached_open_end = end == len(self._pending)
                self._pending = self._pending[end:]
                if reached_open_end:
                    self._suppress_type = secret_type
                continue

            custom_redacted = self._manager.detect_and_redact(self._pending, self._source)
            if custom_redacted != self._pending:
                emitted.append(custom_redacted)
                self._pending = ""
                break

            if final:
                emitted.append(self._pending)
                self._pending = ""
                break

            candidate_start = self._potential_secret_start(self._pending)
            if candidate_start is None:
                emitted.append(self._pending)
                self._pending = ""
                break
            if candidate_start > 0:
                emitted.append(self._pending[:candidate_start])
                self._pending = self._pending[candidate_start:]
            if len(self._pending) > self._MAX_PENDING:
                emitted.append("[REDACTED:possible_secret]")
                self._pending = ""
                self._suppress_type = "possible_secret"
            break
        if final:
            self._pending = ""
            self._suppress_type = None
        return "".join(emitted)

    def _first_match(self, text: str) -> tuple[str, re.Match[str]] | None:
        patterns = getattr(self._manager, "PATTERNS", SecretManager.PATTERNS)
        matches: list[tuple[str, re.Match[str]]] = []
        for secret_type, pattern in patterns.items():
            match = pattern.search(text)
            if match is not None:
                matches.append((str(secret_type), match))
        if not matches:
            return None
        return min(matches, key=lambda item: (item[1].start(), -item[1].end()))

    @classmethod
    def _potential_secret_start(cls, text: str) -> int | None:
        starts: list[int] = []
        for prefix, continuation_pattern in cls._LITERAL_CANDIDATES:
            candidate = re.search(
                re.escape(prefix) + continuation_pattern + r"*$",
                text,
            )
            if candidate is not None:
                starts.append(candidate.start())
            for length in range(1, len(prefix)):
                if text.endswith(prefix[:length]):
                    starts.append(len(text) - length)

        label_match = cls._LABEL_CANDIDATE.search(text)
        if label_match is not None:
            starts.append(label_match.start())
        lower = text.lower()
        for prefix in cls._LABEL_PREFIXES:
            for length in range(1, len(prefix) + 1):
                if lower.endswith(prefix[:length]):
                    starts.append(len(text) - length)
        return min(starts) if starts else None

    @classmethod
    def _suppression_boundary(cls, text: str, secret_type: str) -> int | None:
        continuation = cls._CONTINUATION_PATTERNS[secret_type]
        for index, char in enumerate(text):
            if continuation.fullmatch(char) is None:
                return index
        return None
