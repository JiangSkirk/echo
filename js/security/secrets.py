"""Secret detection, redaction, and encrypted storage."""

from __future__ import annotations

import hashlib
import os
import re
import threading
from pathlib import Path

from cryptography.fernet import Fernet

from js.utils.db import db_connection


class SecretManager:
    """Manages secret detection, redaction, and encrypted storage."""

    # Patterns for common secrets
    PATTERNS = {
        "openai_key": re.compile(r"sk-[a-zA-Z0-9]{20,60}"),
        "anthropic_key": re.compile(r"sk-ant-[a-zA-Z0-9_-]{20,100}"),
        "generic_api_key": re.compile(r"[a-zA-Z0-9_-]*[aA][pP][iI][_-]?[kK][eE][yY]\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{16,})['\"]?"),
        "aws_key": re.compile(r"AKIA[0-9A-Z]{16}"),
        "github_token": re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,}"),
        "jwt": re.compile(r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*"),
        "password": re.compile(r"[pP][aA][sS][sS][wW][oO][rR][dD]\s*[:=]\s*['\"]?([^'\"\s]{8,})['\"]?"),
        "token": re.compile(r"[tT][oO][kK][eE][nN]\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{16,})['\"]?"),
    }

    _init_lock = threading.Lock()

    def __init__(self, state_dir: Path, master_key: str | None = None) -> None:
        self.state_dir = state_dir
        self.db_path = state_dir / "secrets.db"
        self._init_db()
        self._fernet = self._init_fernet(master_key)
        self._redaction_cache: set[str] = set()

    def _init_db(self) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)
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

    def _init_fernet(self, master_key: str | None) -> Fernet:
        key_path = self.state_dir / ".secret_key"
        salt_path = self.state_dir / ".secret_salt"
        if master_key:
            import base64

            with self._init_lock:
                # PBKDF2 with SHA-256 and a random salt persisted to disk.
                if salt_path.exists():
                    salt = salt_path.read_bytes()
                else:
                    salt = os.urandom(16)
                    fd = os.open(
                        str(salt_path), os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o600
                    )
                    try:
                        os.write(fd, salt)
                    finally:
                        os.close(fd)
                key = hashlib.pbkdf2_hmac("sha256", master_key.encode(), salt, 100_000, dklen=32)
                fernet_key = base64.urlsafe_b64encode(key)
                return Fernet(fernet_key)

        with self._init_lock:
            if key_path.exists():
                with open(key_path, "rb") as f:
                    return Fernet(f.read())

            key = Fernet.generate_key()
            # Atomic create with O_EXCL to avoid TOCTOU race between check and write
            fd = os.open(
                str(key_path), os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o600
            )
            try:
                os.write(fd, key)
            finally:
                os.close(fd)
            return Fernet(key)

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

    _BLOB_PREFIX: bytes = b"ENC:v1:"  # Version tag for encrypted blobs

    def encrypt_blob(self, data: bytes) -> bytes:
        """Encrypt arbitrary binary data with the Fernet key.

        Prepends a version tag so that ``decrypt_blob`` can distinguish
        encrypted payloads from pre-upgrade plaintext data.
        """
        return self._BLOB_PREFIX + self._fernet.encrypt(data)

    def decrypt_blob(self, data: bytes) -> bytes:
        """Decrypt data previously encrypted with ``encrypt_blob``.

        If the data does not carry the version prefix, it is assumed to be
        legacy plaintext and returned unchanged.  This provides seamless
        backward compatibility with data written before encryption was
        introduced.
        """
        if not data.startswith(self._BLOB_PREFIX):
            return data  # Legacy plaintext — return as-is
        return self._fernet.decrypt(data[len(self._BLOB_PREFIX) :])

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
