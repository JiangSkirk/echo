"""Web API authentication and authorization.

Supports API key authentication with role-based access control.
Keys are stored as SHA-256 hashes (the plaintext is shown once on creation).
"""

from __future__ import annotations

import hashlib
import secrets
import time
from pathlib import Path
from typing import Any

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader

from js.exceptions import AuthRequiredError
from js.utils.db import db_connection
from js.utils.log import get_logger

logger = get_logger("js.web.auth")

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

_ADMIN_ROLE = "admin"
_USER_ROLE = "user"


def _hash_key(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def _generate_key() -> str:
    """Generate a cryptographically secure API key."""
    return "js_" + secrets.token_urlsafe(32)


class AuthManager:
    """Manage API keys and role-based access."""

    def __init__(self, state_dir: Path) -> None:
        self._db_path = state_dir / "api_keys.db"
        self._init_db()

    def _init_db(self) -> None:
        with db_connection(self._db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS api_keys (
                    key_hash TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'user',
                    created_at REAL NOT NULL,
                    last_used REAL,
                    enabled INTEGER NOT NULL DEFAULT 1
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_api_keys_enabled
                ON api_keys(enabled)
                """
            )
            conn.commit()

    # ------------------------------------------------------------------
    # Key lifecycle
    # ------------------------------------------------------------------

    def create_key(self, name: str, role: str = _USER_ROLE) -> str:
        """Generate and persist a new API key. Returns the plaintext (shown once)."""
        plaintext = _generate_key()
        key_hash = _hash_key(plaintext)
        now = time.time()
        with db_connection(self._db_path) as conn:
            conn.execute(
                "INSERT INTO api_keys (key_hash, name, role, created_at, enabled) VALUES (?, ?, ?, ?, 1)",
                (key_hash, name, role, now),
            )
            conn.commit()
        logger.info(f"Created API key '{name}' with role '{role}'")
        return plaintext

    def list_keys(self) -> list[dict[str, Any]]:
        """Return metadata for all keys (plaintext is never returned)."""
        with db_connection(self._db_path) as conn:
            rows = conn.execute(
                """
                SELECT key_hash, name, role, created_at, last_used, enabled
                FROM api_keys ORDER BY created_at DESC
                """
            ).fetchall()
        return [
            {
                "id": r[0][:16] + "...",  # truncated hash for display
                "name": r[1],
                "role": r[2],
                "created_at": r[3],
                "last_used": r[4],
                "enabled": bool(r[5]),
            }
            for r in rows
        ]

    def revoke_key(self, key_hash_prefix: str) -> bool:
        """Revoke a key by hash prefix."""
        with db_connection(self._db_path) as conn:
            cur = conn.execute(
                "DELETE FROM api_keys WHERE key_hash LIKE ?",
                (key_hash_prefix + "%",),
            )
            conn.commit()
            return cur.rowcount > 0

    def verify(self, key: str | None) -> dict[str, Any]:
        """Verify an API key and return its metadata.

        Raises AuthRequiredError if key is missing or invalid.
        """
        if not key:
            raise AuthRequiredError("X-API-Key header is required")

        key_hash = _hash_key(key)
        with db_connection(self._db_path) as conn:
            row = conn.execute(
                "SELECT name, role, enabled FROM api_keys WHERE key_hash = ?",
                (key_hash,),
            ).fetchone()

        if row is None:
            raise AuthRequiredError("Invalid API key")

        name, role, enabled = row
        if not enabled:
            raise AuthRequiredError("API key has been revoked")

        # Update last_used (best-effort, don't fail if DB is locked)
        try:
            with db_connection(self._db_path) as conn:
                conn.execute(
                    "UPDATE api_keys SET last_used = ? WHERE key_hash = ?",
                    (time.time(), key_hash),
                )
                conn.commit()
        except Exception:
            logger.warning("Failed to update last_used for API key", exc_info=True)

        return {"name": name, "role": role}

    def has_admin(self) -> bool:
        """Check whether at least one admin key exists."""
        with db_connection(self._db_path) as conn:
            row = conn.execute(
                "SELECT 1 FROM api_keys WHERE role = ? AND enabled = 1 LIMIT 1",
                (_ADMIN_ROLE,),
            ).fetchone()
        return row is not None


# ----------------------------------------------------------------------
# FastAPI dependency helpers
# ----------------------------------------------------------------------

async def require_auth(
    api_key: str | None = Security(api_key_header),
) -> dict[str, Any]:
    """FastAPI dependency: verify API key.

    If authentication is disabled in settings, returns a guest context.
    """
    # Lazy import to avoid circular deps at module load time
    from js.web.server import _settings as global_settings

    effective_settings = global_settings
    if effective_settings is None:
        # During lifespan startup before settings are loaded — allow through
        return {"name": "startup", "role": _ADMIN_ROLE}

    if not effective_settings.security.api_key_required:
        return {"name": "anonymous", "role": _ADMIN_ROLE}

    # If no admin key exists yet, bootstrap: first call creates the default key
    auth_mgr = AuthManager(effective_settings.state_dir)
    if not auth_mgr.has_admin():
        # During bootstrap window, any key is accepted if one hasn't been created
        # This allows the first setup to proceed
        return {"name": "bootstrap", "role": _ADMIN_ROLE}

    return auth_mgr.verify(api_key)


# Alias for backward compatibility and router imports
require_auth_dep = require_auth


async def require_admin(
    auth_ctx: dict[str, Any] = Depends(require_auth_dep),
) -> dict[str, Any]:
    """FastAPI dependency: require admin role."""
    if auth_ctx.get("role") != _ADMIN_ROLE:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin role required",
        )
    return auth_ctx


class AuthMiddleware:
    """Optional middleware that applies auth to all routes.

    Not used directly — we use Depends() per-route for finer control.
    """

    pass
