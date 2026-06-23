"""Web API authentication and authorization.

Supports API key authentication with role-based access control.
Keys are stored as SHA-256 hashes (the plaintext is shown once on creation).
"""

from __future__ import annotations

import contextvars
import hashlib
import secrets
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from fastapi import Depends, HTTPException, Request, Security, WebSocket, status
from fastapi.security import APIKeyHeader

from js.exceptions import AuthRequiredError
from js.utils.db import db_connection
from js.utils.log import get_logger

# Context variable for session owner key hash (set by Web API layer)
_session_owner_hash: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "session_owner_hash", default=None
)

logger = get_logger("js.web.auth")

__all__ = [
    "AuthManager",
    "require_auth",
    "require_admin",
    "require_user_write",
    "require_admin_write",
    "require_auth_dep",
    "check_origin",
    "memory_owner",
]

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

_ADMIN_ROLE = "admin"
_USER_ROLE = "user"

# Operator-configured origin allowlist (e.g. real domains behind a reverse
# proxy).  Set via JS_ALLOWED_ORIGINS (comma-separated).  When unset, allowed
# origins are derived dynamically from the request's own (loopback) Host header
# so the server works on any bind port without configuration.
_ALLOWED_ORIGINS: frozenset[str] | None = None

# Hostnames the server may legitimately be reached at without an explicit
# JS_ALLOWED_ORIGINS allowlist.  Anything else requires the operator to opt in.
_LOOPBACK_HOSTNAMES = frozenset({"localhost", "127.0.0.1", "::1", "0.0.0.0"})

# HTTP methods that mutate state and therefore require CSRF/Origin protection.
_STATE_CHANGING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def _load_allowed_origins() -> frozenset[str]:
    """Return the operator-configured origin allowlist (empty if unset)."""
    global _ALLOWED_ORIGINS
    if _ALLOWED_ORIGINS is not None:
        return _ALLOWED_ORIGINS
    import os

    env = os.getenv("JS_ALLOWED_ORIGINS", "")
    if env:
        _ALLOWED_ORIGINS = frozenset(o.strip().rstrip("/") for o in env.split(",") if o.strip())
    else:
        _ALLOWED_ORIGINS = frozenset()
    return _ALLOWED_ORIGINS


def _split_host(host: str) -> tuple[str, str | None]:
    """Split a Host header value into (hostname_lower, port_or_None)."""
    host = host.strip()
    if not host:
        return "", None
    if host.startswith("["):  # bracketed IPv6 literal, e.g. [::1]:8000
        end = host.find("]")
        if end != -1:
            rest = host[end + 1 :]
            port = rest[1:] if rest.startswith(":") else None
            return host[1:end].lower(), port
        return host.lower(), None
    if host.count(":") == 1:  # hostname:port
        hostname, _, port = host.partition(":")
        return hostname.lower(), port or None
    return host.lower(), None  # bare hostname / unbracketed IPv6


def _origin_host(value: str) -> str:
    """Reduce an Origin/Referer value to ``scheme://netloc`` (drop any path)."""
    parsed = urlparse(value)
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}"
    return value.rstrip("/")


def check_origin(request: Request | WebSocket) -> None:
    """Validate the Origin/Referer against the server's own Host (anti-CSRF).

    When ``JS_ALLOWED_ORIGINS`` is configured, the Origin must be in that list.
    Otherwise the allowed origins are derived from the request's Host header,
    which must be a loopback name — this couples Origin to Host (defeating Host
    header / DNS-rebinding tricks) while supporting any bind port automatically.

    Raises HTTPException(403) on violation.
    """
    headers = request.headers
    origin_raw = headers.get("origin") or headers.get("referer")
    if not origin_raw:
        # Non-browser clients (CLI, curl) send no Origin — allow if an API key
        # is present, otherwise reject.
        if not headers.get("x-api-key"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Origin header required for browser-based requests",
            )
        return

    origin = _origin_host(origin_raw)
    env_allowed = _load_allowed_origins()

    if env_allowed:
        allowed = env_allowed
    else:
        hostname, port = _split_host(headers.get("host", ""))
        if hostname not in _LOOPBACK_HOSTNAMES:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Unrecognized Host header — set JS_ALLOWED_ORIGINS to allow this origin",
            )
        suffix = f":{port}" if port else ""
        names = ["localhost", "127.0.0.1"]
        allowed = frozenset(
            f"{scheme}://{h}{suffix}" for scheme in ("http", "https") for h in names
        )
        if hostname == "::1":
            allowed = allowed | {f"http://[::1]{suffix}", f"https://[::1]{suffix}"}

    if origin not in allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cross-origin request rejected",
        )


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
        """Revoke a key by hash prefix.

        Requires at least 8 hex characters to prevent accidental or malicious
        deletion of all keys via an empty or too-short prefix.
        """
        if not key_hash_prefix or len(key_hash_prefix) < 8:
            raise ValueError(
                "Key hash prefix must be at least 8 characters to avoid "
                "accidentally deleting all keys."
            )
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

        return {"name": name, "role": role, "key_hash": key_hash}

    def has_admin(self) -> bool:
        """Check whether at least one admin key exists."""
        with db_connection(self._db_path) as conn:
            row = conn.execute(
                "SELECT 1 FROM api_keys WHERE role = ? AND enabled = 1 LIMIT 1",
                (_ADMIN_ROLE,),
            ).fetchone()
        return row is not None

    def ensure_bootstrap_admin_key(self) -> str | None:
        """Mint a one-time admin key if none exists yet.

        Returns the plaintext of the newly-created key, or ``None`` when an
        admin key already exists (idempotent — never mints a second one).

        This guarantees the site is never left in a keyless state while auth
        is required, which would otherwise lock everyone out of every endpoint
        with no recovery path.
        """
        if self.has_admin():
            return None
        return self.create_key("bootstrap", role=_ADMIN_ROLE)


# ----------------------------------------------------------------------
# FastAPI dependency helpers
# ----------------------------------------------------------------------


def memory_owner(auth_ctx: dict[str, Any] | None) -> str | None:
    """Owner key for per-user memory scoping.

    Anonymous / no-auth (single-user) requests map to ``None`` so the user
    consistently sees the shared pool — never a fresh random ``key_hash`` per
    request (which would make them unable to recall their own memories).
    Bootstrap admin also has no key_hash, so it too falls back to the shared
    pool.
    """
    if not auth_ctx or auth_ctx.get("name") in ("anonymous", "bootstrap"):
        return None
    return auth_ctx.get("key_hash")


async def require_auth(
    api_key: str | None = Security(api_key_header),
) -> dict[str, Any]:
    """FastAPI dependency: verify API key.

    If authentication is disabled in settings, a valid key is still honoured
    (so admin endpoints work when an admin key is explicitly supplied).
    Without a key, a low-privilege guest context is returned.
    """
    # Lazy import to avoid circular deps at module load time
    from js.web.server import _settings as global_settings

    effective_settings = global_settings
    if effective_settings is None:
        # Settings not yet loaded.  Reject with a clear error instead of
        # granting admin access — this prevents a race window where the
        # FastAPI lifespan hasn't finished yet.
        raise HTTPException(
            status_code=503,
            detail="Server is still starting up. Please wait a moment and try again.",
        )

    auth_mgr = AuthManager(effective_settings.state_dir)

    if not effective_settings.security.api_key_required:
        # Auth optional: if a key is provided, verify it for role info;
        # otherwise return an admin context so local convenience mode works.
        if api_key:
            return auth_mgr.verify(api_key)
        return {
            "name": "anonymous",
            "role": _ADMIN_ROLE,
            "key_hash": _hash_key(secrets.token_urlsafe(16)),
        }

    try:
        return auth_mgr.verify(api_key)
    except AuthRequiredError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


# Alias for backward compatibility and router imports
require_auth_dep = require_auth


async def require_admin(
    request: Request,
    auth_ctx: dict[str, Any] = Depends(require_auth_dep),
) -> dict[str, Any]:
    """FastAPI dependency: require admin role.

    For state-changing methods (POST/PUT/PATCH/DELETE) the Origin/Host is also
    validated to block cross-site request forgery — read-only GETs are exempt.
    """
    if auth_ctx.get("role") != _ADMIN_ROLE:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin role required",
        )
    if request.method.upper() in _STATE_CHANGING_METHODS:
        check_origin(request)
    return auth_ctx


async def require_user_write(
    request: Request,
    auth_ctx: dict[str, Any] = Depends(require_auth_dep),
) -> dict[str, Any]:
    """FastAPI dependency: any authenticated user may modify their own state.

    State-changing methods always require Origin/Host validation.  This is the
    user-scoped counterpart to ``require_admin`` for endpoints that mutate data
    belonging to the current owner (e.g. sessions, personal memories).
    """
    if request.method.upper() in _STATE_CHANGING_METHODS:
        check_origin(request)
    return auth_ctx


async def require_admin_write(
    request: Request,
    auth_ctx: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    """FastAPI dependency: admin role + Origin/Host check for state changes.

    This is a convenience wrapper for global-state mutation endpoints (provider
    config, Hermes refresh, embedder recovery, etc.) that must be both admin-only
    and CSRF-protected regardless of HTTP method.
    """
    # require_admin already enforces role and checks Origin for mutating methods.
    # Force Origin validation even for GET/POST-style admin actions that do not
    # naturally fall under _STATE_CHANGING_METHODS in all call sites.
    check_origin(request)
    return auth_ctx


async def require_setup_auth(
    api_key: str | None = Security(api_key_header),
) -> dict[str, Any]:
    """FastAPI dependency: for setup wizard endpoints.

    During bootstrap (no admin key exists yet AND first_run_completed is False),
    allows access without auth. Once setup is complete, requires admin role.
    This prevents re-entering bootstrap by deleting all admin keys.
    """
    from js.web.server import _settings as global_settings

    effective_settings = global_settings
    if effective_settings is None:
        raise HTTPException(
            status_code=503,
            detail="Server is still starting up. Please wait a moment and try again.",
        )

    auth_mgr = AuthManager(effective_settings.state_dir)

    # When auth is disabled, honour explicit keys but allow anonymous access
    if not effective_settings.security.api_key_required:
        if api_key:
            return auth_mgr.verify(api_key)
        return {
            "name": "anonymous",
            "role": _USER_ROLE,
            "key_hash": _hash_key(secrets.token_urlsafe(16)),
        }

    # Bootstrap window only when BOTH conditions hold:
    # 1. No admin key exists yet
    # 2. First run has NOT been completed
    # This prevents the "delete all admin keys → re-enter bootstrap" attack.
    if not auth_mgr.has_admin() and not effective_settings.first_run_completed:
        return {"name": "bootstrap", "role": _ADMIN_ROLE}

    try:
        return auth_mgr.verify(api_key)
    except AuthRequiredError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


class AuthMiddleware:
    """Optional middleware that applies auth to all routes.

    Not used directly — we use Depends() per-route for finer control.
    """

    pass
