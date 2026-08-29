"""Web API authentication and authorization.

Supports API key authentication with role-based access control.
Keys are stored as SHA-256 hashes (the plaintext is shown once on creation).
"""

from __future__ import annotations

import hashlib
import os
import secrets
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from fastapi import Depends, HTTPException, Request, Security, WebSocket, status
from fastapi.security import APIKeyHeader

from js.echo import turn_context as _echo_turn_context
from js.exceptions import AuthRequiredError
from js.utils.db import db_connection
from js.utils.log import get_logger

# Context variable for session owner key hash (set by Web API layer).  The
# canonical storage lives in Echo so agent internals do not depend on Web.
_session_owner_hash = _echo_turn_context._session_owner_hash

logger = get_logger("js.web.auth")

__all__ = [
    "AuthManager",
    "authenticate_credentials",
    "require_auth",
    "require_admin",
    "require_user_write",
    "require_admin_write",
    "require_auth_dep",
    "check_origin",
    "memory_owner",
    "resolve_session_cookie",
    "request_is_direct_loopback",
    "session_cookie_name",
    "runtime_owner",
    "websocket_presented_api_key",
    "cors_allow_origins",
]

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

_ADMIN_ROLE = "admin"
_USER_ROLE = "user"
_GUEST_ROLE = "guest"

# Legacy unscoped session cookie name. Kept only as a Personal migration
# fallback: browsers treat cookies as host-scoped (not port-scoped), so a
# shared ``js_session`` on 127.0.0.1:8000 and :8765 clobbers AppShell
# Personal↔Work logins. New cookies are product-scoped via
# ``session_cookie_name``.
_SESSION_COOKIE = "js_session"
_SESSION_TTL_SECONDS = 7 * 24 * 60 * 60
# Historical non-HttpOnly cookie that carried the plaintext API key. Rejected
# on WebSocket upgrades so a same-origin script cannot mint a credential.
_LEGACY_API_KEY_COOKIE = "x-api-key"


def session_cookie_name(product_id: str | None = None) -> str:
    """Return the HttpOnly session cookie name for a product backend."""
    raw = (product_id or "js-agent").strip() or "js-agent"
    safe = "".join(ch if (ch.isalnum() or ch in "-_") else "-" for ch in raw)
    return f"js_session_{safe}"


def resolve_session_cookie(
    cookies: Mapping[str, str],
    product_id: str | None = None,
) -> str | None:
    """Read the product session token from a cookie mapping.

    Prefer the product-scoped cookie. Bare ``js_session`` is accepted only for
    the Personal product (``js-agent``) so older installs keep working; Work
    must never accept it, or a Personal login would authenticate Work.
    """
    primary = cookies.get(session_cookie_name(product_id))
    if isinstance(primary, str) and primary:
        return primary
    if (product_id or "js-agent") == "js-agent":
        legacy = cookies.get(_SESSION_COOKIE)
        if isinstance(legacy, str) and legacy:
            return legacy
    return None


def websocket_presented_api_key(websocket: WebSocket) -> str:
    """Return the ``X-API-Key`` header, or empty string.

    A non-empty ``x-api-key`` cookie is rejected: plaintext keys must not
    ride a non-HttpOnly cookie (header + HttpOnly session cookie only).
    """
    cookie = websocket.cookies.get(_LEGACY_API_KEY_COOKIE)
    if isinstance(cookie, str) and cookie:
        logger.warning("Rejected WebSocket upgrade that presented an x-api-key cookie")
        raise AuthRequiredError("x-api-key cookie is no longer accepted")
    header = websocket.headers.get("x-api-key", "")
    return header if isinstance(header, str) else ""


# Client hosts allowed to use the unauthenticated setup bootstrap window.
_LOOPBACK_CLIENT_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})

# Presence of any of these means a reverse proxy may be rewriting the peer;
# bootstrap must not trust request.client.host alone in that case.
_FORWARDED_CLIENT_HEADERS = frozenset(
    {
        "forwarded",
        "x-forwarded-for",
        "x-real-ip",
        "x-forwarded-host",
    }
)

# Operator-configured origin allowlist (e.g. real domains behind a reverse
# proxy).  Set via JS_ALLOWED_ORIGINS (comma-separated).  When unset, allowed
# origins are derived dynamically from the request's own (loopback) Host header
# so the server works on any bind port without configuration.
_ALLOWED_ORIGINS: frozenset[str] | None = None
_ALLOWED_ORIGINS_ENV: str | None = None

# Hostnames the server may legitimately be reached at without an explicit
# JS_ALLOWED_ORIGINS allowlist.  Anything else requires the operator to opt in.
_LOOPBACK_HOSTNAMES = frozenset({"localhost", "127.0.0.1", "::1", "0.0.0.0"})

# HTTP methods that mutate state and therefore require CSRF/Origin protection.
_STATE_CHANGING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def _request_has_forwarded_client_headers(request: Request) -> bool:
    """True when the request carries reverse-proxy client-identity headers."""
    return any(name in request.headers for name in _FORWARDED_CLIENT_HEADERS)


def request_is_direct_loopback(request: Request) -> bool:
    """Return whether the peer is loopback with no forwarded-client headers."""
    client_host = request.client.host if request.client is not None else None
    return client_host in _LOOPBACK_CLIENT_HOSTS and not _request_has_forwarded_client_headers(
        request
    )


def _load_allowed_origins() -> frozenset[str]:
    """Return the operator-configured origin allowlist (empty if unset)."""
    global _ALLOWED_ORIGINS, _ALLOWED_ORIGINS_ENV

    env = os.getenv("JS_ALLOWED_ORIGINS", "")
    if _ALLOWED_ORIGINS is not None and env == _ALLOWED_ORIGINS_ENV:
        return _ALLOWED_ORIGINS
    _ALLOWED_ORIGINS_ENV = env
    if env:
        _ALLOWED_ORIGINS = frozenset(o.strip().rstrip("/") for o in env.split(",") if o.strip())
    else:
        _ALLOWED_ORIGINS = frozenset()
    return _ALLOWED_ORIGINS


_CORS_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
_LISTEN_ALL_HOSTS = frozenset({"0.0.0.0", "::", "*"})


def cors_allow_origins(bind_host: str, bind_port: int) -> list[str]:
    """Loopback aliases plus ``JS_ALLOWED_ORIGINS``; never the bind-host literal.

    ``http://0.0.0.0:port`` is not a browser Origin. A concrete non-loopback
    bind requires the operator to set ``JS_ALLOWED_ORIGINS``.
    """
    origins = [
        f"http://127.0.0.1:{bind_port}",
        f"http://localhost:{bind_port}",
    ]
    extra = sorted(_load_allowed_origins())
    origins.extend(extra)
    host = (bind_host or "127.0.0.1").strip().lower().strip("[]")
    if host not in _CORS_LOOPBACK_HOSTS and host not in _LISTEN_ALL_HOSTS and not extra:
        raise RuntimeError(f"Non-loopback bind_host {bind_host!r} requires JS_ALLOWED_ORIGINS")
    return list(dict.fromkeys(origins))


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


def _state_dirs_for_origin_key(request: Request | WebSocket) -> tuple[Path, ...]:
    """Collect AuthManager state dirs reachable from this request.

    Used only to decide whether a presented ``X-API-Key`` may skip Origin
    (CLI clients).  An unverified header must not grant that exemption.
    """
    dirs: list[Path] = []
    scope = getattr(request, "scope", None)
    app = scope.get("app") if isinstance(scope, Mapping) else None
    state = getattr(app, "state", None) if app is not None else None
    if state is not None:
        settings = getattr(state, "runtime_settings", None)
        state_dir = getattr(settings, "state_dir", None) if settings is not None else None
        if state_dir is not None:
            dirs.append(Path(state_dir))
        for attr in ("personal_app", "work_app"):
            child = getattr(state, attr, None)
            child_settings = getattr(getattr(child, "state", None), "runtime_settings", None)
            child_dir = (
                getattr(child_settings, "state_dir", None) if child_settings is not None else None
            )
            if child_dir is not None:
                dirs.append(Path(child_dir))
    if not dirs:
        try:
            from js.web.runtime_context import current_web_runtime

            runtime = current_web_runtime()
            if runtime is not None:
                dirs.append(Path(runtime.settings.state_dir))
        except Exception:
            pass
    if not dirs:
        try:
            from js.web.server import _settings as fallback_settings

            if fallback_settings is not None:
                dirs.append(Path(fallback_settings.state_dir))
        except Exception:
            pass
    unique: list[Path] = []
    seen: set[str] = set()
    for item in dirs:
        marker = str(item)
        if marker in seen:
            continue
        seen.add(marker)
        unique.append(item)
    return tuple(unique)


def _api_key_verified_for_origin_exempt(request: Request | WebSocket, key: str) -> bool:
    for state_dir in _state_dirs_for_origin_key(request):
        try:
            AuthManager(state_dir).verify(key)
            return True
        except Exception:
            continue
    return False


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
        # Non-browser clients (CLI, curl) send no Origin — allow only when a
        # presented API key verifies. An unverified header must not skip CSRF.
        _presented_key = headers.get("x-api-key")
        if not _presented_key or not _api_key_verified_for_origin_exempt(request, _presented_key):
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

    # Process-wide positive verify cache shared across AuthManager instances that
    # open the same DB path (FastAPI deps construct a fresh manager per request).
    _SHARED_VERIFY_CACHE: dict[str, tuple[float, dict[str, Any]]] = {}
    _SHARED_LAST_USED: dict[str, float] = {}
    # Per-DB-path epoch plus per-entry stamp. Revoke bumps the epoch so a
    # verify that raced a revoke cannot rewrite (or reuse) a stale positive.
    _SHARED_VERIFY_EPOCH: dict[str, int] = {}
    _SHARED_VERIFY_STAMP: dict[str, int] = {}
    _INITIALIZED_DBS: set[str] = set()
    _VERIFY_CACHE_TTL_SECONDS = 5.0  # positive cache only; revoke bumps epoch
    _LAST_USED_MIN_INTERVAL_SECONDS = 60.0
    # Hard cap on the shared positive caches. Entries are keyed by distinct
    # key-hash, so without a bound the dicts grow for the life of the process.
    _VERIFY_CACHE_MAX_ENTRIES = 10_000

    def __init__(self, state_dir: Path) -> None:
        self._db_path = state_dir / "api_keys.db"
        # Avoid Path.resolve() on the hot path; absolute() is enough for a cache ns.
        self._cache_ns = str(
            self._db_path if self._db_path.is_absolute() else self._db_path.absolute()
        )
        self._init_db()

    def _cache_key(self, key_hash: str) -> str:
        return f"{self._cache_ns}:{key_hash}"

    def _current_epoch(self) -> int:
        return self._SHARED_VERIFY_EPOCH.get(self._cache_ns, 0)

    def _bump_verify_epoch(self) -> None:
        self._SHARED_VERIFY_EPOCH[self._cache_ns] = self._current_epoch() + 1

    def _invalidate_verify_cache(self, key_hash: str | None = None) -> None:
        self._bump_verify_epoch()
        if key_hash is None:
            prefix = f"{self._cache_ns}:"
            for cached_key in list(self._SHARED_VERIFY_CACHE):
                if cached_key.startswith(prefix):
                    self._SHARED_VERIFY_CACHE.pop(cached_key, None)
                    self._SHARED_LAST_USED.pop(cached_key, None)
                    self._SHARED_VERIFY_STAMP.pop(cached_key, None)
            return
        cache_key = self._cache_key(key_hash)
        self._SHARED_VERIFY_CACHE.pop(cache_key, None)
        self._SHARED_LAST_USED.pop(cache_key, None)
        self._SHARED_VERIFY_STAMP.pop(cache_key, None)

    @classmethod
    def _enforce_verify_cache_bounds(cls, now: float) -> None:
        """Keep the process-wide shared caches bounded.

        Entries are keyed by distinct key-hash, so the dicts would otherwise
        grow for the life of the process. Expired entries are purged first;
        if the cache still exceeds the cap, both caches are cleared — they
        are positive caches only, so a clear costs one extra DB lookup per
        key and nothing more.
        """
        if len(cls._SHARED_VERIFY_CACHE) <= cls._VERIFY_CACHE_MAX_ENTRIES:
            return
        expired = [
            cached_key
            for cached_key, (ts, _) in cls._SHARED_VERIFY_CACHE.items()
            if (now - ts) >= cls._VERIFY_CACHE_TTL_SECONDS
        ]
        for cached_key in expired:
            cls._SHARED_VERIFY_CACHE.pop(cached_key, None)
            cls._SHARED_LAST_USED.pop(cached_key, None)
            cls._SHARED_VERIFY_STAMP.pop(cached_key, None)
        if len(cls._SHARED_VERIFY_CACHE) > cls._VERIFY_CACHE_MAX_ENTRIES:
            cls._SHARED_VERIFY_CACHE.clear()
            cls._SHARED_LAST_USED.clear()
            cls._SHARED_VERIFY_STAMP.clear()

    def _init_db(self) -> None:
        # Schema bootstrap once per DB path — CREATE IF NOT EXISTS is not free on
        # every AuthManager construction (WS connect / HTTP dep hot path).
        if self._cache_ns in self._INITIALIZED_DBS:
            return
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
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS auth_sessions (
                    token_hash TEXT PRIMARY KEY,
                    key_hash TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    expires_at REAL NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS managed_api_keys (
                    key_hash TEXT PRIMARY KEY,
                    issuer TEXT NOT NULL,
                    created_at REAL NOT NULL
                )
                """
            )
            managed_columns = [
                (str(row[1]), str(row[2]).upper(), int(row[3]), int(row[5]))
                for row in conn.execute("PRAGMA table_info(managed_api_keys)")
            ]
            if managed_columns != [
                ("key_hash", "TEXT", 0, 1),
                ("issuer", "TEXT", 1, 0),
                ("created_at", "REAL", 1, 0),
            ]:
                raise RuntimeError("managed API key provenance schema is invalid")
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_managed_api_keys_issuer
                ON managed_api_keys(issuer)
                """
            )
            conn.commit()
        self._harden_auth_store()
        self._INITIALIZED_DBS.add(self._cache_ns)

    def _harden_auth_store(self) -> None:
        """Restrict the key database and its parent directory (0600 / 0700)."""
        state_dir = self._db_path.parent
        state_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(state_dir, 0o700)
        except OSError:
            logger.warning("Could not restrict auth state_dir permissions", path=str(state_dir))
        for path in (
            self._db_path,
            Path(str(self._db_path) + "-wal"),
            Path(str(self._db_path) + "-shm"),
        ):
            if path.exists():
                try:
                    os.chmod(path, 0o600)
                except OSError:
                    logger.warning("Could not restrict auth database permissions", path=str(path))

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

    def provision_existing_key(
        self,
        key: str,
        *,
        name: str,
        role: str,
    ) -> dict[str, Any]:
        """Install one already-generated key into this isolated role store.

        Only the trusted AppShell bootstrap broker calls this method to bind
        one plaintext credential to both Personal and Work. Existing rows are
        never widened, re-enabled, or overwritten.
        """
        if not isinstance(key, str) or not key.startswith("js_") or len(key) < 16:
            raise ValueError("shared API key is invalid")
        if role not in {_ADMIN_ROLE, _USER_ROLE}:
            raise ValueError("shared API key role is invalid")
        if not isinstance(name, str) or not name.strip():
            raise ValueError("shared API key name is required")
        key_hash = _hash_key(key)
        now = time.time()
        with db_connection(self._db_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT name, role, enabled FROM api_keys WHERE key_hash = ?",
                (key_hash,),
            ).fetchone()
            if row is None:
                connection.execute(
                    "INSERT INTO api_keys "
                    "(key_hash, name, role, created_at, enabled) VALUES (?, ?, ?, ?, 1)",
                    (key_hash, name.strip(), role, now),
                )
                connection.commit()
                identity = {"name": name.strip(), "role": role, "key_hash": key_hash}
            else:
                existing_name, existing_role, enabled = row
                connection.rollback()
                if not enabled:
                    raise AuthRequiredError("API key has been revoked")
                if existing_role != role:
                    raise PermissionError("existing API key role cannot be widened")
                identity = {
                    "name": existing_name,
                    "role": existing_role,
                    "key_hash": key_hash,
                }
        self._invalidate_verify_cache(key_hash)
        return identity

    def provision_managed_key(
        self,
        key: str,
        *,
        name: str,
        role: str,
        issuer: str,
    ) -> dict[str, Any]:
        """Create a new key and trusted provenance marker atomically.

        A pre-existing key is never adopted as managed. This prevents a caller
        from attaching trusted cleanup authority to an ordinary user key.
        """
        if not isinstance(key, str) or not key.startswith("js_") or len(key) < 16:
            raise ValueError("managed API key is invalid")
        if role not in {_ADMIN_ROLE, _USER_ROLE}:
            raise ValueError("managed API key role is invalid")
        if not isinstance(name, str) or not name.strip():
            raise ValueError("managed API key name is required")
        if not isinstance(issuer, str) or not issuer.strip():
            raise ValueError("managed API key issuer is required")

        normalized_name = name.strip()
        normalized_issuer = issuer.strip()
        key_hash = _hash_key(key)
        now = time.time()
        with db_connection(self._db_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing_key = connection.execute(
                "SELECT 1 FROM api_keys WHERE key_hash = ?",
                (key_hash,),
            ).fetchone()
            existing_marker = connection.execute(
                "SELECT 1 FROM managed_api_keys WHERE key_hash = ?",
                (key_hash,),
            ).fetchone()
            if existing_key is not None or existing_marker is not None:
                connection.rollback()
                raise ValueError("managed API key identity already exists")
            connection.execute(
                "INSERT INTO api_keys "
                "(key_hash, name, role, created_at, enabled) VALUES (?, ?, ?, ?, 1)",
                (key_hash, normalized_name, role, now),
            )
            connection.execute(
                "INSERT INTO managed_api_keys (key_hash, issuer, created_at) VALUES (?, ?, ?)",
                (key_hash, normalized_issuer, now),
            )
            connection.commit()
        self._invalidate_verify_cache(key_hash)
        return {"name": normalized_name, "role": role, "key_hash": key_hash}

    @staticmethod
    def _validate_managed_hash(key_hash: str) -> None:
        if (
            not isinstance(key_hash, str)
            or len(key_hash) != 64
            or any(ch not in "0123456789abcdef" for ch in key_hash)
        ):
            raise ValueError("managed API key hash is invalid")

    @staticmethod
    def _validate_managed_issuer(issuer: str) -> str:
        if not isinstance(issuer, str) or not issuer.strip():
            raise ValueError("managed API key issuer is required")
        return issuer.strip()

    def revoke_managed_key(self, key_hash: str, *, issuer: str) -> bool:
        """Remove one identity only when its exact trusted marker is present."""
        self._validate_managed_hash(key_hash)
        normalized_issuer = self._validate_managed_issuer(issuer)
        with db_connection(self._db_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            marked = connection.execute(
                "SELECT 1 FROM managed_api_keys WHERE key_hash = ? AND issuer = ?",
                (key_hash, normalized_issuer),
            ).fetchone()
            if marked is None:
                connection.rollback()
                return False
            connection.execute(
                "DELETE FROM auth_sessions WHERE key_hash = ?",
                (key_hash,),
            )
            connection.execute(
                "DELETE FROM api_keys WHERE key_hash = ?",
                (key_hash,),
            )
            connection.execute(
                "DELETE FROM managed_api_keys WHERE key_hash = ? AND issuer = ?",
                (key_hash, normalized_issuer),
            )
            connection.commit()
        self._invalidate_verify_cache(key_hash)
        return True

    def purge_managed_keys(
        self,
        *,
        issuer: str,
        preserve_key_hashes: set[str] | None = None,
    ) -> list[str]:
        """Remove exact issuer-marked identities except active parent owners."""
        normalized_issuer = self._validate_managed_issuer(issuer)
        preserved = set(preserve_key_hashes or ())
        for key_hash in preserved:
            self._validate_managed_hash(key_hash)

        with db_connection(self._db_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            marked_hashes = {
                str(row[0])
                for row in connection.execute(
                    "SELECT key_hash FROM managed_api_keys WHERE issuer = ?",
                    (normalized_issuer,),
                )
            }
            removed = sorted(marked_hashes - preserved)
            for key_hash in removed:
                connection.execute(
                    "DELETE FROM auth_sessions WHERE key_hash = ? "
                    "AND EXISTS (SELECT 1 FROM managed_api_keys "
                    "WHERE key_hash = ? AND issuer = ?)",
                    (key_hash, key_hash, normalized_issuer),
                )
                connection.execute(
                    "DELETE FROM api_keys WHERE key_hash = ? "
                    "AND EXISTS (SELECT 1 FROM managed_api_keys "
                    "WHERE key_hash = ? AND issuer = ?)",
                    (key_hash, key_hash, normalized_issuer),
                )
                connection.execute(
                    "DELETE FROM managed_api_keys WHERE key_hash = ? AND issuer = ?",
                    (key_hash, normalized_issuer),
                )
            connection.commit()
        for key_hash in removed:
            self._invalidate_verify_cache(key_hash)
        return removed

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
        # Exact prefix match: the prefix is compared literally (never as a
        # LIKE pattern), so "%"/"_" cannot widen the match to other keys.
        with db_connection(self._db_path) as conn:
            conn.execute("BEGIN IMMEDIATE")
            key_hashes = [
                str(row[0])
                for row in conn.execute(
                    "SELECT key_hash FROM api_keys WHERE substr(key_hash, 1, ?) = ?",
                    (len(key_hash_prefix), key_hash_prefix),
                )
            ]
            for key_hash in key_hashes:
                conn.execute("DELETE FROM auth_sessions WHERE key_hash = ?", (key_hash,))
                conn.execute("DELETE FROM managed_api_keys WHERE key_hash = ?", (key_hash,))
            cur = conn.execute(
                "DELETE FROM api_keys WHERE substr(key_hash, 1, ?) = ?",
                (len(key_hash_prefix), key_hash_prefix),
            )
            conn.commit()
            deleted = cur.rowcount > 0
        if deleted:
            # Prefix revoke — drop the whole namespace to avoid stale positives.
            self._invalidate_verify_cache()
        return deleted

    def verify(self, key: str | None) -> dict[str, Any]:
        """Verify an API key and return its metadata.

        Raises AuthRequiredError if key is missing or invalid.
        """
        if not key:
            raise AuthRequiredError("X-API-Key header is required")

        key_hash = _hash_key(key)
        now = time.time()
        cache_key = self._cache_key(key_hash)
        epoch_at_start = self._current_epoch()
        cached = self._SHARED_VERIFY_CACHE.get(cache_key)
        if cached is not None and (now - cached[0]) < self._VERIFY_CACHE_TTL_SECONDS:
            cached_identity = cached[1]
            stamped = self._SHARED_VERIFY_STAMP.get(cache_key)
            # Admin identities never use the positive cache: revoke must be
            # visible on the next privileged request, not after TTL.
            if (
                cached_identity.get("role") != _ADMIN_ROLE
                and stamped == epoch_at_start
                and epoch_at_start == self._current_epoch()
            ):
                self._maybe_touch_last_used(key_hash, now)
                return dict(cached_identity)

        with db_connection(self._db_path) as conn:
            row = conn.execute(
                "SELECT name, role, enabled FROM api_keys WHERE key_hash = ?",
                (key_hash,),
            ).fetchone()

        if row is None:
            self._invalidate_verify_cache(key_hash)
            raise AuthRequiredError("Invalid API key")

        name, role, enabled = row
        if not enabled:
            self._invalidate_verify_cache(key_hash)
            raise AuthRequiredError("API key has been revoked")

        identity = {"name": name, "role": role, "key_hash": key_hash}
        if role != _ADMIN_ROLE and epoch_at_start == self._current_epoch():
            self._enforce_verify_cache_bounds(now)
            self._SHARED_VERIFY_CACHE[cache_key] = (now, identity)
            self._SHARED_VERIFY_STAMP[cache_key] = epoch_at_start
        self._maybe_touch_last_used(key_hash, now)
        return dict(identity)

    def verify_key_hash(self, key_hash: str) -> dict[str, Any]:
        """Revalidate a server-held identity binding without plaintext input.

        This is intentionally for trusted parent session brokers only. Browser
        callers never receive the full hash and cannot authenticate with it.
        """
        if (
            not isinstance(key_hash, str)
            or len(key_hash) != 64
            or any(ch not in "0123456789abcdef" for ch in key_hash)
        ):
            raise AuthRequiredError("Invalid API key identity")
        with db_connection(self._db_path) as connection:
            row = connection.execute(
                "SELECT name, role, enabled FROM api_keys WHERE key_hash = ?",
                (key_hash,),
            ).fetchone()
        if row is None:
            raise AuthRequiredError("Invalid API key identity")
        name, role, enabled = row
        if not enabled:
            raise AuthRequiredError("API key has been revoked")
        return {"name": name, "role": role, "key_hash": key_hash}

    def _maybe_touch_last_used(self, key_hash: str, now: float) -> None:
        """Best-effort last_used update, throttled to limit SQLite churn."""
        cache_key = self._cache_key(key_hash)
        last = self._SHARED_LAST_USED.get(cache_key)
        if last is not None and (now - last) < self._LAST_USED_MIN_INTERVAL_SECONDS:
            return
        try:
            with db_connection(self._db_path) as conn:
                conn.execute(
                    "UPDATE api_keys SET last_used = ? WHERE key_hash = ?",
                    (now, key_hash),
                )
                conn.commit()
            self._SHARED_LAST_USED[cache_key] = now
        except Exception:
            logger.warning("Failed to update last_used for API key", exc_info=True)

    # ------------------------------------------------------------------
    # Browser session lifecycle (HttpOnly cookie login)
    # ------------------------------------------------------------------

    def create_session(
        self,
        key: str | None,
        ttl_seconds: int = _SESSION_TTL_SECONDS,
    ) -> tuple[str, float]:
        """Verify *key* and mint a session token bound to it.

        Returns ``(plaintext_token, expires_at)``.  Only the token hash is
        persisted; the session dies with its originating key (revoking the
        API key implicitly revokes all of its sessions).

        Raises AuthRequiredError if the key is missing or invalid.
        """
        identity = self.verify(key)
        token = "jss_" + secrets.token_urlsafe(32)
        now = time.time()
        expires_at = now + ttl_seconds
        with db_connection(self._db_path) as conn:
            conn.execute(
                "INSERT INTO auth_sessions (token_hash, key_hash, created_at, expires_at) "
                "VALUES (?, ?, ?, ?)",
                (_hash_key(token), identity["key_hash"], now, expires_at),
            )
            conn.commit()
        logger.info(f"Created browser session for API key '{identity['name']}'")
        return token, expires_at

    def verify_session(self, token: str | None) -> dict[str, Any]:
        """Verify a session token and return the owning key's metadata.

        Fails closed: unknown, expired, or revoked-key sessions all raise
        AuthRequiredError.
        """
        if not token:
            raise AuthRequiredError("Session cookie is required")

        token_hash = _hash_key(token)
        with db_connection(self._db_path) as conn:
            row = conn.execute(
                """
                SELECT s.expires_at, s.key_hash, k.name, k.role, k.enabled
                FROM auth_sessions s
                JOIN api_keys k ON k.key_hash = s.key_hash
                WHERE s.token_hash = ?
                """,
                (token_hash,),
            ).fetchone()

        if row is None:
            raise AuthRequiredError("Invalid session")

        expires_at, key_hash, name, role, enabled = row
        if not enabled:
            raise AuthRequiredError("API key has been revoked")
        if expires_at <= time.time():
            # Lazy cleanup of the expired session.
            try:
                with db_connection(self._db_path) as conn:
                    conn.execute(
                        "DELETE FROM auth_sessions WHERE token_hash = ?",
                        (token_hash,),
                    )
                    conn.commit()
            except Exception:
                logger.warning("Failed to purge expired session", exc_info=True)
            raise AuthRequiredError("Session has expired")

        return {"name": name, "role": role, "key_hash": key_hash}

    def revoke_session(self, token: str | None) -> bool:
        """Revoke a session token (logout). Returns True if one existed."""
        if not token:
            return False
        with db_connection(self._db_path) as conn:
            cur = conn.execute(
                "DELETE FROM auth_sessions WHERE token_hash = ?",
                (_hash_key(token),),
            )
            conn.commit()
            return cur.rowcount > 0

    def has_admin(self) -> bool:
        """Check whether at least one admin key exists."""
        with db_connection(self._db_path) as conn:
            row = conn.execute(
                "SELECT 1 FROM api_keys WHERE role = ? AND enabled = 1 LIMIT 1",
                (_ADMIN_ROLE,),
            ).fetchone()
        return row is not None

    def ensure_bootstrap_admin_key(
        self,
        persist: Callable[[str], None] | None = None,
    ) -> str | None:
        """Mint a one-time admin key if none exists yet.

        Returns the plaintext of the newly-created key, or ``None`` when an
        admin key already exists (idempotent — never mints a second one).

        This guarantees the site is never left in a keyless state while auth
        is required, which would otherwise lock everyone out of every endpoint
        with no recovery path.
        """
        with db_connection(self._db_path) as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT 1 FROM api_keys WHERE role = ? AND enabled = 1 LIMIT 1",
                (_ADMIN_ROLE,),
            ).fetchone()
            if row is not None:
                conn.rollback()
                return None

            plaintext = _generate_key()
            key_hash = _hash_key(plaintext)
            conn.execute(
                "INSERT INTO api_keys "
                "(key_hash, name, role, created_at, enabled) VALUES (?, ?, ?, ?, 1)",
                (key_hash, "bootstrap", _ADMIN_ROLE, time.time()),
            )
            if persist is not None:
                persist(plaintext)
            conn.commit()
        logger.info("Created bootstrap API key with admin role")
        return plaintext


# ----------------------------------------------------------------------
# FastAPI dependency helpers
# ----------------------------------------------------------------------


def memory_owner(auth_ctx: dict[str, Any] | None) -> str | None:
    """Owner key for per-user memory scoping.

    Anonymous / no-auth (single-user) requests map to ``None`` so the user
    consistently sees the local legacy partition — never a fresh random
    ``key_hash`` per request (which would make them unable to recall their own
    memories). A verified bootstrap API key does carry a stable ``key_hash``
    and must retain it; only the unauthenticated setup bootstrap context falls
    back to the local partition.
    """
    if not auth_ctx or auth_ctx.get("name") == "anonymous":
        # Work uses a named local tenant so its files, uploads, memory, Fleet,
        # and Echo contexts share one identity instead of silently splitting
        # between ``None``, ``local-user``, and ``js-work-local``.
        from js.web.runtime_context import current_web_runtime

        runtime = current_web_runtime()
        if runtime is not None and str(getattr(runtime.settings, "product_id", "")) == "js-work":
            from js_work.file_scope import LOCAL_WORK_OWNER

            return LOCAL_WORK_OWNER
        return None
    key_hash = auth_ctx.get("key_hash")
    return key_hash if isinstance(key_hash, str) and key_hash else None


def runtime_owner(auth_ctx: dict[str, Any] | None) -> str:
    """Return the non-empty owner identity required by Echo runtime scopes.

    Memory keeps a legacy ``None`` partition for old local data, but runtime
    effects, uploads, sessions, and ledgers require an explicit physical
    tenant. JS Work's anonymous tenant is already resolved by ``memory_owner``;
    the main product uses the stable ``local-user`` tenant.
    """

    return memory_owner(auth_ctx) or "local-user"


async def authenticate_credentials(
    api_key: str | None,
    session_token: str | None,
) -> dict[str, Any]:
    """Verify presented credentials and return the auth context.

    Shared by the FastAPI dependencies and raw ASGI mounts (e.g. /metrics).
    Precedence: an explicit X-API-Key header wins over the HttpOnly session
    cookie.  A presented-but-invalid credential always fails closed (401);
    only a request with no credentials at all may fall back to the anonymous
    guest context when auth is optional.
    """
    # Prefer the settings owned by the current app while preserving the
    # historical module fallback for embedded apps and tests without lifespan.
    from js.web.runtime_context import current_web_runtime

    runtime = current_web_runtime()
    if runtime is not None:
        effective_settings = runtime.settings
    else:
        from js.web.server import _settings as effective_settings

    if effective_settings is None:
        raise HTTPException(
            status_code=503,
            detail="Server is still starting up. Please wait a moment and try again.",
        )

    auth_mgr = AuthManager(effective_settings.state_dir)

    def _unauthorized(exc: AuthRequiredError) -> HTTPException:
        return HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        )

    if api_key:
        try:
            return auth_mgr.verify(api_key)
        except AuthRequiredError as exc:
            raise _unauthorized(exc) from exc
    if session_token:
        try:
            return auth_mgr.verify_session(session_token)
        except AuthRequiredError as exc:
            raise _unauthorized(exc) from exc

    if not effective_settings.security.api_key_required:
        # Auth optional and no credentials presented: read-only guest context.
        # Guests may browse but can neither administer (require_admin) nor
        # mutate state (require_user_write).
        return {
            "name": "anonymous",
            "role": _GUEST_ROLE,
            "key_hash": _hash_key(secrets.token_urlsafe(16)),
        }
    raise _unauthorized(AuthRequiredError("X-API-Key header is required"))


async def require_auth(
    request: Request,
    api_key: str | None = Security(api_key_header),
) -> dict[str, Any]:
    """FastAPI dependency: verify API key or HttpOnly session cookie.

    If authentication is disabled in settings, a valid credential is still
    honoured (so admin endpoints work when an admin key is explicitly
    supplied).  Without any credential, a low-privilege guest context is
    returned.  For state-changing methods (POST/PUT/PATCH/DELETE) the
    Origin/Host is validated before any credential is resolved, so cross-site
    browser requests fail closed even in auth-optional mode.
    """
    from js.appshell.principal import appshell_auth_context_from_scope

    managed, appshell_auth = appshell_auth_context_from_scope(request.scope)
    if managed:
        if appshell_auth is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="AppShell session is required",
                headers={"WWW-Authenticate": "Bearer"},
            )
        # In parent-managed scopes client API keys and child cookies are never
        # consulted; this injected context is the sole identity authority.
        if request.method.upper() in _STATE_CHANGING_METHODS:
            check_origin(request)
        return appshell_auth

    # Anti-CSRF: state-changing requests pass the Origin/Host check before any
    # credential is resolved (mirrors require_user_write), so a cross-site page
    # cannot ride the guest context or a victim's session cookie.
    if request.method.upper() in _STATE_CHANGING_METHODS:
        check_origin(request)

    # Direct (non-DI) callers receive the unresolved parameter defaults.
    if not isinstance(api_key, str):
        api_key = None

    from js.web.runtime_context import current_web_runtime

    runtime = current_web_runtime()
    if runtime is not None:
        effective_settings = runtime.settings
    else:
        from js.web.server import _settings as effective_settings

    product_id = (
        str(getattr(effective_settings, "product_id", "js-agent") or "js-agent")
        if effective_settings is not None
        else "js-agent"
    )
    session_cookie = resolve_session_cookie(request.cookies, product_id)
    return await authenticate_credentials(api_key, session_cookie)


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
    Anonymous guests (auth-optional mode without credentials) are read-only
    and are rejected here.  The Origin check runs first so browser clients get
    the same CSRF diagnostic they received before the guest role existed.
    """
    if request.method.upper() in _STATE_CHANGING_METHODS:
        check_origin(request)
    if auth_ctx.get("role") == _GUEST_ROLE:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Guest role is read-only; authenticate to make changes",
        )
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
    request: Request,
    api_key: str | None = Security(api_key_header),
) -> dict[str, Any]:
    """FastAPI dependency: for setup wizard endpoints.

    During bootstrap (no admin key exists yet AND first_run_completed is False),
    allows access without auth — but only for loopback clients, so a remote
    attacker cannot race the operator into the setup wizard.  Once setup is
    complete, requires valid credentials.  This prevents re-entering bootstrap
    by deleting all admin keys.
    """
    from js.appshell.principal import appshell_auth_context_from_scope

    managed, appshell_auth = appshell_auth_context_from_scope(request.scope)
    if managed:
        if appshell_auth is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="AppShell session is required",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return appshell_auth

    from js.web.server import _settings as global_settings

    effective_settings = global_settings
    if effective_settings is None:
        raise HTTPException(
            status_code=503,
            detail="Server is still starting up. Please wait a moment and try again.",
        )

    # Direct (non-DI) callers receive the unresolved parameter defaults.
    if not isinstance(api_key, str):
        api_key = None

    product_id = str(getattr(effective_settings, "product_id", "js-agent") or "js-agent")
    session_cookie = resolve_session_cookie(request.cookies, product_id)

    auth_mgr = AuthManager(effective_settings.state_dir)

    # When auth is disabled, honour explicit credentials but keep anonymous
    # callers read-only (guest) — same posture as authenticate_credentials.
    if not effective_settings.security.api_key_required:
        if api_key or session_cookie:
            return await authenticate_credentials(api_key, session_cookie)
        return {
            "name": "anonymous",
            "role": _GUEST_ROLE,
            "key_hash": _hash_key(secrets.token_urlsafe(16)),
        }

    # Bootstrap window only when BOTH conditions hold:
    # 1. No admin key exists yet
    # 2. First run has NOT been completed
    # This prevents the "delete all admin keys → re-enter bootstrap" attack.
    # The window is additionally restricted to loopback clients: bootstrap
    # grants admin, so a remote requester must never reach it.
    # Forwarded-client headers mean a reverse proxy sits in front — peer is
    # then always loopback and cannot prove the original client. Fail closed.
    if (
        not api_key
        and not session_cookie
        and not auth_mgr.has_admin()
        and not effective_settings.first_run_completed
    ):
        client_host = request.client.host if request.client is not None else None
        if client_host not in _LOOPBACK_CLIENT_HOSTS:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Setup bootstrap is restricted to loopback clients",
            )
        if not request_is_direct_loopback(request):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    "Setup bootstrap is unavailable behind reverse-proxy forwarded-client headers"
                ),
            )
        # Anti-rebinding/CSRF: the bootstrap window grants ADMIN with no
        # credentials, so a state-changing request must also prove it came
        # from the operator's own browser session (Origin bound to a loopback
        # Host).  Without this, a DNS-rebinding page (or any cross-site form
        # POST) could complete setup and steal the one-time admin key that
        # /api/setup/complete returns in its response body.
        if request.method.upper() in _STATE_CHANGING_METHODS:
            check_origin(request)
        return {"name": "bootstrap", "role": _ADMIN_ROLE}
    return await authenticate_credentials(api_key, session_cookie)


class AuthMiddleware:
    """Optional middleware that applies auth to all routes.

    Not used directly — we use Depends() per-route for finer control.
    """

    pass
