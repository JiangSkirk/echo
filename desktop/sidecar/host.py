"""Single-process Python Host sidecar for the native JS Agent shell.

The native parent supplies exactly one 256-bit bootstrap token over stdin.  The
token is never accepted from argv or the environment, and stdout is reserved
for one canonical ready sentinel consumed by the Rust supervisor.
"""

from __future__ import annotations

import argparse
import asyncio
import hmac
import json
import os
import re
import secrets
import socket
import sys
import threading
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Literal, cast

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict

from js.appshell.principal import (
    APPSHELL_SESSION_COOKIE,
    APPSHELL_SESSION_TTL_SECONDS,
    AppShellPrincipalV1,
)
from js.web.auth import AuthManager, _generate_key, check_origin, request_is_direct_loopback

READY_SCHEMA = "JSAgentHostReadyV1"
BOOTSTRAP_TTL_SECONDS = 60
_TOKEN_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
_DIGEST_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
_EPHEMERAL_IDENTITY_NAME = "desktop-bootstrap-ephemeral"
_DESKTOP_MANAGED_ISSUER = "js-agent-desktop-bootstrap-v1"


def _sentinel_pid() -> int:
    """PID reported in the ready sentinel for Tauri process-group validation.

    For PyInstaller onefile, the bootloader (process-group leader) is the PID
    Tauri launched. The real Python runtime runs as a child of that leader and
    must report the leader PID, otherwise setup fails with
    ``sidecar sentinel PID escaped the externalBin process group``.
    """
    try:
        pgid = os.getpgid(0)
    except OSError:
        return os.getpid()
    if pgid > 0 and pgid != os.getpid():
        return int(pgid)
    return os.getpid()


def _desktop_csp(port: int) -> str:
    if not 1 <= port <= 65535 or port == 8765:
        raise ValueError(f"invalid desktop port for CSP: {port}")
    return (
        f"default-src 'self'; connect-src 'self' ws://127.0.0.1:{port}; "
        "img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; font-src 'self'; object-src 'none'; "
        "base-uri 'none'; frame-ancestors 'none'"
    )


class DesktopBootstrapRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    token: str


class OneTimeBootstrapToken:
    """Thread-safe one-use token with a monotonic lifetime."""

    def __init__(self, token: str, *, ttl_seconds: int) -> None:
        if _TOKEN_PATTERN.fullmatch(token) is None:
            raise ValueError("bootstrap token must be 256-bit lower-hex")
        if not 1 <= ttl_seconds <= BOOTSTRAP_TTL_SECONDS:
            raise ValueError("bootstrap token TTL must be between 1 and 60 seconds")
        self._token = token
        self._expires_at = time.monotonic() + ttl_seconds
        self._consumed = False
        self._lock = threading.Lock()

    def consume(self, presented: str) -> Literal["ok", "invalid", "expired", "consumed"]:
        with self._lock:
            if self._consumed:
                return "consumed"
            if time.monotonic() >= self._expires_at:
                return "expired"
            if _TOKEN_PATTERN.fullmatch(presented) is None:
                return "invalid"
            if not hmac.compare_digest(self._token, presented):
                return "invalid"
            self._consumed = True
            self._token = "0" * 64
            return "ok"


class EphemeralDesktopIdentity:
    """Provision one process-bound shared parent identity without a key file."""

    def __init__(self, app: FastAPI) -> None:
        self._app = app
        self._owner_hash: str | None = None
        self._parent_session_token: str | None = None
        self._generation = secrets.token_hex(16)
        self._lock = threading.Lock()
        personal_state = app.state.personal_app.state.runtime_settings.state_dir
        work_state = app.state.work_app.state.runtime_settings.state_dir
        personal_auth = AuthManager(personal_state)
        work_auth = AuthManager(work_state)
        legacy_owners = self._managed_owner_hashes(personal_state)
        legacy_owners.update(self._managed_owner_hashes(work_state))

        # Revoke browser authority before removing its backing keys. Each store
        # mutation is transactional; any failure aborts Host startup, while a
        # retry can safely finish exact-issuer residue left in another store.
        app.state.appshell_session_store.revoke_issuer_sessions(
            issuer=_DESKTOP_MANAGED_ISSUER,
            legacy_owner_hashes=legacy_owners,
        )
        personal_auth.purge_managed_keys(issuer=_DESKTOP_MANAGED_ISSUER)
        work_auth.purge_managed_keys(issuer=_DESKTOP_MANAGED_ISSUER)

    @staticmethod
    def _managed_owner_hashes(state_dir: Path) -> set[str]:
        from js.utils.db import db_connection

        with db_connection(state_dir / "api_keys.db") as connection:
            return {
                str(row[0])
                for row in connection.execute(
                    "SELECT key_hash FROM managed_api_keys WHERE issuer = ?",
                    (_DESKTOP_MANAGED_ISSUER,),
                )
            }

    @staticmethod
    def _parent_session_count(personal_state_dir: Path, *, owner: str) -> int:
        from js.utils.db import db_connection

        with db_connection(personal_state_dir / "appshell_sessions.db") as connection:
            row = connection.execute(
                "SELECT COUNT(*) FROM appshell_sessions WHERE owner = ?",
                (owner,),
            ).fetchone()
        return int(row[0]) if row is not None else 0

    def create_parent_session(self) -> tuple[str, AppShellPrincipalV1]:
        with self._lock:
            if self._owner_hash is not None:
                raise RuntimeError("desktop identity was already exchanged")
            key = _generate_key()
            personal_settings = self._app.state.personal_app.state.runtime_settings
            work_settings = self._app.state.work_app.state.runtime_settings
            personal_auth = AuthManager(personal_settings.state_dir)
            work_auth = AuthManager(work_settings.state_dir)
            personal_identity: dict[str, Any] | None = None
            work_identity: dict[str, Any] | None = None
            try:
                personal_identity = personal_auth.provision_managed_key(
                    key,
                    name=_EPHEMERAL_IDENTITY_NAME,
                    role="admin",
                    issuer=_DESKTOP_MANAGED_ISSUER,
                )
                work_identity = work_auth.provision_managed_key(
                    key,
                    name=_EPHEMERAL_IDENTITY_NAME,
                    role="admin",
                    issuer=_DESKTOP_MANAGED_ISSUER,
                )
                owner = str(personal_identity["key_hash"])
                if work_identity.get("key_hash") != owner:
                    raise RuntimeError("desktop identity binding mismatch")
                session = cast(
                    "tuple[str, AppShellPrincipalV1]",
                    self._app.state.appshell_session_store.create(
                        owner=owner,
                        mode_roles={"personal": "admin", "work": "admin"},
                        issuer=_DESKTOP_MANAGED_ISSUER,
                        generation=self._generation,
                    ),
                )
            except Exception:
                for auth, provisioned in (
                    (personal_auth, personal_identity),
                    (work_auth, work_identity),
                ):
                    if provisioned is None:
                        continue
                    try:
                        auth.revoke_managed_key(
                            str(provisioned["key_hash"]),
                            issuer=_DESKTOP_MANAGED_ISSUER,
                        )
                    except Exception:
                        pass
                raise
            finally:
                key = ""
            self._owner_hash = owner
            self._parent_session_token = session[0]
            return session

    def close(self) -> None:
        with self._lock:
            owner = self._owner_hash
            parent_token = self._parent_session_token
            if owner is None and parent_token is None:
                return
            if owner is None or parent_token is None:
                return

            session_store = self._app.state.appshell_session_store
            try:
                session_store.revoke(parent_token)
                if session_store.resolve(parent_token) is not None:
                    return
                personal_state = self._app.state.personal_app.state.runtime_settings.state_dir
                if self._parent_session_count(personal_state, owner=owner) != 0:
                    return
            except Exception:
                # Preserve the live parent session and both issuer-marked keys
                # as one recoverable authority set. A later close may retry.
                return

            keys_clean = True
            for child_name in ("personal_app", "work_app"):
                settings = getattr(self._app.state, child_name).state.runtime_settings
                try:
                    AuthManager(settings.state_dir).revoke_managed_key(
                        owner,
                        issuer=_DESKTOP_MANAGED_ISSUER,
                    )
                except Exception:
                    # The parent session is already absent. Keep the remaining
                    # issuer marker so this exact residue can be retried/purged.
                    keys_clean = False
            if keys_clean:
                self._owner_hash = None
                self._parent_session_token = None


def _read_bootstrap_token() -> str:
    raw = sys.stdin.buffer.readline(130)
    if not raw.endswith(b"\n") or len(raw) != 65:
        raise ValueError("invalid bootstrap token input")
    try:
        token = raw[:-1].decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("invalid bootstrap token input") from exc
    if _TOKEN_PATTERN.fullmatch(token) is None:
        raise ValueError("invalid bootstrap token input")
    return token


def _bind_loopback_socket() -> socket.socket:
    while True:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        if listener.getsockname()[1] == 8765:
            listener.close()
            continue
        listener.listen(128)
        listener.set_inheritable(False)
        return listener


def create_desktop_host_app(
    *,
    token: str,
    ttl_seconds: int,
    port: int,
) -> tuple[FastAPI, EphemeralDesktopIdentity]:
    from js.appshell.server import create_appshell_app

    app = create_appshell_app(host="127.0.0.1", port=port, manage_orind=True)
    bootstrap = OneTimeBootstrapToken(token, ttl_seconds=ttl_seconds)
    identity = EphemeralDesktopIdentity(app)
    child_lifespan = app.router.lifespan_context
    csp = _desktop_csp(port)

    @asynccontextmanager
    async def desktop_lifespan(host_app: FastAPI) -> Any:
        try:
            async with child_lifespan(host_app):
                yield
        finally:
            # Uvicorn deliberately re-raises SIGTERM after its graceful ASGI
            # shutdown. Clean process-bound admin rows inside the lifespan,
            # before that final signal can bypass main()'s outer finally.
            identity.close()

    app.router.lifespan_context = desktop_lifespan

    @app.post("/api/appshell/desktop-bootstrap")
    async def desktop_bootstrap(
        request: Request,
        body: DesktopBootstrapRequest,
    ) -> JSONResponse:
        if not request_is_direct_loopback(request):
            raise HTTPException(403, "desktop bootstrap requires direct loopback")
        check_origin(request)
        result = bootstrap.consume(body.token)
        if result == "invalid":
            raise HTTPException(401, {"code": "bootstrap_token_invalid"})
        if result == "expired":
            raise HTTPException(410, {"code": "bootstrap_token_expired"})
        if result == "consumed":
            raise HTTPException(409, {"code": "bootstrap_token_consumed"})

        session_token, principal = identity.create_parent_session()
        response = JSONResponse(
            {"success": True, "principal": principal.public_dict()},
            headers={"Cache-Control": "no-store"},
        )
        response.set_cookie(
            APPSHELL_SESSION_COOKIE,
            session_token,
            max_age=APPSHELL_SESSION_TTL_SECONDS,
            httponly=True,
            samesite="strict",
            secure=False,
            path="/",
        )
        for name in ("js_session", "js_session_js-agent", "js_session_js-work"):
            response.delete_cookie(name, path="/")
        return response

    @app.middleware("http")
    async def desktop_security_headers(request: Request, call_next: Any) -> Any:
        path = request.url.path
        # In desktop mode, sensitive documentation and schema endpoints are
        # locked before the desktop token is exchanged.
        if path in ("/docs", "/redoc", "/openapi.json") or path.startswith("/docs/"):
            response = JSONResponse(
                {"detail": {"code": "desktop_docs_disabled"}},
                status_code=404,
                headers={"Cache-Control": "no-store"},
            )
        elif request.method == "POST" and path == "/api/appshell/bootstrap":
            response = JSONResponse(
                {"detail": {"code": "desktop_bootstrap_required"}},
                status_code=410,
                headers={"Cache-Control": "no-store"},
            )
        elif request.method == "GET" and path == "/api/appshell/bootstrap":
            response = JSONResponse(
                {"detail": "Method Not Allowed"},
                status_code=405,
                headers={"Cache-Control": "no-store"},
            )
        elif request.method == "POST" and path == "/api/appshell/session":
            response = JSONResponse(
                {"detail": "AppShell session is required"},
                status_code=401,
                headers={"Cache-Control": "no-store"},
            )
        elif request.method == "POST" and path in {
            "/api/auth/setup",
            "/api/auth/login",
        }:
            response = JSONResponse(
                {"detail": "Not Found"},
                status_code=404,
                headers={"Cache-Control": "no-store"},
            )
        else:
            response = await call_next(request)
        response.headers["Content-Security-Policy"] = csp
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        return response

    return app, identity


async def _serve(
    *,
    app: FastAPI,
    listener: socket.socket,
    source_digest: str,
    protocol_stdout: Any,
) -> int:
    import uvicorn

    config = uvicorn.Config(
        app,
        host="127.0.0.1",
        port=int(listener.getsockname()[1]),
        access_log=False,
        log_level="warning",
    )
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve(sockets=[listener]))
    while not server.started and not task.done():
        await asyncio.sleep(0.01)
    if task.done():
        await task
        return 70

    ready = {
        # PyInstaller onefile re-execs into a child; Tauri validates the
        # sentinel PID against the externalBin launch process group leader.
        "pid": _sentinel_pid(),
        "port": int(listener.getsockname()[1]),
        "schema": READY_SCHEMA,
        "source_digest": source_digest,
    }
    sentinel = json.dumps(ready, sort_keys=True, separators=(",", ":"))
    protocol_stdout.write(sentinel + "\n")
    protocol_stdout.flush()

    # Parent process watchdog: if the Rust supervisor (parent) dies, the
    # sidecar will be orphaned. Exit immediately so no orphan sidecar or
    # listener survives the desktop shell.  The Rust supervisor passes its
    # PID via JS_AGENT_SUPERVISOR_PID; we also fall back to ppid monitoring
    # for older builds that do not set the env var.
    supervisor_pid_str = os.environ.get("JS_AGENT_SUPERVISOR_PID")
    supervisor_pid: int | None = None
    if supervisor_pid_str and supervisor_pid_str.isdigit():
        supervisor_pid = int(supervisor_pid_str)
    parent_pid = os.getppid()

    async def _parent_watchdog() -> None:
        while True:
            await asyncio.sleep(1.0)
            try:
                current_ppid = os.getppid()
            except OSError:
                break
            # If the supervisor PID was provided, check if it is still alive.
            if supervisor_pid is not None:
                try:
                    os.kill(supervisor_pid, 0)
                except OSError:
                    break
            # Also break if our direct parent changed (orphaned by init).
            if current_ppid != parent_pid:
                break
        server.should_exit = True

    watchdog_task = asyncio.create_task(_parent_watchdog())
    try:
        await task
    finally:
        watchdog_task.cancel()
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="js-agent-host")
    parser.add_argument("--source-digest", required=True)
    parser.add_argument(
        "--bootstrap-ttl-seconds",
        type=int,
        default=BOOTSTRAP_TTL_SECONDS,
        help=argparse.SUPPRESS,
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    # The Rust supervisor passes the digest it was compiled with. The sidecar
    # must NOT simply echo it back; compare against its own embedded value.
    from desktop.source_digest import EmbeddedProvenanceError, load_embedded_sidecar_digest

    try:
        if _DIGEST_PATTERN.fullmatch(args.source_digest) is None:
            raise EmbeddedProvenanceError("supervisor source digest is malformed")
        embedded = load_embedded_sidecar_digest()
        if not hmac.compare_digest(embedded, args.source_digest):
            raise EmbeddedProvenanceError("embedded and supervisor digests differ")
    except EmbeddedProvenanceError:
        print("desktop host provenance validation failed", file=sys.stderr)
        return 64
    # Existing AppShell libraries may use stdout for ordinary local logs.
    # Reserve the inherited descriptor before importing/building that runtime,
    # then silence regular stdout so the Rust protocol sees one sentinel only.
    protocol_stdout = sys.stdout
    # This descriptor intentionally remains open for the process lifetime: it
    # owns regular-library stdout while the inherited descriptor is protocol-only.
    sys.stdout = open(os.devnull, "w", encoding="utf-8")  # noqa: SIM115
    try:
        token = _read_bootstrap_token()
        listener = _bind_loopback_socket()
        port = int(listener.getsockname()[1])
        app, identity = create_desktop_host_app(
            token=token,
            ttl_seconds=args.bootstrap_ttl_seconds,
            port=port,
        )
    except (ValueError, OSError):
        print("invalid desktop host startup input", file=sys.stderr)
        return 64

    token = "0" * 64
    try:
        return asyncio.run(
            _serve(
                app=app,
                listener=listener,
                source_digest=embedded,
                protocol_stdout=protocol_stdout,
            )
        )
    finally:
        identity.close()
        listener.close()


if __name__ == "__main__":
    raise SystemExit(main())
