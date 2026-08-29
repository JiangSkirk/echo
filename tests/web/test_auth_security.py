"""Regression tests for Web identity/credential security fixes.

Covers:
- F-01: anonymous requests never receive the admin role (guest is read-only)
- F-02: the setup bootstrap window is restricted to loopback clients
- F-03/F-04: HttpOnly session-cookie login, revocation, and cookie flags
- F-05: the Prometheus /metrics mount requires admin auth
- F-06: API-key revocation uses exact prefix matching (no LIKE wildcards)
- F-07: WebSocket auth failures close with 1008 instead of anonymous downgrade
"""

from __future__ import annotations

import os
import sqlite3
import stat
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from js.config import JSSettings, SecurityConfig
from js.exceptions import AuthRequiredError
from js.web import server as web_server
from js.web.auth import AuthManager, authenticate_credentials
from js.web.server import create_app


def _settings(
    tmp_path: Path,
    *,
    api_key_required: bool,
    first_run_completed: bool = True,
) -> JSSettings:
    return JSSettings(
        workspace=tmp_path / "workspace",
        state_dir=tmp_path / "state",
        first_run_completed=first_run_completed,
        security=SecurityConfig(api_key_required=api_key_required),
    )


def _agent(settings: JSSettings) -> MagicMock:
    agent = MagicMock()
    agent.settings = settings
    agent.registry.get_stats.return_value = {}
    agent.secrets.get_stats.return_value = {}
    agent.memory.get_sessions.return_value = []
    agent.audit.query.return_value = []
    return agent


def _wire(settings: JSSettings, agent: MagicMock) -> TestClient:
    from js.web.deps import set_globals

    web_server._agent = agent
    web_server._settings = settings
    set_globals(agent, settings)
    return TestClient(create_app())


# ----------------------------------------------------------------------
# F-01: anonymous must be guest, never admin
# ----------------------------------------------------------------------


class TestAnonymousIsGuest:
    @pytest.mark.asyncio
    async def test_anonymous_context_is_guest_when_auth_optional(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        settings = _settings(tmp_path, api_key_required=False)
        monkeypatch.setattr(web_server, "_settings", settings)

        ctx = await authenticate_credentials(None, None)

        assert ctx["role"] == "guest"
        assert ctx["role"] != "admin"

    def test_guest_cannot_call_admin_endpoints(self, tmp_path: Path) -> None:
        settings = _settings(tmp_path, api_key_required=False)
        client = _wire(settings, _agent(settings))

        assert client.get("/api/audit").status_code == 403

    def test_guest_can_read_but_not_write(self, tmp_path: Path) -> None:
        settings = _settings(tmp_path, api_key_required=False)
        client = _wire(settings, _agent(settings))

        # Read-only endpoint stays reachable for the local convenience mode.
        assert client.get("/api/sessions").status_code == 200
        # State-changing endpoints are denied for the anonymous guest.
        assert client.post("/api/cancel/some-session").status_code == 403
        # Reconnaissance / model probes require an authenticated principal.
        assert client.get("/api/diag").status_code == 403
        assert (
            client.get("/api/file-preview", params={"path": "x.txt", "session_id": "s"}).status_code
            == 403
        )


# ----------------------------------------------------------------------
# require_auth: state-changing requests must pass the Origin/Host check
# ----------------------------------------------------------------------


class TestRequireAuthOriginGuard:
    """POST endpoints on ``require_user_write`` reject cross-site requests.

    /api/setup/test-model is one of the state-changing endpoints; a missing
    model_id makes the handler answer 400, which proves the request passed
    the Origin guard and reached the endpoint.
    """

    def test_cross_origin_post_rejected(self, tmp_path: Path) -> None:
        settings = _settings(tmp_path, api_key_required=False)
        client = _wire(settings, _agent(settings))

        resp = client.post(
            "/api/setup/test-model",
            json={"model_id": "fake/model"},
            headers={"Host": "localhost:8000", "Origin": "https://evil-attacker.com"},
        )

        assert resp.status_code == 403
        assert resp.json()["detail"] == "Cross-origin request rejected"

    def test_cross_origin_post_rejected_before_valid_key(self, tmp_path: Path) -> None:
        """The Origin check runs before any credential is resolved."""
        settings = _settings(tmp_path, api_key_required=False)
        user_key = AuthManager(settings.state_dir).create_key("user", role="user")
        client = _wire(settings, _agent(settings))

        resp = client.post(
            "/api/setup/test-model",
            json={"model_id": "fake/model"},
            headers={
                "Host": "localhost:8000",
                "Origin": "https://evil-attacker.com",
                "X-API-Key": user_key,
            },
        )

        assert resp.status_code == 403

    def test_same_origin_post_allowed(self, tmp_path: Path) -> None:
        settings = _settings(tmp_path, api_key_required=False)
        user_key = AuthManager(settings.state_dir).create_key("user", role="user")
        client = _wire(settings, _agent(settings))

        resp = client.post(
            "/api/setup/test-model",
            json={},
            headers={
                "Host": "localhost",
                "Origin": "http://localhost",
                "X-API-Key": user_key,
            },
        )

        assert resp.status_code == 422  # reached the handler: model_id missing

    def test_guest_same_origin_test_model_denied(self, tmp_path: Path) -> None:
        settings = _settings(tmp_path, api_key_required=False)
        client = _wire(settings, _agent(settings))

        resp = client.post(
            "/api/setup/test-model",
            json={"model_id": "fake/model"},
            headers={"Host": "localhost", "Origin": "http://localhost"},
        )

        assert resp.status_code == 403

    def test_non_browser_post_without_origin_allowed(self, tmp_path: Path) -> None:
        """curl/CLI clients send no Origin; a presented API key passes the guard."""
        settings = _settings(tmp_path, api_key_required=False)
        user_key = AuthManager(settings.state_dir).create_key("cli", role="user")
        client = _wire(settings, _agent(settings))

        resp = client.post(
            "/api/setup/test-model",
            json={},
            headers={"X-API-Key": user_key},
        )

        assert resp.status_code == 422  # reached the handler: model_id missing

    def test_check_origin_dummy_key_without_app_scope_is_403(self) -> None:
        """Missing ASGI app must not turn Origin rejection into a 500."""
        from starlette.requests import Request

        from js.web.auth import check_origin

        scope = {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": "POST",
            "scheme": "http",
            "path": "/",
            "raw_path": b"/",
            "query_string": b"",
            "headers": [(b"host", b"localhost:8000"), (b"x-api-key", b"not-real")],
            "client": ("127.0.0.1", 1),
            "server": ("127.0.0.1", 8000),
        }
        with pytest.raises(Exception) as exc_info:
            check_origin(Request(scope))
        assert getattr(exc_info.value, "status_code", None) == 403

    def test_non_browser_post_dummy_key_without_origin_rejected(self, tmp_path: Path) -> None:
        """A present but unverified X-API-Key must not skip Origin."""
        settings = _settings(tmp_path, api_key_required=False)
        client = _wire(settings, _agent(settings))

        resp = client.post(
            "/api/setup/test-model",
            json={},
            headers={"X-API-Key": "js_dummy_unverified"},
        )

        assert resp.status_code == 403
        assert resp.json()["detail"] == "Origin header required for browser-based requests"


# ----------------------------------------------------------------------
# F-02: bootstrap window is loopback-only
# ----------------------------------------------------------------------


class TestBootstrapLoopbackOnly:
    def _bootstrap_settings(self, tmp_path: Path) -> JSSettings:
        settings = _settings(tmp_path, api_key_required=True, first_run_completed=False)
        assert not AuthManager(settings.state_dir).has_admin()
        return settings

    def test_bootstrap_allowed_from_loopback(self, tmp_path: Path) -> None:
        settings = self._bootstrap_settings(tmp_path)
        agent = _agent(settings)
        from js.web.deps import set_globals

        web_server._agent = agent
        web_server._settings = settings
        set_globals(agent, settings)
        client = TestClient(create_app(), client=("127.0.0.1", 50000))

        resp = client.get("/api/setup/first-start")
        assert resp.status_code == 200

    @pytest.mark.parametrize("host", ["203.0.113.10", "10.0.0.5", "testclient"])
    def test_bootstrap_denied_from_non_loopback(self, tmp_path: Path, host: str) -> None:
        settings = self._bootstrap_settings(tmp_path)
        agent = _agent(settings)
        from js.web.deps import set_globals

        web_server._agent = agent
        web_server._settings = settings
        set_globals(agent, settings)
        client = TestClient(create_app(), client=(host, 50000))

        resp = client.get("/api/setup/first-start")
        assert resp.status_code == 403

    def test_non_loopback_with_valid_key_still_authenticates(self, tmp_path: Path) -> None:
        settings = self._bootstrap_settings(tmp_path)
        user_key = AuthManager(settings.state_dir).create_key("remote-user", role="user")
        agent = _agent(settings)
        from js.web.deps import set_globals

        web_server._agent = agent
        web_server._settings = settings
        set_globals(agent, settings)
        client = TestClient(create_app(), client=("203.0.113.10", 50000))

        resp = client.get("/api/setup/first-start", headers={"X-API-Key": user_key})
        assert resp.status_code == 200

    def test_bootstrap_denied_when_forwarded_headers_present(self, tmp_path: Path) -> None:
        """Loopback peer behind a reverse proxy must not win the bootstrap window."""
        settings = self._bootstrap_settings(tmp_path)
        agent = _agent(settings)
        from js.web.deps import set_globals

        web_server._agent = agent
        web_server._settings = settings
        set_globals(agent, settings)
        client = TestClient(create_app(), client=("127.0.0.1", 50000))

        resp = client.get(
            "/api/setup/first-start",
            headers={"X-Forwarded-For": "203.0.113.50"},
        )
        assert resp.status_code == 403
        assert (
            "reverse-proxy" in resp.json()["detail"].lower()
            or "forwarded" in resp.json()["detail"].lower()
        )

    @pytest.mark.parametrize(
        "headers",
        [
            # DNS-rebinding: browser connects to 127.0.0.1 but Host/Origin
            # carry the attacker's domain.
            {"Host": "evil-attacker.com:8000", "Origin": "https://evil-attacker.com"},
            # Plain CSRF: loopback Host but a cross-site Origin.
            {"Host": "localhost:8000", "Origin": "https://evil-attacker.com"},
            # Origin stripped entirely (curl-style non-browser client).
            {},
        ],
    )
    def test_bootstrap_mutations_require_origin(
        self, tmp_path: Path, headers: dict[str, str]
    ) -> None:
        """R3-1: the bootstrap window grants ADMIN without credentials, and
        /api/setup/complete returns a one-time admin key in its body — so
        mutating setup calls must pass the Origin/Host check or a rebinding
        page can steal full admin access."""
        settings = self._bootstrap_settings(tmp_path)
        agent = _agent(settings)
        from js.web.deps import set_globals

        web_server._agent = agent
        web_server._settings = settings
        set_globals(agent, settings)
        client = TestClient(create_app(), client=("127.0.0.1", 50000))

        for route in ("/api/setup/complete", "/api/setup/skip", "/api/setup/reset"):
            resp = client.post(route, headers=headers)
            assert resp.status_code == 403, (route, headers, resp.text[:200])
            assert "admin_key" not in resp.text


# ----------------------------------------------------------------------
# Setup auth-optional: anonymous is guest (read-only)
# ----------------------------------------------------------------------


class TestSetupAuthOptionalIsGuest:
    def test_setup_anonymous_is_guest_when_auth_optional(self, tmp_path: Path) -> None:
        settings = _settings(tmp_path, api_key_required=False, first_run_completed=False)
        client = _wire(settings, _agent(settings))

        # first-start is read-only and remains reachable for guests
        assert client.get("/api/setup/first-start").status_code == 200

    def test_setup_complete_denied_for_anonymous_guest(self, tmp_path: Path) -> None:
        settings = _settings(tmp_path, api_key_required=False, first_run_completed=False)
        client = _wire(settings, _agent(settings))

        resp = client.post("/api/setup/complete")
        assert resp.status_code == 403

    def test_setup_reset_denied_for_anonymous_guest(self, tmp_path: Path) -> None:
        settings = _settings(tmp_path, api_key_required=False, first_run_completed=False)
        client = _wire(settings, _agent(settings))

        resp = client.post("/api/setup/reset")
        assert resp.status_code == 403


# ----------------------------------------------------------------------
# F-03/F-04: HttpOnly session cookie login
# ----------------------------------------------------------------------


class TestSessionCookieLogin:
    def _client_with_admin_key(self, tmp_path: Path) -> tuple[TestClient, str]:
        settings = _settings(tmp_path, api_key_required=True, first_run_completed=True)
        admin_key = AuthManager(settings.state_dir).create_key("admin", role="admin")
        return _wire(settings, _agent(settings)), admin_key

    def test_login_sets_httponly_session_cookie(self, tmp_path: Path) -> None:
        client, admin_key = self._client_with_admin_key(tmp_path)

        resp = client.post("/api/auth/session", headers={"X-API-Key": admin_key})

        assert resp.status_code == 200
        set_cookie = resp.headers["set-cookie"]
        assert "HttpOnly" in set_cookie
        assert "SameSite=strict" in set_cookie
        assert resp.cookies.get("js_session_js-agent")

    def test_login_rejects_invalid_key(self, tmp_path: Path) -> None:
        client, _admin_key = self._client_with_admin_key(tmp_path)

        resp = client.post("/api/auth/session", headers={"X-API-Key": "js_wrong"})

        assert resp.status_code == 401

    def test_session_cookie_authenticates_protected_endpoints(self, tmp_path: Path) -> None:
        client, admin_key = self._client_with_admin_key(tmp_path)
        # No header key on this client: the cookie alone must authenticate.
        assert client.get("/api/audit").status_code == 401

        resp = client.post("/api/auth/session", headers={"X-API-Key": admin_key})
        assert resp.status_code == 200

        assert client.get("/api/audit").status_code == 200

    def test_login_deletes_bootstrap_admin_key_file(self, tmp_path: Path) -> None:
        settings = _settings(tmp_path, api_key_required=True, first_run_completed=True)
        admin_key = AuthManager(settings.state_dir).create_key("admin", role="admin")
        key_file = settings.state_dir / "bootstrap_admin_key.txt"
        key_file.write_text(admin_key + "\n", encoding="utf-8")
        key_file.chmod(0o600)
        client = _wire(settings, _agent(settings))

        resp = client.post("/api/auth/session", headers={"X-API-Key": admin_key})
        assert resp.status_code == 200
        assert not key_file.exists()

    def test_revoked_session_is_rejected(self, tmp_path: Path) -> None:
        client, admin_key = self._client_with_admin_key(tmp_path)
        resp = client.post("/api/auth/session", headers={"X-API-Key": admin_key})
        token = resp.cookies.get("js_session_js-agent")
        assert token
        assert client.get("/api/audit").status_code == 200

        logout = client.post(
            "/api/auth/logout",
            headers={"Host": "localhost", "Origin": "http://localhost"},
        )
        assert logout.status_code == 200

        # Re-present the revoked token: the server must fail closed.
        client.cookies.set("js_session_js-agent", token)
        assert client.get("/api/audit").status_code == 401

    def test_session_dies_with_underlying_key(self, tmp_path: Path) -> None:
        settings = _settings(tmp_path, api_key_required=True, first_run_completed=True)
        auth_mgr = AuthManager(settings.state_dir)
        admin_key = auth_mgr.create_key("admin", role="admin")
        client = _wire(settings, _agent(settings))
        resp = client.post("/api/auth/session", headers={"X-API-Key": admin_key})
        assert resp.status_code == 200
        assert client.get("/api/audit").status_code == 200

        key_id = auth_mgr.list_keys()[0]["id"].replace("...", "")
        assert auth_mgr.revoke_key(key_id) is True
        assert client.get("/api/audit").status_code == 401


# ----------------------------------------------------------------------
# F-05: /metrics requires admin
# ----------------------------------------------------------------------


@pytest.mark.skipif(not web_server._MONITORING_AVAILABLE, reason="prometheus not installed")
class TestMetricsRequiresAdmin:
    def test_metrics_denied_for_anonymous_guest(self, tmp_path: Path) -> None:
        settings = _settings(tmp_path, api_key_required=False)
        client = _wire(settings, _agent(settings))

        assert client.get("/metrics").status_code == 403

    def test_metrics_denied_for_non_admin_key(self, tmp_path: Path) -> None:
        settings = _settings(tmp_path, api_key_required=True)
        user_key = AuthManager(settings.state_dir).create_key("user", role="user")
        client = _wire(settings, _agent(settings))

        assert client.get("/metrics", headers={"X-API-Key": user_key}).status_code == 403

    def test_metrics_allowed_for_admin_key(self, tmp_path: Path) -> None:
        settings = _settings(tmp_path, api_key_required=True)
        admin_key = AuthManager(settings.state_dir).create_key("admin", role="admin")
        client = _wire(settings, _agent(settings))

        assert client.get("/metrics", headers={"X-API-Key": admin_key}).status_code == 200


# ----------------------------------------------------------------------
# F-06: revoke_key must not interpret LIKE wildcards
# ----------------------------------------------------------------------


class TestRevokeKeyExactMatch:
    def test_wildcard_prefix_does_not_delete_keys(self, tmp_path: Path) -> None:
        mgr = AuthManager(tmp_path)
        key_a = mgr.create_key("a", role="admin")
        key_b = mgr.create_key("b", role="user")

        # "_" and "%" are LIKE wildcards; they must be treated literally.
        assert mgr.revoke_key("________") is False
        assert mgr.revoke_key("%%%%%%%%") is False
        assert mgr.verify(key_a)["name"] == "a"
        assert mgr.verify(key_b)["name"] == "b"

    def test_exact_prefix_still_revokes(self, tmp_path: Path) -> None:
        mgr = AuthManager(tmp_path)
        key = mgr.create_key("victim", role="admin")
        prefix = mgr.list_keys()[0]["id"].replace("...", "")

        assert mgr.revoke_key(prefix) is True

        with pytest.raises(AuthRequiredError):
            mgr.verify(key)


class TestManagedApiKeyProvenance:
    _ISSUER = "js-agent-desktop-bootstrap-v1"

    @staticmethod
    def _database_rows(state_dir: Path) -> dict[str, list[tuple[object, ...]]]:
        with sqlite3.connect(state_dir / "api_keys.db") as connection:
            return {
                "api_keys": connection.execute(
                    "SELECT key_hash, name, role, created_at, last_used, enabled "
                    "FROM api_keys ORDER BY key_hash"
                ).fetchall(),
                "auth_sessions": connection.execute(
                    "SELECT token_hash, key_hash, created_at, expires_at "
                    "FROM auth_sessions ORDER BY token_hash"
                ).fetchall(),
            }

    def test_desktop_purge_preserves_unmarked_same_name_key_and_session(
        self,
        tmp_path: Path,
    ) -> None:
        mgr = AuthManager(tmp_path)
        ordinary_key = mgr.create_key("desktop-bootstrap-ephemeral", role="admin")
        mgr.create_session(ordinary_key)
        before = self._database_rows(tmp_path)

        assert mgr.purge_managed_keys(issuer=self._ISSUER) == []

        assert self._database_rows(tmp_path) == before
        assert mgr.verify(ordinary_key)["name"] == "desktop-bootstrap-ephemeral"

    def test_managed_key_and_marker_are_one_transaction(self, tmp_path: Path) -> None:
        tmp_path.mkdir(exist_ok=True)
        with sqlite3.connect(tmp_path / "api_keys.db") as connection:
            connection.execute(
                "CREATE TABLE managed_api_keys ("
                "key_hash TEXT PRIMARY KEY, issuer TEXT NOT NULL, created_at REAL NOT NULL)"
            )
            connection.commit()
        mgr = AuthManager(tmp_path)
        with sqlite3.connect(tmp_path / "api_keys.db") as connection:
            connection.execute(
                "CREATE TRIGGER reject_managed_marker "
                "BEFORE INSERT ON managed_api_keys "
                "BEGIN SELECT RAISE(ABORT, 'marker rejected'); END"
            )
            connection.commit()

        key = "js_" + "a" * 43
        with pytest.raises(sqlite3.IntegrityError, match="marker rejected"):
            mgr.provision_managed_key(
                key,
                name="desktop-bootstrap-ephemeral",
                role="admin",
                issuer=self._ISSUER,
            )

        with sqlite3.connect(tmp_path / "api_keys.db") as connection:
            assert connection.execute("SELECT * FROM api_keys").fetchall() == []
            assert connection.execute("SELECT * FROM managed_api_keys").fetchall() == []

    def test_managed_revoke_removes_marker_sessions_and_cached_identity(
        self,
        tmp_path: Path,
    ) -> None:

        mgr = AuthManager(tmp_path)
        key = "js_" + "b" * 43
        identity = mgr.provision_managed_key(
            key,
            name="desktop-bootstrap-ephemeral",
            role="admin",
            issuer=self._ISSUER,
        )
        mgr.create_session(key)
        assert mgr.verify(key)["key_hash"] == identity["key_hash"]

        assert mgr.revoke_key(str(identity["key_hash"])[:16])

        with sqlite3.connect(tmp_path / "api_keys.db") as connection:
            assert connection.execute("SELECT * FROM api_keys").fetchall() == []
            assert connection.execute("SELECT * FROM auth_sessions").fetchall() == []
            assert connection.execute("SELECT * FROM managed_api_keys").fetchall() == []
        with pytest.raises(AuthRequiredError):
            mgr.verify(key)

    def test_malformed_managed_provenance_schema_fails_closed(self, tmp_path: Path) -> None:
        tmp_path.mkdir(exist_ok=True)
        with sqlite3.connect(tmp_path / "api_keys.db") as connection:
            connection.execute("CREATE TABLE managed_api_keys (key_hash TEXT PRIMARY KEY)")
            connection.commit()

        with pytest.raises(RuntimeError, match="managed API key provenance schema"):
            AuthManager(tmp_path)


# ----------------------------------------------------------------------
# F-07: WebSocket auth failure must not downgrade to anonymous
# ----------------------------------------------------------------------


class TestWebSocketAuthFailClosed:
    def test_ws_invalid_key_closed_when_auth_optional(self, tmp_path: Path) -> None:
        settings = _settings(tmp_path, api_key_required=False)
        client = _wire(settings, _agent(settings))

        with (
            pytest.raises(WebSocketDisconnect) as exc_info,
            client.websocket_connect("/ws", headers={"X-API-Key": "js_invalid"}),
        ):
            pass
        assert exc_info.value.code == 1008

    _WS_ORIGIN = {"Host": "localhost", "Origin": "http://localhost"}

    def test_ws_anonymous_still_allowed_when_auth_optional(self, tmp_path: Path) -> None:
        settings = _settings(tmp_path, api_key_required=False)
        client = _wire(settings, _agent(settings))

        with client.websocket_connect("/ws", headers=self._WS_ORIGIN) as ws:
            # Connection may stay open for browsing, but chat turns are rejected.
            ws.send_json({"type": "message", "content": "hello"})
            reply = ws.receive_json()
            assert reply["type"] == "error"
            assert (
                "read-only" in reply["content"].lower()
                or "authenticate" in reply["content"].lower()
            )

    def test_ws_accepts_session_cookie(self, tmp_path: Path) -> None:
        settings = _settings(tmp_path, api_key_required=True, first_run_completed=True)
        admin_key = AuthManager(settings.state_dir).create_key("admin", role="admin")
        client = _wire(settings, _agent(settings))
        resp = client.post("/api/auth/session", headers={"X-API-Key": admin_key})
        assert resp.status_code == 200

        with client.websocket_connect("/ws", headers=self._WS_ORIGIN):
            pass  # accepted via HttpOnly session cookie

    def test_ws_rejects_revoked_session_cookie(self, tmp_path: Path) -> None:
        settings = _settings(tmp_path, api_key_required=True, first_run_completed=True)
        auth_mgr = AuthManager(settings.state_dir)
        admin_key = auth_mgr.create_key("admin", role="admin")
        client = _wire(settings, _agent(settings))
        resp = client.post("/api/auth/session", headers={"X-API-Key": admin_key})
        token = resp.cookies.get("js_session_js-agent")
        assert token
        auth_mgr.revoke_session(token)

        with (
            pytest.raises(WebSocketDisconnect) as exc_info,
            client.websocket_connect("/ws", headers=self._WS_ORIGIN),
        ):
            pass
        assert exc_info.value.code == 1008


# ----------------------------------------------------------------------
# Verify-cache bounds: the process-wide shared caches must not grow forever
# ----------------------------------------------------------------------


class TestVerifyCacheBounds:
    """_SHARED_VERIFY_CACHE / _SHARED_LAST_USED stay under the hard cap."""

    @pytest.fixture
    def _restore_caches(self):
        saved_verify = dict(AuthManager._SHARED_VERIFY_CACHE)
        saved_last = dict(AuthManager._SHARED_LAST_USED)
        AuthManager._SHARED_VERIFY_CACHE.clear()
        AuthManager._SHARED_LAST_USED.clear()
        yield
        AuthManager._SHARED_VERIFY_CACHE.clear()
        AuthManager._SHARED_VERIFY_CACHE.update(saved_verify)
        AuthManager._SHARED_LAST_USED.clear()
        AuthManager._SHARED_LAST_USED.update(saved_last)

    def test_expired_entries_purged_before_clear(self, _restore_caches) -> None:
        now = time.time()
        fresh_identity = {"name": "a", "role": "user", "key_hash": "x"}
        AuthManager._SHARED_VERIFY_CACHE["fresh"] = (now, fresh_identity)
        for i in range(AuthManager._VERIFY_CACHE_MAX_ENTRIES + 1):
            stale_identity = {"name": "s", "role": "user", "key_hash": "h"}
            AuthManager._SHARED_VERIFY_CACHE[f"stale:{i}"] = (now - 60.0, stale_identity)
            AuthManager._SHARED_LAST_USED[f"stale:{i}"] = now - 60.0

        AuthManager._enforce_verify_cache_bounds(now)

        assert dict(AuthManager._SHARED_VERIFY_CACHE) == {"fresh": (now, fresh_identity)}
        assert not AuthManager._SHARED_LAST_USED

    def test_full_clear_when_still_over_cap(self, _restore_caches) -> None:
        now = time.time()
        for i in range(AuthManager._VERIFY_CACHE_MAX_ENTRIES + 1):
            identity = {"name": "n", "role": "user", "key_hash": "h"}
            AuthManager._SHARED_VERIFY_CACHE[f"k:{i}"] = (now, identity)
            AuthManager._SHARED_LAST_USED[f"k:{i}"] = now

        AuthManager._enforce_verify_cache_bounds(now)

        assert not AuthManager._SHARED_VERIFY_CACHE
        assert not AuthManager._SHARED_LAST_USED

    def test_under_cap_is_noop(self, _restore_caches) -> None:
        now = time.time()
        identity = {"name": "n", "role": "user", "key_hash": "h"}
        AuthManager._SHARED_VERIFY_CACHE["k"] = (now - 60.0, identity)
        AuthManager._SHARED_LAST_USED["k"] = now - 60.0

        AuthManager._enforce_verify_cache_bounds(now)

        # Expired but under the cap — left alone on the cheap path.
        assert "k" in AuthManager._SHARED_VERIFY_CACHE
        assert "k" in AuthManager._SHARED_LAST_USED


class TestRevokeInvalidatesVerifyCacheImmediately:
    def test_user_key_revoke_is_visible_on_next_verify(self, tmp_path: Path) -> None:
        mgr = AuthManager(tmp_path)
        key = mgr.create_key("user", role="user")
        assert mgr.verify(key)["role"] == "user"
        prefix = mgr.list_keys()[0]["id"].replace("...", "")
        assert mgr.revoke_key(prefix) is True
        with pytest.raises(AuthRequiredError, match="Invalid API key"):
            mgr.verify(key)

    def test_admin_key_is_never_positively_cached(self, tmp_path: Path) -> None:
        mgr = AuthManager(tmp_path)
        key = mgr.create_key("admin", role="admin")
        assert mgr.verify(key)["role"] == "admin"
        assert not any(
            identity.get("role") == "admin"
            for _, identity in AuthManager._SHARED_VERIFY_CACHE.values()
        )
        prefix = mgr.list_keys()[0]["id"].replace("...", "")
        assert mgr.revoke_key(prefix) is True
        with pytest.raises(AuthRequiredError, match="Invalid API key"):
            mgr.verify(key)

    def test_stale_cache_write_after_epoch_bump_is_ignored(self, tmp_path: Path) -> None:
        mgr = AuthManager(tmp_path)
        key = mgr.create_key("user", role="user")
        identity = mgr.verify(key)
        prefix = mgr.list_keys()[0]["id"].replace("...", "")
        assert mgr.revoke_key(prefix) is True
        cache_key = mgr._cache_key(identity["key_hash"])
        # Plant a positive entry as if a raced writer won after revoke.
        AuthManager._SHARED_VERIFY_CACHE[cache_key] = (time.time(), identity)
        AuthManager._SHARED_VERIFY_STAMP[cache_key] = mgr._current_epoch() - 1
        with pytest.raises(AuthRequiredError, match="Invalid API key"):
            mgr.verify(key)


class TestAuthStorePermissions:
    def test_api_keys_db_is_owner_only(self, tmp_path: Path) -> None:
        state_dir = tmp_path / "state"
        AuthManager(state_dir)
        db_path = state_dir / "api_keys.db"
        assert db_path.exists()
        dir_mode = stat.S_IMODE(os.stat(state_dir).st_mode)
        db_mode = stat.S_IMODE(os.stat(db_path).st_mode)
        assert dir_mode == 0o700
        assert db_mode == 0o600


class TestLegacyApiKeyCookieRejected:
    _WS_ORIGIN = {"Host": "localhost", "Origin": "http://localhost"}

    def test_ws_rejects_x_api_key_cookie(self, tmp_path: Path) -> None:
        settings = _settings(tmp_path, api_key_required=True, first_run_completed=True)
        admin_key = AuthManager(settings.state_dir).create_key("admin", role="admin")
        client = _wire(settings, _agent(settings))
        client.cookies.set("x-api-key", admin_key)

        with (
            pytest.raises(WebSocketDisconnect) as exc_info,
            client.websocket_connect("/ws", headers=self._WS_ORIGIN),
        ):
            pass
        assert exc_info.value.code == 1008

    def test_ws_still_accepts_x_api_key_header(self, tmp_path: Path) -> None:
        settings = _settings(tmp_path, api_key_required=True, first_run_completed=True)
        admin_key = AuthManager(settings.state_dir).create_key("admin", role="admin")
        client = _wire(settings, _agent(settings))

        with client.websocket_connect(
            "/ws",
            headers={**self._WS_ORIGIN, "X-API-Key": admin_key},
        ):
            pass
