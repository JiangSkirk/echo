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

from pathlib import Path
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from js.config import JSSettings, SecurityConfig
from js.web import server as web_server
from js.web.auth import AuthManager, require_auth
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

        ctx = await require_auth(api_key=None)

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
        assert resp.cookies.get("js_session")

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

    def test_revoked_session_is_rejected(self, tmp_path: Path) -> None:
        client, admin_key = self._client_with_admin_key(tmp_path)
        resp = client.post("/api/auth/session", headers={"X-API-Key": admin_key})
        token = resp.cookies.get("js_session")
        assert token
        assert client.get("/api/audit").status_code == 200

        logout = client.post(
            "/api/auth/logout",
            headers={"Host": "localhost", "Origin": "http://localhost"},
        )
        assert logout.status_code == 200

        # Re-present the revoked token: the server must fail closed.
        client.cookies.set("js_session", token)
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

        from js.exceptions import AuthRequiredError

        with pytest.raises(AuthRequiredError):
            mgr.verify(key)


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

        with client.websocket_connect("/ws", headers=self._WS_ORIGIN):
            pass  # accepted: no credentials presented, local convenience mode

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
        token = resp.cookies.get("js_session")
        assert token
        auth_mgr.revoke_session(token)

        with (
            pytest.raises(WebSocketDisconnect) as exc_info,
            client.websocket_connect("/ws", headers=self._WS_ORIGIN),
        ):
            pass
        assert exc_info.value.code == 1008
