"""Fresh-install / first-run bootstrap regression tests.

These guard the experience after ``macos_start.sh`` runs ``js setup`` and then
``js open``: with ``api_key_required=True`` (the production default) the site
must land in a *usable* state.  The historical bug was that no admin key was
ever created, so either the first-run wizard 401'd on ``/api/models`` or — worse
— ``/api/setup/complete`` set ``first_run_completed=true`` with no admin key in
``api_keys.db``, locking every endpoint behind 401 with no recovery path.

The fix: startup provisioning mints a one-time admin key whenever auth is
required and none exists (self-healing the lockdown), persists it to a 0600
file + logs it, and injects it into the local browser so the fresh install
authenticates automatically.
"""

from __future__ import annotations

import stat
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from js.config import JSSettings
from js.web import server as web_server
from js.web.auth import AuthManager, require_auth
from js.web.server import (
    _inject_bootstrap_key,
    _is_loopback,
    _provision_bootstrap_admin_key,
    create_app,
)


def _settings(tmp_path: Path, *, api_key_required: bool, first_run: bool = False) -> JSSettings:
    s = JSSettings(workspace=tmp_path / "ws", state_dir=tmp_path / "state")
    s.security.api_key_required = api_key_required
    s.first_run_completed = first_run
    return s


class TestEnsureBootstrapAdminKey:
    def test_mints_once_and_is_idempotent(self, tmp_path: Path) -> None:
        mgr = AuthManager(tmp_path / "state")
        assert mgr.has_admin() is False
        key = mgr.ensure_bootstrap_admin_key()
        assert key
        assert mgr.has_admin() is True
        # The minted key is a working admin credential.
        assert mgr.verify(key)["role"] == "admin"
        # Never mints a second one.
        assert mgr.ensure_bootstrap_admin_key() is None


class TestProvisioning:
    def test_skips_when_auth_disabled(self, tmp_path: Path) -> None:
        s = _settings(tmp_path, api_key_required=False)
        assert _provision_bootstrap_admin_key(s) is None
        assert AuthManager(s.state_dir).has_admin() is False

    def test_mints_and_persists_when_auth_required(self, tmp_path: Path) -> None:
        s = _settings(tmp_path, api_key_required=True)
        key = _provision_bootstrap_admin_key(s)
        assert key
        assert AuthManager(s.state_dir).has_admin() is True
        key_file = s.state_dir / "bootstrap_admin_key.txt"
        assert key_file.exists()
        assert key_file.read_text().strip() == key
        # Owner-readable only (0600).
        mode = stat.S_IMODE(key_file.stat().st_mode)
        assert mode == 0o600

    def test_lockdown_state_self_heals(self, tmp_path: Path) -> None:
        # The dangerous state: setup marked complete but NO admin key exists.
        s = _settings(tmp_path, api_key_required=True, first_run=True)
        assert AuthManager(s.state_dir).has_admin() is False  # would be a 401 lockdown
        key = _provision_bootstrap_admin_key(s)
        assert key
        # No longer keyless → the site can never be fully locked out.
        assert AuthManager(s.state_dir).has_admin() is True


class TestInjectionHelpers:
    def test_inject_places_key_before_head_close(self) -> None:
        html = "<html><head><title>x</title></head><body>hi</body></html>"
        out = _inject_bootstrap_key(html, "abc-123")
        assert "window.__BOOTSTRAP_API_KEY__" in out
        assert "abc-123" in out
        assert out.index("__BOOTSTRAP_API_KEY__") < out.index("</head>")

    def test_inject_without_head_prepends(self) -> None:
        out = _inject_bootstrap_key("<body>x</body>", "k")
        assert out.startswith("<script>")

    def test_is_loopback(self) -> None:
        def req(host: str | None) -> MagicMock:
            r = MagicMock()
            r.client = None if host is None else MagicMock(host=host)
            return r

        assert _is_loopback(req("127.0.0.1")) is True
        assert _is_loopback(req("::1")) is True
        assert _is_loopback(req("203.0.113.5")) is False
        assert _is_loopback(req(None)) is False


class TestAuthEnforcement:
    @pytest.mark.asyncio
    async def test_no_key_401_but_minted_key_authorizes_admin(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        s = _settings(tmp_path, api_key_required=True)
        key = _provision_bootstrap_admin_key(s)
        assert key
        # require_auth reads the module-global settings.
        monkeypatch.setattr(web_server, "_settings", s)

        # No key → enforced 401 (auth is NOT silently disabled).
        with pytest.raises(HTTPException) as ei:
            await require_auth(api_key=None)
        assert ei.value.status_code == 401

        # The minted bootstrap key unlocks the site as admin.
        ctx = await require_auth(api_key=key)
        assert ctx["role"] == "admin"


class TestRootInjection:
    def test_root_injects_key_for_local_browser(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(web_server, "_bootstrap_admin_key", "KEY-XYZ")
        monkeypatch.setattr(web_server, "_is_loopback", lambda req: True)
        client = TestClient(create_app())
        r = client.get("/")
        assert r.status_code == 200
        assert "window.__BOOTSTRAP_API_KEY__" in r.text
        assert "KEY-XYZ" in r.text

    def test_root_no_inject_when_no_bootstrap_key(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(web_server, "_bootstrap_admin_key", None)
        client = TestClient(create_app())
        r = client.get("/")
        assert r.status_code == 200
        assert "__BOOTSTRAP_API_KEY__" not in r.text

    def test_root_no_inject_for_remote_client(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Even if a key was minted, a non-loopback client must never receive it.
        monkeypatch.setattr(web_server, "_bootstrap_admin_key", "KEY-XYZ")
        monkeypatch.setattr(web_server, "_is_loopback", lambda req: False)
        client = TestClient(create_app())
        r = client.get("/")
        assert "KEY-XYZ" not in r.text


class TestSetupCompleteProvisioning:
    def test_setup_complete_returns_admin_key_in_bootstrap(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import yaml

        config_path = tmp_path / "config.yaml"
        config_path.write_text(yaml.safe_dump({
            "version": "0.1.1",
            "first_run_completed": False,
            # Pin to tmp dirs so the test never touches the real ~/.js state.
            "state_dir": str(tmp_path / "state"),
            "workspace": str(tmp_path / "ws"),
        }))
        monkeypatch.setenv("JS_CONFIG_PATH", str(config_path))

        settings = JSSettings.from_file(config_path)
        settings.security.api_key_required = True
        settings.first_run_completed = False
        assert not AuthManager(settings.state_dir).has_admin()  # genuinely fresh

        mock_agent = MagicMock()
        mock_agent.settings = settings
        mock_agent.router = MagicMock()
        mock_agent.router.health_check = AsyncMock(return_value={})

        web_server._agent = mock_agent
        from js.web.deps import set_globals

        set_globals(mock_agent, settings)
        web_server._settings = settings

        client = TestClient(create_app())
        resp = client.post("/api/setup/complete")
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        # A usable admin key was minted before the bootstrap window closed.
        assert data.get("admin_key")
        assert AuthManager(settings.state_dir).has_admin() is True
        assert settings.first_run_completed is True
