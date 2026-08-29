"""Fresh-install / first-run bootstrap regression tests.

These guard the experience after ``macos_start.sh`` runs ``js setup`` and the
desktop Host starts: with ``api_key_required=True`` (the production default)
the site must land in a *usable* state.  The historical bug was that no admin
key was ever created, so either the first-run wizard 401'd on ``/api/models``
or — worse — ``/api/setup/complete`` set ``first_run_completed=true`` with no
admin key in ``api_keys.db``, locking every endpoint behind 401 with no
recovery path.

The fix: startup provisioning mints a one-time admin key whenever auth is
required and none exists (self-healing the lockdown), persists it to a 0600
file, logs only that file's path, and injects it into the local desktop window
so the fresh install authenticates automatically.
"""

from __future__ import annotations

import asyncio
import multiprocessing
import os
import stat
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from js.agent import JSAgent
from js.appshell.entry_url import bootstrap_browser_url
from js.config import JSSettings
from js.web import server as web_server
from js.web.auth import AuthManager, authenticate_credentials
from js.web.server import _provision_bootstrap_admin_key, create_app


def _concurrent_bootstrap_worker(
    workspace: str,
    state_dir: str,
    start: object,
    results: object,
) -> None:
    try:
        start.wait(timeout=10)  # type: ignore[attr-defined]
        settings = JSSettings(workspace=Path(workspace), state_dir=Path(state_dir))
        settings.security.api_key_required = True
        results.put(("ok", _provision_bootstrap_admin_key(settings)))  # type: ignore[attr-defined]
    except Exception as exc:  # pragma: no cover - assertion reports child failure
        results.put(("error", f"{type(exc).__name__}: {exc}"))  # type: ignore[attr-defined]


def _settings(tmp_path: Path, *, api_key_required: bool, first_run: bool = False) -> JSSettings:
    s = JSSettings(workspace=tmp_path / "ws", state_dir=tmp_path / "state")
    s.security.api_key_required = api_key_required
    s.first_run_completed = first_run
    return s


def _directory_mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def test_personal_storage_roots_are_private_under_umask_022(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("JS_WORKSPACE", raising=False)
    monkeypatch.delenv("JS_STATE_DIR", raising=False)
    root = tmp_path / ".js"
    previous_umask = os.umask(0o022)
    try:
        settings = JSSettings(providers=[])
    finally:
        os.umask(previous_umask)

    assert [_directory_mode(path) for path in (root, settings.workspace, settings.state_dir)] == [
        0o700,
        0o700,
        0o700,
    ]


def test_personal_storage_tightens_existing_directories(tmp_path: Path) -> None:
    root = tmp_path / ".js"
    workspace = root / "workspace"
    state_dir = root / "state"
    workspace.mkdir(parents=True)
    state_dir.mkdir()
    for path in (root, workspace, state_dir):
        path.chmod(0o755)

    JSSettings(workspace=workspace, state_dir=state_dir, providers=[])

    assert [_directory_mode(path) for path in (root, workspace, state_dir)] == [
        0o700,
        0o700,
        0o700,
    ]


def test_workspace_must_not_be_state_dir_or_its_ancestor(tmp_path: Path) -> None:
    """A state directory inside the workspace is reachable by tool writes."""
    from pydantic import ValidationError

    with pytest.raises(ValidationError, match="workspace must not be"):
        JSSettings(workspace=tmp_path, state_dir=tmp_path, providers=[])
    with pytest.raises(ValidationError, match="workspace must not be"):
        JSSettings(workspace=tmp_path, state_dir=tmp_path / "state", providers=[])

    # Sibling directories remain a valid configuration.
    JSSettings(workspace=tmp_path / "ws", state_dir=tmp_path / "state", providers=[])


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS system alias contract")
def test_personal_storage_accepts_root_owned_macos_tmp_alias(tmp_path: Path) -> None:
    aliases = ((Path("/tmp"), Path("/private/tmp")), (Path("/var"), Path("/private/var")))
    try:
        alias, private_root = next(
            (alias, private_root)
            for alias, private_root in aliases
            if tmp_path.is_relative_to(private_root)
        )
    except StopIteration:
        pytest.skip("pytest temp root is outside macOS private aliases")
    relative = tmp_path.relative_to(private_root)
    root = alias / relative / ".js"
    workspace = root / "workspace"
    state_dir = root / "state"

    JSSettings(workspace=workspace, state_dir=state_dir, providers=[])

    canonical_root = private_root / relative / ".js"
    assert [_directory_mode(path) for path in (canonical_root, workspace, state_dir)] == [
        0o700,
        0o700,
        0o700,
    ]


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS system alias contract")
@pytest.mark.parametrize("system_alias", (Path("/tmp"), Path("/var")))
def test_personal_storage_rejects_exact_system_alias_without_chmod(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    system_alias: Path,
) -> None:
    fchmod_calls: list[tuple[int, int]] = []
    monkeypatch.setattr(
        os,
        "fchmod",
        lambda descriptor, mode: fchmod_calls.append((descriptor, mode)),
    )

    with pytest.raises(ValueError, match="private directory|workspace must not be"):
        JSSettings(
            workspace=system_alias,
            state_dir=tmp_path / "state",
            providers=[],
        )

    assert fchmod_calls == []


@pytest.mark.parametrize("managed_name", ("root", "workspace", "state"))
@pytest.mark.parametrize("node_kind", ("symlink", "file"))
def test_personal_storage_rejects_unsafe_nodes_without_following_them(
    tmp_path: Path,
    managed_name: str,
    node_kind: str,
) -> None:
    root = tmp_path / ".js"
    workspace = root / "workspace"
    state_dir = root / "state"
    managed = {"root": root, "workspace": workspace, "state": state_dir}[managed_name]
    if managed != root:
        root.mkdir(mode=0o700)

    external = tmp_path / f"external-{managed_name}-{node_kind}"
    if node_kind == "symlink":
        external.mkdir(mode=0o755)
        managed.symlink_to(external, target_is_directory=True)
    else:
        managed.write_text("not a directory", encoding="utf-8")

    with pytest.raises(ValueError, match="private directory"):
        JSSettings(workspace=workspace, state_dir=state_dir, providers=[])

    assert managed.is_symlink() if node_kind == "symlink" else managed.is_file()
    if node_kind == "symlink":
        assert _directory_mode(external) == 0o755


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

    def test_consume_helper_deletes_regular_key_file_only(self, tmp_path: Path) -> None:
        from js.web.bootstrap import consume_bootstrap_admin_key_file

        s = _settings(tmp_path, api_key_required=True)
        key = _provision_bootstrap_admin_key(s)
        assert key
        key_file = s.state_dir / "bootstrap_admin_key.txt"
        assert key_file.exists()
        assert consume_bootstrap_admin_key_file(s.state_dir) is True
        assert not key_file.exists()
        assert consume_bootstrap_admin_key_file(s.state_dir) is False

        symlink = s.state_dir / "bootstrap_admin_key.txt"
        target = s.state_dir / "other.txt"
        target.write_text("js_not_the_key\n", encoding="utf-8")
        symlink.symlink_to(target)
        assert consume_bootstrap_admin_key_file(s.state_dir) is False
        assert target.exists()

    def test_plaintext_bootstrap_key_is_never_logged(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        s = _settings(tmp_path, api_key_required=True)

        key = _provision_bootstrap_admin_key(s)
        captured = capsys.readouterr()

        assert key
        assert key not in captured.out
        assert "bootstrap_admin_key.txt" in captured.out

    def test_persistence_failure_revokes_key_and_never_logs_plaintext(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        s = _settings(tmp_path, api_key_required=True)

        def fail_persist(_path: Path, _key: str) -> None:
            raise OSError("simulated write failure")

        monkeypatch.setattr(web_server, "_persist_bootstrap_admin_key", fail_persist)

        with pytest.raises(RuntimeError, match="bootstrap admin key"):
            _provision_bootstrap_admin_key(s)

        captured = capsys.readouterr()
        assert "js_" not in captured.out
        assert AuthManager(s.state_dir).has_admin() is False
        assert not (s.state_dir / "bootstrap_admin_key.txt").exists()

    def test_lockdown_state_self_heals(self, tmp_path: Path) -> None:
        # The dangerous state: setup marked complete but NO admin key exists.
        s = _settings(tmp_path, api_key_required=True, first_run=True)
        assert AuthManager(s.state_dir).has_admin() is False  # would be a 401 lockdown
        key = _provision_bootstrap_admin_key(s)
        assert key
        # No longer keyless → the site can never be fully locked out.
        assert AuthManager(s.state_dir).has_admin() is True

    def test_concurrent_first_start_mints_one_recoverable_key(self, tmp_path: Path) -> None:
        context = multiprocessing.get_context("spawn")
        start = context.Event()
        results = context.Queue()
        state_dir = tmp_path / "state"
        processes = [
            context.Process(
                target=_concurrent_bootstrap_worker,
                args=(str(tmp_path / "ws"), str(state_dir), start, results),
            )
            for _ in range(2)
        ]

        for process in processes:
            process.start()
        start.set()
        for process in processes:
            process.join(timeout=15)

        outcomes = [results.get(timeout=2) for _ in processes]
        assert all(process.exitcode == 0 for process in processes)
        assert all(outcome[0] == "ok" for outcome in outcomes), outcomes
        minted = [outcome[1] for outcome in outcomes if outcome[1] is not None]
        assert len(minted) == 1
        assert (state_dir / "bootstrap_admin_key.txt").read_text().strip() == minted[0]
        assert AuthManager(state_dir).verify(minted[0])["role"] == "admin"


class TestBootstrapBrowserUrl:
    def test_places_key_in_fragment_not_http_request(self, tmp_path: Path) -> None:
        key_file = tmp_path / "bootstrap_admin_key.txt"
        key_file.write_text("js_secret/value\n", encoding="utf-8")
        key_file.chmod(0o600)

        url = bootstrap_browser_url("http://127.0.0.1:8000", tmp_path)

        assert url.startswith("http://127.0.0.1:8000/#bootstrap-api-key=")
        assert "js_secret/value" not in url

    def test_rejects_symlink_or_non_private_key_file(self, tmp_path: Path) -> None:
        target = tmp_path / "target"
        target.write_text("js_secret\n", encoding="utf-8")
        key_file = tmp_path / "bootstrap_admin_key.txt"
        key_file.symlink_to(target)
        assert bootstrap_browser_url("http://localhost:8000", tmp_path) == ("http://localhost:8000")

        key_file.unlink()
        key_file.write_text("js_secret\n", encoding="utf-8")
        key_file.chmod(0o644)
        assert bootstrap_browser_url("http://localhost:8000", tmp_path) == ("http://localhost:8000")


class TestAuthEnforcement:
    @pytest.mark.asyncio
    async def test_no_key_401_but_minted_key_authorizes_admin(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        s = _settings(tmp_path, api_key_required=True)
        key = _provision_bootstrap_admin_key(s)
        assert key
        # require_auth / authenticate_credentials read the module-global settings.
        monkeypatch.setattr(web_server, "_settings", s)

        # No key → enforced 401 (auth is NOT silently disabled).
        with pytest.raises(HTTPException) as ei:
            await authenticate_credentials(None, None)
        assert ei.value.status_code == 401

        # The minted bootstrap key unlocks the site as admin.
        ctx = await authenticate_credentials(key, None)
        assert ctx["role"] == "admin"


class TestRootInjection:
    def test_root_never_embeds_key_even_for_local_browser(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(web_server, "_bootstrap_admin_key", "KEY-XYZ")
        client = TestClient(create_app(), base_url="http://localhost")
        r = client.get("/")
        assert r.status_code == 200
        assert "window.__BOOTSTRAP_API_KEY__" not in r.text
        assert "KEY-XYZ" not in r.text

    def test_root_never_injects_key_into_forwarded_request(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(web_server, "_bootstrap_admin_key", "KEY-XYZ")
        client = TestClient(create_app(), base_url="http://localhost")

        response = client.get("/", headers={"X-Forwarded-For": "203.0.113.9"})

        assert "KEY-XYZ" not in response.text

    def test_root_never_injects_key_for_non_loopback_host(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(web_server, "_bootstrap_admin_key", "KEY-XYZ")
        client = TestClient(create_app(), base_url="http://agent.example")

        response = client.get("/")

        assert "KEY-XYZ" not in response.text

    def test_root_no_inject_when_no_bootstrap_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(web_server, "_bootstrap_admin_key", None)
        client = TestClient(create_app())
        r = client.get("/")
        assert r.status_code == 200
        assert "__BOOTSTRAP_API_KEY__" not in r.text

    def test_root_no_inject_for_remote_client(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # The HTTP response never carries a credential, regardless of peer.
        monkeypatch.setattr(web_server, "_bootstrap_admin_key", "KEY-XYZ")
        client = TestClient(create_app())
        r = client.get("/")
        assert "KEY-XYZ" not in r.text

    def test_frontend_consumes_and_removes_bootstrap_fragment(self) -> None:
        script = (Path(web_server.__file__).parent / "static" / "app.js").read_text(
            encoding="utf-8"
        )

        assert "bootstrap-api-key" in script
        assert "history.replaceState" in script


def _status_mock_agent(settings: JSSettings, *, degraded: bool = False) -> MagicMock:
    """A minimal agent stand-in that satisfies the /api/status endpoint."""
    agent = MagicMock()
    agent.settings = settings
    agent._check_degraded = AsyncMock(return_value=None)
    agent.degraded = degraded
    agent.degraded_reason = "All providers unhealthy" if degraded else ""
    agent.registry.get_stats.return_value = {}
    agent.secrets.get_stats.return_value = {}
    return agent


def _wire_globals(settings: JSSettings, agent: MagicMock) -> None:
    from js.web.deps import set_globals

    set_globals(agent, settings)
    web_server._agent = agent
    web_server._settings = settings


class TestProcessSmoke:
    """End-to-end: a fresh install must land *usable*, not 401-locked."""

    def test_fresh_install_authenticates_and_reaches_status(self, tmp_path: Path) -> None:
        # Genuinely fresh: auth required, no admin key, no models configured.
        s = _settings(tmp_path, api_key_required=True)
        s.providers = []
        key = _provision_bootstrap_admin_key(s)
        assert key  # startup minted a working credential

        _wire_globals(s, _status_mock_agent(s, degraded=True))
        client = TestClient(create_app())

        # Without a key the site stays enforced (no silent auth bypass).
        assert client.get("/api/status").status_code == 401
        # With the minted bootstrap key the employee is in — no lockdown.
        resp = client.get("/api/status", headers={"X-API-Key": key})
        assert resp.status_code == 200
        assert "overall_status" in resp.json()


class TestFirstStartWizard:
    """The wizard is shown iff first-run is not yet completed."""

    def test_first_start_reports_setup_needed(self, tmp_path: Path) -> None:
        s = _settings(tmp_path, api_key_required=False, first_run=False)
        s.providers = []
        _wire_globals(s, _status_mock_agent(s))

        client = TestClient(create_app())
        resp = client.get("/api/setup/first-start")
        assert resp.status_code == 200
        data = resp.json()
        # Frontend shows the wizard exactly when this is False.
        assert data["first_run_completed"] is False
        assert data["diagnostics"]["has_configured_models"] is False


class TestStatusChineseDegradation:
    """When no model is configured, status speaks plain Chinese to the user."""

    def test_status_reports_no_provider_in_chinese(self, tmp_path: Path) -> None:
        s = _settings(tmp_path, api_key_required=False)
        s.providers = []
        _wire_globals(s, _status_mock_agent(s, degraded=True))

        client = TestClient(create_app())
        resp = client.get("/api/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["overall_status"] == "no_provider"
        assert "模型" in data["overall_status_text"]
        assert data["suggestion"]  # actionable Chinese guidance
        # The English diagnostic field is still present for developers.
        assert data["degraded_reason"] == "All providers unhealthy"


class TestSetupCompleteProvisioning:
    def test_setup_complete_returns_admin_key_in_bootstrap(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import yaml

        config_path = tmp_path / "config.yaml"
        config_path.write_text(
            yaml.safe_dump(
                {
                    "version": "0.1.5",
                    "first_run_completed": False,
                    # Pin to tmp dirs so the test never touches the real ~/.js state.
                    "state_dir": str(tmp_path / "state"),
                    "workspace": str(tmp_path / "ws"),
                }
            )
        )
        monkeypatch.setenv("JS_CONFIG_PATH", str(config_path))

        settings = JSSettings.from_file(config_path)
        settings.security.api_key_required = True
        settings.first_run_completed = False
        assert not AuthManager(settings.state_dir).has_admin()  # genuinely fresh

        agent = JSAgent(settings)

        web_server._agent = agent
        from js.web.deps import set_globals

        set_globals(agent, settings)
        web_server._settings = settings

        client = TestClient(create_app(), client=("127.0.0.1", 50000))
        try:
            # The real wizard is a browser fetch, which always sends Origin;
            # originless mutation calls are rejected as CSRF/rebinding risks.
            resp = client.post(
                "/api/setup/complete",
                headers={
                    "Host": "localhost:50000",
                    "Origin": "http://localhost:50000",
                },
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["success"] is True
            # A usable admin key was minted before the bootstrap window closed.
            assert data.get("admin_key")
            assert AuthManager(settings.state_dir).verify(data["admin_key"])["role"] == ("admin")
            assert settings.first_run_completed is True
        finally:
            client.close()
            asyncio.run(agent.close())
