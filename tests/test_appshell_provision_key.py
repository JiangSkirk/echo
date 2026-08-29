"""AppShell startup key minting via JS_APPSHELL_PROVISION_KEY."""

from __future__ import annotations

import shutil
import stat
from pathlib import Path
from typing import Any

import pytest
import yaml
from fastapi.testclient import TestClient


def _write_fresh_personal(root: Path) -> Path:
    state = root / "personal-state"
    workspace = root / "personal-workspace"
    config = root / "personal.yaml"
    config.write_text(
        yaml.safe_dump(
            {
                "state_dir": str(state),
                "workspace": str(workspace),
                "echo_engine": "on",
                "first_run_completed": False,
                "onboarding_status": "pending",
                "security": {"api_key_required": True},
                "providers": [],
                "models": [],
            }
        ),
        encoding="utf-8",
    )
    return config


def _write_fresh_work(root: Path) -> tuple[Path, Path]:
    home = root / "work-home"
    state = home / ".js-work" / "state"
    workspace = home / ".js-work" / "workspace"
    config = root / "work.yaml"
    config.write_text(
        yaml.safe_dump(
            {
                "state_dir": str(state),
                "workspace": str(workspace),
                "echo_engine": "on",
                "first_run_completed": False,
                "onboarding_status": "pending",
                "security": {"api_key_required": True},
                "providers": [],
                "models": [],
            }
        ),
        encoding="utf-8",
    )
    return config, home


def _build_appshell(tmp_path: Path) -> Any:
    from js.appshell.server import create_appshell_app
    from js_work.tools import WorkToolProfile

    personal = _write_fresh_personal(tmp_path)
    work, home = _write_fresh_work(tmp_path)
    return create_appshell_app(
        personal_config=str(personal),
        work_config=str(work),
        work_home=home,
        work_profile=WorkToolProfile.SAFE,
        host="127.0.0.1",
        port=8000,
    )


def _rebuild_appshell(tmp_path: Path) -> Any:
    from js.appshell.server import create_appshell_app
    from js_work.tools import WorkToolProfile

    return create_appshell_app(
        personal_config=str(tmp_path / "personal.yaml"),
        work_config=str(tmp_path / "work.yaml"),
        work_home=tmp_path / "work-home",
        work_profile=WorkToolProfile.SAFE,
        host="127.0.0.1",
        port=8000,
    )


def _loopback_client(app: Any) -> TestClient:
    return TestClient(
        app,
        base_url="http://localhost",
        headers={"Origin": "http://localhost"},
        client=("127.0.0.1", 50123),
    )


def _personal_state(tmp_path: Path) -> Path:
    return tmp_path / "personal-state"


def _work_state(tmp_path: Path) -> Path:
    return tmp_path / "work-home" / ".js-work" / "state"


def _forget_auth_store(state_dir: Path) -> None:
    """Drop process-local AuthManager caches so a wiped store looks like a new process."""
    from js.web.auth import AuthManager

    db_path = state_dir / "api_keys.db"
    cache_ns = str(db_path if db_path.is_absolute() else db_path.absolute())
    AuthManager._INITIALIZED_DBS.discard(cache_ns)
    AuthManager._SHARED_VERIFY_EPOCH.pop(cache_ns, None)
    prefix = f"{cache_ns}:"
    for cached_key in list(AuthManager._SHARED_VERIFY_CACHE):
        if cached_key.startswith(prefix):
            AuthManager._SHARED_VERIFY_CACHE.pop(cached_key, None)
            AuthManager._SHARED_LAST_USED.pop(cached_key, None)
            AuthManager._SHARED_VERIFY_STAMP.pop(cached_key, None)


def _wipe_work_state(tmp_path: Path) -> None:
    work_state = _work_state(tmp_path)
    _forget_auth_store(work_state)
    shutil.rmtree(work_state, ignore_errors=True)


def test_provision_flag_mints_shared_admin_on_fresh_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from js.web.auth import AuthManager

    monkeypatch.setenv("JS_APPSHELL_PROVISION_KEY", "1")
    app = _build_appshell(tmp_path)
    key_file = _personal_state(tmp_path) / "bootstrap_admin_key.txt"

    with _loopback_client(app) as client:
        assert key_file.is_file()
        assert stat.S_IMODE(key_file.stat().st_mode) == 0o600
        key = key_file.read_text(encoding="utf-8").strip()
        personal = AuthManager(_personal_state(tmp_path)).verify(key)
        work = AuthManager(_work_state(tmp_path)).verify(key)
        assert personal["role"] == work["role"] == "admin"
        assert personal["key_hash"] == work["key_hash"]

        assert client.get("/api/status").status_code == 401
        login = client.post("/api/appshell/session", headers={"X-API-Key": key})
        assert login.status_code == 200, login.text
        assert client.get("/api/status").status_code == 200


def test_provision_flag_is_idempotent_when_admin_exists(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("JS_APPSHELL_PROVISION_KEY", "1")
    first = _build_appshell(tmp_path)
    key_file = _personal_state(tmp_path) / "bootstrap_admin_key.txt"
    with _loopback_client(first):
        original = key_file.read_text(encoding="utf-8")
        mtime = key_file.stat().st_mtime_ns

    second = _rebuild_appshell(tmp_path)
    with _loopback_client(second):
        assert key_file.read_text(encoding="utf-8") == original
        assert key_file.stat().st_mtime_ns == mtime


def test_default_off_keeps_loopback_bootstrap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from js.web.auth import AuthManager

    monkeypatch.delenv("JS_APPSHELL_PROVISION_KEY", raising=False)
    app = _build_appshell(tmp_path)
    key_file = _personal_state(tmp_path) / "bootstrap_admin_key.txt"

    with _loopback_client(app) as client:
        assert not key_file.exists()
        boot = client.post("/api/appshell/bootstrap")
        assert boot.status_code == 200, boot.text
        assert key_file.is_file()
        key = key_file.read_text(encoding="utf-8").strip()
        assert AuthManager(_personal_state(tmp_path)).verify(key)["role"] == "admin"
        assert AuthManager(_work_state(tmp_path)).verify(key)["role"] == "admin"


def test_persist_failure_aborts_startup_without_partial_admin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from js.web import server as web_server
    from js.web.auth import AuthManager

    monkeypatch.setenv("JS_APPSHELL_PROVISION_KEY", "1")

    def fail_persist(*_args: object, **_kwargs: object) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(web_server, "_persist_bootstrap_admin_key", fail_persist)
    app = _build_appshell(tmp_path)

    with pytest.raises(RuntimeError, match="bootstrap admin key"), _loopback_client(app):
        pass

    assert not AuthManager(_personal_state(tmp_path)).has_admin()
    assert not AuthManager(_work_state(tmp_path)).has_admin()
    assert not (_personal_state(tmp_path) / "bootstrap_admin_key.txt").exists()


def test_session_restores_work_admin_after_empty_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from js.web.auth import AuthManager

    monkeypatch.setenv("JS_APPSHELL_PROVISION_KEY", "1")
    first = _build_appshell(tmp_path)
    key_file = _personal_state(tmp_path) / "bootstrap_admin_key.txt"
    with _loopback_client(first):
        key = key_file.read_text(encoding="utf-8").strip()

    _wipe_work_state(tmp_path)
    second = _rebuild_appshell(tmp_path)
    with _loopback_client(second) as client:
        login = client.post("/api/appshell/session", headers={"X-API-Key": key})
        assert login.status_code == 200, login.text
        assert login.json()["principal"]["mode_roles"] == {
            "personal": "admin",
            "work": "admin",
        }
        restored = AuthManager(_work_state(tmp_path)).verify(key)
        assert restored["role"] == "admin"
        assert (
            restored["key_hash"] == AuthManager(_personal_state(tmp_path)).verify(key)["key_hash"]
        )


def test_session_does_not_heal_when_work_already_has_admin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from js.exceptions import AuthRequiredError
    from js.web.auth import AuthManager

    monkeypatch.setenv("JS_APPSHELL_PROVISION_KEY", "1")
    first = _build_appshell(tmp_path)
    key_file = _personal_state(tmp_path) / "bootstrap_admin_key.txt"
    with _loopback_client(first):
        personal_key = key_file.read_text(encoding="utf-8").strip()

    _wipe_work_state(tmp_path)
    work_state = _work_state(tmp_path)
    work_state.mkdir(parents=True, exist_ok=True)
    other_key = AuthManager(work_state).create_key("other-work-admin", role="admin")

    second = _rebuild_appshell(tmp_path)
    with _loopback_client(second) as client:
        login = client.post("/api/appshell/session", headers={"X-API-Key": personal_key})
        assert login.status_code == 200, login.text
        assert login.json()["principal"]["mode_roles"] == {"personal": "admin"}
        with pytest.raises(AuthRequiredError):
            AuthManager(_work_state(tmp_path)).verify(personal_key)
        assert AuthManager(_work_state(tmp_path)).verify(other_key)["role"] == "admin"


def test_session_does_not_heal_for_personal_non_admin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from js.web.auth import AuthManager

    monkeypatch.setenv("JS_APPSHELL_PROVISION_KEY", "1")
    first = _build_appshell(tmp_path)
    with _loopback_client(first):
        pass

    user_key = AuthManager(_personal_state(tmp_path)).create_key(
        "personal-user",
        role="user",
    )
    _wipe_work_state(tmp_path)

    second = _rebuild_appshell(tmp_path)
    with _loopback_client(second) as client:
        login = client.post("/api/appshell/session", headers={"X-API-Key": user_key})
        assert login.status_code == 200, login.text
        assert login.json()["principal"]["mode_roles"] == {"personal": "user"}
        assert not AuthManager(_work_state(tmp_path)).has_admin()


def test_provision_flag_truthy_values(monkeypatch: pytest.MonkeyPatch) -> None:
    from js.appshell.bootstrap_key import appshell_provision_key_enabled

    monkeypatch.delenv("JS_APPSHELL_PROVISION_KEY", raising=False)
    assert appshell_provision_key_enabled() is False
    for raw in ("0", "false", "no", ""):
        monkeypatch.setenv("JS_APPSHELL_PROVISION_KEY", raw)
        assert appshell_provision_key_enabled() is False
    for raw in ("1", "true", "YES", "On"):
        monkeypatch.setenv("JS_APPSHELL_PROVISION_KEY", raw)
        assert appshell_provision_key_enabled() is True
