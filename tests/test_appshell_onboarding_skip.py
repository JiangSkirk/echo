"""AppShell real first-start path: shared skip, P↔W isolation, restart persistence.

Uses synthetic configs and fake keys only — no real API keys, no Accessibility.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml
from fastapi.testclient import TestClient

from js.echo.turn_runtime import _workspace_handle


def _write_fresh_personal(root: Path, *, first_run: bool = False) -> Path:
    state = root / "personal-state"
    workspace = root / "personal-workspace"
    config = root / "personal.yaml"
    config.write_text(
        yaml.safe_dump(
            {
                "state_dir": str(state),
                "workspace": str(workspace),
                "echo_engine": "on",
                "first_run_completed": first_run,
                "onboarding_status": "completed" if first_run else "pending",
                "security": {"api_key_required": True},
                "providers": [],
                "models": [],
            }
        ),
        encoding="utf-8",
    )
    return config


def _write_fresh_work(root: Path, *, first_run: bool = False) -> tuple[Path, Path]:
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
                "first_run_completed": first_run,
                "onboarding_status": "completed" if first_run else "pending",
                "security": {"api_key_required": True},
                "providers": [],
                "models": [],
            }
        ),
        encoding="utf-8",
    )
    return config, home


def _build_appshell(tmp_path: Path, *, first_run: bool = False) -> Any:
    from js.appshell.server import create_appshell_app
    from js_work.tools import WorkToolProfile

    personal = _write_fresh_personal(tmp_path, first_run=first_run)
    work, home = _write_fresh_work(tmp_path, first_run=first_run)
    return create_appshell_app(
        personal_config=str(personal),
        work_config=str(work),
        work_home=home,
        work_profile=WorkToolProfile.SAFE,
        host="127.0.0.1",
        port=8000,
    )


def _loopback_client(app: Any) -> TestClient:
    """TestClient must advertise a loopback peer for AppShell bootstrap."""
    return TestClient(
        app,
        base_url="http://localhost",
        headers={"Origin": "http://localhost"},
        client=("127.0.0.1", 50123),
    )


@pytest.fixture()
def fresh_appshell(tmp_path: Path) -> Any:
    return _build_appshell(tmp_path, first_run=False)


class TestAppShellBootstrapOnboardingE2E:
    def test_bootstrap_then_skip_uses_server_authority(
        self, fresh_appshell: Any, tmp_path: Path
    ) -> None:
        app = fresh_appshell

        with _loopback_client(app) as client:
            # Personal boots immediately; Work stays lazy until switch / Work API.
            personal = app.state.personal_app.state.web_runtime.settings
            work = app.state.work_app.state.runtime_settings
            assert getattr(app.state.work_app.state, "web_runtime", None) is None
            assert personal.state_dir != work.state_dir
            assert personal.workspace != work.workspace
            assert getattr(personal, "_appshell_peer_settings", None) is work
            assert getattr(work, "_appshell_peer_settings", None) is personal

            # Real AppShell first-start: bootstrap session on loopback.
            boot = client.post("/api/appshell/bootstrap")
            assert boot.status_code == 200, boot.text
            principal = boot.json()["principal"]
            assert principal["active_mode"] == "personal"
            assert "personal" in principal["mode_roles"]
            assert "work" in principal["mode_roles"]

            # Without skip, wizard blocks (server authority).
            first = client.get("/api/setup/first-start")
            assert first.status_code == 200, first.text
            data = first.json()
            assert data["wizard_blocking"] is True
            assert data["onboarding_status"] == "pending"
            assert data["first_run_completed"] is False

            # Skip must persist via Echo/setup path — not localStorage.
            skip = client.post("/api/setup/skip")
            assert skip.status_code == 200, skip.text
            body = skip.json()
            assert body["success"] is True
            assert body["onboarding_status"] == "skipped"
            assert body["first_run_completed"] is True
            assert body["wizard_blocking"] is False

            # No fake providers / models invented by skip.
            assert personal.providers == [] or all(
                not getattr(p, "api_key", None) for p in personal.providers
            )
            assert work.providers == [] or all(
                not getattr(p, "api_key", None) for p in work.providers
            )
            assert personal.onboarding_status == "skipped"
            assert work.onboarding_status == "skipped"
            assert personal.first_run_completed is True
            assert work.first_run_completed is True

            # Personal entry remains available after skip.
            status = client.get("/api/status")
            assert status.status_code == 200

            # Personal → Work → Personal switch still works; workspaces stay isolated.
            work_handle = app.state.work_workspace_handle
            to_work = client.post(
                "/api/appshell/switch",
                json={
                    "expected_from_mode": "personal",
                    "to_mode": "work",
                    "session_id": None,
                    "workspace_handle": work_handle,
                },
            )
            assert to_work.status_code == 200, to_work.text
            assert to_work.json()["ok"] is True
            assert to_work.json()["to_mode"] == "work"
            assert app.state.work_runtime_ready is True
            assert app.state.work_app.state.web_runtime.agent is not None

            # Work mode also sees non-blocking onboarding (shared entry).
            work_first = client.get("/api/setup/first-start")
            assert work_first.status_code == 200
            assert work_first.json()["wizard_blocking"] is False
            assert work_first.json()["onboarding_status"] == "skipped"

            # Isolation: workspaces and state dirs still distinct after skip.
            assert personal.workspace != work.workspace
            assert personal.state_dir != work.state_dir

            # Back to Personal.
            to_personal = client.post(
                "/api/appshell/switch",
                json={
                    "expected_from_mode": "work",
                    "to_mode": "personal",
                    "session_id": None,
                    "workspace_handle": None,
                },
            )
            assert to_personal.status_code == 200, to_personal.text
            assert to_personal.json()["ok"] is True
            assert to_personal.json()["to_mode"] == "personal"
            assert client.get("/api/setup/first-start").json()["wizard_blocking"] is False

    def test_skip_does_not_create_approvals_or_leases(self, fresh_appshell: Any) -> None:
        app = fresh_appshell
        with _loopback_client(app) as client:
            assert client.post("/api/appshell/bootstrap").status_code == 200

            def _pending_and_leases(agent: Any) -> tuple[list[Any], list[Any]]:
                pending_fn = getattr(agent.approvals, "list_pending", None)
                pending = list(pending_fn()) if callable(pending_fn) else []
                leases: list[Any] = []
                authority = getattr(agent, "_get_echo_tool_lease_authority", None)
                if callable(authority):
                    auth = authority()
                    list_fn = getattr(auth, "list_active", None) or getattr(
                        auth, "list_leases", None
                    )
                    if callable(list_fn):
                        leases = list(list_fn())
                return pending, leases

            personal_agent = app.state.personal_app.state.web_runtime.agent
            assert getattr(app.state.work_app.state, "web_runtime", None) is None
            before = _pending_and_leases(personal_agent)
            assert client.post("/api/setup/skip").status_code == 200
            after = _pending_and_leases(personal_agent)
            # Skip must not mint new approvals or tool leases, and must not boot Work.
            assert after[0] == before[0]
            assert len(after[1]) == len(before[1])
            assert getattr(app.state.work_app.state, "web_runtime", None) is None
            assert personal_agent.settings.providers == []
            assert app.state.work_app.state.runtime_settings.providers == []


class TestAppShellRestartPersistence:
    def test_sidecar_restart_keeps_skipped_and_no_wizard_block(self, tmp_path: Path) -> None:
        """Simulate full process restart by rebuilding AppShell from saved configs."""
        app1 = _build_appshell(tmp_path, first_run=False)
        personal_cfg = tmp_path / "personal.yaml"
        work_cfg = tmp_path / "work.yaml"
        work_home = tmp_path / "work-home"

        with _loopback_client(app1) as client:
            assert client.post("/api/appshell/bootstrap").status_code == 200
            skip = client.post("/api/setup/skip")
            assert skip.status_code == 200
            assert skip.json()["onboarding_status"] == "skipped"

        # "Restart": new process loads the same config files from disk.
        from js.appshell.server import create_appshell_app
        from js_work.tools import WorkToolProfile

        app2 = create_appshell_app(
            personal_config=str(personal_cfg),
            work_config=str(work_cfg),
            work_home=work_home,
            work_profile=WorkToolProfile.SAFE,
            host="127.0.0.1",
            port=8000,
        )
        personal = app2.state.personal_app.state.runtime_settings
        work = app2.state.work_app.state.runtime_settings
        assert personal.onboarding_status == "skipped"
        assert work.onboarding_status == "skipped"
        assert personal.first_run_completed is True
        assert work.first_run_completed is True

        with _loopback_client(app2) as client:
            # Existing admin from prior bootstrap — login via session exchange.
            # Bootstrap refuses when personal admin already exists without key.
            # Use the persisted bootstrap key file if present.
            key_file = personal.state_dir / "bootstrap_admin_key.txt"
            assert key_file.is_file()
            api_key = key_file.read_text(encoding="utf-8").strip()
            # Never log the key; only use it for the exchange.
            sess = client.post(
                "/api/appshell/session",
                headers={"X-API-Key": api_key},
            )
            assert sess.status_code == 200, sess.text
            first = client.get("/api/setup/first-start")
            assert first.status_code == 200
            assert first.json()["wizard_blocking"] is False
            assert first.json()["onboarding_status"] == "skipped"


class TestSkipWriteFailureNoFakeDismiss:
    def test_api_write_failure_does_not_mark_skipped(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from js.config import JSSettings
        from js_work.config import WorkSettings

        app = _build_appshell(tmp_path, first_run=False)

        with _loopback_client(app) as client:
            personal = app.state.personal_app.state.web_runtime.settings
            work = app.state.work_app.state.runtime_settings
            assert client.post("/api/appshell/bootstrap").status_code == 200

            # Force in-memory pending before failed skip.
            personal.onboarding_status = "pending"
            personal.first_run_completed = False
            work.onboarding_status = "pending"
            work.first_run_completed = False

            def _boom(self: Any, *args: Any, **kwargs: Any) -> None:
                raise OSError("synthetic disk failure")

            # Work uses WorkSettings which may subclass JSSettings — patch both.
            monkeypatch.setattr(JSSettings, "save", _boom)
            if WorkSettings is not JSSettings:
                monkeypatch.setattr(WorkSettings, "save", _boom, raising=False)

            res = client.post("/api/setup/skip")
            assert res.status_code == 500
            # Handler rolls back both modes — no fake skip.
            assert personal.onboarding_status == "pending"
            assert personal.first_run_completed is False
            assert work.onboarding_status == "pending"
            assert work.first_run_completed is False

            key_file = personal.state_dir / "bootstrap_admin_key.txt"
            api_key = key_file.read_text(encoding="utf-8").strip()
            # Keep same session; first-start must still block.
            first = client.get("/api/setup/first-start")
            assert first.status_code == 200
            assert first.json()["wizard_blocking"] is True
            assert api_key  # recovery key exists; not logged


class TestOwnerSessionIsolation:
    def test_skip_is_install_wide_but_runtimes_stay_isolated(self, tmp_path: Path) -> None:
        app = _build_appshell(tmp_path, first_run=False)

        with _loopback_client(app) as client:
            personal = app.state.personal_app.state.web_runtime.settings
            work = app.state.work_app.state.runtime_settings
            personal_ws = personal.workspace.resolve()
            work_ws = work.workspace.resolve()

            assert client.post("/api/appshell/bootstrap").status_code == 200
            assert client.post("/api/setup/skip").status_code == 200

            # Shared onboarding entry on live request-path settings
            assert personal.onboarding_status == work.onboarding_status == "skipped"

            # Physical isolation of workspaces / state
            assert personal_ws != work_ws
            assert personal.state_dir.resolve() != work.state_dir.resolve()
            assert personal.product_id == "js-agent"
            assert work.product_id == "js-work"

            # Work principal requires the correct workspace handle (no free grant).
            bad = client.post(
                "/api/appshell/switch",
                json={
                    "expected_from_mode": "personal",
                    "to_mode": "work",
                    "session_id": None,
                    "workspace_handle": "not-a-real-handle",
                },
            )
            assert bad.status_code == 400
            assert bad.json()["detail"]["code"] == "invalid_work_workspace_handle"

            good = client.post(
                "/api/appshell/switch",
                json={
                    "expected_from_mode": "personal",
                    "to_mode": "work",
                    "session_id": None,
                    "workspace_handle": _workspace_handle(work_ws),
                },
            )
            assert good.status_code == 200, good.text
            body = good.json()
            assert body["ok"] is True
            assert body["to_mode"] == "work"
            # Work binding is the work handle — not personal workspace.
            assert body["workspace"] == _workspace_handle(work_ws)
            assert body["workspace"] != _workspace_handle(personal_ws)

            # Personal workspace must stay null when returning.
            back = client.post(
                "/api/appshell/switch",
                json={
                    "expected_from_mode": "work",
                    "to_mode": "personal",
                    "session_id": None,
                    "workspace_handle": str(personal_ws),
                },
            )
            assert back.status_code == 400
            assert back.json()["detail"]["code"] == "personal_workspace_must_be_null"

    def test_reopen_from_settings_after_skip(self, tmp_path: Path) -> None:
        app = _build_appshell(tmp_path, first_run=False)
        with _loopback_client(app) as client:
            assert client.post("/api/appshell/bootstrap").status_code == 200
            assert client.post("/api/setup/skip").status_code == 200
            assert client.get("/api/setup/first-start").json()["wizard_blocking"] is False

            reopen = client.post("/api/setup/reopen")
            assert reopen.status_code == 200, reopen.text
            body = reopen.json()
            assert body["onboarding_status"] == "in_progress"
            assert body["first_run_completed"] is True  # bootstrap stays closed
            assert body["wizard_blocking"] is True

            personal = app.state.personal_app.state.runtime_settings
            work = app.state.work_app.state.runtime_settings
            assert personal.onboarding_status == work.onboarding_status == "in_progress"
            assert personal.first_run_completed is True
            assert work.first_run_completed is True

            # Can skip again.
            assert client.post("/api/setup/skip").status_code == 200
            assert client.get("/api/setup/first-start").json()["wizard_blocking"] is False
