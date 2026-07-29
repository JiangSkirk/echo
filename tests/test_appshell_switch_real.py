"""AppShell switch — real cancel + lease revoke + rebind payload."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml
from httpx import ASGITransport, AsyncClient


@pytest.mark.asyncio
async def test_switch_revokes_session_leases_and_returns_rebind(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from js.appshell.global_prefs import GlobalPrefs, save_global_prefs
    from js.config import JSSettings
    from js.echo.capability import LeaseAuthority
    from js.web import server as web_server

    prefs_path = tmp_path / "prefs.json"
    save_global_prefs(
        GlobalPrefs(
            personal_base_url="http://127.0.0.1:8000",
            work_base_url="http://127.0.0.1:8765",
        ),
        prefs_path,
    )
    monkeypatch.setenv("JS_APPSHELL_PREFS_PATH", str(prefs_path))

    state = tmp_path / "state"
    ws = tmp_path / "ws"
    state.mkdir()
    ws.mkdir()
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text(
        yaml.safe_dump(
            {
                "workspace": str(ws),
                "state_dir": str(state),
                "echo_engine": "on",
                "first_run_completed": True,
                "providers": [],
                "models": [],
                "security": {"api_key_required": False},
            }
        ),
        encoding="utf-8",
    )
    settings = JSSettings.from_file(cfg, allow_hermes_merge=False)
    app = web_server.create_app(runtime_settings=settings)
    transport = ASGITransport(app=app)
    async with (
        web_server.lifespan(app),
        AsyncClient(transport=transport, base_url="http://test") as client,
    ):
        agent = app.state.web_runtime.agent
        authority: LeaseAuthority = agent._get_echo_tool_lease_authority()
        lease = authority.issue(
            tool_name="file_list",
            owner_key_hash="local-user",
            run_id="run-switch-1",
            session_id="sess-switch-1",
            args_schema="{}",
            resource_scope="workspace",
            max_bytes=1024,
            max_duration_ms=1000,
            ttl_ms=60_000,
        )
        assert authority.is_revoked(lease.lease_id) is False

        response = await client.post(
            "/api/workspace/switch",
            json={"to_product": "js-work", "session_id": "sess-switch-1"},
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["ok"] is True
        assert body["from_product"] == "js-agent"
        assert body["to_product"] == "js-work"
        assert "cancel_streams" in body["completed_steps"]
        assert "invalidate_leases" in body["completed_steps"]
        assert "rebind_context" in body["completed_steps"]
        assert lease.lease_id in body["revoked_lease_ids"]
        assert authority.is_revoked(lease.lease_id) is True
        assert body["rebind"]["target_base_url"] == "http://127.0.0.1:8765"
        assert body["rebind"]["must_reconnect"] is True
        assert "messages" in body["clear_ui_cache_keys"]


@pytest.mark.asyncio
async def test_switch_fail_closed_keeps_product_on_cancel_error(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from js.config import JSSettings
    from js.web import server as web_server

    state = tmp_path / "state"
    ws = tmp_path / "ws"
    state.mkdir()
    ws.mkdir()
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text(
        yaml.safe_dump(
            {
                "workspace": str(ws),
                "state_dir": str(state),
                "echo_engine": "on",
                "first_run_completed": True,
                "providers": [],
                "models": [],
                "security": {"api_key_required": False},
            }
        ),
        encoding="utf-8",
    )
    settings = JSSettings.from_file(cfg, allow_hermes_merge=False)
    app = web_server.create_app(runtime_settings=settings)
    transport = ASGITransport(app=app)
    async with (
        web_server.lifespan(app),
        AsyncClient(transport=transport, base_url="http://test") as client,
    ):
        agent = app.state.web_runtime.agent

        def _boom(session_id: str, owner_key_hash: str | None = None) -> bool:
            raise PermissionError("cross-owner cancel blocked")

        monkeypatch.setattr(agent, "request_cancel", _boom)
        response = await client.post(
            "/api/workspace/switch",
            json={"to_product": "js-work", "session_id": "sess-x"},
        )
        assert response.status_code == 409
        body = response.json()
        # FastAPI may wrap detail
        detail = body.get("detail", body)
        assert detail["ok"] is False
        assert detail["failed_step"] == "cancel_streams"


def test_global_prefs_rejects_raw_secrets(tmp_path: Path) -> None:
    from js.appshell.global_prefs import prefs_from_mapping

    with pytest.raises(ValueError, match="raw secret"):
        prefs_from_mapping({"credential_refs": ["sk-live-secret-value"]})


def test_launcher_builds_isolated_argv(tmp_path: Path, monkeypatch: Any) -> None:
    from js.appshell import launcher

    captured: list[list[str]] = []

    class _Proc:
        def __init__(self, argv: list[str], env: dict[str, str] | None = None) -> None:
            captured.append(list(argv))
            self.pid = len(captured)
            self._alive = True

        def poll(self) -> int | None:
            # First child "exits" so launch_appshell returns.
            if self.pid == 1 and self._alive:
                self._alive = False
                return 0
            return None if self._alive else 0

        def send_signal(self, _sig: int) -> None:
            self._alive = False

        def wait(self, timeout: float | None = None) -> int:
            self._alive = False
            return 0

        def kill(self) -> None:
            self._alive = False

    monkeypatch.setattr(launcher.subprocess, "Popen", _Proc)
    prefs = tmp_path / "prefs.json"
    rc = launcher.launch_appshell(
        personal_config=str(tmp_path / "p.yaml"),
        work_config=str(tmp_path / "w.yaml"),
        personal_base_url="http://127.0.0.1:18000",
        work_base_url="http://127.0.0.1:18765",
        open_browser=False,
        prefs_path=prefs,
    )
    assert rc == 0
    assert len(captured) == 2
    assert "js" in captured[0]
    assert "--config" in captured[0]
    assert "js_work" in captured[1]
    # Work config belongs on the parent group before `web`.
    assert captured[1].index("--config") < captured[1].index("web")
