"""AppShell switch — real cancel + lease revoke + rebind payload."""

from __future__ import annotations

import asyncio
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import pytest
import yaml
from fastapi.testclient import TestClient
from httpx import ASGITransport, AsyncClient


@asynccontextmanager
async def _switch_harness(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    api_key_required: bool = True,
):
    from js.appshell.global_prefs import GlobalPrefs, save_global_prefs
    from js.config import JSSettings
    from js.web import server as web_server
    from js.web.auth import AuthManager

    state = tmp_path / "state"
    target_state = tmp_path / "work-state"
    ws = tmp_path / "ws"
    state.mkdir()
    target_state.mkdir()
    ws.mkdir()
    target_key = target_state / "bootstrap_admin_key.txt"
    target_key.write_text("synthetic-target-key", encoding="utf-8")
    os.chmod(target_key, 0o600)

    prefs_path = tmp_path / "prefs.json"
    save_global_prefs(
        GlobalPrefs(
            personal_base_url="http://127.0.0.1:8000",
            work_base_url="http://127.0.0.1:8765",
            personal_state_dir=str(state),
            work_state_dir=str(target_state),
        ),
        prefs_path,
    )
    monkeypatch.setenv("JS_APPSHELL_PREFS_PATH", str(prefs_path))

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
                "security": {"api_key_required": api_key_required},
            }
        ),
        encoding="utf-8",
    )
    settings = JSSettings.from_file(cfg, allow_hermes_merge=False)
    auth_manager = AuthManager(settings.state_dir)
    admin_key = auth_manager.create_key("switch-admin", role="admin")
    user_key = auth_manager.create_key("switch-user", role="user")
    app = web_server.create_app(runtime_settings=settings)
    transport = ASGITransport(app=app, client=("127.0.0.1", 50123))
    async with (
        web_server.lifespan(app),
        AsyncClient(
            transport=transport,
            base_url="http://127.0.0.1:8000",
            headers={"Host": "127.0.0.1:8000", "Origin": "http://127.0.0.1:8000"},
        ) as client,
    ):
        yield client, app.state.web_runtime.agent, auth_manager, admin_key, user_key


@pytest.mark.parametrize("client_session_id", [None, "forged-session"])
def test_standalone_appshell_switch_requires_parent_without_touching_resources(
    tmp_path: Path,
    client_session_id: str | None,
) -> None:
    """A child cannot run or claim an AppShell transition without the parent."""
    from js.config import JSSettings
    from js.web import server as web_server
    from js.web.auth import AuthManager

    workspace = tmp_path / "workspace"
    state_dir = tmp_path / "state"
    workspace.mkdir()
    state_dir.mkdir()
    settings = JSSettings(
        workspace=workspace,
        state_dir=state_dir,
        echo_engine="on",
        first_run_completed=True,
        providers=[],
        models=[],
    )
    auth_manager = AuthManager(state_dir)
    admin_key = auth_manager.create_key("standalone-parent-required", role="admin")
    owner = auth_manager.verify(admin_key)["key_hash"]
    app = web_server.create_app(runtime_settings=settings)

    with TestClient(
        app,
        base_url="http://localhost",
        headers={"Origin": "http://localhost", "X-API-Key": admin_key},
    ) as client:
        agent = app.state.web_runtime.agent
        cancel_token = asyncio.Event()
        agent.bind_cancel_token(
            "real-child-session",
            cancel_token,
            owner_key_hash=owner,
            run_id="real-child-run",
        )
        authority = agent._get_echo_tool_lease_authority()
        lease = authority.issue(
            product_id="js-agent",
            owner_key_hash=owner,
            session_id="real-child-session",
            run_id="real-child-run",
            tool_name="file_list",
            args_schema="{}",
            resource_scope="workspace",
            max_bytes=1024,
            max_duration_ms=1000,
            ttl_ms=60_000,
        )

        response = client.post(
            "/api/appshell/switch",
            json={"to_mode": "work", "session_id": client_session_id},
        )

        assert response.status_code == 410, response.text
        assert response.json()["detail"] == {"code": "appshell_parent_required"}
        assert "completed_steps" not in response.text
        assert "target_path" not in response.text
        assert not cancel_token.is_set()
        assert not authority.is_revoked(lease.lease_id)


@pytest.mark.asyncio
async def test_standalone_legacy_switch_is_410_and_cannot_mutate_runtime(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from js.echo.capability import LeaseAuthority

    async with _switch_harness(monkeypatch, tmp_path) as harness:
        client, agent, auth_manager, admin_key, _user_key = harness
        owner = auth_manager.verify(admin_key)["key_hash"]
        cancel_token = asyncio.Event()
        agent.bind_cancel_token(
            "sess-switch-1",
            cancel_token,
            owner_key_hash=owner,
            run_id="run-switch-1",
        )
        authority: LeaseAuthority = agent._get_echo_tool_lease_authority()
        lease = authority.issue(
            tool_name="file_list",
            owner_key_hash=owner,
            run_id="run-switch-1",
            session_id="sess-switch-1",
            product_id="js-agent",
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
            headers={"X-API-Key": admin_key},
        )
        assert response.status_code == 410, response.text
        body = response.json()
        assert body["detail"] == {
            "code": "legacy_workspace_switch_retired",
            "use": "/api/appshell/switch",
        }
        assert "target_base_url" not in response.text
        assert "target_entry_url" not in response.text
        assert not authority.is_revoked(lease.lease_id)
        assert not cancel_token.is_set()


@pytest.mark.parametrize(
    ("header", "value"),
    [
        ("Forwarded", "for=203.0.113.8"),
        ("X-Forwarded-For", "203.0.113.8"),
        ("X-Real-IP", "203.0.113.8"),
        ("X-Forwarded-Host", "remote.example"),
    ],
)
@pytest.mark.asyncio
async def test_forwarded_legacy_switch_is_also_410_without_target_url(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    header: str,
    value: str,
) -> None:
    async with _switch_harness(monkeypatch, tmp_path) as harness:
        client, _agent, _auth_manager, admin_key, _user_key = harness
        response = await client.post(
            "/api/workspace/switch",
            json={"to_product": "js-work", "session_id": None},
            headers={"X-API-Key": admin_key, header: value},
        )
        assert response.status_code == 410
        assert "target_" not in response.text
        assert "bootstrap-api-key" not in response.text


@pytest.mark.asyncio
async def test_switch_guest_and_cross_origin_fail_before_mutation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    async with _switch_harness(
        monkeypatch,
        tmp_path,
        api_key_required=False,
    ) as harness:
        client, _agent, _auth_manager, _admin_key, user_key = harness
        guest = await client.post(
            "/api/workspace/switch",
            json={"to_product": "js-work", "session_id": None},
        )
        cross_origin = await client.post(
            "/api/workspace/switch",
            json={"to_product": "js-work", "session_id": None},
            headers={"X-API-Key": user_key, "Origin": "http://evil.example"},
        )

        assert guest.status_code == 410
        assert cross_origin.status_code == 410


@pytest.mark.asyncio
async def test_switch_with_victim_session_fails_closed_without_mutation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    async with _switch_harness(monkeypatch, tmp_path) as harness:
        client, agent, auth_manager, admin_key, user_key = harness
        victim_owner = auth_manager.verify(admin_key)["key_hash"]
        victim_token = asyncio.Event()
        agent.bind_cancel_token(
            "shared-session",
            victim_token,
            owner_key_hash=victim_owner,
            run_id="victim-run",
        )
        authority = agent._get_echo_tool_lease_authority()
        victim_lease = authority.issue(
            product_id="js-agent",
            owner_key_hash=victim_owner,
            session_id="shared-session",
            run_id="victim-run",
            tool_name="file_list",
            args_schema="{}",
            resource_scope="workspace",
            max_bytes=1024,
            max_duration_ms=1000,
            ttl_ms=60_000,
        )

        response = await client.post(
            "/api/workspace/switch",
            json={"to_product": "js-work", "session_id": "shared-session"},
            headers={"X-API-Key": user_key},
        )

        assert response.status_code == 410
        assert not victim_token.is_set()
        assert not authority.is_revoked(victim_lease.lease_id)


@pytest.mark.asyncio
async def test_same_owner_idle_revokes_only_its_same_named_session(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    async with _switch_harness(monkeypatch, tmp_path) as harness:
        client, agent, auth_manager, admin_key, user_key = harness
        owner = auth_manager.verify(user_key)["key_hash"]
        other_owner = auth_manager.verify(admin_key)["key_hash"]
        authority = agent._get_echo_tool_lease_authority()
        own_lease = authority.issue(
            product_id="js-agent",
            owner_key_hash=owner,
            session_id="idle-session",
            run_id="own-run",
            tool_name="file_list",
            args_schema="{}",
            resource_scope="workspace",
            max_bytes=1024,
            max_duration_ms=1000,
            ttl_ms=60_000,
        )
        other_lease = authority.issue(
            product_id="js-agent",
            owner_key_hash=other_owner,
            session_id="idle-session",
            run_id="other-run",
            tool_name="file_list",
            args_schema="{}",
            resource_scope="workspace",
            max_bytes=1024,
            max_duration_ms=1000,
            ttl_ms=60_000,
        )

        response = await client.post(
            "/api/workspace/switch",
            json={"to_product": "js-work", "session_id": "idle-session"},
            headers={"X-API-Key": user_key},
        )

        assert response.status_code == 410, response.text
        assert not authority.is_revoked(own_lease.lease_id)
        assert not authority.is_revoked(other_lease.lease_id)


def test_global_prefs_rejects_raw_secrets(tmp_path: Path) -> None:
    from js.appshell.global_prefs import prefs_from_mapping

    with pytest.raises(ValueError, match="raw secret"):
        prefs_from_mapping({"credential_refs": ["sk-live-secret-value"]})


def test_launcher_builds_isolated_argv(tmp_path: Path, monkeypatch: Any) -> None:
    from js.appshell import launcher

    captured: list[list[str]] = []
    served: list[tuple[Any, str, int]] = []
    personal_workspace = tmp_path / "personal-workspace"
    personal_workspace.mkdir()
    personal_config = tmp_path / "p.yaml"
    personal_config.write_text(
        yaml.safe_dump(
            {
                "workspace": str(personal_workspace),
                "state_dir": str(tmp_path / "personal-state"),
                "providers": [],
            }
        ),
        encoding="utf-8",
    )
    work_config = tmp_path / "w.yaml"
    work_config.write_text("providers: []\n", encoding="utf-8")

    monkeypatch.setattr(
        "subprocess.Popen",
        lambda *args, **kwargs: captured.append(list(args[0])),
    )
    monkeypatch.setattr(
        "uvicorn.run",
        lambda app, *, host, port, reload=False: served.append((app, host, port)),
    )
    prefs = tmp_path / "prefs.json"
    rc = launcher.launch_appshell(
        personal_config=str(personal_config),
        work_config=str(work_config),
        personal_base_url="http://127.0.0.1:18000",
        work_base_url="http://127.0.0.1:18765",
        open_browser=False,
        prefs_path=prefs,
    )
    assert rc == 0
    assert captured == []
    assert len(served) == 1
    app, host, port = served[0]
    assert host == "127.0.0.1"
    assert port == 18000
    assert app.state.personal_app is not None
    assert app.state.work_app is not None
