"""B1: one parent identity, one cookie, and trusted server-side mode routing."""

from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
import yaml
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

_SHARED_KEY = "js_shared-appshell-test-key"
_SECOND_SHARED_KEY = "js_second-shared-appshell-test-key"
_PERSONAL_ONLY_KEY = "js_personal-only-appshell-test-key"
_PERSONAL_ADMIN_ONLY_KEY = "js_personal-admin-only-appshell-test-key"


def _write_personal_config(root: Path) -> tuple[Path, Path]:
    state = root / "personal-state"
    workspace = root / "personal-workspace"
    config = root / "personal.yaml"
    config.write_text(
        yaml.safe_dump(
            {
                "state_dir": str(state),
                "workspace": str(workspace),
                "echo_engine": "on",
                "first_run_completed": True,
                "security": {"api_key_required": True},
                "providers": [],
                "models": [],
            }
        ),
        encoding="utf-8",
    )
    return config, state


def _write_work_config(root: Path) -> tuple[Path, Path, Path]:
    home = root / "work-home"
    product_home = home / ".js-work"
    state = product_home / "state"
    workspace = product_home / "workspace"
    config = root / "work.yaml"
    config.write_text(
        yaml.safe_dump(
            {
                "state_dir": str(state),
                "workspace": str(workspace),
                "echo_engine": "on",
                "first_run_completed": True,
                "security": {"api_key_required": True},
                "providers": [],
                "models": [],
            }
        ),
        encoding="utf-8",
    )
    return config, home, workspace


def _install_key(state_dir: Path, key: str, *, name: str, role: str) -> None:
    """Provision a literal test key without deriving expectations from production."""
    from js.web.auth import AuthManager

    AuthManager(state_dir)
    key_hash = hashlib.sha256(key.encode("utf-8")).hexdigest()
    with sqlite3.connect(state_dir / "api_keys.db") as connection:
        connection.execute(
            "INSERT INTO api_keys "
            "(key_hash, name, role, created_at, enabled) VALUES (?, ?, ?, 1.0, 1)",
            (key_hash, name, role),
        )
        connection.commit()


@dataclass
class _Harness:
    client: TestClient
    app: Any
    owner: str
    work_handle: str

    def login(self, key: str = _SHARED_KEY) -> dict[str, Any]:
        response = self.client.post(
            "/api/appshell/session",
            headers={"X-API-Key": key},
        )
        assert response.status_code == 200, response.text
        return response.json()


@pytest.fixture()
def appshell(tmp_path: Path) -> Any:
    from js.appshell.server import create_appshell_app
    from js.echo.turn_runtime import _workspace_handle
    from js_work.tools import WorkToolProfile

    personal_config, personal_state = _write_personal_config(tmp_path)
    work_config, work_home, work_workspace = _write_work_config(tmp_path)
    for key, name in (
        (_SHARED_KEY, "shared-owner"),
        (_SECOND_SHARED_KEY, "second-owner"),
    ):
        _install_key(personal_state, key, name=name, role="admin")
        _install_key(work_home / ".js-work" / "state", key, name=name, role="user")
    _install_key(personal_state, _PERSONAL_ONLY_KEY, name="personal-only", role="user")
    _install_key(
        personal_state,
        _PERSONAL_ADMIN_ONLY_KEY,
        name="personal-admin-only",
        role="admin",
    )

    app = create_appshell_app(
        personal_config=str(personal_config),
        work_config=str(work_config),
        work_home=work_home,
        work_profile=WorkToolProfile.SAFE,
        host="127.0.0.1",
        port=8000,
    )
    with TestClient(
        app,
        base_url="http://localhost",
        headers={"Origin": "http://localhost"},
        client=("127.0.0.1", 50123),
    ) as client:
        yield _Harness(
            client=client,
            app=app,
            owner=hashlib.sha256(_SHARED_KEY.encode("utf-8")).hexdigest(),
            work_handle=_workspace_handle(work_workspace),
        )


def _switch_payload(
    *,
    expected_from_mode: str,
    to_mode: str,
    workspace_handle: str | None,
    session_id: str | None = None,
) -> dict[str, Any]:
    return {
        "expected_from_mode": expected_from_mode,
        "to_mode": to_mode,
        "session_id": session_id,
        "workspace_handle": workspace_handle,
    }


def test_one_login_sets_only_parent_cookie_and_root_api_uses_principal(
    appshell: _Harness,
) -> None:
    body = appshell.login()

    set_cookie = appshell.client.cookies.get("js_appshell_session")
    assert set_cookie
    assert not appshell.client.cookies.get("js_session_js-agent")
    assert not appshell.client.cookies.get("js_session_js-work")
    assert body["principal"] == {
        "schema": "AppShellPrincipalV1",
        "session": body["principal"]["session"],
        "active_mode": "personal",
        "mode_roles": {"personal": "admin", "work": "user"},
        "workspace": None,
        "expires_at": body["principal"]["expires_at"],
        "epoch": 0,
    }

    status = appshell.client.get("/api/status")
    assert status.status_code == 200, status.text
    assert status.json()["product_id"] == "js-agent"
    assert appshell.client.get("/work/api/status").status_code == 404
    assert "8765" not in appshell.client.get("/api/appshell/capabilities").text


def test_parent_logout_revokes_session_and_expires_parent_cookie(
    appshell: _Harness,
) -> None:
    appshell.login()
    token = appshell.client.cookies.get("js_appshell_session")
    assert token

    response = appshell.client.post("/api/appshell/logout")

    assert response.status_code == 200, response.text
    assert response.json() == {"success": True}
    assert "js_appshell_session=" in response.headers["set-cookie"]
    assert "Max-Age=0" in response.headers["set-cookie"]
    assert appshell.app.state.appshell_session_store.resolve(token) is None
    assert appshell.client.get("/api/status").status_code == 401


def test_work_role_is_required_and_failed_switch_does_not_mutate_mode(
    appshell: _Harness,
) -> None:
    body = appshell.login(_PERSONAL_ONLY_KEY)
    assert body["principal"]["mode_roles"] == {"personal": "user"}

    response = appshell.client.post(
        "/api/appshell/switch",
        json=_switch_payload(
            expected_from_mode="personal",
            to_mode="work",
            workspace_handle=appshell.work_handle,
        ),
    )
    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "work_role_required"
    assert appshell.client.get("/api/status").json()["product_id"] == "js-agent"


def test_cross_origin_switch_is_rejected_before_mode_mutation(appshell: _Harness) -> None:
    appshell.login()
    response = appshell.client.post(
        "/api/appshell/switch",
        json=_switch_payload(
            expected_from_mode="personal",
            to_mode="work",
            workspace_handle=appshell.work_handle,
        ),
        headers={"Origin": "http://evil.example"},
    )
    assert response.status_code == 403
    assert appshell.client.get("/api/status").json()["product_id"] == "js-agent"


def test_revoking_underlying_key_invalidates_parent_session(appshell: _Harness) -> None:
    from js.web.auth import AuthManager

    appshell.login()
    personal_settings = appshell.app.state.personal_app.state.runtime_settings
    assert AuthManager(personal_settings.state_dir).revoke_key(appshell.owner[:16])

    response = appshell.client.get("/api/status")
    assert response.status_code == 401
    assert response.json()["detail"] == "AppShell session is required"


def test_loopback_admin_bootstrap_provisions_same_key_into_work(appshell: _Harness) -> None:
    from js.web.auth import AuthManager

    response = appshell.client.post(
        "/api/appshell/bootstrap",
        headers={"X-API-Key": _PERSONAL_ADMIN_ONLY_KEY},
    )
    assert response.status_code == 200, response.text
    assert response.json()["principal"]["mode_roles"] == {
        "personal": "admin",
        "work": "admin",
    }
    work_settings = appshell.app.state.work_app.state.runtime_settings
    assert AuthManager(work_settings.state_dir).verify(_PERSONAL_ADMIN_ONLY_KEY)["role"] == "admin"


def test_fresh_loopback_bootstrap_creates_one_shared_recovery_identity(
    tmp_path: Path,
) -> None:
    import stat

    from js.appshell.server import create_appshell_app
    from js.web.auth import AuthManager
    from js_work.tools import WorkToolProfile

    personal_config, personal_state = _write_personal_config(tmp_path)
    work_config, work_home, _work_workspace = _write_work_config(tmp_path)
    app = create_appshell_app(
        personal_config=str(personal_config),
        work_config=str(work_config),
        work_home=work_home,
        work_profile=WorkToolProfile.SAFE,
        host="127.0.0.1",
        port=8000,
    )
    with TestClient(
        app,
        base_url="http://localhost",
        headers={"Origin": "http://localhost"},
        client=("127.0.0.1", 50123),
    ) as client:
        response = client.post("/api/appshell/bootstrap")
        assert response.status_code == 200, response.text
        assert response.json()["principal"]["mode_roles"] == {
            "personal": "admin",
            "work": "admin",
        }
        assert "api_key" not in response.text
        assert client.cookies.get("js_appshell_session")

    recovery_file = personal_state / "bootstrap_admin_key.txt"
    recovery_key = recovery_file.read_text(encoding="utf-8").strip()
    assert stat.S_IMODE(recovery_file.stat().st_mode) == 0o600
    personal_identity = AuthManager(personal_state).verify(recovery_key)
    work_identity = AuthManager(work_home / ".js-work" / "state").verify(recovery_key)
    assert personal_identity["key_hash"] == work_identity["key_hash"]
    assert personal_identity["role"] == work_identity["role"] == "admin"


def test_switch_contract_validates_mode_and_opaque_workspace_then_routes_root(
    appshell: _Harness,
) -> None:
    appshell.login()
    caps = appshell.client.get("/api/appshell/capabilities").json()
    assert caps["workspace_handles"] == {
        "personal": None,
        "work": appshell.work_handle,
    }

    missing_workspace = appshell.client.post(
        "/api/appshell/switch",
        json=_switch_payload(
            expected_from_mode="personal",
            to_mode="work",
            workspace_handle=None,
        ),
    )
    raw_workspace = appshell.client.post(
        "/api/appshell/switch",
        json=_switch_payload(
            expected_from_mode="personal",
            to_mode="work",
            workspace_handle="/tmp/not-an-opaque-handle",
        ),
    )
    client_product = appshell.client.post(
        "/api/appshell/switch",
        json={
            **_switch_payload(
                expected_from_mode="personal",
                to_mode="work",
                workspace_handle=appshell.work_handle,
            ),
            "product": "js-work",
        },
    )
    assert missing_workspace.status_code == 400
    assert raw_workspace.status_code == 400
    assert client_product.status_code == 422

    switched = appshell.client.post(
        "/api/appshell/switch",
        json=_switch_payload(
            expected_from_mode="personal",
            to_mode="work",
            workspace_handle=appshell.work_handle,
        ),
    )
    assert switched.status_code == 200, switched.text
    payload = switched.json()
    assert payload["completed_steps"] == [
        "verify_departing_resources_cleared",
        "update_principal",
    ]
    assert payload["client_required_steps"] == [
        "clear_stream_and_attachments",
        "reconnect_at_target_path",
    ]
    assert payload["resource_session_ids"] == []
    assert payload["websocket_close"] == {
        "revoked": 0,
        "closed": 0,
        "errors": [],
    }
    assert payload["target_path"] == "/"
    assert payload["must_reconnect"] is True
    assert "8765" not in switched.text
    assert appshell.client.get("/api/status").json()["product_id"] == "js-work"

    stale = appshell.client.post(
        "/api/appshell/switch",
        json=_switch_payload(
            expected_from_mode="personal",
            to_mode="work",
            workspace_handle=appshell.work_handle,
        ),
    )
    personal_with_workspace = appshell.client.post(
        "/api/appshell/switch",
        json=_switch_payload(
            expected_from_mode="work",
            to_mode="personal",
            workspace_handle=appshell.work_handle,
        ),
    )
    assert stale.status_code == 409
    assert personal_with_workspace.status_code == 400

    back = appshell.client.post(
        "/api/appshell/switch",
        json=_switch_payload(
            expected_from_mode="work",
            to_mode="personal",
            workspace_handle=None,
        ),
    )
    assert back.status_code == 200, back.text
    assert appshell.client.get("/api/status").json()["product_id"] == "js-agent"


def test_owner_mode_and_workspace_are_isolated_by_parent_session(
    appshell: _Harness,
) -> None:
    first = appshell.login(_SHARED_KEY)
    first_cookie = appshell.client.cookies.get("js_appshell_session")
    appshell.client.cookies.clear()
    second = appshell.login(_SECOND_SHARED_KEY)
    second_cookie = appshell.client.cookies.get("js_appshell_session")
    assert first["principal"]["session"] != second["principal"]["session"]

    appshell.client.cookies.set("js_appshell_session", first_cookie)
    switched = appshell.client.post(
        "/api/appshell/switch",
        json=_switch_payload(
            expected_from_mode="personal",
            to_mode="work",
            workspace_handle=appshell.work_handle,
        ),
    )
    assert switched.status_code == 200, switched.text
    assert appshell.client.get("/api/status").json()["product_id"] == "js-work"

    appshell.client.cookies.set("js_appshell_session", second_cookie)
    assert appshell.client.get("/api/status").json()["product_id"] == "js-agent"
    assert (
        appshell.client.get("/api/appshell/capabilities").json()["workspace"]
        is None
    )


def test_switch_cancels_run_revokes_lease_and_rejects_pending_approval(
    appshell: _Harness,
) -> None:
    import asyncio

    appshell.login()
    personal_agent = appshell.app.state.personal_app.state.web_runtime.agent
    session_id = "departing-chat-session"
    cancel_token = asyncio.Event()
    personal_agent.bind_cancel_token(
        session_id,
        cancel_token,
        owner_key_hash=appshell.owner,
        run_id="departing-run",
    )
    authority = personal_agent._get_echo_tool_lease_authority()
    lease = authority.issue(
        product_id="js-agent",
        owner_key_hash=appshell.owner,
        session_id=session_id,
        run_id="departing-run",
        tool_name="file_list",
        args_schema="{}",
        resource_scope="workspace",
        max_bytes=1024,
        max_duration_ms=1000,
        ttl_ms=60_000,
    )
    approval = personal_agent.approvals.request_decision(
        "file_write",
        {"path": "fixture.txt"},
        context="web",
        session_id=session_id,
        run_id="departing-run",
        owner_key_hash=appshell.owner,
        queue_if_unhandled=True,
    )

    switched = appshell.client.post(
        "/api/appshell/switch",
        json=_switch_payload(
            expected_from_mode="personal",
            to_mode="work",
            workspace_handle=appshell.work_handle,
            session_id=session_id,
        ),
    )
    assert switched.status_code == 200, switched.text
    assert cancel_token.is_set()
    assert authority.is_revoked(lease.lease_id)
    assert personal_agent.approvals.get_pending_request(
        approval.request_id,
        owner_key_hash=appshell.owner,
    ) is None
    decision = personal_agent.approvals.take_decision(
        approval.request_id,
        owner_key_hash=appshell.owner,
    )
    assert decision is not None
    assert decision.reason == "appshell_mode_switch"


def test_switch_with_null_session_derives_and_clears_all_owner_sessions(
    appshell: _Harness,
) -> None:
    import asyncio

    appshell.login()
    personal_agent = appshell.app.state.personal_app.state.web_runtime.agent
    authority = personal_agent._get_echo_tool_lease_authority()
    tokens: dict[str, asyncio.Event] = {}
    lease_ids: list[str] = []
    approval_ids: list[str] = []
    for index, session_id in enumerate(("departing-one", "departing-two"), start=1):
        token = asyncio.Event()
        tokens[session_id] = token
        personal_agent.bind_cancel_token(
            session_id,
            token,
            owner_key_hash=appshell.owner,
            run_id=f"run-{index}",
        )
        lease_ids.append(
            authority.issue(
                product_id="js-agent",
                owner_key_hash=appshell.owner,
                session_id=session_id,
                run_id=f"run-{index}",
                tool_name="file_list",
                args_schema="{}",
                resource_scope="workspace",
                max_bytes=1024,
                max_duration_ms=1000,
                ttl_ms=60_000,
            ).lease_id
        )
        approval_ids.append(
            personal_agent.approvals.request_decision(
                "file_write",
                {"path": f"fixture-{index}.txt"},
                context="web",
                session_id=session_id,
                run_id=f"run-{index}",
                owner_key_hash=appshell.owner,
                queue_if_unhandled=True,
            ).request_id
        )

    switched = appshell.client.post(
        "/api/appshell/switch",
        json=_switch_payload(
            expected_from_mode="personal",
            to_mode="work",
            workspace_handle=appshell.work_handle,
            session_id=None,
        ),
    )

    assert switched.status_code == 200, switched.text
    payload = switched.json()
    assert payload["resource_session_ids"] == ["departing-one", "departing-two"]
    assert set(payload["cancelled_sessions"]) == set(tokens)
    assert "cancel_old_runs" in payload["completed_steps"]
    assert "revoke_leases_and_approvals" in payload["completed_steps"]
    assert all(token.is_set() for token in tokens.values())
    assert all(authority.is_revoked(lease_id) for lease_id in lease_ids)
    assert all(
        personal_agent.approvals.get_pending_request(
            approval_id,
            owner_key_hash=appshell.owner,
        )
        is None
        for approval_id in approval_ids
    )


def test_switch_rejects_forged_explicit_session_when_trusted_resources_exist(
    appshell: _Harness,
) -> None:
    import asyncio

    appshell.login()
    personal_agent = appshell.app.state.personal_app.state.web_runtime.agent
    real_token = asyncio.Event()
    personal_agent.bind_cancel_token(
        "real-session",
        real_token,
        owner_key_hash=appshell.owner,
        run_id="real-run",
    )

    switched = appshell.client.post(
        "/api/appshell/switch",
        json=_switch_payload(
            expected_from_mode="personal",
            to_mode="work",
            workspace_handle=appshell.work_handle,
            session_id="forged-session",
        ),
    )

    assert switched.status_code == 409, switched.text
    assert switched.json()["detail"]["code"] == "session_binding_mismatch"
    assert real_token.is_set() is False
    assert appshell.client.get("/api/status").json()["product_id"] == "js-agent"


def test_switch_fails_closed_when_departing_resources_cannot_be_proved_clear(
    appshell: _Harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    appshell.login()
    personal_agent = appshell.app.state.personal_app.state.web_runtime.agent
    monkeypatch.setattr(
        personal_agent,
        "owned_active_session_ids",
        lambda *, owner_key_hash: ("stuck-session",),
    )

    switched = appshell.client.post(
        "/api/appshell/switch",
        json=_switch_payload(
            expected_from_mode="personal",
            to_mode="work",
            workspace_handle=appshell.work_handle,
            session_id="stuck-session",
        ),
    )

    assert switched.status_code == 503, switched.text
    assert switched.json()["detail"]["code"] == "departing_resources_not_cleared"
    assert appshell.client.get("/api/status").json()["product_id"] == "js-agent"


def test_switch_reports_websocket_close_errors_without_claiming_close_completed(
    appshell: _Harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    appshell.login()

    async def close_with_one_error(_session: str, _mode: str) -> dict[str, Any]:
        return {
            "revoked": 2,
            "closed": 1,
            "errors": ["RuntimeError: synthetic-close-failure"],
        }

    monkeypatch.setattr(
        appshell.app.state.appshell_ws_registry,
        "close_for_session",
        close_with_one_error,
    )
    switched = appshell.client.post(
        "/api/appshell/switch",
        json=_switch_payload(
            expected_from_mode="personal",
            to_mode="work",
            workspace_handle=appshell.work_handle,
        ),
    )

    assert switched.status_code == 503, switched.text
    assert switched.json()["detail"]["code"] == "old_websocket_close_failed"
    assert appshell.client.get("/api/status").json()["product_id"] == "js-agent"


@pytest.mark.asyncio
async def test_websocket_registry_revokes_all_before_isolated_parallel_close() -> None:
    import asyncio

    from js.appshell.principal import AppShellPrincipalV1
    from js.appshell.routing import AppShellWebSocketRegistry

    registry = AppShellWebSocketRegistry()
    principal = AppShellPrincipalV1(
        owner="owner",
        session="parent-session",
        active_mode="personal",
        mode_roles={"personal": "admin"},
        workspace=None,
        expires_at=9_999_999_999,
    )
    bindings: list[Any] = []
    attempts: list[str] = []

    async def make_send(name: str, *, fail: bool = False) -> Any:
        async def send(_message: dict[str, Any]) -> None:
            assert all(binding.revoked.is_set() for binding in bindings)
            attempts.append(name)
            await asyncio.sleep(0)
            if fail:
                raise RuntimeError(f"{name}-close-failed")

        return send

    for name, fail in (("first", False), ("broken", True), ("last", False)):
        binding = await registry.register(
            principal,
            await make_send(name, fail=fail),
        )
        binding.accepted = True
        bindings.append(binding)

    result = await registry.close_for_session("parent-session", "personal")

    assert set(attempts) == {"first", "broken", "last"}
    assert result["revoked"] == 3
    assert result["closed"] == 2
    assert len(result["errors"]) == 1
    assert "broken-close-failed" in result["errors"][0]
    assert all(binding.revoked.is_set() for binding in bindings)


def test_switch_closes_websocket_bound_to_departing_principal(
    appshell: _Harness,
) -> None:
    appshell.login()
    with appshell.client.websocket_connect(
        "/ws",
        headers={
            "Host": "localhost",
            "Origin": "http://localhost",
            "Cookie": (
                "js_appshell_session="
                + str(appshell.client.cookies.get("js_appshell_session"))
            ),
        },
    ) as websocket:
        switched = appshell.client.post(
            "/api/appshell/switch",
            json=_switch_payload(
                expected_from_mode="personal",
                to_mode="work",
                workspace_handle=appshell.work_handle,
            ),
        )
        assert switched.status_code == 200, switched.text
        with pytest.raises(WebSocketDisconnect) as closed:
            websocket.receive_json()
        assert closed.value.code == 1012


def test_switch_waits_for_threaded_http_worker_or_reopens_old_epoch(
    appshell: _Harness,
    tmp_path: Path,
) -> None:
    import asyncio
    import threading
    from concurrent.futures import ThreadPoolExecutor

    from fastapi import Depends

    from js.web.auth import require_user_write

    appshell.login()
    appshell.app.state.appshell_mode_gate._drain_timeout_seconds = 0.15
    entered = threading.Event()
    release = threading.Event()
    worker_committed = threading.Event()
    committed = tmp_path / "old-personal-epoch.txt"

    @appshell.app.state.personal_app.post("/api/task3a/personal-mutation")
    async def _paused_personal_mutation(
        _auth: dict[str, Any] = Depends(require_user_write),
    ) -> dict[str, bool]:
        def _blocking_commit() -> None:
            entered.set()
            release.wait(5.0)
            committed.write_text("old personal worker completed", encoding="utf-8")
            worker_committed.set()

        await asyncio.to_thread(_blocking_commit)
        return {"ok": True}

    with ThreadPoolExecutor(max_workers=1) as pool:
        mutation_future = pool.submit(
            appshell.client.post,
            "/api/task3a/personal-mutation",
        )
        assert entered.wait(2.0), "Personal mutation did not reach its pre-commit barrier"

        try:
            switched = appshell.client.post(
                "/api/appshell/switch",
                json=_switch_payload(
                    expected_from_mode="personal",
                    to_mode="work",
                    workspace_handle=appshell.work_handle,
                ),
            )
        finally:
            release.set()
        mutation = mutation_future.result(timeout=5.0)

    assert switched.status_code in {409, 503}, switched.text
    assert mutation.status_code == 200, mutation.text
    assert worker_committed.is_set()
    assert committed.read_text(encoding="utf-8") == "old personal worker completed"
    assert appshell.client.get("/api/status").json()["product_id"] == "js-agent"


def test_stale_appshell_epoch_rejects_real_echo_tool_before_ledger_commit(
    appshell: _Harness,
) -> None:
    from fastapi import Depends, HTTPException

    from js.echo.effect_interpreter import ToolEffect
    from js.web.auth import require_user_write, runtime_owner
    from js.web.deps import get_agent

    appshell.login()
    captured: dict[str, Any] = {}
    personal_app = appshell.app.state.personal_app
    work_app = appshell.app.state.work_app

    @personal_app.post("/api/task3a/capture-echo-context")
    async def _capture_echo_context(
        auth: dict[str, Any] = Depends(require_user_write),
    ) -> dict[str, bool]:
        agent = get_agent()
        captured["runtime"] = agent.echo_runtime
        captured["context"] = agent.echo_runtime.build_context(
            channel="web",
            owner_key_hash=runtime_owner(auth),
            session_id="task3a-stale-effect-session",
            run_id="task3a-stale-effect-run",
            capabilities=("file_list",),
        )
        captured["ledger"] = agent.echo_safety_service
        return {"ok": True}

    @work_app.post("/api/task3a/commit-captured-echo-effect")
    async def _commit_captured_echo_effect(
        _auth: dict[str, Any] = Depends(require_user_write),
    ) -> dict[str, bool]:
        try:
            _message, result = await captured["runtime"].execute_tool_effect(
                ToolEffect.from_arguments(
                    "file_list",
                    {"path": "."},
                    tool_call_id="task3a-stale-effect-call",
                    allowed_tools=("file_list",),
                ),
                captured["context"],
            )
        except PermissionError as exc:
            raise HTTPException(
                409,
                {"code": "appshell_epoch_stale"},
            ) from exc
        return {"ok": result.success}

    captured_response = appshell.client.post("/api/task3a/capture-echo-context")
    assert captured_response.status_code == 200, captured_response.text
    ledger = captured["ledger"]
    before_records = ledger.health().record_count

    switched = appshell.client.post(
        "/api/appshell/switch",
        json=_switch_payload(
            expected_from_mode="personal",
            to_mode="work",
            workspace_handle=appshell.work_handle,
        ),
    )
    assert switched.status_code == 200, switched.text

    committed = appshell.client.post("/api/task3a/commit-captured-echo-effect")

    assert committed.status_code == 409, committed.text
    assert committed.json()["detail"]["code"] == "appshell_epoch_stale"
    assert ledger.health().record_count == before_records


def test_switch_waits_for_cancelled_mutating_echo_receipt_and_merge(
    appshell: _Harness,
) -> None:
    import asyncio
    import threading
    import time
    from concurrent.futures import ThreadPoolExecutor

    from fastapi import Depends

    from js.echo.effect_interpreter import ToolEffect
    from js.echo.ledger.journal import FileEchoLedger
    from js.echo.turn_context import runtime_partition_key
    from js.tools.registry import ToolResult, ToolSpec
    from js.web.auth import require_user_write, runtime_owner

    appshell.login()
    token = appshell.client.cookies.get("js_appshell_session")
    assert token
    personal_app = appshell.app.state.personal_app
    agent = personal_app.state.web_runtime.agent
    service = agent.echo_safety_service
    tool_name = "task3a_mutating_pause"
    session_id = "task3a-mid-effect-session"
    run_id = "task3a-mid-effect-run"
    tool_call_id = "task3a-mid-effect-call"
    handler_entered = threading.Event()
    handler_cancelled = threading.Event()
    effect_done = threading.Event()
    captured: dict[str, Any] = {}

    async def _mutating_handler() -> ToolResult:
        handler_entered.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            handler_cancelled.set()
            raise

    agent.registry.register(
        ToolSpec(
            name=tool_name,
            description="Task 3A mutating cancellation barrier",
            parameters=[],
            read_only=False,
        ),
        _mutating_handler,
    )
    assert agent.registry.get(tool_name) is not None
    agent._current_allowed_tools.add(tool_name)

    @personal_app.post("/api/task3a/start-mid-effect")
    async def _start_mid_effect(
        auth: dict[str, Any] = Depends(require_user_write),
    ) -> dict[str, bool]:
        owner = runtime_owner(auth)
        context = agent.echo_runtime.build_context(
            channel="web",
            owner_key_hash=owner,
            session_id=session_id,
            run_id=run_id,
            capabilities=(tool_name,),
        )
        cancel_token = context.cancel_token
        assert isinstance(cancel_token, asyncio.Event)
        partition = runtime_partition_key(context.product_id, owner, session_id)

        async def _run_effect() -> None:
            task = asyncio.current_task()
            assert task is not None
            agent.bind_cancel_token(
                session_id,
                cancel_token,
                owner_key_hash=owner,
                run_id=run_id,
            )
            agent._active_run_tasks[partition] = (task, run_id, owner)
            try:
                await agent.echo_runtime.execute_tool_effect(
                    ToolEffect.from_arguments(
                        tool_name,
                        {},
                        tool_call_id=tool_call_id,
                        allowed_tools=(tool_name,),
                    ),
                    context,
                )
            except asyncio.CancelledError:
                captured["terminal"] = "cancelled"
            finally:
                agent.unbind_cancel_token(
                    session_id,
                    cancel_token,
                    owner_key_hash=owner,
                )
                active = agent._active_run_tasks.get(partition)
                if active is not None and active[0] is task:
                    agent._active_run_tasks.pop(partition, None)
                effect_done.set()

        captured["context"] = context
        captured["task"] = asyncio.create_task(_run_effect())
        return {"ok": True}

    started = appshell.client.post("/api/task3a/start-mid-effect")
    assert started.status_code == 200, started.text
    assert handler_entered.wait(2.0), "Mutating tool did not reach its handler"

    pool = ThreadPoolExecutor(max_workers=1)
    service._state_lock.acquire()
    try:
        switch_future = pool.submit(
            appshell.client.post,
            "/api/appshell/switch",
            json=_switch_payload(
                expected_from_mode="personal",
                to_mode="work",
                workspace_handle=appshell.work_handle,
            ),
        )
        assert handler_cancelled.wait(2.0), "Switch did not cancel the active tool"
        deadline = time.monotonic() + 0.3
        advanced_before_terminal = False
        while time.monotonic() < deadline:
            current = appshell.app.state.appshell_session_store.resolve(token)
            advanced_before_terminal = bool(
                current is not None and current.active_mode == "work"
            )
            if advanced_before_terminal or switch_future.done():
                break
            threading.Event().wait(0.005)
    finally:
        service._state_lock.release()

    switched = switch_future.result(timeout=5.0)
    pool.shutdown(wait=True)
    assert effect_done.wait(3.0), "Cancelled effect did not finish its durable terminal"
    assert not advanced_before_terminal
    assert switched.status_code == 200, switched.text
    assert captured["terminal"] == "cancelled"

    context = captured["context"]
    journal_path = service.journal_path_for_scope(
        context.owner_key_hash,
        product_id=context.product_id,
        session_id=context.session_id,
    )
    records = FileEchoLedger(
        journal_path,
        mac_key=service.journal_key_for_scope(
            context.owner_key_hash,
            product_id=context.product_id,
            session_id=context.session_id,
        ),
    ).records
    receipts = [record for record in records if record.record_type == "receipt"]
    merges = [record for record in records if record.record_type == "merge"]
    assert len(receipts) == len(merges) == 1
    assert receipts[0].payload["status"] == "cancelled"
    assert merges[0].payload["status"] == "cancelled"
    record_count_after_switch = len(records)
    assert (
        FileEchoLedger(
            journal_path,
            mac_key=service.journal_key_for_scope(
                context.owner_key_hash,
                product_id=context.product_id,
                session_id=context.session_id,
            ),
        ).record_count
        == record_count_after_switch
    )


def test_request_arriving_after_switch_closes_old_epoch_is_rejected(
    appshell: _Harness,
) -> None:
    import asyncio
    import threading
    import time
    from concurrent.futures import ThreadPoolExecutor

    from fastapi import Depends

    from js.web.auth import require_user_write

    appshell.login()
    token = appshell.client.cookies.get("js_appshell_session")
    principal = appshell.app.state.appshell_session_store.resolve(token)
    assert principal is not None
    old_request_entered = threading.Event()
    allow_old_request_exit = threading.Event()

    @appshell.app.state.personal_app.get("/api/task3a/drain-old-request")
    async def _drain_old_request(
        _auth: dict[str, Any] = Depends(require_user_write),
    ) -> dict[str, bool]:
        def _blocking_request() -> None:
            allow_old_request_exit.wait(5.0)

        old_request_entered.set()
        await asyncio.to_thread(_blocking_request)
        return {"ok": True}

    with ThreadPoolExecutor(max_workers=2) as pool:
        old_request_future = pool.submit(
            appshell.client.get,
            "/api/task3a/drain-old-request",
        )
        assert old_request_entered.wait(2.0), "Old request did not enter its handler"
        switch_future = pool.submit(
            appshell.client.post,
            "/api/appshell/switch",
            json=_switch_payload(
                expected_from_mode="personal",
                to_mode="work",
                workspace_handle=appshell.work_handle,
            ),
        )
        deadline = time.monotonic() + 2.0
        while appshell.app.state.appshell_session_store.is_epoch_current(
            principal.epoch_binding()
        ):
            assert time.monotonic() < deadline, "Switch did not close admission"
            threading.Event().wait(0.005)

        rejected = appshell.client.get("/api/status")
        allow_old_request_exit.set()
        old_request = old_request_future.result(timeout=5.0)
        switched = switch_future.result(timeout=5.0)

    assert rejected.status_code == 409, rejected.text
    assert rejected.json()["detail"]["code"] == "appshell_epoch_closed"
    assert old_request.status_code == 200, old_request.text
    assert switched.status_code == 200, switched.text


def test_concurrent_double_switch_has_at_most_one_successful_cas(
    appshell: _Harness,
) -> None:
    import threading
    from concurrent.futures import ThreadPoolExecutor

    appshell.login()
    start = threading.Barrier(3)

    def _switch() -> Any:
        start.wait(timeout=5.0)
        return appshell.client.post(
            "/api/appshell/switch",
            json=_switch_payload(
                expected_from_mode="personal",
                to_mode="work",
                workspace_handle=appshell.work_handle,
            ),
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_switch) for _index in range(2)]
        start.wait(timeout=5.0)
        responses = [future.result(timeout=5.0) for future in futures]

    assert sum(response.status_code == 200 for response in responses) <= 1
    assert sorted(response.status_code for response in responses) == [200, 409]


@pytest.mark.asyncio
async def test_two_mode_gates_share_authoritative_operation_drain(tmp_path: Path) -> None:
    from js.appshell.principal import AppShellSessionStore
    from js.appshell.routing import AppShellEpochDrainTimeoutError, AppShellModeGate

    store = AppShellSessionStore(tmp_path / "shared-appshell.db")
    token, principal = store.create(
        owner="owner-a",
        mode_roles={"personal": "admin", "work": "user"},
    )
    switch_gate = AppShellModeGate(store, drain_timeout_seconds=0.05)
    worker_gate = AppShellModeGate(store, drain_timeout_seconds=0.05)
    admitted = await worker_gate.admit(principal)
    binding = await switch_gate.begin_switch(token, principal)
    try:
        from js.appshell.routing import AppShellEpochClosedError

        with pytest.raises(AppShellEpochClosedError):
            await worker_gate.admit(principal)
        with pytest.raises(AppShellEpochDrainTimeoutError):
            await switch_gate.wait_for_drain(binding)
    finally:
        await switch_gate.abort_switch(binding)
        await worker_gate.release(admitted)

    assert store.is_epoch_current(principal.epoch_binding())


def test_hung_websocket_close_fails_switch_before_cas_and_reopens_epoch(
    appshell: _Harness,
) -> None:
    import asyncio
    import threading
    from concurrent.futures import (
        ThreadPoolExecutor,
    )
    from concurrent.futures import (
        TimeoutError as FutureTimeoutError,
    )

    appshell.login()
    token = appshell.client.cookies.get("js_appshell_session")
    principal = appshell.app.state.appshell_session_store.resolve(token)
    assert principal is not None
    close_started = threading.Event()
    release_close = threading.Event()
    registry = appshell.app.state.appshell_ws_registry
    registry.close_timeout_seconds = 0.05

    async def _hung_send(_message: dict[str, Any]) -> None:
        close_started.set()
        await asyncio.to_thread(release_close.wait, 5.0)

    assert appshell.client.portal is not None
    binding = appshell.client.portal.call(registry.register, principal, _hung_send)
    binding.accepted = True

    with ThreadPoolExecutor(max_workers=1) as pool:
        switch_future = pool.submit(
            appshell.client.post,
            "/api/appshell/switch",
            json=_switch_payload(
                expected_from_mode="personal",
                to_mode="work",
                workspace_handle=appshell.work_handle,
            ),
        )
        assert close_started.wait(2.0), "Switch did not attempt the real WebSocket close"
        hung_after_deadline = False
        try:
            switched = switch_future.result(timeout=0.3)
        except FutureTimeoutError:
            hung_after_deadline = True
            release_close.set()
            switched = switch_future.result(timeout=5.0)
        finally:
            release_close.set()

    assert not hung_after_deadline
    assert switched.status_code == 503, switched.text
    assert switched.json()["detail"]["code"] == "old_websocket_close_timeout"
    assert appshell.client.get("/api/status").json()["product_id"] == "js-agent"


def test_locked_legacy_session_migration_raises_instead_of_hiding_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import sqlite3

    from js.appshell.principal import AppShellSessionStore
    from js.utils import db as db_utils

    db_path = tmp_path / "locked-legacy.db"
    lock = sqlite3.connect(db_path)
    assert lock.execute("PRAGMA journal_mode=WAL").fetchone() == ("wal",)
    lock.execute(
        """
        CREATE TABLE appshell_sessions (
            token_hash TEXT PRIMARY KEY,
            owner TEXT NOT NULL,
            session TEXT NOT NULL UNIQUE,
            active_mode TEXT NOT NULL,
            mode_roles_json TEXT NOT NULL,
            workspace TEXT,
            created_at REAL NOT NULL,
            expires_at REAL NOT NULL
        )
        """
    )
    lock.execute(
        "CREATE INDEX idx_appshell_sessions_expiry ON appshell_sessions(expires_at)"
    )
    lock.commit()
    lock.execute("BEGIN IMMEDIATE")
    monkeypatch.setattr(db_utils, "_NORMAL_BUSY_TIMEOUT_MS", 50)
    try:
        with pytest.raises(sqlite3.OperationalError, match="locked"):
            AppShellSessionStore(db_path)
    finally:
        lock.rollback()
        lock.close()


def _appshell_lifecycle_row_counts(
    db_path: Path,
    *,
    session: str,
) -> tuple[int, int]:
    with sqlite3.connect(db_path) as connection:
        session_count = int(
            connection.execute(
                "SELECT COUNT(*) FROM appshell_sessions WHERE session = ?",
                (session,),
            ).fetchone()[0]
        )
        operation_count = int(
            connection.execute(
                "SELECT COUNT(*) FROM appshell_operations WHERE session = ?",
                (session,),
            ).fetchone()[0]
        )
    return session_count, operation_count


def test_revoke_removes_session_and_operations_atomically(tmp_path: Path) -> None:
    from js.appshell.principal import AppShellSessionStore

    db_path = tmp_path / "revoke-lifecycle.db"
    store = AppShellSessionStore(db_path)
    token, principal = store.create(
        owner="revoke-owner",
        mode_roles={"personal": "admin"},
    )
    store.begin_operation(principal.epoch_binding(), operation_kind="http")

    assert store.revoke(token)
    assert _appshell_lifecycle_row_counts(
        db_path,
        session=principal.session,
    ) == (0, 0)


def test_expired_resolve_removes_session_and_operations_atomically(
    tmp_path: Path,
) -> None:
    from js.appshell.principal import AppShellSessionStore

    db_path = tmp_path / "expired-lifecycle.db"
    store = AppShellSessionStore(db_path)
    token, principal = store.create(
        owner="expired-owner",
        mode_roles={"personal": "admin"},
    )
    store.begin_operation(principal.epoch_binding(), operation_kind="http")
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            "UPDATE appshell_sessions SET expires_at = 0 WHERE session = ?",
            (principal.session,),
        )
        connection.commit()

    assert store.resolve(token) is None
    assert _appshell_lifecycle_row_counts(
        db_path,
        session=principal.session,
    ) == (0, 0)


def test_store_init_removes_only_historical_orphan_operations(tmp_path: Path) -> None:
    from js.appshell.principal import AppShellSessionStore

    db_path = tmp_path / "startup-orphan-gc.db"
    store = AppShellSessionStore(db_path)
    _token, orphaned = store.create(
        owner="orphan-owner",
        mode_roles={"personal": "admin"},
    )
    operation = store.begin_operation(
        orphaned.epoch_binding(),
        operation_kind="http",
    )
    _active_token, active = store.create(
        owner="active-owner",
        mode_roles={"personal": "admin"},
    )
    store.begin_operation(active.epoch_binding(), operation_kind="http")
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            "DELETE FROM appshell_sessions WHERE session = ?",
            (orphaned.session,),
        )
        connection.commit()
    assert _appshell_lifecycle_row_counts(
        db_path,
        session=orphaned.session,
    ) == (0, 1)

    AppShellSessionStore(db_path)

    assert _appshell_lifecycle_row_counts(
        db_path,
        session=orphaned.session,
    ) == (0, 0)
    assert _appshell_lifecycle_row_counts(
        db_path,
        session=active.session,
    ) == (1, 1)
    assert not store.release_operation(operation)


def test_operation_capacity_rejects_without_mutating_then_recovers_after_release(
    tmp_path: Path,
) -> None:
    from js.appshell.principal import (
        AppShellOperationLimitError,
        AppShellSessionStore,
    )

    db_path = tmp_path / "operation-capacity.db"
    store = AppShellSessionStore(db_path)
    _token, principal = store.create(
        owner="capacity-owner",
        mode_roles={"personal": "admin"},
    )
    binding = principal.epoch_binding()
    operations = [
        store.begin_operation(binding, operation_kind=f"capacity_{index}")
        for index in range(256)
    ]
    assert _appshell_lifecycle_row_counts(
        db_path,
        session=principal.session,
    ) == (1, 256)

    with pytest.raises(AppShellOperationLimitError) as raised:
        store.begin_operation(binding, operation_kind="over_capacity")

    assert not isinstance(raised.value, PermissionError)
    assert _appshell_lifecycle_row_counts(
        db_path,
        session=principal.session,
    ) == (1, 256)

    assert store.release_operation(operations.pop())
    replacement = store.begin_operation(binding, operation_kind="replacement")
    assert _appshell_lifecycle_row_counts(
        db_path,
        session=principal.session,
    ) == (1, 256)
    assert store.release_operation(replacement)


def test_http_operation_capacity_returns_429_without_epoch_stale(
    appshell: _Harness,
) -> None:
    appshell.login()
    token = appshell.client.cookies.get("js_appshell_session")
    store = appshell.app.state.appshell_session_store
    principal = store.resolve(token)
    assert principal is not None
    operations = [
        store.begin_operation(
            principal.epoch_binding(),
            operation_kind=f"capacity_{index}",
        )
        for index in range(256)
    ]
    try:
        response = appshell.client.get("/api/status")

        assert response.status_code == 429, response.text
        assert response.json()["detail"]["code"] == "appshell_operation_limit"
    finally:
        for operation in operations:
            assert store.release_operation(operation)
