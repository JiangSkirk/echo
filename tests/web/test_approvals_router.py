"""Echo approval API contracts."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from js.config import JSSettings, SecurityConfig
from js.security.approvals import ApprovalDecisionType
from js.web.auth import AuthManager
from js.web.runtime_context import WebRuntime, bind_web_runtime, clear_web_runtime
from js.web.server import create_app


def _request(
    request_id: str,
    owner_key_hash: str,
    *,
    arguments: dict[str, Any] | None = None,
    resolved: bool = False,
) -> SimpleNamespace:
    return SimpleNamespace(
        id=request_id,
        tool_name="shell",
        arguments=arguments or {"command": "pwd"},
        timestamp=1_700_000_000.0,
        context="web",
        session_id="session-1",
        run_id="run-1",
        owner_key_hash=owner_key_hash,
        resolved=resolved,
    )


def _app_and_keys(tmp_path: Path) -> tuple[Any, str, str, str, MagicMock]:
    settings = JSSettings(
        workspace=tmp_path / "workspace",
        state_dir=tmp_path / "state",
        providers=[],
        security=SecurityConfig(api_key_required=True),
    )
    agent = MagicMock()
    agent.secrets.detect_and_redact.side_effect = lambda value, _source: value.replace(
        "TOP_SECRET", "[REDACTED]"
    )

    @asynccontextmanager
    async def lifespan(app: Any) -> AsyncIterator[None]:
        runtime = WebRuntime(agent=agent, settings=settings)
        bind_web_runtime(app, runtime)
        try:
            yield
        finally:
            clear_web_runtime(app, runtime)

    app = create_app(
        lifespan_context=lifespan,
        title="Approval Router Test App",
        runtime_settings=settings,
    )
    auth = AuthManager(settings.state_dir)
    admin_key = auth.create_key("admin", role="admin")
    other_admin_key = auth.create_key("other-admin", role="admin")
    user_key = auth.create_key("user", role="user")
    return app, admin_key, other_admin_key, user_key, agent


def test_list_approvals_is_owner_scoped_and_recursively_redacts_arguments(tmp_path: Path) -> None:
    app, admin_key, other_admin_key, _user_key, agent = _app_and_keys(tmp_path)
    owner = AuthManager(tmp_path / "state").verify(admin_key)["key_hash"]
    other_owner = AuthManager(tmp_path / "state").verify(other_admin_key)["key_hash"]
    owned = _request(
        "owned",
        owner,
        arguments={
            "token": "TOP_SECRET",
            "nested": {"items": ["safe", {"password": "TOP_SECRET"}]},
        },
    )
    other = _request("other", other_owner)
    resolved = _request("resolved", owner, resolved=True)
    agent.approvals.get_pending.return_value = [owned, other, resolved]

    with TestClient(app, base_url="http://localhost") as client:
        response = client.get("/api/echo/approvals", headers={"X-API-Key": admin_key})

    assert response.status_code == 200
    assert response.json() == {
        "approvals": [
            {
                "id": "owned",
                "tool_name": "shell",
                "arguments": {
                    "token": "[REDACTED]",
                    "nested": {"items": ["safe", {"password": "[REDACTED]"}]},
                },
                "timestamp": 1_700_000_000.0,
                "context": "web",
                "session_id": "session-1",
                "run_id": "run-1",
            }
        ]
    }
    agent.approvals.get_pending.assert_called_once_with(owner_key_hash=owner)


@pytest.mark.parametrize(
    ("payload", "expected_action", "expected_kwargs"),
    [
        ({"action": "approve", "reason": "verified"}, ApprovalDecisionType.APPROVE, {}),
        (
            {"action": "edit", "edited_arguments": {"path": "/tmp/safe"}},
            ApprovalDecisionType.EDIT,
            {"edited_arguments": {"path": "/tmp/safe"}},
        ),
        ({"action": "reject", "reason": "not authorized"}, ApprovalDecisionType.REJECT, {}),
        (
            {"action": "respond", "response": "Please choose a safe path."},
            ApprovalDecisionType.RESPOND,
            {"response": "Please choose a safe path."},
        ),
    ],
)
def test_decide_approval_forwards_valid_owner_scoped_decisions(
    tmp_path: Path,
    payload: dict[str, Any],
    expected_action: ApprovalDecisionType,
    expected_kwargs: dict[str, Any],
) -> None:
    app, admin_key, _other_admin_key, _user_key, agent = _app_and_keys(tmp_path)
    owner = AuthManager(tmp_path / "state").verify(admin_key)["key_hash"]
    agent.approvals.get_pending_request.return_value = _request("request-1", owner)
    agent.approvals.decide.return_value = SimpleNamespace(
        action=expected_action,
        request_id="request-1",
    )

    with TestClient(app, base_url="http://localhost") as client:
        response = client.post(
            "/api/echo/approvals/request-1/decision",
            headers={"X-API-Key": admin_key, "Origin": "http://localhost"},
            json=payload,
        )

    assert response.status_code == 200
    assert response.json() == {"ok": True, "action": expected_action.value, "request_id": "request-1"}
    agent.approvals.get_pending_request.assert_called_once_with(
        "request-1", owner_key_hash=owner
    )
    _, kwargs = agent.approvals.decide.call_args
    assert agent.approvals.decide.call_args.args == ("request-1", expected_action)
    assert kwargs["reason"] == payload.get("reason", "")
    for key, value in expected_kwargs.items():
        assert kwargs[key] == value


def test_decide_approval_hides_cross_owner_and_missing_requests_as_not_found(tmp_path: Path) -> None:
    app, admin_key, _other_admin_key, _user_key, agent = _app_and_keys(tmp_path)
    agent.approvals.get_pending_request.return_value = None

    with TestClient(app, base_url="http://localhost") as client:
        cross_owner = client.post(
            "/api/echo/approvals/other-owner/decision",
            headers={"X-API-Key": admin_key, "Origin": "http://localhost"},
            json={"action": "reject"},
        )
        missing = client.post(
            "/api/echo/approvals/missing/decision",
            headers={"X-API-Key": admin_key, "Origin": "http://localhost"},
            json={"action": "reject"},
        )

    assert cross_owner.status_code == missing.status_code == 404
    agent.approvals.decide.assert_not_called()


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"action": "pending"},
        {"action": "edit"},
        {"action": "edit", "edited_arguments": "not-an-object"},
        {"action": "respond"},
        {"action": "respond", "response": "   "},
        {"action": "approve", "response": "unexpected"},
        {"action": "reject", "edited_arguments": {}},
        {"action": "approve", "reason": 3},
    ],
)
def test_decide_approval_rejects_invalid_actions_and_payloads(
    tmp_path: Path,
    payload: dict[str, Any],
) -> None:
    app, admin_key, _other_admin_key, _user_key, agent = _app_and_keys(tmp_path)

    with TestClient(app, base_url="http://localhost") as client:
        response = client.post(
            "/api/echo/approvals/request-1/decision",
            headers={"X-API-Key": admin_key, "Origin": "http://localhost"},
            json=payload,
        )

    assert response.status_code == 400
    agent.approvals.get_pending_request.assert_not_called()
    agent.approvals.decide.assert_not_called()


def test_decide_approval_allows_authenticated_owner_user_write(tmp_path: Path) -> None:
    app, _admin_key, _other_admin_key, user_key, agent = _app_and_keys(tmp_path)
    owner = AuthManager(tmp_path / "state").verify(user_key)["key_hash"]
    agent.approvals.get_pending_request.return_value = _request("request-1", owner)
    agent.approvals.decide.return_value = SimpleNamespace(
        action=ApprovalDecisionType.REJECT,
        request_id="request-1",
    )

    with TestClient(app, base_url="http://localhost") as client:
        response = client.post(
            "/api/echo/approvals/request-1/decision",
            headers={"X-API-Key": user_key, "Origin": "http://localhost"},
            json={"action": "reject"},
        )

    assert response.status_code == 200
    agent.approvals.get_pending_request.assert_called_once_with(
        "request-1", owner_key_hash=owner
    )
    agent.approvals.decide.assert_called_once()
