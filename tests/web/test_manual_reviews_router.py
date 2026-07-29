from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from js.config import JSSettings, SecurityConfig
from js.echo.ledger.journal import FileEchoLedger
from js.echo.ledger.service import EchoSafetyService
from js.web.auth import AuthManager
from js.web.runtime_context import WebRuntime, bind_web_runtime, clear_web_runtime
from js.web.server import create_app


def _app_and_keys(tmp_path: Path) -> tuple[Any, str, str, EchoSafetyService]:
    settings = JSSettings(
        workspace=tmp_path / "workspace",
        state_dir=tmp_path / "state",
        providers=[],
        security=SecurityConfig(api_key_required=True),
    )
    service = EchoSafetyService.from_settings(settings)

    @asynccontextmanager
    async def lifespan(app: Any) -> AsyncIterator[None]:
        runtime = WebRuntime(
            agent=object(),
            settings=settings,
            echo_safety_service=service,
        )
        bind_web_runtime(app, runtime)
        try:
            yield
        finally:
            clear_web_runtime(app, runtime)

    app = create_app(
        lifespan_context=lifespan,
        title="Manual Review Test App",
        runtime_settings=settings,
    )
    auth = AuthManager(settings.state_dir)
    admin_key = auth.create_key("admin", role="admin")
    user_key = auth.create_key("user", role="user")
    return app, admin_key, user_key, service


def _manual_review(service: EchoSafetyService, tenant_id: str) -> str:
    context = service.begin_chat_turn(
        tenant_id=tenant_id,
        run_id=f"run-{tenant_id}",
        user_text="review this side effect",
        model_id="mock",
    )
    service.assert_model_execution_permitted(context)
    service.close()
    return context.effect_id


def test_manual_review_routes_enforce_admin_tenant_and_resolution_contracts(tmp_path: Path) -> None:
    app, admin_key, user_key, service = _app_and_keys(tmp_path)
    owner_tenant = AuthManager(service.state_dir).verify(admin_key)["key_hash"]
    owner_effect = _manual_review(service, owner_tenant)
    other_effect = _manual_review(service, "other-tenant")

    with TestClient(app, base_url="http://localhost") as client:
        forbidden = client.get("/api/echo/manual-reviews", headers={"X-API-Key": user_key})
        assert forbidden.status_code == 403

        owner_rows = client.get(
            "/api/echo/manual-reviews",
            headers={"X-API-Key": admin_key},
        )
        assert owner_rows.status_code == 200
        assert [row["effect_id"] for row in owner_rows.json()["manual_reviews"]] == [owner_effect]

        selected_rows = client.get(
            "/api/echo/manual-reviews?tenant_id=other-tenant",
            headers={"X-API-Key": admin_key},
        )
        assert selected_rows.status_code == 200
        assert [row["effect_id"] for row in selected_rows.json()["manual_reviews"]] == [other_effect]

        cross_origin = client.post(
            f"/api/echo/manual-reviews/{owner_effect}/resolve",
            headers={"X-API-Key": admin_key, "Origin": "https://attacker.invalid"},
            json={"action": "cancel", "reason": "operator verified no dispatch"},
        )
        assert cross_origin.status_code == 403

        empty_reason = client.post(
            f"/api/echo/manual-reviews/{owner_effect}/resolve",
            headers={"X-API-Key": admin_key, "Origin": "http://localhost"},
            json={"action": "cancel", "reason": "   "},
        )
        assert empty_reason.status_code == 400

        oversized_reason = client.post(
            f"/api/echo/manual-reviews/{owner_effect}/resolve",
            headers={"X-API-Key": admin_key, "Origin": "http://localhost"},
            json={"action": "cancel", "reason": "x" * 1_001},
        )
        assert oversized_reason.status_code == 400

        oversized_tenant = client.post(
            f"/api/echo/manual-reviews/{owner_effect}/resolve?tenant_id={'x' * 257}",
            headers={"X-API-Key": admin_key, "Origin": "http://localhost"},
            json={"action": "cancel", "reason": "operator verified no dispatch"},
        )
        assert oversized_tenant.status_code == 400

        invalid_action = client.post(
            f"/api/echo/manual-reviews/{owner_effect}/resolve",
            headers={"X-API-Key": admin_key, "Origin": "http://localhost"},
            json={"action": "delete", "reason": "operator verified no dispatch"},
        )
        assert invalid_action.status_code == 400

        cross_tenant = client.post(
            f"/api/echo/manual-reviews/{other_effect}/resolve",
            headers={"X-API-Key": admin_key, "Origin": "http://localhost"},
            json={"action": "cancel", "reason": "operator verified no dispatch"},
        )
        assert cross_tenant.status_code == 404

        selected_other_tenant = client.post(
            f"/api/echo/manual-reviews/{other_effect}/resolve?tenant_id=other-tenant",
            headers={"X-API-Key": admin_key, "Origin": "http://localhost"},
            json={
                "action": "resolved",
                "reason": "global admin verified the external outcome",
                "operator": "caller-controlled-value",
            },
        )
        assert selected_other_tenant.status_code == 200

        resolved = client.post(
            f"/api/echo/manual-reviews/{owner_effect}/resolve",
            headers={"X-API-Key": admin_key, "Origin": "http://localhost"},
            json={
                "action": "override",
                "reason": "operator verified the external outcome",
                "operator": "caller-controlled-value",
            },
        )
        assert resolved.status_code == 200
        assert resolved.json()["record_types"] == ["manual_review_resolution", "merge"]

        conflict = client.post(
            f"/api/echo/manual-reviews/{owner_effect}/resolve",
            headers={"X-API-Key": admin_key, "Origin": "http://localhost"},
            json={"action": "resolved", "reason": "duplicate attempt"},
        )
        assert conflict.status_code == 409

    records = FileEchoLedger(
        service.journal_path_for(owner_tenant),
        mac_key=service.journal_key_for(owner_tenant),
    ).records
    resolution = next(record for record in records if record.record_type == "manual_review_resolution")
    other_records = FileEchoLedger(
        service.journal_path_for("other-tenant"),
        mac_key=service.journal_key_for("other-tenant"),
    ).records
    other_resolution = next(
        record for record in other_records if record.record_type == "manual_review_resolution"
    )
    expected_operator = f"admin:{owner_tenant}"
    assert resolution.payload["operator"] == expected_operator
    assert other_resolution.payload["operator"] == expected_operator
    assert service.health().ok is True


def test_manual_review_routes_fail_closed_on_ledger_validation_errors(
    monkeypatch: Any,
    tmp_path: Path,
) -> None:
    app, admin_key, _user_key, service = _app_and_keys(tmp_path)

    def invalid_ledger(**_kwargs: Any) -> Any:
        raise ValueError("invalid required journal archive")

    monkeypatch.setattr(service, "list_manual_reviews", invalid_ledger)
    monkeypatch.setattr(service, "resolve_manual_review", invalid_ledger)

    with TestClient(
        app,
        base_url="http://localhost",
        raise_server_exceptions=False,
    ) as client:
        listed = client.get(
            "/api/echo/manual-reviews",
            headers={"X-API-Key": admin_key},
        )
        resolved = client.post(
            "/api/echo/manual-reviews/effect-id/resolve",
            headers={"X-API-Key": admin_key, "Origin": "http://localhost"},
            json={"action": "cancel", "reason": "operator verified no dispatch"},
        )

    assert listed.status_code == 503
    assert resolved.status_code == 503


def test_work_app_includes_manual_review_routes(tmp_path: Path) -> None:
    from js_work.web import create_work_web_app

    config = tmp_path / "config.yaml"
    config.write_text("security:\n  api_key_required: false\nproviders: []\n", encoding="utf-8")
    app = create_work_web_app(config=str(config), home=tmp_path)

    with TestClient(app, base_url="http://localhost") as client:
        # Anonymous guests are read-only; admin routes need an explicit key.
        from js.web.auth import AuthManager

        state_dir = app.state.web_runtime.settings.state_dir
        admin_key = AuthManager(state_dir).create_key("admin", role="admin")
        headers = {"X-API-Key": admin_key}
        response = client.get("/api/echo/manual-reviews", headers=headers)
        cross_tenant = client.get(
            "/api/echo/manual-reviews",
            params={"tenant_id": "other-owner"},
            headers=headers,
        )

    assert response.status_code == 200
    assert response.json() == {"manual_reviews": []}
    assert cross_tenant.status_code == 403
