"""B0: deferred Mobile stays outside the product surface; Friends is opt-in."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import ValidationError


def _appshell_router_client() -> TestClient:
    from js.appshell.routers import router
    from js.web.auth import require_auth_dep

    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[require_auth_dep] = lambda: {"role": "admin"}
    return TestClient(app)


def test_default_settings_disable_deferred_mobile_friends_and_remote_collaboration(
    tmp_path: Path,
) -> None:
    """A missing gate must not accidentally make a deferred feature available."""
    from js.config import JSSettings

    settings = JSSettings(workspace=tmp_path / "workspace", state_dir=tmp_path / "state")

    assert settings.mobile_enabled is False
    assert settings.friends_enabled is False
    assert settings.remote_collaboration_enabled is False


class _TruthyButNotBool:
    def __bool__(self) -> bool:
        return True


@pytest.mark.parametrize(
    "field_name",
    ("mobile_enabled", "friends_enabled", "remote_collaboration_enabled"),
)
@pytest.mark.parametrize("invalid_value", ("yes", "true", 1, _TruthyButNotBool()))
def test_deferred_feature_gates_reject_coercible_non_boolean_values(
    tmp_path: Path,
    field_name: str,
    invalid_value: object,
) -> None:
    """Removing exact-bool validation must not silently enable a deferred surface."""
    from js.config import JSSettings

    with pytest.raises(ValidationError):
        JSSettings.model_validate(
            {
                "workspace": tmp_path / field_name / "workspace",
                "state_dir": tmp_path / field_name / "state",
                field_name: invalid_value,
            }
        )


def test_deferred_devices_and_friends_return_explicit_feature_not_enabled_404() -> None:
    """Replacing the lock response with success or a generic 404 is a regression."""
    client = _appshell_router_client()
    try:
        for path, feature in (
            ("/api/appshell/devices", "devices"),
            ("/api/appshell/friends", "friends"),
        ):
            response = client.get(path)
            assert response.status_code == 404
            assert response.json() == {
                "detail": {"code": "feature_not_enabled", "feature": feature}
            }
    finally:
        client.close()


def test_product_capability_manifest_and_navigation_omit_deferred_r5_r7_surfaces(
    tmp_path: Path,
) -> None:
    """Empty-shell surfaces stay off nav. Friends is opt-in v1, default hidden."""
    from js.config import JSSettings
    from js.web.capability_manifest import NAV_TAB_IDS, build_capability_manifest

    settings = JSSettings(workspace=tmp_path / "workspace", state_dir=tmp_path / "state")
    manifest = build_capability_manifest(settings)
    deferred_surface_ids = {"devices", "mobile", "remote_collaboration"}

    assert settings.friends_enabled is False
    assert deferred_surface_ids.isdisjoint(NAV_TAB_IDS)
    assert deferred_surface_ids.isdisjoint(manifest["tabs"])
    assert deferred_surface_ids.isdisjoint(manifest["enabled_tabs"])
    assert deferred_surface_ids.isdisjoint(manifest["api"])
    assert deferred_surface_ids.isdisjoint(manifest["features"])
    assert "friends" in NAV_TAB_IDS
    assert manifest["tabs"]["friends"]["enabled"] is False
    assert "friends" not in manifest["enabled_tabs"]
    assert manifest["features"]["friends_enabled"] is False
    assert manifest["api"]["friends_actions"] is False
