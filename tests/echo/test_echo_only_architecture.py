from __future__ import annotations

import pytest
from pydantic import ValidationError

from js.config import JSSettings
from js.echo.ledger.service import EchoSafetyService
from js.web.echo_status import echo_ledger_status, echo_status


@pytest.mark.parametrize(
    "value",
    (
        "off",
        "shadow",
    ),
)
def test_removed_engine_modes_are_rejected(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
    value: str,
) -> None:
    monkeypatch.setenv("JS_ECHO_ENGINE", value)

    with pytest.raises(ValidationError, match="Echo is the only supported architecture"):
        JSSettings(workspace=tmp_path / "workspace", state_dir=tmp_path / "state")


def test_runtime_env_cannot_reenable_removed_architecture(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    settings = JSSettings(workspace=tmp_path / "workspace", state_dir=tmp_path / "state")
    monkeypatch.setenv("JS_ECHO_ENGINE", "off")

    with pytest.raises(ValueError, match="Echo is the only supported architecture"):
        settings.with_runtime_engine_env()


def test_legacy_rivetline_engine_env_is_inert(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    """Old JS_RIVETLINE_ENGINE no longer acts as a runtime switch."""
    monkeypatch.setenv("JS_RIVETLINE_ENGINE", "off")
    settings = JSSettings(workspace=tmp_path / "workspace", state_dir=tmp_path / "state")

    assert settings.echo_engine == "on"
    assert "rivetline_engine" not in type(settings).model_fields
    assert not hasattr(settings, "rivetline_engine")


def test_status_exposes_echo_only_without_legacy_or_rollback_fields(tmp_path) -> None:
    settings = JSSettings(workspace=tmp_path / "workspace", state_dir=tmp_path / "state")
    health = EchoSafetyService.from_settings(settings).health()

    status = echo_status(settings, health=health)
    ledger = echo_ledger_status(health)

    assert status["mode"] == "on"
    assert status["architecture_state"] == "primary_healthy"
    assert status["default_architecture"] is True
    assert "deprecated_rollback" not in status
    assert "legacy_status_alias" not in ledger
    assert "deprecated_alias" not in ledger
