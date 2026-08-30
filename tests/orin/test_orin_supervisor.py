"""Product orind supervisor: JS Agent starts Stage A leases, not Stage C."""

from __future__ import annotations

import asyncio
from pathlib import Path

from js.config import JSSettings, OrinConfig, OrinPolicyProfile
from js.orin.supervisor import (
    _argv,
    _socket_live,
    ensure_orind,
    orind_owned_starting,
    prepare_product_orin,
    release_orind,
    wait_orind_socket,
)


def _settings(tmp_path: Path) -> JSSettings:
    return JSSettings(
        workspace=tmp_path / "ws",
        state_dir=tmp_path / "st",
        providers=[],
    )


def test_default_settings_keep_orin_disabled(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    assert settings.orin.enabled is False
    assert settings.orin.enforce is False


def test_prepare_product_orin_enables_stage_a_without_enforce(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    prepare_product_orin(settings)
    assert settings.orin.enabled is True
    assert settings.orin.enforce is False
    assert settings.orin.stage_b is False
    assert settings.orin.policy_profile.value == "conservative"
    assert settings.orin.cell_desktop is False
    assert settings.orin.cell_memory is False


def test_prepare_keeps_conservative_when_orin_already_enabled(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    settings.orin.enabled = True
    prepare_product_orin(settings)
    assert settings.orin.enabled is True
    assert settings.orin.policy_profile.value == "conservative"


def test_js_orind_opt_out_disables_product_orind(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("JS_ORIND", "0")
    settings = _settings(tmp_path)
    settings.orin.enabled = True
    prepare_product_orin(settings)
    assert settings.orin.enabled is False


def test_supervisor_argv_includes_desktop_memory_when_stage_b_identity(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    settings.orin.stage_b = True
    settings.orin.cell_identity_enforce = True
    settings.orin.cell_desktop = True
    settings.orin.cell_memory = True
    argv = _argv(settings, tmp_path / "orind.sock")
    assert "--stage-b" in argv
    assert "--cell-identity-enforce" in argv
    assert "--cell-desktop" in argv
    assert "--cell-memory" in argv
    assert "--orin-enforce" not in argv


def test_prepare_keeps_explicit_compat_profile(tmp_path: Path) -> None:
    settings = JSSettings(
        workspace=tmp_path / "ws",
        state_dir=tmp_path / "st",
        providers=[],
        orin=OrinConfig(policy_profile=OrinPolicyProfile.COMPAT),
    )
    prepare_product_orin(settings)
    assert settings.orin.enabled is True
    assert settings.orin.enforce is False
    assert settings.orin.policy_profile.value == "compat"


def test_supervisor_argv_is_stage_a_only(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    prepare_product_orin(settings)
    settings.orin.cell_desktop = True
    settings.orin.cell_memory = True
    argv = _argv(settings, tmp_path / "orind.sock")
    assert "--dev" in argv
    assert "--policy-profile" in argv
    assert "conservative" in argv
    assert "compat" not in argv
    assert "--stage-b" not in argv
    assert "--cell-desktop" not in argv
    assert "--cell-memory" not in argv


def test_ensure_orind_can_spawn_without_waiting_then_wait(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    path = ensure_orind(settings, wait=False)
    try:
        assert orind_owned_starting(path)
        wait_orind_socket(path)
        assert _socket_live(path)
    finally:
        release_orind(settings)


def test_ensure_orind_starts_attaches_and_stops(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    path = ensure_orind(settings)
    try:
        assert _socket_live(path)
        assert settings.orin.socket_path == path
        attached = ensure_orind(settings)
        assert attached == path
    finally:
        release_orind(settings)
        release_orind(settings)
    assert not _socket_live(path)


def test_default_jsagent_does_not_start_orind(tmp_path: Path) -> None:
    from js.agent import JSAgent

    settings = _settings(tmp_path)
    agent = JSAgent(settings)
    try:
        assert settings.orin.enabled is False
        assert not (Path(settings.state_dir) / "orin" / "orind.sock").exists()
        assert settings.orin.socket_path is None
    finally:
        asyncio.run(agent.close())


def test_jsagent_product_prepare_uses_orind_adapter(tmp_path: Path) -> None:
    from js.agent import JSAgent
    from js.orin.client import OrinLeaseClientAdapter

    settings = _settings(tmp_path)
    prepare_product_orin(settings)
    agent = JSAgent(settings)
    try:
        authority = agent._get_echo_tool_lease_authority()
        assert isinstance(authority, OrinLeaseClientAdapter)
        assert authority.healthy()
        assert settings.orin.enforce is False
        assert _socket_live(Path(settings.orin.socket_path))
    finally:
        asyncio.run(agent.close())
    assert not _socket_live(Path(settings.orin.socket_path))


def test_heartbeat_interval_is_ten_seconds() -> None:
    from js.orin.protocol import HEARTBEAT_INTERVAL_S

    assert HEARTBEAT_INTERVAL_S == 10.0


def test_create_app_does_not_manage_orind_by_default() -> None:
    from js.web.server import create_app

    app = create_app()
    assert app.state.manage_orind is False


def test_create_appshell_app_does_not_manage_orind_by_default() -> None:
    import inspect

    from js.appshell.server import create_appshell_app

    assert inspect.signature(create_appshell_app).parameters["manage_orind"].default is False
