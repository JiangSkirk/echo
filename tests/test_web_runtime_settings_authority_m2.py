"""M2: explicit runtime_settings must own Personal web lifespan (not HOME default)."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml


@pytest.mark.asyncio
async def test_lifespan_uses_runtime_settings_not_poisoned_home(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from httpx import ASGITransport, AsyncClient

    from js.config import JSSettings
    from js.web import server as web_server

    home = tmp_path / "home"
    poison_state = home / ".js-poison-state"
    poison_ws = home / ".js-poison-ws"
    poison_cfg_dir = home / ".config" / "js"
    poison_cfg_dir.mkdir(parents=True)
    poison_state.mkdir(parents=True)
    poison_ws.mkdir(parents=True)
    (poison_cfg_dir / "config.yaml").write_text(
        yaml.safe_dump(
            {
                "workspace": str(poison_ws),
                "state_dir": str(poison_state),
                "echo_engine": "on",
                "first_run_completed": True,
                "providers": [],
                "models": [],
                "security": {"api_key_required": False},
            }
        ),
        encoding="utf-8",
    )

    good_state = tmp_path / "good-state"
    good_ws = tmp_path / "good-ws"
    good_cfg = tmp_path / "good.yaml"
    good_state.mkdir(parents=True)
    good_ws.mkdir(parents=True)
    good_cfg.write_text(
        yaml.safe_dump(
            {
                "workspace": str(good_ws),
                "state_dir": str(good_state),
                "echo_engine": "on",
                "first_run_completed": True,
                "providers": [],
                "models": [],
                "security": {"api_key_required": False},
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("JS_CONFIG_PATH", raising=False)
    monkeypatch.delenv("JS_STATE_DIR", raising=False)
    monkeypatch.delenv("JS_WARM_START", raising=False)
    monkeypatch.setenv("JS_ECHO_ENGINE", "on")

    runtime_settings = JSSettings.from_file(good_cfg, allow_hermes_merge=False)
    assert runtime_settings.state_dir.resolve() == good_state.resolve()

    app = web_server.create_app(runtime_settings=runtime_settings)
    transport = ASGITransport(app=app)
    async with (
        web_server.lifespan(app),
        AsyncClient(transport=transport, base_url="http://test") as client,
    ):
        runtime = app.state.web_runtime
        assert runtime is not None
        assert Path(runtime.settings.state_dir).resolve() == good_state.resolve()
        assert Path(runtime.agent.settings.state_dir).resolve() == good_state.resolve()
        assert Path(runtime.settings.state_dir).resolve() != poison_state.resolve()
        response = await client.get("/api/status")
        assert response.status_code == 200


def test_get_settings_refuses_silent_home_fallback_when_uninitialized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from js.web import deps as web_deps

    monkeypatch.setattr(web_deps, "_settings", None)
    monkeypatch.setattr(web_deps, "_agent", None)
    with pytest.raises(RuntimeError, match="refusing silent HOME"):
        web_deps.get_settings()


def test_get_settings_prefers_module_globals_over_home(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from js.config import JSSettings
    from js.web import deps as web_deps

    good = JSSettings(
        workspace=tmp_path / "gws",
        state_dir=tmp_path / "good-state",
        providers=[],
        security={"api_key_required": False},
    )
    monkeypatch.setattr(web_deps, "_settings", good)
    assert web_deps.get_settings().state_dir == good.state_dir
