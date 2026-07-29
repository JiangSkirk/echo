"""M3: Hermes skills must be opt-in; isolated/Work starts fail-closed."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml


def _plant_hermes_skill(home: Path, *, skill_id: str = "planted-privacy-skill") -> Path:
    skill_dir = home / ".hermes" / "skills" / skill_id
    skill_dir.mkdir(parents=True)
    manifest = skill_dir / "SKILL.md"
    manifest.write_text(
        "---\n"
        f"name: {skill_id}\n"
        "description: planted hermes skill for isolation tests\n"
        "---\n"
        "# Planted\n",
        encoding="utf-8",
    )
    return skill_dir


@pytest.mark.asyncio
async def test_personal_web_default_does_not_load_planted_hermes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from httpx import ASGITransport, AsyncClient

    from js.config import JSSettings
    from js.web import server as web_server

    home = tmp_path / "home"
    home.mkdir()
    _plant_hermes_skill(home)
    state = tmp_path / "state"
    ws = tmp_path / "ws"
    state.mkdir()
    ws.mkdir()
    cfg = tmp_path / "good.yaml"
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
                "features": {"hermes_skills_enabled": False},
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("HERMES_HOME", raising=False)
    monkeypatch.delenv("JS_CONFIG_PATH", raising=False)
    monkeypatch.delenv("JS_STATE_DIR", raising=False)
    monkeypatch.delenv("JS_WARM_START", raising=False)

    settings = JSSettings.from_file(cfg, allow_hermes_merge=False)
    assert settings.features.hermes_skills_enabled is False
    app = web_server.create_app(runtime_settings=settings)
    transport = ASGITransport(app=app)
    async with (
        web_server.lifespan(app),
        AsyncClient(transport=transport, base_url="http://test") as client,
    ):
        skills = app.state.web_runtime.agent.skills
        assert skills is not None
        hermes_ids = [sid for sid in skills.get_all() if sid.startswith("hermes:")]
        assert hermes_ids == []
        status = await client.get("/api/status")
        assert status.status_code == 200
        bridge = status.json().get("hermes_bridge", {})
        assert bridge.get("opt_in") is False
        assert bridge.get("skills_loaded") == 0


def test_skill_manager_opt_in_loads_only_isolated_hermes_tree(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from js.skills.manager import SkillManager

    home = tmp_path / "home"
    home.mkdir()
    _plant_hermes_skill(home, skill_id="isolated-only")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("HERMES_HOME", raising=False)

    state = tmp_path / "state"
    ws = tmp_path / "ws"
    state.mkdir()
    ws.mkdir()
    mgr = SkillManager(state, ws, hermes_skills_enabled=True)
    mgr.load_hermes_sync()
    hermes_ids = [sid for sid in mgr.get_all() if sid.startswith("hermes:")]
    assert any("isolated-only" in sid for sid in hermes_ids)


def test_work_feature_config_disables_hermes_skills() -> None:
    from js_work.config import work_feature_config

    features = work_feature_config()
    assert features.skills_enabled is False
    assert features.hermes_skills_enabled is False


def test_hermes_skills_dir_resolves_at_call_time(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from js.skills import hermes_bridge

    home = tmp_path / "isolated-home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("HERMES_HOME", raising=False)
    assert hermes_bridge.hermes_skills_dir() == (home / ".hermes" / "skills").resolve()
