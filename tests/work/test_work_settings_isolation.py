from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from js.config import JSSettings
from js_work.agent_factory import create_work_agent
from js_work.config import WorkSettings, load_work_settings


def test_work_settings_use_independent_product_and_environment_namespace(
    tmp_path: Path,
) -> None:
    settings = load_work_settings(home=tmp_path)

    assert isinstance(settings, WorkSettings)
    assert settings.product_id == "js-work"
    assert settings.model_config.get("env_prefix") == "JS_WORK_"
    assert settings.workspace.is_relative_to(tmp_path / ".js-work")
    assert settings.state_dir.is_relative_to(tmp_path / ".js-work")


def test_work_save_never_uses_main_agent_config_path(
    tmp_path: Path,
    monkeypatch,
) -> None:
    main_config = tmp_path / "main-agent.yaml"
    work_config = tmp_path / "work-agent.yaml"
    main_config.write_text("max_turns: 99\n", encoding="utf-8")
    monkeypatch.setenv("JS_CONFIG_PATH", str(main_config))

    settings = load_work_settings(config_path=work_config, home=tmp_path)
    settings.max_turns = 7
    settings.save()

    assert yaml.safe_load(main_config.read_text(encoding="utf-8")) == {"max_turns": 99}
    assert yaml.safe_load(work_config.read_text(encoding="utf-8"))["max_turns"] == 7


def test_work_home_cannot_overlap_main_agent_home(tmp_path: Path) -> None:
    main_home = tmp_path / ".js"
    assert not main_home.exists()
    try:
        WorkSettings(work_home=main_home, workspace=main_home, state_dir=main_home / "state")
    except ValueError as exc:
        assert "overlap" in str(exc).lower()
    else:
        raise AssertionError("WorkSettings accepted a main-agent home overlap")
    assert not main_home.exists(), "invalid Work paths must be rejected before disk writes"


def test_main_agent_env_does_not_affect_work_js_work_env_does(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """JS_CONFIG_PATH / JS_ECHO_ENGINE must not affect Work; JS_WORK_* must."""
    main_config = tmp_path / "main-agent.yaml"
    main_config.write_text("max_turns: 99\n", encoding="utf-8")
    monkeypatch.setenv("JS_CONFIG_PATH", str(main_config))
    monkeypatch.setenv("JS_ECHO_ENGINE", "off")  # invalid if ever read
    monkeypatch.setenv("JS_MAX_TURNS", "99")
    monkeypatch.setenv("JS_WORK_MAX_TURNS", "7")
    monkeypatch.delenv("JS_WORK_ECHO_ENGINE", raising=False)

    settings = load_work_settings(home=tmp_path)

    assert isinstance(settings, WorkSettings)
    assert settings.max_turns == 7
    assert settings.echo_engine == "on"

    # Parent JS_ECHO_ENGINE must be ignored; apply is a no-op without JS_WORK_.
    settings.apply_runtime_engine_env()
    assert settings.echo_engine == "on"

    monkeypatch.setenv("JS_WORK_ECHO_ENGINE", "on")
    runtime = settings.with_runtime_engine_env()
    assert runtime.echo_engine == "on"

    settings.max_turns = 7
    settings.save()
    assert yaml.safe_load(main_config.read_text(encoding="utf-8")) == {"max_turns": 99}
    work_cfg = tmp_path / ".config" / "js-work" / "config.yaml"
    assert work_cfg.exists()
    assert yaml.safe_load(work_cfg.read_text(encoding="utf-8"))["max_turns"] == 7


def test_main_security_env_cannot_weaken_work_security(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("JS_API_KEY_REQUIRED", "false")
    monkeypatch.setenv("JS_ALLOW_PRIVATE_MODEL_PROVIDERS", "true")
    monkeypatch.delenv("JS_WORK_SECURITY__API_KEY_REQUIRED", raising=False)
    monkeypatch.delenv(
        "JS_WORK_SECURITY__ALLOW_PRIVATE_MODEL_PROVIDERS",
        raising=False,
    )

    settings = load_work_settings(home=tmp_path)

    assert settings.security.api_key_required is True
    assert settings.security.allow_private_model_providers is False

    monkeypatch.setenv("JS_WORK_SECURITY__API_KEY_REQUIRED", "false")
    monkeypatch.setenv(
        "JS_WORK_SECURITY__ALLOW_PRIVATE_MODEL_PROVIDERS",
        "true",
    )
    explicitly_overridden = load_work_settings(home=tmp_path / "explicit")

    assert explicitly_overridden.security.api_key_required is False
    assert explicitly_overridden.security.allow_private_model_providers is True


def test_create_work_agent_rejects_main_settings(tmp_path: Path) -> None:
    settings = JSSettings(
        workspace=tmp_path / "main-workspace",
        state_dir=tmp_path / "main-state",
    )

    with pytest.raises(TypeError, match="WorkSettings"):
        create_work_agent(settings=settings)  # type: ignore[arg-type]


def test_create_work_agent_deep_copies_without_mutating_input(tmp_path: Path) -> None:
    settings = load_work_settings(home=tmp_path)
    settings.pipeline.enabled = True
    before = settings.model_dump()

    agent = create_work_agent(settings=settings)

    assert settings.model_dump() == before
    assert agent.settings is not settings
    assert agent.settings.pipeline is not settings.pipeline
    assert agent.settings.pipeline.enabled is False


def test_create_work_agent_revalidates_mutated_work_paths(tmp_path: Path) -> None:
    settings = load_work_settings(home=tmp_path)
    main_workspace = tmp_path / ".js" / "workspace"
    object.__setattr__(settings, "workspace", main_workspace)

    with pytest.raises(ValueError, match="overlap"):
        create_work_agent(settings=settings)

    assert not main_workspace.exists()
