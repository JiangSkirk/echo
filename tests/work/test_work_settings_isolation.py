from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

import pytest
import yaml

from js.config import JSSettings
from js.product_storage import (
    StorageOverlapError,
    StorageRoots,
    assert_disjoint,
    canonical_for_compare,
)
from js_work.agent_factory import create_work_agent
from js_work.config import WorkSettings, load_work_settings

ROOT_KINDS = ("config_path", "workspace", "state_dir")
RELATIONS = ("equal", "personal_ancestor", "work_ancestor")


def _directory_mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def _roots(base: Path, prefix: str) -> StorageRoots:
    return StorageRoots(
        config_path=base / f"{prefix}-config.yaml",
        workspace=base / f"{prefix}-workspace",
        state_dir=base / f"{prefix}-state",
    )


def test_work_storage_roots_are_private_under_umask_022(tmp_path: Path) -> None:
    previous_umask = os.umask(0o022)
    try:
        settings = load_work_settings(home=tmp_path)
    finally:
        os.umask(previous_umask)

    assert [
        _directory_mode(path)
        for path in (settings.work_home, settings.workspace, settings.state_dir)
    ] == [0o700, 0o700, 0o700]


def test_work_storage_tightens_existing_directories(tmp_path: Path) -> None:
    root = tmp_path / ".js-work"
    workspace = root / "workspace"
    state_dir = root / "state"
    workspace.mkdir(parents=True)
    state_dir.mkdir()
    for path in (root, workspace, state_dir):
        path.chmod(0o755)

    load_work_settings(home=tmp_path)

    assert [_directory_mode(path) for path in (root, workspace, state_dir)] == [
        0o700,
        0o700,
        0o700,
    ]


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS system alias contract")
def test_work_storage_accepts_root_owned_macos_tmp_alias(tmp_path: Path) -> None:
    aliases = ((Path("/tmp"), Path("/private/tmp")), (Path("/var"), Path("/private/var")))
    try:
        alias, private_root = next(
            (alias, private_root)
            for alias, private_root in aliases
            if tmp_path.is_relative_to(private_root)
        )
    except StopIteration:
        pytest.skip("pytest temp root is outside macOS private aliases")
    relative = tmp_path.relative_to(private_root)
    root = alias / relative / ".js-work"

    settings = WorkSettings(
        work_home=root,
        workspace=root / "workspace",
        state_dir=root / "state",
    )

    canonical_root = private_root / relative / ".js-work"
    assert [
        _directory_mode(path)
        for path in (canonical_root, settings.workspace, settings.state_dir)
    ] == [0o700, 0o700, 0o700]


@pytest.mark.parametrize("managed_name", ("root", "workspace", "state"))
@pytest.mark.parametrize("node_kind", ("symlink", "file"))
def test_work_storage_rejects_unsafe_nodes_without_following_them(
    tmp_path: Path,
    managed_name: str,
    node_kind: str,
) -> None:
    root = tmp_path / ".js-work"
    workspace = root / "workspace"
    state_dir = root / "state"
    managed = {"root": root, "workspace": workspace, "state": state_dir}[managed_name]
    if managed != root:
        root.mkdir(mode=0o700)

    external = (root if root.exists() else tmp_path) / f"external-{managed_name}-{node_kind}"
    if node_kind == "symlink":
        external.mkdir(mode=0o755)
        managed.symlink_to(external, target_is_directory=True)
    else:
        managed.write_text("not a directory", encoding="utf-8")

    with pytest.raises(ValueError):
        load_work_settings(home=tmp_path)

    assert managed.is_symlink() if node_kind == "symlink" else managed.is_file()
    if node_kind == "symlink":
        assert _directory_mode(external) == 0o755


@pytest.mark.parametrize("personal_kind", ROOT_KINDS)
@pytest.mark.parametrize("work_kind", ROOT_KINDS)
@pytest.mark.parametrize("relation", RELATIONS)
def test_storage_roots_reject_complete_bidirectional_overlap_matrix(
    tmp_path: Path,
    personal_kind: str,
    work_kind: str,
    relation: str,
) -> None:
    personal = _roots(tmp_path, "personal")
    work = _roots(tmp_path, "work")
    shared = tmp_path / "shared"
    if relation == "equal":
        personal_value = work_value = shared
    elif relation == "personal_ancestor":
        personal_value, work_value = shared, shared / "child"
    else:
        personal_value, work_value = shared / "child", shared
    personal = StorageRoots(**{**personal.__dict__, personal_kind: personal_value})
    work = StorageRoots(**{**work.__dict__, work_kind: work_value})

    with pytest.raises(
        StorageOverlapError,
        match=rf"Personal\.{personal_kind}.*Work\.{work_kind}",
    ):
        assert_disjoint(personal=personal, work=work)


def test_work_load_rejects_config_overlap_before_parsing_invalid_yaml(tmp_path: Path) -> None:
    config = tmp_path / "shared" / "config.yaml"
    config.parent.mkdir()
    config.write_text("[invalid yaml", encoding="utf-8")
    personal = StorageRoots(
        config_path=config,
        workspace=tmp_path / "personal-workspace",
        state_dir=tmp_path / "personal-state",
    )

    with pytest.raises(StorageOverlapError, match=r"Personal\.config_path.*Work\.config_path"):
        load_work_settings(config, home=tmp_path / "work-home", personal_roots=personal)


def test_work_save_rechecks_all_roots_before_write(monkeypatch, tmp_path: Path) -> None:
    personal = _roots(tmp_path, "personal")
    settings = load_work_settings(
        home=tmp_path / "work-home",
        personal_roots=personal,
    )
    settings.workspace = personal.state_dir / "nested"
    calls = 0

    def fail_write(*args, **kwargs) -> None:
        nonlocal calls
        calls += 1

    monkeypatch.setattr("js.utils.atomic_config.save_yaml_config", fail_write)
    with pytest.raises(StorageOverlapError, match=r"Personal\.state_dir.*Work\.workspace"):
        settings.save(tmp_path / "work.yaml")
    assert calls == 0


@pytest.mark.parametrize(
    "relative",
    (Path(".config/js-work/config.yaml"), Path(".js-work/state/config.yaml")),
)
def test_personal_loader_and_save_reject_reserved_work_namespace_before_io(
    monkeypatch, tmp_path: Path, relative: Path
) -> None:
    reserved = tmp_path / relative
    reserved.parent.mkdir(parents=True)
    reserved.write_text("[invalid yaml", encoding="utf-8")
    with pytest.raises(ValueError, match="reserved Work"):
        JSSettings.from_file(reserved, allow_hermes_merge=False)

    settings = JSSettings(
        workspace=tmp_path / "personal-workspace",
        state_dir=tmp_path / "personal-state",
        providers=[],
    )
    calls = 0

    def fail_write(*args, **kwargs) -> None:
        nonlocal calls
        calls += 1

    monkeypatch.setattr("js.utils.atomic_config.save_yaml_config", fail_write)
    with pytest.raises(ValueError, match="reserved Work"):
        settings.save(reserved)
    assert calls == 0


def test_canonical_compare_resolves_symlink_parent_and_nonexistent_tail(tmp_path: Path) -> None:
    personal_root = tmp_path / "personal"
    personal_root.mkdir()
    link = tmp_path / "work-link"
    link.symlink_to(personal_root, target_is_directory=True)
    personal = StorageRoots(
        config_path=tmp_path / "p.yaml",
        workspace=personal_root,
        state_dir=tmp_path / "p-state",
    )
    work = StorageRoots(
        config_path=tmp_path / "w.yaml",
        workspace=link / "new" / "workspace",
        state_dir=tmp_path / "w-state",
    )
    with pytest.raises(StorageOverlapError):
        assert_disjoint(personal=personal, work=work)
    assert canonical_for_compare(tmp_path / ".JS-WORK", case_insensitive=True) == (
        canonical_for_compare(tmp_path / ".js-work", case_insensitive=True)
    )


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
