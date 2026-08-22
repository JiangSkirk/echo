from __future__ import annotations

import ast
import inspect
import runpy
import sys
from pathlib import Path

import pytest
from click.testing import CliRunner

from js.product_storage import StorageOverlapError, StorageRoots
from js.ui.cli import main as js_main
from js_work import cli as work_cli


def test_canonical_work_command_passes_explicit_personal_roots(monkeypatch, tmp_path: Path) -> None:
    personal_config = tmp_path / "personal.yaml"
    personal_workspace = tmp_path / "personal-workspace"
    personal_state = tmp_path / "personal-state"
    personal_config.write_text(
        f"workspace: {personal_workspace}\nstate_dir: {personal_state}\nproviders: []\n",
        encoding="utf-8",
    )
    captured: dict[str, object] = {}

    def fake_load(config=None, *, home=None, personal_roots=None):
        captured.update(config=config, home=home, personal_roots=personal_roots)
        raise RuntimeError("hook reached")

    monkeypatch.setattr(work_cli, "load_work_settings", fake_load)
    result = CliRunner().invoke(
        js_main,
        ["--config", str(personal_config), "work", "--config", str(tmp_path / "work.yaml"), "run", "hello"],
    )
    assert isinstance(result.exception, RuntimeError)
    assert captured["personal_roots"] == StorageRoots(
        config_path=personal_config.resolve(),
        workspace=personal_workspace.resolve(),
        state_dir=personal_state.resolve(),
    )


def test_non_work_help_does_not_load_work_settings(monkeypatch) -> None:
    monkeypatch.setattr(
        work_cli,
        "load_work_settings",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("Work loaded")),
    )
    result = CliRunner().invoke(js_main, ["--help"])
    assert result.exit_code == 0


def test_canonical_work_web_passes_personal_roots_and_rejects_overlap(
    monkeypatch, tmp_path: Path
) -> None:
    personal_config = tmp_path / "personal.yaml"
    personal_workspace = tmp_path / "personal-workspace"
    personal_state = tmp_path / "personal-state"
    personal_workspace.mkdir()
    personal_config.write_text(
        f"workspace: {personal_workspace}\nstate_dir: {personal_state}\nproviders: []\n",
        encoding="utf-8",
    )
    overlapping_work_config = personal_workspace / "work.yaml"
    overlapping_work_config.write_text("providers: []\n", encoding="utf-8")

    monkeypatch.setattr("uvicorn.run", lambda *args, **kwargs: None)
    result = CliRunner().invoke(
        js_main,
        [
            "--config",
            str(personal_config),
            "work",
            "--config",
            str(overlapping_work_config),
            "web",
        ],
    )
    assert isinstance(result.exception, StorageOverlapError)
    assert "Personal.workspace" in str(result.exception)
    assert "Work.config_path" in str(result.exception)


def test_compat_main_warns_once_and_dispatches_to_canonical(monkeypatch) -> None:
    calls: list[list[str]] = []

    def fake_main(*, args, prog_name, standalone_mode):
        calls.append(list(args))

    monkeypatch.setattr("js.ui.cli.main", fake_main)
    monkeypatch.setattr(sys, "argv", ["js-work", "--personal-config", "/p.yaml", "--config", "/w.yaml", "--help"])
    work_cli.compat_main()
    assert calls == [["--config", "/p.yaml", "work", "--config", "/w.yaml", "--help"]]


def test_module_entry_calls_compat_main(monkeypatch) -> None:
    calls = 0

    def fake_compat_main() -> None:
        nonlocal calls
        calls += 1

    monkeypatch.setattr(work_cli, "compat_main", fake_compat_main)
    runpy.run_module("js_work", run_name="__main__")
    assert calls == 1


def test_compat_and_module_dispatch_through_same_canonical_hook(monkeypatch) -> None:
    calls: list[list[str]] = []

    def fake_main(*, args, prog_name, standalone_mode) -> None:
        calls.append(list(args))

    monkeypatch.setattr("js.ui.cli.main", fake_main)
    argv = ["js-work", "--personal-config", "/p.yaml", "--config", "/w.yaml", "web"]
    monkeypatch.setattr(sys, "argv", argv)
    work_cli.compat_main()
    runpy.run_module("js_work", run_name="__main__")
    expected = ["--config", "/p.yaml", "work", "--config", "/w.yaml", "web"]
    assert calls == [expected, expected]


def test_compat_web_inherits_canonical_overlap_gate(monkeypatch, tmp_path: Path) -> None:
    personal_workspace = tmp_path / "personal-workspace"
    personal_workspace.mkdir()
    personal_config = tmp_path / "personal.yaml"
    personal_config.write_text(
        f"workspace: {personal_workspace}\nstate_dir: {tmp_path / 'personal-state'}\nproviders: []\n",
        encoding="utf-8",
    )
    work_config = personal_workspace / "work.yaml"
    work_config.write_text("providers: []\n", encoding="utf-8")
    monkeypatch.setattr("uvicorn.run", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "js-work",
            "--personal-config",
            str(personal_config),
            "--config",
            str(work_config),
            "web",
        ],
    )
    with pytest.raises(StorageOverlapError):
        work_cli.compat_main()


def test_compat_main_is_only_an_argv_dispatch_shim() -> None:
    source = inspect.getsource(work_cli.compat_main)
    function = ast.parse(source).body[0]
    assert isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef))
    called_names = set()
    for node in ast.walk(function):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name):
            called_names.add(node.func.id)
        elif isinstance(node.func, ast.Attribute):
            called_names.add(node.func.attr)
    assert "load_work_settings" not in called_names
    assert not any(
        isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node is not function
        for node in ast.walk(function)
    )


def test_project_script_targets_compat_dispatcher() -> None:
    import tomllib

    data = tomllib.loads((Path(__file__).parents[1] / "pyproject.toml").read_text(encoding="utf-8"))
    assert data["project"]["scripts"]["js-work"] == "js_work.cli:compat_main"


def test_compat_web_serves_parent_appshell_instead_of_work_only_host(
    monkeypatch, tmp_path: Path
) -> None:
    personal_config = tmp_path / "personal.yaml"
    personal_config.write_text(
        f"workspace: {tmp_path / 'personal-workspace'}\n"
        f"state_dir: {tmp_path / 'personal-state'}\n"
        "providers: []\n",
        encoding="utf-8",
    )
    work_config = tmp_path / "work.yaml"
    work_config.write_text("providers: []\n", encoding="utf-8")
    served: list[tuple[object, str, int]] = []
    monkeypatch.setattr(
        "uvicorn.run",
        lambda app, *, host, port, reload=False: served.append((app, host, port)),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "js-work",
            "--personal-config",
            str(personal_config),
            "--config",
            str(work_config),
            "web",
        ],
    )

    with pytest.raises(SystemExit) as exited:
        work_cli.compat_main()

    assert exited.value.code == 0
    assert len(served) == 1
    app, host, port = served[0]
    assert host == "127.0.0.1"
    assert port == 8000
    assert getattr(app.state, "personal_app", None) is not None
    assert getattr(app.state, "work_app", None) is not None
