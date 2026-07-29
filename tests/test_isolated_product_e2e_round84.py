from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from js.config import JSSettings
from js.echo.ledger.release_gates import (
    _ISOLATED_VENV_E2E_REQUIRED_STEPS,
    _ISOLATED_VENV_E2E_SERVER_STEP,
    _valid_isolated_venv_e2e,
)
from scripts.isolated_venv_e2e import (
    ISO_E2E_HOME_ENV,
    ISO_E2E_PROVIDER_FAIL_ENV,
    ISO_E2E_SANDBOX_ENV,
    _write_server_e2e_script,
)
from tests.test_isolated_product_e2e_round85 import _valid_payload


@pytest.fixture
def iso_root(tmp_path: Path) -> Path:
    (tmp_path / "js").mkdir()
    (tmp_path / "js" / "marker.py").write_text("ISO = 1\n", encoding="utf-8")
    (tmp_path / "js_work").mkdir()
    (tmp_path / "js_work" / "marker.py").write_text("ISO = 1\n", encoding="utf-8")
    return tmp_path


def test_valid_isolated_e2e_round84_fixture_accepts_v5_schema(iso_root: Path) -> None:
    path, _payload = _valid_payload(iso_root)
    assert _valid_isolated_venv_e2e(iso_root, path)


@pytest.mark.parametrize("required_step", _ISOLATED_VENV_E2E_REQUIRED_STEPS)
def test_delete_each_required_step_rejects(iso_root: Path, required_step: str) -> None:
    path, payload = _valid_payload(iso_root)
    payload["results"] = [step for step in payload["results"] if step["step"] != required_step]
    out = iso_root / f"missing_{required_step.replace(': ', '_').replace('/', '_')}.json"
    out.write_text(json.dumps(payload), encoding="utf-8")
    assert _valid_isolated_venv_e2e(iso_root, out) is False


@pytest.mark.parametrize(
    ("mutation", "label"),
    [
        (lambda payload: payload.update({"schema_version": "isolated-venv-e2e-v3"}), "old_schema"),
        (
            lambda payload: payload["results"][0].update({"ok": False}),
            "step_not_ok",
        ),
        (
            lambda payload: payload["results"][0].update({"exit_code": 1}),
            "nonzero_exit",
        ),
        (
            lambda payload: payload["results"][0].pop("argv"),
            "missing_argv",
        ),
        (
            lambda payload: payload["results"][0].update({"source_digest": "0" * 64}),
            "step_digest_drift",
        ),
        (
            lambda payload: payload["pip_check"]["wheel"].update({"ok": False}),
            "pip_summary_mismatch",
        ),
        (
            lambda payload: next(
                step
                for step in payload["results"]
                if step["step"].startswith("wheel:")
                and _ISOLATED_VENV_E2E_SERVER_STEP in step["step"]
            )["detail"].update({"provider_calls": 0}),
            "provider_calls_zero",
        ),
        (
            lambda payload: next(
                step
                for step in payload["results"]
                if step["step"].startswith("wheel:")
                and _ISOLATED_VENV_E2E_SERVER_STEP in step["step"]
            )["detail"].update({"attachment_marker_in_messages": False}),
            "attachment_marker_missing",
        ),
        (
            lambda payload: next(
                step
                for step in payload["results"]
                if step["step"].startswith("wheel:")
                and _ISOLATED_VENV_E2E_SERVER_STEP in step["step"]
            )["detail"].update({"unexpected_provider_calls": ["xai-oauth"]}),
            "unexpected_provider",
        ),
        (
            lambda payload: next(
                step
                for step in payload["results"]
                if step["step"].startswith("wheel:")
                and _ISOLATED_VENV_E2E_SERVER_STEP in step["step"]
            )["detail"]["work_receipt"].update({"lease_consumed": False}),
            "lease_not_consumed",
        ),
        (
            lambda payload: next(
                step
                for step in payload["results"]
                if step["step"].startswith("wheel:")
                and _ISOLATED_VENV_E2E_SERVER_STEP in step["step"]
            )["detail"]["work_receipt"].update({"output_cells": [["bad"]]}),
            "wrong_output_cells",
        ),
    ],
)
def test_isolated_e2e_round84_negative_controls(
    iso_root: Path,
    mutation: object,
    label: str,
) -> None:
    payload = _valid_payload(iso_root)[1]
    mutation(payload)  # type: ignore[operator]
    path = iso_root / f"invalid_{label}.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert _valid_isolated_venv_e2e(iso_root, path) is False


def test_explicit_js_config_ignores_fake_hermes_provider(tmp_path: Path, monkeypatch) -> None:
    home = tmp_path / "home"
    home.mkdir()
    xdg_config = home / ".config"
    xdg_config.mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(xdg_config))
    hermes_dir = home / ".hermes"
    hermes_dir.mkdir()
    hermes_dir.joinpath("config.yaml").write_text(
        yaml.safe_dump(
            {
                "model": {
                    "provider": "hermes-leaked",
                    "base_url": "http://127.0.0.1:9999/v1",
                    "default": "hermes-model",
                }
            }
        ),
        encoding="utf-8",
    )
    js_config = xdg_config / "js" / "config.yaml"
    js_config.parent.mkdir(parents=True)
    js_config.write_text(
        yaml.safe_dump(
            {
                "workspace": str(home / "workspace"),
                "state_dir": str(home / "state"),
                "providers": [
                    {
                        "name": "iso-local",
                        "base_url": "http://127.0.0.1:18080/v1",
                        "default_model": "iso-local-model",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("JS_CONFIG_PATH", str(js_config))
    settings = JSSettings.from_file()
    provider_names = {provider.name for provider in settings.providers}
    assert provider_names == {"iso-local"}
    assert "hermes-leaked" not in provider_names


def test_loopback_socket_guard_blocks_example_com(tmp_path: Path) -> None:
    script = tmp_path / "server_e2e.py"
    _write_server_e2e_script(script)
    probe = tmp_path / "probe.py"
    probe.write_text(
        "\n".join(
            [
                "import json",
                "import socket",
                "from server_e2e import _install_loopback_socket_guard",
                "_install_loopback_socket_guard()",
                "try:",
                "    socket.getaddrinfo('example.com', 443)",
                "    print(json.dumps({'blocked': False}))",
                "except OSError:",
                "    print(json.dumps({'blocked': True}))",
            ]
        ),
        encoding="utf-8",
    )
    proc = subprocess.run(
        [sys.executable, str(probe)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout.strip().splitlines()[-1])
    assert payload["blocked"] is True


def test_generated_server_e2e_fail_closed_without_isolation_marker(tmp_path: Path) -> None:
    script = tmp_path / "server_e2e.py"
    _write_server_e2e_script(script)
    env = os.environ.copy()
    env.pop(ISO_E2E_SANDBOX_ENV, None)
    env.pop(ISO_E2E_HOME_ENV, None)
    proc = subprocess.run(
        [sys.executable, str(script)],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode != 0
    payload = json.loads(proc.stdout.strip().splitlines()[-1])
    assert payload["ok"] is False


def test_provider_failure_mode_exits_nonzero(tmp_path: Path) -> None:
    script = tmp_path / "server_e2e.py"
    _write_server_e2e_script(script)
    home = tmp_path / "home"
    home.mkdir()
    env = os.environ.copy()
    env[ISO_E2E_SANDBOX_ENV] = "1"
    env[ISO_E2E_HOME_ENV] = str(home)
    env[ISO_E2E_PROVIDER_FAIL_ENV] = "1"
    env["HOME"] = str(home)
    env["TMPDIR"] = str(tmp_path / "tmp")
    env["XDG_CONFIG_HOME"] = str(home / ".config")
    env["XDG_CACHE_HOME"] = str(home / ".cache")
    env["XDG_STATE_HOME"] = str(home / ".local" / "state")
    for directory in (
        env["TMPDIR"],
        env["XDG_CONFIG_HOME"],
        env["XDG_CACHE_HOME"],
        env["XDG_STATE_HOME"],
    ):
        Path(directory).mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(
        [sys.executable, str(script)],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode != 0
