"""Opt-in AppShell/Echo process split observations and worker env."""

from __future__ import annotations

import os
from pathlib import Path

from js.appshell.echo_process_split import (
    product_process_split_enabled,
    worker_environment,
)
from js.config import JSSettings
from js.orin.process_split import (
    mark_appshell_echo_separated,
    production_appshell_echo_separated,
    reset_process_split_observations,
)


def test_process_split_flag_defaults_off(tmp_path: Path) -> None:
    settings = JSSettings(workspace=tmp_path / "ws", state_dir=tmp_path / "st")
    assert settings.appshell_process_split is False
    assert product_process_split_enabled(settings) is False


def test_worker_environment_strips_authority_keys() -> None:
    cleaned = worker_environment(
        {
            "PATH": "/usr/bin",
            "OPENAI_API_KEY": "sk-test",
            "ORIN_OWNER_PRIVATE_KEY": "secret",
        }
    )
    assert "OPENAI_API_KEY" not in cleaned
    assert "ORIN_OWNER_PRIVATE_KEY" not in cleaned
    assert cleaned["JS_ECHO_WORKER"] == "1"
    assert cleaned["PATH"] == "/usr/bin"


def test_marking_split_is_observed_and_resettable() -> None:
    reset_process_split_observations()
    assert production_appshell_echo_separated() is False
    mark_appshell_echo_separated(True)
    assert production_appshell_echo_separated() is True
    reset_process_split_observations()
    assert production_appshell_echo_separated() is False


def test_forged_approved_payload_is_not_an_owner_key(tmp_path: Path) -> None:
    """Worker env must not carry owner keys even if the caller forges approved=True."""

    env = worker_environment(
        {
            **os.environ,
            "ORIN_OWNER_PRIVATE_KEY": "forged",
            "ORIN_OWNER_WITNESS_KEY": "forged",
        }
    )
    assert "ORIN_OWNER_PRIVATE_KEY" not in env
    assert "ORIN_OWNER_WITNESS_KEY" not in env
    assert env.get("JS_ECHO_WORKER") == "1"
    _ = tmp_path
