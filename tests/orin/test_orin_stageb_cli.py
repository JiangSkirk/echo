"""Product CLI coverage for opt-in Orin Stage-B startup flags."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

from js.orind import __main__ as orind_main
from js.orind import daemon as daemon_module


class _StartedError(RuntimeError):
    """Stops startup after constructor arguments have been observed."""


class _RecordingDaemon:
    def __init__(self, captured: dict[str, Any], **kwargs: Any) -> None:
        captured.update(kwargs)

    async def start(self) -> None:
        raise _StartedError


def test_stage_a_cli_defaults_keep_every_stage_b_switch_disabled() -> None:
    args = orind_main._parse_args(["--dev"])

    assert args.stage_b is False
    assert args.cell_build is False
    assert args.cell_secret is False
    assert args.cell_net is False
    assert args.cell_file is False
    assert args.commit_membrane is False
    assert args.cell_identity_enforce is False
    assert args.policy_profile == "conservative"


@pytest.mark.parametrize(
    "flag",
    [
        "--cell-build",
        "--cell-secret",
        "--cell-net",
        "--cell-file",
        "--commit-membrane",
        "--cell-identity-enforce",
    ],
)
def test_stage_b_subswitch_without_stage_b_fails_before_start(
    flag: str, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit, match="2"):
        orind_main._parse_args(["--dev", flag])
    assert "require --stage-b" in capsys.readouterr().err


def test_product_cli_passes_all_stage_b_switches_to_daemon(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    captured: dict[str, Any] = {}
    monkeypatch.setattr(
        daemon_module,
        "OrinDaemon",
        lambda **kwargs: _RecordingDaemon(captured, **kwargs),
    )
    args = orind_main._parse_args(
        [
            "--dev",
            "--state-dir",
            str(tmp_path),
            "--stage-b",
            "--cell-build",
            "--cell-secret",
            "--cell-net",
            "--cell-file",
            "--commit-membrane",
        ]
    )

    with pytest.raises(_StartedError):
        asyncio.run(orind_main._main_async(args))

    assert captured == {
        "state_dir": tmp_path,
        "socket_path": None,
        "keybox_tier": "dev",
        "policy_profile": "conservative",
        "stage_b": True,
        "cell_build": True,
        "cell_secret": True,
        "cell_net": True,
        "cell_file": True,
        "commit_membrane": True,
        "cell_identity_enforce": False,
    }


def test_run_daemon_passes_all_stage_b_switches_to_constructor(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    captured: dict[str, Any] = {}
    monkeypatch.setattr(
        daemon_module,
        "OrinDaemon",
        lambda **kwargs: _RecordingDaemon(captured, **kwargs),
    )

    with pytest.raises(_StartedError):
        asyncio.run(
            daemon_module.run_daemon(
                state_dir=tmp_path,
                stage_b=True,
                cell_build=True,
                cell_secret=True,
                cell_net=True,
                cell_file=True,
                commit_membrane=True,
            )
        )

    assert captured == {
        "state_dir": tmp_path,
        "socket_path": None,
        "keybox_tier": "dev",
        "stage_b": True,
        "cell_build": True,
        "cell_secret": True,
        "cell_net": True,
        "cell_file": True,
        "commit_membrane": True,
        "cell_identity_enforce": False,
    }


def test_product_cli_passes_cell_identity_enforce(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    captured: dict[str, Any] = {}
    monkeypatch.setattr(
        daemon_module,
        "OrinDaemon",
        lambda **kwargs: _RecordingDaemon(captured, **kwargs),
    )
    args = orind_main._parse_args(
        ["--dev", "--state-dir", str(tmp_path), "--stage-b", "--cell-identity-enforce"]
    )

    with pytest.raises(_StartedError):
        asyncio.run(orind_main._main_async(args))

    assert captured["stage_b"] is True
    assert captured["cell_identity_enforce"] is True
    assert "cell_desktop" not in captured
    assert "cell_memory" not in captured
    assert "orin_enforce" not in captured
