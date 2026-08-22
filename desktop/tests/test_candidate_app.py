from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from desktop.tests import test_app_process_smoke, test_bundle_smoke


def _resolver() -> Callable[[], Path]:
    return test_bundle_smoke.resolve_candidate_app


def test_smoke_tests_share_one_candidate_app_resolver() -> None:
    assert (
        test_app_process_smoke.resolve_candidate_app
        is test_bundle_smoke.resolve_candidate_app
    )


def test_candidate_app_requires_explicit_environment_variable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("JS_AGENT_APP_PATH", raising=False)

    with pytest.raises(AssertionError, match="JS_AGENT_APP_PATH must be set"):
        _resolver()()


def test_candidate_app_rejects_relative_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("JS_AGENT_APP_PATH", "relative/JS Agent.app")

    with pytest.raises(AssertionError, match="must be an absolute path"):
        _resolver()()


def test_candidate_app_rejects_missing_app(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("JS_AGENT_APP_PATH", str(tmp_path / "missing.app"))

    with pytest.raises(AssertionError, match="must be an existing .app directory"):
        _resolver()()


def test_candidate_app_rejects_existing_non_app_directory(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    directory = tmp_path / "not-an-app"
    directory.mkdir()
    monkeypatch.setenv("JS_AGENT_APP_PATH", str(directory))

    with pytest.raises(AssertionError, match="must be an existing .app directory"):
        _resolver()()


def test_candidate_app_accepts_absolute_existing_app(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    app = tmp_path / "Candidate.app"
    app.mkdir()
    monkeypatch.setenv("JS_AGENT_APP_PATH", str(app))

    assert _resolver()() == app
