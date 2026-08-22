from __future__ import annotations

import json
from pathlib import Path

import pytest

from js.echo.ledger.release_gates import (
    _ISOLATED_VENV_E2E_SCHEMA_VERSION,
    _ISOLATED_VENV_E2E_SERVER_STEP,
    _valid_isolated_venv_e2e,
)
from tests.test_isolated_product_e2e_round85 import _valid_payload


@pytest.fixture
def iso_root(tmp_path: Path) -> Path:
    (tmp_path / "js").mkdir()
    (tmp_path / "js" / "marker.py").write_text("ISO = 1\n", encoding="utf-8")
    (tmp_path / "js_work").mkdir()
    (tmp_path / "js_work" / "marker.py").write_text("ISO = 1\n", encoding="utf-8")
    return tmp_path


def test_valid_isolated_e2e_round83_fixture_accepts_real_schema(iso_root: Path) -> None:
    path, _payload = _valid_payload(iso_root)
    assert _valid_isolated_venv_e2e(iso_root, path)


@pytest.mark.parametrize(
    ("mutation", "label"),
    [
        (lambda payload: payload["results"].pop(), "missing_step"),
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
            )["detail"].update({"chat_status": 403}),
            "chat_403",
        ),
        (
            lambda payload: next(
                step
                for step in payload["results"]
                if step["step"].startswith("wheel:")
                and _ISOLATED_VENV_E2E_SERVER_STEP in step["step"]
            )["detail"].update({"ws_terminal_ok": False, "ws_saw_done": False}),
            "ws_error",
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
            )["detail"].update({"attachment_consumed": False}),
            "upload_only_attachment",
        ),
        (
            lambda payload: payload.update({"source_digest": "0" * 64}),
            "digest_drift",
        ),
    ],
)
def test_isolated_e2e_round83_negative_controls(
    iso_root: Path,
    mutation: object,
    label: str,
) -> None:
    path, payload = _valid_payload(iso_root)
    mutation(payload)  # type: ignore[operator]
    out = iso_root / f"invalid_{label}.json"
    out.write_text(json.dumps(payload), encoding="utf-8")
    assert _valid_isolated_venv_e2e(iso_root, out) is False


def test_isolated_e2e_requires_both_wheel_and_sdist_server_steps(iso_root: Path) -> None:
    path, payload = _valid_payload(iso_root)
    payload["results"] = [
        step
        for step in payload["results"]
        if step["step"] != f"sdist: {_ISOLATED_VENV_E2E_SERVER_STEP}"
    ]
    out = iso_root / "missing_sdist_server.json"
    out.write_text(json.dumps(payload), encoding="utf-8")
    assert _valid_isolated_venv_e2e(iso_root, out) is False


def test_round83_schema_version_is_current() -> None:
    assert _ISOLATED_VENV_E2E_SCHEMA_VERSION == "isolated-venv-e2e-v8"
