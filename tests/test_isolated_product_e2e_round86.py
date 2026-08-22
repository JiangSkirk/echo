from __future__ import annotations

import json
from pathlib import Path

from js.echo.ledger.release_gates import (
    _ISOLATED_VENV_E2E_SCHEMA_VERSION,
    _valid_isolated_venv_e2e,
)
from scripts.isolated_venv_e2e import _write_server_e2e_script
from tests.test_isolated_product_e2e_round85 import _valid_payload


def _write(path: Path, payload: dict[str, object]) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_embedded_server_e2e_script_compiles(tmp_path: Path) -> None:
    script = tmp_path / "server_e2e.py"
    _write_server_e2e_script(script)
    compile(script.read_text(encoding="utf-8"), str(script), "exec")


def test_valid_v8_fixture_and_exact_contract_negatives(tmp_path: Path) -> None:
    path, payload = _valid_payload(tmp_path)
    assert _ISOLATED_VENV_E2E_SCHEMA_VERSION == "isolated-venv-e2e-v8"
    assert _valid_isolated_venv_e2e(tmp_path, path)

    first = payload["results"][0]
    first["argv"] = ["/usr/bin/true"]
    _write(path, payload)
    assert not _valid_isolated_venv_e2e(tmp_path, path)


def test_rejects_nonexistent_cwd_and_bad_output_hash(tmp_path: Path) -> None:
    path, payload = _valid_payload(tmp_path)
    payload["results"][1]["cwd"] = str(tmp_path / "missing")
    _write(path, payload)
    assert not _valid_isolated_venv_e2e(tmp_path, path)

    path, payload = _valid_payload(tmp_path)
    payload["results"][1]["stdout_sha256"] = "0" * 64
    _write(path, payload)
    assert not _valid_isolated_venv_e2e(tmp_path, path)


def test_rejects_manifest_drift_pip_exit_and_work_bytes(tmp_path: Path) -> None:
    path, payload = _valid_payload(tmp_path)
    payload["manifest"].pop()
    _write(path, payload)
    assert not _valid_isolated_venv_e2e(tmp_path, path)

    path, payload = _valid_payload(tmp_path)
    payload["pip_check"]["wheel"]["exit_code"] = 1
    _write(path, payload)
    assert not _valid_isolated_venv_e2e(tmp_path, path)

    path, payload = _valid_payload(tmp_path)
    payload["work_outputs"]["sdist"]["bytes"] += 1
    payload["work_output"]["bytes"] += 1
    _write(path, payload)
    assert not _valid_isolated_venv_e2e(tmp_path, path)
