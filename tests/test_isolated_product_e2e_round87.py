from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from js.echo.ledger.release_gates import (
    _ISOLATED_VENV_E2E_REQUIRED_STEPS,
    _ISOLATED_VENV_E2E_SCHEMA_VERSION,
    _valid_isolated_venv_e2e,
)
from scripts.isolated_venv_e2e import (
    IMPORT_CHECK,
    ISOLATED_VENV_E2E_SCHEMA_VERSION,
    _normalize_step_contracts,
    _validate_summary_schema,
    _validate_wheelhouse,
)
from tests.test_isolated_product_e2e_round85 import _valid_payload


def test_round87_e2e_schema_and_import_provenance() -> None:
    assert _ISOLATED_VENV_E2E_SCHEMA_VERSION == "isolated-venv-e2e-v8"
    assert ISOLATED_VENV_E2E_SCHEMA_VERSION == "isolated-venv-e2e-v8"
    assert "file_sha256" in IMPORT_CHECK
    assert "site_packages" in IMPORT_CHECK


def test_release_gate_requires_all_work_cli_entries_for_both_artifacts() -> None:
    required = {
        f"{kind}: CLI {entry} --help"
        for kind in ("wheel", "sdist")
        for entry in ("js work", "js-work", "python -m js_work")
    }
    assert set(_ISOLATED_VENV_E2E_REQUIRED_STEPS) >= required


def test_summary_requires_all_twenty_two_step_receipts(tmp_path: Path) -> None:
    summary = {
        "schema_version": ISOLATED_VENV_E2E_SCHEMA_VERSION,
        "offline": True,
        "source_digest": "a" * 64,
        "evidence_root": str(tmp_path),
        "ok": True,
        "artifacts": {},
        "work_output": {},
        "work_outputs": {},
        "manifest": [],
        "pip_check": {},
        "results": [],
    }
    errors = _validate_summary_schema(summary)
    assert "results must contain exactly 22 steps" in errors


def _write(path: Path, payload: dict[str, object]) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


def _step(payload: dict[str, object], suffix: str) -> dict[str, object]:
    return next(step for step in payload["results"] if str(step["step"]).endswith(suffix))


def test_valid_v7_behavioral_fixture_passes(tmp_path: Path) -> None:
    path, _payload = _valid_payload(tmp_path)
    assert _valid_isolated_venv_e2e(tmp_path, path)


@pytest.mark.parametrize(
    "fault",
    ["true_argv", "nonexistent_cwd", "missing_receipt", "missing_import_sha", "missing_pip_report"],
)
def test_v7_step_evidence_fails_closed(tmp_path: Path, fault: str) -> None:
    path, payload = _valid_payload(tmp_path)
    if fault == "true_argv":
        payload["results"][0]["argv"] = ["/usr/bin/true"]
    elif fault == "nonexistent_cwd":
        payload["results"][1]["cwd"] = str(tmp_path / "does-not-exist")
    elif fault == "missing_receipt":
        Path(payload["results"][0]["step_receipt_path"]).unlink()
    elif fault == "missing_import_sha":
        step = _step(payload, "import js/js_work from venv site-packages")
        step["import_evidence"]["modules"]["js"].pop("file_sha256")
    else:
        _step(payload, "pip install artifact offline (echo-tokenizer,office)").pop("pip_report")
    _write(path, payload)
    assert not _valid_isolated_venv_e2e(tmp_path, path)


def test_comment_only_import_keyword_evidence_fails(tmp_path: Path) -> None:
    path, payload = _valid_payload(tmp_path)
    step = _step(payload, "import js/js_work from venv site-packages")
    step["argv"][2] = "# import js, js_work from site-packages"
    step["import_evidence"] = {
        "modules": {
            "js": {"file": "# site-packages", "file_sha256": "0" * 64},
            "js_work": {"file": "# site-packages", "file_sha256": "0" * 64},
        },
        "errors": [],
    }
    receipt = json.loads(Path(step["step_receipt_path"]).read_text(encoding="utf-8"))
    receipt["argv"] = step["argv"]
    Path(step["step_receipt_path"]).write_text(json.dumps(receipt), encoding="utf-8")
    _write(path, payload)
    assert not _valid_isolated_venv_e2e(tmp_path, path)


def test_wheelhouse_rejects_product_wheels(tmp_path: Path) -> None:
    (tmp_path / "dependency-1.0-py3-none-any.whl").write_bytes(b"dependency")
    (tmp_path / "js_agent-9.9-py3-none-any.whl").write_bytes(b"product")
    with pytest.raises(SystemExit, match="dependencies only"):
        _validate_wheelhouse(tmp_path)


def test_normalize_rewrites_import_evidence_onto_durable_runtime(tmp_path: Path) -> None:
    work_root = tmp_path / "work"
    evidence_dir = tmp_path / "evidence"
    source = work_root / "install-wheel" / "venv" / "lib" / "python3.12" / "site-packages"
    source.mkdir(parents=True)
    module_file = source / "js" / "__init__.py"
    module_file.parent.mkdir(parents=True)
    module_file.write_text("x = 1\n", encoding="utf-8")
    steps_dir = evidence_dir / "e2e" / "steps"
    steps_dir.mkdir(parents=True)
    stdout_path = steps_dir / "05_import.stdout.txt"
    stderr_path = steps_dir / "05_import.stderr.txt"
    receipt_path = steps_dir / "05_import.receipt.json"
    stdout_body = json.dumps(
        {
            "modules": {
                "js": {
                    "file": str(module_file),
                    "file_sha256": "deadbeef",
                    "site_packages": str(source),
                }
            },
            "errors": [],
        }
    )
    stdout_path.write_text(stdout_body + "\n", encoding="utf-8")
    stderr_path.write_text("", encoding="utf-8")
    cwd = str(work_root / "install-wheel")
    argv = [str(work_root / "install-wheel" / "venv" / "bin" / "python"), "-c", "import js"]
    receipt_path.write_text(
        json.dumps(
            {
                "argv": argv,
                "cwd": cwd,
                "exit_code": 0,
                "stdout_sha256": "0" * 64,
                "stderr_sha256": "0" * 64,
                "stdout_path": str(stdout_path),
                "stderr_path": str(stderr_path),
                "step_receipt_path": str(receipt_path),
            }
        ),
        encoding="utf-8",
    )
    results: list[dict[str, object]] = [
        {
            "step": "wheel: import js/js_work from venv site-packages",
            "argv": argv,
            "cwd": cwd,
            "stdout_path": str(stdout_path),
            "stderr_path": str(stderr_path),
            "step_receipt_path": str(receipt_path),
            "stdout_tail": stdout_body[-4000:],
            "stderr_tail": "",
            "stdout_sha256": "0" * 64,
            "stderr_sha256": "0" * 64,
            "import_evidence": {
                "modules": {
                    "js": {
                        "file": str(module_file),
                        "file_sha256": "deadbeef",
                        "site_packages": str(source),
                    }
                },
                "errors": [],
            },
        }
    ]
    _normalize_step_contracts(results, work_root=work_root, evidence_dir=evidence_dir)
    step = results[0]
    durable_site = (
        evidence_dir
        / "e2e"
        / "runtime"
        / "install-wheel"
        / "venv"
        / "lib"
        / "python3.12"
        / "site-packages"
    ).resolve()
    durable_file = (durable_site / "js" / "__init__.py").resolve()
    assert step["cwd"] == str((evidence_dir / "e2e" / "runtime" / "install-wheel").resolve())
    assert durable_file.is_file()
    evidence = step["import_evidence"]["modules"]["js"]
    assert Path(evidence["file"]).resolve() == durable_file
    assert Path(evidence["site_packages"]).resolve() == durable_site
    assert evidence["file_sha256"] == hashlib.sha256(durable_file.read_bytes()).hexdigest()
    assert str(work_root) not in evidence["file"]
    assert step["stdout_tail"] == stdout_path.read_text(encoding="utf-8")[-4000:]
    assert step["stdout_sha256"] == hashlib.sha256(stdout_path.read_bytes()).hexdigest()
