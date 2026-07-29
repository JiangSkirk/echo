from __future__ import annotations

import json
from pathlib import Path

import pytest

from js.echo.ledger.release_gates import (
    _ISOLATED_VENV_E2E_SERVER_STEP,
    _valid_isolated_venv_e2e,
)
from tests.test_isolated_product_e2e_round85 import _valid_payload


def _receipt(payload: dict[str, object], kind: str) -> dict[str, object]:
    return next(
        step["detail"]["work_receipt"]
        for step in payload["results"]
        if step["step"] == f"{kind}: {_ISOLATED_VENV_E2E_SERVER_STEP}"
    )


@pytest.mark.parametrize("kind", ["wheel", "sdist"])
def test_each_artifact_binds_its_own_archived_xlsx_and_journal(
    tmp_path: Path,
    kind: str,
) -> None:
    path, payload = _valid_payload(tmp_path)
    receipt = _receipt(payload, kind)
    assert receipt["journal_evidence_path"] == f"e2e/work/{kind}/ledger.journal"
    assert payload["work_outputs"][kind]["path"] == f"e2e/work/{kind}/iso-e2e.xlsx"
    assert _valid_isolated_venv_e2e(tmp_path, path)


@pytest.mark.parametrize("fault", ["missing", "sha", "session", "product", "outbox"])
def test_archived_journal_binding_rejects_rewrites(tmp_path: Path, fault: str) -> None:
    path, payload = _valid_payload(tmp_path)
    receipt = _receipt(payload, "wheel")
    evidence_root = tmp_path / payload["evidence_root"]
    if fault == "missing":
        (evidence_root / receipt["journal_evidence_path"]).unlink()
    elif fault == "sha":
        receipt["journal_sha256"] = "0" * 64
    elif fault == "session":
        receipt["session"] = "rewritten-session"
    elif fault == "product":
        receipt["product_id"] = "js-agent"
    else:
        receipt["ledger_chain"][1]["payload"]["outbox_id"] = "rewritten-outbox"
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert not _valid_isolated_venv_e2e(tmp_path, path)


def test_status_and_terminal_must_match_verified_terminal_status(tmp_path: Path) -> None:
    path, payload = _valid_payload(tmp_path)
    receipt = _receipt(payload, "sdist")
    receipt["status"] = "failed"
    receipt["terminal"] = False
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert not _valid_isolated_venv_e2e(tmp_path, path)
