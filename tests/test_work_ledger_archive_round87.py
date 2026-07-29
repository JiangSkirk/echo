from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from js.echo.ledger.release_gates import (
    _ISOLATED_VENV_E2E_SERVER_STEP,
    _valid_isolated_venv_e2e,
    _verify_work_ledger_receipt_binding,
)
from tests.test_isolated_product_e2e_round85 import _valid_payload, _write_xlsx


def test_frozen_ledger_key_documents_ephemeral_consistency_only() -> None:
    root = Path(__file__).resolve().parents[1]
    frozen = json.loads(
        (root / "docs/security/ECHO_E2E_LEDGER_PUBKEY.json").read_text(encoding="utf-8")
    )
    assert frozen["algorithm"] == "Ed25519"
    assert frozen["schema_version"] == "echo-e2e-ledger-pubkey-v1"
    public_raw = base64.b64decode(frozen["public_key_b64"])
    assert frozen["fingerprint_sha256"] == hashlib.sha256(public_raw).hexdigest()
    # Must not be the retired Round 8.7 fixed public seed.
    retired = hashlib.sha256(b"js-agent-round87-e2e-ledger-signing-key-v1").digest()
    retired_pub = Ed25519PrivateKey.from_private_bytes(retired).public_key().public_bytes_raw()
    assert public_raw != retired_pub
    assert frozen.get("not_a_third_party_signature") is True


def test_ledger_signature_payload_binds_output_and_arguments() -> None:
    payload = {
        "journal_sha256": "a" * 64,
        "arguments_sha256": "b" * 64,
        "output_sha256": "c" * 64,
        "product_id": "js-work",
        "owner": "owner",
        "session": "session",
        "run_id": "run",
        "effect_id": "effect",
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    # Fixture-only ephemeral key — not a production trust root.
    key = Ed25519PrivateKey.generate()
    signature = key.sign(canonical)
    mutated = dict(payload, output_sha256="d" * 64)
    assert signature != key.sign(
        json.dumps(mutated, sort_keys=True, separators=(",", ":")).encode()
    )


def _receipt(payload: dict[str, object], kind: str = "wheel") -> dict[str, object]:
    return next(
        step["detail"]["work_receipt"]
        for step in payload["results"]
        if step["step"] == f"{kind}: {_ISOLATED_VENV_E2E_SERVER_STEP}"
    )


def test_signed_archived_journal_and_xlsx_pass_without_mac_key(tmp_path: Path) -> None:
    path, payload = _valid_payload(tmp_path)
    receipt = _receipt(payload)
    assert "mac_key" not in receipt
    assert _verify_work_ledger_receipt_binding(
        receipt,
        evidence_root=tmp_path / payload["evidence_root"],
    )
    assert _valid_isolated_venv_e2e(tmp_path, path)


def test_second_xlsx_row_breaks_archived_output_binding(tmp_path: Path) -> None:
    path, payload = _valid_payload(tmp_path)
    output = tmp_path / payload["evidence_root"] / payload["work_outputs"]["wheel"]["path"]
    _write_xlsx(output, [["iso", "e2e", "leased"], ["forged", "second", "row"]])
    assert not _valid_isolated_venv_e2e(tmp_path, path)


def test_argument_hash_or_archived_journal_rewrite_fails(tmp_path: Path) -> None:
    path, payload = _valid_payload(tmp_path)
    receipt = _receipt(payload)
    receipt["arguments_sha256"] = "0" * 64
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert not _valid_isolated_venv_e2e(tmp_path, path)

    path, payload = _valid_payload(tmp_path)
    receipt = _receipt(payload)
    receipt["ledger_chain"][0]["payload"]["tool_effect"]["args_hash"] = "0" * 64
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert not _valid_isolated_venv_e2e(tmp_path, path)

    path, payload = _valid_payload(tmp_path)
    receipt = _receipt(payload)
    journal = tmp_path / payload["evidence_root"] / receipt["journal_evidence_path"]
    journal.write_bytes(journal.read_bytes() + b"\n")
    assert not _valid_isolated_venv_e2e(tmp_path, path)


def test_path_and_output_hash_rewrites_fail(tmp_path: Path) -> None:
    path, payload = _valid_payload(tmp_path)
    receipt = _receipt(payload)
    receipt["journal_relative_path"] = "echo/ledger/partitions/rewritten/chat.jsonl"
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert not _valid_isolated_venv_e2e(tmp_path, path)

    path, payload = _valid_payload(tmp_path)
    receipt = _receipt(payload)
    receipt["output_sha256"] = "0" * 64
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert not _valid_isolated_venv_e2e(tmp_path, path)


def test_mac_stripped_chain_without_signature_is_not_trusted(tmp_path: Path) -> None:
    _path, payload = _valid_payload(tmp_path)
    receipt = _receipt(payload)
    receipt.pop("ledger_signature_b64")
    assert not _verify_work_ledger_receipt_binding(
        receipt,
        evidence_root=tmp_path / payload["evidence_root"],
    )
