from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from js.echo.ledger.e2e_signing import (
    E2E_LEDGER_PUBKEY_RELATIVE,
    assert_no_private_key_under,
    destroy_private_key,
    prepare_ephemeral_keypair,
    write_frozen_pubkey,
)
from js.echo.ledger.release_gates import _valid_isolated_venv_e2e
from tests.test_isolated_product_e2e_round85 import _valid_payload

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXED_SEED = b"js-agent-round87-e2e-ledger-signing-key-v1"


def test_production_paths_have_no_fixed_e2e_private_seed() -> None:
    needle = FIXED_SEED.decode()
    for relative in ("js", "scripts"):
        root = REPO_ROOT / relative
        for path in root.rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            assert needle not in text, f"fixed E2E seed present in {path}"


def test_ephemeral_keypair_private_outside_evidence_and_destroyed(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "docs" / "security").mkdir(parents=True)
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    external = tmp_path / "external-keys"
    external.mkdir()
    os.chmod(external, 0o700)
    handle, payload, provenance = prepare_ephemeral_keypair(
        repo, evidence_root=evidence, keys_parent=external
    )
    private_path = handle.path
    assert private_path.is_file()
    assert stat.S_IMODE(private_path.stat().st_mode) == 0o600
    assert not private_path.resolve().is_relative_to(repo.resolve())
    assert payload["not_a_third_party_signature"] is True
    assert provenance["location_class"] == "external_temp"
    frozen = json.loads((repo / E2E_LEDGER_PUBKEY_RELATIVE).read_text(encoding="utf-8"))
    assert frozen["fingerprint_sha256"] == payload["fingerprint_sha256"]
    assert_no_private_key_under(evidence)
    destroy_private_key(handle)
    assert not private_path.exists()
    assert_no_private_key_under(evidence)


def test_private_key_residue_under_evidence_fails(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    (evidence / "e2e" / "keys").mkdir(parents=True)
    leaked = evidence / "e2e" / "keys" / "ledger.ed25519.private"
    leaked.write_bytes(os.urandom(32))
    with pytest.raises(RuntimeError, match="private key material leaked"):
        assert_no_private_key_under(evidence)


def test_wrong_pubkey_rejects_valid_signature_binding(tmp_path: Path) -> None:
    path, payload = _valid_payload(tmp_path)
    other = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    write_frozen_pubkey(tmp_path, other)
    assert not _valid_isolated_venv_e2e(tmp_path, path)


def test_tampered_work_output_fails_after_ephemeral_sign(tmp_path: Path) -> None:
    path, payload = _valid_payload(tmp_path)
    output = tmp_path / payload["evidence_root"] / payload["work_outputs"]["wheel"]["path"]
    output.write_bytes(output.read_bytes() + b"\x00tamper")
    assert not _valid_isolated_venv_e2e(tmp_path, path)


def test_frozen_repo_pubkey_is_not_fixed_seed_derived() -> None:
    frozen_path = REPO_ROOT / "docs/security/ECHO_E2E_LEDGER_PUBKEY.json"
    if not frozen_path.is_file():
        pytest.skip("pubkey not present yet")
    frozen = json.loads(frozen_path.read_text(encoding="utf-8"))
    seed_pub = (
        Ed25519PrivateKey.from_private_bytes(hashlib.sha256(FIXED_SEED).digest())
        .public_key()
        .public_bytes_raw()
    )
    assert base64.b64decode(frozen["public_key_b64"]) != seed_pub
    assert frozen.get("not_a_third_party_signature") is True
