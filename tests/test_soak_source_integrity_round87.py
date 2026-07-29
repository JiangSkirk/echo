from __future__ import annotations

import base64
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from js.echo.ledger.release_gates import _valid_echo_live_acceptance
from tests.test_soak_source_integrity_round85 import (
    _minimal_release_tree,
    _resign_live_payload,
    _valid_live_payload,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


def _resign_integrity(payload: dict[str, Any]) -> None:
    _resign_live_payload(payload)


def test_frozen_soak_key_matches_integrity_signer() -> None:
    frozen = json.loads(
        (REPO_ROOT / "docs/security/ECHO_SOAK_INTEGRITY_PUBKEY.json").read_text(encoding="utf-8")
    )
    seed = hashlib.sha256(b"js-agent-round87-soak-integrity-signing-key-v1").digest()
    public_raw = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw()
    assert frozen["algorithm"] == "Ed25519"
    assert base64.b64decode(frozen["public_key_b64"]) == public_raw
    assert frozen["fingerprint_sha256"] == hashlib.sha256(public_raw).hexdigest()


def test_live_acceptance_records_signed_timing_evidence() -> None:
    source = (REPO_ROOT / "scripts/echo_live_acceptance.py").read_text(encoding="utf-8")
    for marker in (
        '"echo-live-acceptance-v4"',
        '"monotonic_s"',
        '"wall_utc"',
        '"chain_root_signature_b64"',
        '"pubkey_fingerprint"',
        "MIN_INTEGRITY_INTERVAL_SECONDS",
    ):
        assert marker in source


def test_integrity_chain_append_binds_timing_fields() -> None:
    source = (REPO_ROOT / "scripts/echo_live_acceptance.py").read_text(encoding="utf-8")
    match = re.search(
        r"def _integrity_chain_append\(.*?\) -> str:\n(?P<body>.*?\n)(?=\ndef )",
        source,
        flags=re.DOTALL,
    )
    assert match is not None
    body = match.group("body")
    for field in (
        '"index"',
        '"metadata_fingerprint"',
        '"monotonic_s"',
        '"source_digest"',
        '"wall_utc"',
    ):
        assert field in body
    assert "MIN_INTEGRITY_INTERVAL_SECONDS" in source
    assert "monotonic_s - float(prior)) < MIN_INTEGRITY_INTERVAL_SECONDS" in source


def _write(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_valid_v4_signed_live_acceptance_fixture_passes(tmp_path: Path) -> None:
    _minimal_release_tree(tmp_path)
    path = tmp_path / "docs/security/ECHO_LIVE_ACCEPTANCE.json"
    _write(path, _valid_live_payload(tmp_path))
    assert _valid_echo_live_acceptance(tmp_path, path)


def test_unsigned_and_wrong_signed_chain_roots_fail(tmp_path: Path) -> None:
    _minimal_release_tree(tmp_path)
    path = tmp_path / "docs/security/ECHO_LIVE_ACCEPTANCE.json"
    payload = _valid_live_payload(tmp_path)
    payload["source_integrity"]["chain_root_signature_b64"] = ""
    _write(path, payload)
    assert not _valid_echo_live_acceptance(tmp_path, path)

    payload = _valid_live_payload(tmp_path)
    payload["source_integrity"]["chain_root_signature_b64"] = base64.b64encode(b"x" * 64).decode()
    _write(path, payload)
    assert not _valid_echo_live_acceptance(tmp_path, path)


def test_integrity_timing_and_coverage_fail_closed(tmp_path: Path) -> None:
    _minimal_release_tree(tmp_path)
    path = tmp_path / "docs/security/ECHO_LIVE_ACCEPTANCE.json"
    payload = _valid_live_payload(tmp_path)
    payload["source_integrity"]["checks"][0].pop("monotonic_s")
    _write(path, payload)
    assert not _valid_echo_live_acceptance(tmp_path, path)

    payload = _valid_live_payload(tmp_path)
    payload["source_integrity"]["checks"][1].pop("wall_utc")
    _write(path, payload)
    assert not _valid_echo_live_acceptance(tmp_path, path)

    payload = _valid_live_payload(tmp_path)
    payload["source_integrity"]["check_count"] = 2
    payload["source_integrity"]["checks"] = payload["source_integrity"]["checks"][:2]
    _write(path, payload)
    assert not _valid_echo_live_acceptance(tmp_path, path)


def test_short_final_integrity_interval_fails_even_when_re_signed(tmp_path: Path) -> None:
    """Mutation: trailing check <2.5s after prior must fail closed (Round 8.6 residual)."""
    _minimal_release_tree(tmp_path)
    path = tmp_path / "docs/security/ECHO_LIVE_ACCEPTANCE.json"
    payload = _valid_live_payload(tmp_path)
    integrity = payload["source_integrity"]
    assert isinstance(integrity, dict)
    checks = integrity["checks"]
    assert isinstance(checks, list) and len(checks) >= 2
    prior = checks[-2]
    final = checks[-1]
    assert isinstance(prior, dict) and isinstance(final, dict)
    final["monotonic_s"] = float(prior["monotonic_s"]) + 0.328
    _resign_integrity(payload)
    _write(path, payload)
    assert not _valid_echo_live_acceptance(tmp_path, path)


def test_process_tree_and_resource_pid_mismatches_fail(tmp_path: Path) -> None:
    _minimal_release_tree(tmp_path)
    path = tmp_path / "docs/security/ECHO_LIVE_ACCEPTANCE.json"
    payload = _valid_live_payload(tmp_path)
    payload["process_tree"]["acceptance"]["pid"] += 1
    _write(path, payload)
    assert not _valid_echo_live_acceptance(tmp_path, path)

    payload = _valid_live_payload(tmp_path)
    payload["resources"]["processes"]["js_agent"]["pid"] += 1
    _write(path, payload)
    assert not _valid_echo_live_acceptance(tmp_path, path)


def test_inflated_check_count_without_signed_checks_fails(tmp_path: Path) -> None:
    _minimal_release_tree(tmp_path)
    path = tmp_path / "docs/security/ECHO_LIVE_ACCEPTANCE.json"
    payload = _valid_live_payload(tmp_path)
    payload["source_integrity"]["check_count"] += 1000
    _write(path, payload)
    assert not _valid_echo_live_acceptance(tmp_path, path)
