from __future__ import annotations

import json
import math
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from js.echo.ledger.release_gates import _valid_echo_live_acceptance
from tests.test_soak_source_integrity_round85 import (
    _minimal_release_tree,
    _resign_live_payload,
    _valid_live_payload,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


def _resign(payload: dict[str, Any]) -> None:
    _resign_live_payload(payload)


def _write(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_soak_pubkey_documents_deterministic_consistency_only() -> None:
    frozen = json.loads(
        (REPO_ROOT / "docs/security/ECHO_SOAK_INTEGRITY_PUBKEY.json").read_text(encoding="utf-8")
    )
    assert frozen.get("purpose") == "deterministic-hash-chain-consistency-v1"
    assert frozen.get("not_a_third_party_signature") is True
    source = (REPO_ROOT / "scripts/echo_live_acceptance.py").read_text(encoding="utf-8")
    assert "deterministic hash-chain consistency" in source.lower() or (
        "Deterministic hash-chain consistency" in source
    )
    assert "NOT an unforgeable authenticity signature" in source


def test_valid_fixture_still_passes(tmp_path: Path) -> None:
    _minimal_release_tree(tmp_path)
    path = tmp_path / "docs/security/ECHO_LIVE_ACCEPTANCE.json"
    payload = _valid_live_payload(tmp_path)
    _write(path, payload)
    assert _valid_echo_live_acceptance(tmp_path, path)


def test_compressed_1701s_late_start_attack_fails(tmp_path: Path) -> None:
    """Round 8.8 attack: declare 3600s while wall span ~1701 and first mono=1900."""
    _minimal_release_tree(tmp_path)
    path = tmp_path / "docs/security/ECHO_LIVE_ACCEPTANCE.json"
    payload = _valid_live_payload(tmp_path)
    started = datetime(2026, 7, 24, 0, 0, 0, tzinfo=UTC)
    finished = started + timedelta(seconds=1701)
    duration = 3600.0
    digest = payload["source_digest"]
    meta = payload["source_integrity"]["expected_metadata_fingerprint"]
    checks: list[dict[str, object]] = []
    mono = 1900.0
    while mono < duration - 1:
        checks.append(
            {
                "index": len(checks) + 1,
                "source_digest": digest,
                "metadata_fingerprint": meta,
                "monotonic_s": mono,
                "wall_utc": (started + timedelta(seconds=mono - 1900))
                .isoformat()
                .replace("+00:00", "Z"),
            }
        )
        mono += 2.5
    if float(checks[-1]["monotonic_s"]) < duration - 15:
        checks.append(
            {
                "index": len(checks) + 1,
                "source_digest": digest,
                "metadata_fingerprint": meta,
                "monotonic_s": duration - 1,
                "wall_utc": (started + timedelta(seconds=1700)).isoformat().replace("+00:00", "Z"),
            }
        )
    payload["started_utc"] = started.isoformat().replace("+00:00", "Z")
    payload["finished_utc"] = finished.isoformat().replace("+00:00", "Z")
    payload["duration_seconds"] = duration
    payload["source_integrity"]["checks"] = checks
    _resign(payload)
    _write(path, payload)
    assert not _valid_echo_live_acceptance(tmp_path, path)


def test_first_monotonic_late_start_fails(tmp_path: Path) -> None:
    _minimal_release_tree(tmp_path)
    path = tmp_path / "docs/security/ECHO_LIVE_ACCEPTANCE.json"
    payload = _valid_live_payload(tmp_path)
    checks = payload["source_integrity"]["checks"]
    assert isinstance(checks, list)
    for check in checks:
        assert isinstance(check, dict)
        check["monotonic_s"] = float(check["monotonic_s"]) + 1900.0
        wall = datetime.fromisoformat(str(check["wall_utc"]).replace("Z", "+00:00"))
        check["wall_utc"] = (wall + timedelta(seconds=1900)).isoformat().replace("+00:00", "Z")
    started = datetime.fromisoformat(str(payload["started_utc"]).replace("Z", "+00:00"))
    payload["finished_utc"] = (
        (started + timedelta(seconds=3600 + 1900 + 1)).isoformat().replace("+00:00", "Z")
    )
    _resign(payload)
    _write(path, payload)
    assert not _valid_echo_live_acceptance(tmp_path, path)


def test_short_wall_span_fails(tmp_path: Path) -> None:
    _minimal_release_tree(tmp_path)
    path = tmp_path / "docs/security/ECHO_LIVE_ACCEPTANCE.json"
    payload = _valid_live_payload(tmp_path)
    started = datetime.fromisoformat(str(payload["started_utc"]).replace("Z", "+00:00"))
    payload["finished_utc"] = (started + timedelta(seconds=1701)).isoformat().replace("+00:00", "Z")
    # Keep checks inside the shortened window by rewriting walls/monos to fit — still short span.
    checks = payload["source_integrity"]["checks"]
    assert isinstance(checks, list)
    n = len(checks)
    for index, check in enumerate(checks):
        assert isinstance(check, dict)
        mono = (index / max(n - 1, 1)) * 1690.0
        check["monotonic_s"] = mono
        check["wall_utc"] = (started + timedelta(seconds=mono)).isoformat().replace("+00:00", "Z")
    _resign(payload)
    _write(path, payload)
    assert not _valid_echo_live_acceptance(tmp_path, path)


def test_first_wall_mono_mismatch_fails(tmp_path: Path) -> None:
    _minimal_release_tree(tmp_path)
    path = tmp_path / "docs/security/ECHO_LIVE_ACCEPTANCE.json"
    payload = _valid_live_payload(tmp_path)
    checks = payload["source_integrity"]["checks"]
    assert isinstance(checks[0], dict)
    started = datetime.fromisoformat(str(payload["started_utc"]).replace("Z", "+00:00"))
    checks[0]["wall_utc"] = (started + timedelta(seconds=120)).isoformat().replace("+00:00", "Z")
    _resign(payload)
    _write(path, payload)
    assert not _valid_echo_live_acceptance(tmp_path, path)


def test_wall_clock_regression_fails(tmp_path: Path) -> None:
    _minimal_release_tree(tmp_path)
    path = tmp_path / "docs/security/ECHO_LIVE_ACCEPTANCE.json"
    payload = _valid_live_payload(tmp_path)
    checks = payload["source_integrity"]["checks"]
    assert isinstance(checks[2], dict) and isinstance(checks[1], dict)
    earlier = datetime.fromisoformat(str(checks[1]["wall_utc"]).replace("Z", "+00:00"))
    checks[2]["wall_utc"] = (earlier - timedelta(seconds=1)).isoformat().replace("+00:00", "Z")
    _resign(payload)
    _write(path, payload)
    assert not _valid_echo_live_acceptance(tmp_path, path)


def test_mono_jump_without_wall_jump_fails(tmp_path: Path) -> None:
    _minimal_release_tree(tmp_path)
    path = tmp_path / "docs/security/ECHO_LIVE_ACCEPTANCE.json"
    payload = _valid_live_payload(tmp_path)
    checks = payload["source_integrity"]["checks"]
    assert isinstance(checks[3], dict) and isinstance(checks[2], dict)
    checks[3]["monotonic_s"] = float(checks[2]["monotonic_s"]) + 30.0
    # wall stays on the original 5s cadence → interval mismatch
    _resign(payload)
    _write(path, payload)
    assert not _valid_echo_live_acceptance(tmp_path, path)


def test_last_check_too_far_from_finished_fails(tmp_path: Path) -> None:
    _minimal_release_tree(tmp_path)
    path = tmp_path / "docs/security/ECHO_LIVE_ACCEPTANCE.json"
    payload = _valid_live_payload(tmp_path)
    started = datetime.fromisoformat(str(payload["started_utc"]).replace("Z", "+00:00"))
    payload["finished_utc"] = (
        (started + timedelta(seconds=3600 + 120)).isoformat().replace("+00:00", "Z")
    )
    _resign(payload)
    _write(path, payload)
    assert not _valid_echo_live_acceptance(tmp_path, path)


def test_enough_checks_but_insufficient_coverage_fails(tmp_path: Path) -> None:
    _minimal_release_tree(tmp_path)
    path = tmp_path / "docs/security/ECHO_LIVE_ACCEPTANCE.json"
    payload = _valid_live_payload(tmp_path)
    checks = payload["source_integrity"]["checks"]
    assert isinstance(checks, list)
    # Truncate coverage while keeping many checks via compressed early window then stop.
    started = datetime.fromisoformat(str(payload["started_utc"]).replace("Z", "+00:00"))
    short_checks: list[dict[str, object]] = []
    for index in range(1, 200):
        mono = (index - 1) * 5.0
        short_checks.append(
            {
                "index": index,
                "source_digest": payload["source_digest"],
                "metadata_fingerprint": payload["source_integrity"][
                    "expected_metadata_fingerprint"
                ],
                "monotonic_s": mono,
                "wall_utc": (started + timedelta(seconds=mono)).isoformat().replace("+00:00", "Z"),
            }
        )
    payload["source_integrity"]["checks"] = short_checks
    payload["finished_utc"] = (started + timedelta(seconds=3601)).isoformat().replace("+00:00", "Z")
    _resign(payload)
    _write(path, payload)
    assert not _valid_echo_live_acceptance(tmp_path, path)
    assert math.isfinite(float(short_checks[-1]["monotonic_s"]))
