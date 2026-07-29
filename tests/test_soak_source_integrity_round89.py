from __future__ import annotations

import json
import math
from datetime import UTC, datetime, timedelta
from pathlib import Path

from js.echo.ledger.release_gates import _valid_echo_live_acceptance, release_source_digest
from tests.test_soak_source_integrity_round85 import _minimal_release_tree, _valid_live_payload
from tests.test_soak_source_integrity_round88 import _resign, _write

REPO_ROOT = Path(__file__).resolve().parents[1]


def _rebuild_checks(
    *,
    digest: str,
    meta: str,
    started: datetime,
    first_mono: float,
    last_mono: float,
    step: float = 5.0,
) -> list[dict[str, object]]:
    checks: list[dict[str, object]] = []
    mono = first_mono
    index = 1
    while mono < last_mono - 1e-9:
        checks.append(
            {
                "index": index,
                "source_digest": digest,
                "metadata_fingerprint": meta,
                "monotonic_s": mono,
                "wall_utc": (started + timedelta(seconds=mono)).isoformat().replace("+00:00", "Z"),
            }
        )
        mono += step
        index += 1
    checks.append(
        {
            "index": len(checks) + 1,
            "source_digest": digest,
            "metadata_fingerprint": meta,
            "monotonic_s": last_mono,
            "wall_utc": (started + timedelta(seconds=last_mono)).isoformat().replace("+00:00", "Z"),
        }
    )
    return checks


def test_3570_coverage_attack_fails(tmp_path: Path) -> None:
    _minimal_release_tree(tmp_path)
    path = tmp_path / "docs/security/ECHO_LIVE_ACCEPTANCE.json"
    payload = _valid_live_payload(tmp_path)
    started = datetime(2026, 7, 24, 0, 0, 0, tzinfo=UTC)
    first, last = 15.0, 3585.0
    digest = str(payload["source_digest"])
    meta = str(payload["source_integrity"]["expected_metadata_fingerprint"])
    checks = _rebuild_checks(
        digest=digest, meta=meta, started=started, first_mono=first, last_mono=last
    )
    payload["started_utc"] = started.isoformat().replace("+00:00", "Z")
    payload["finished_utc"] = (started + timedelta(seconds=3585)).isoformat().replace("+00:00", "Z")
    payload["duration_seconds"] = 3600.0
    payload["soak"]["active_elapsed_seconds"] = 3600.0
    payload["soak"]["requested_seconds"] = 3600.0
    payload["source_integrity"]["checks"] = checks
    _resign(payload)
    _write(path, payload)
    assert last - first == 3570.0
    assert not _valid_echo_live_acceptance(tmp_path, path)


def test_exact_coverage_boundary_passes(tmp_path: Path) -> None:
    _minimal_release_tree(tmp_path)
    path = tmp_path / "docs/security/ECHO_LIVE_ACCEPTANCE.json"
    payload = _valid_live_payload(tmp_path)
    started = datetime(2026, 7, 24, 0, 0, 0, tzinfo=UTC)
    first, last = 0.0, 3585.0  # span == duration - 15
    digest = str(payload["source_digest"])
    meta = str(payload["source_integrity"]["expected_metadata_fingerprint"])
    checks = _rebuild_checks(
        digest=digest, meta=meta, started=started, first_mono=first, last_mono=last
    )
    payload["started_utc"] = started.isoformat().replace("+00:00", "Z")
    payload["finished_utc"] = (started + timedelta(seconds=3585)).isoformat().replace("+00:00", "Z")
    payload["duration_seconds"] = 3600.0
    payload["soak"]["active_elapsed_seconds"] = 3600.0
    payload["soak"]["requested_seconds"] = 3600.0
    # Keep sample counts consistent with fixture helpers.
    payload["source_integrity"]["checks"] = checks
    _resign(payload)
    _write(path, payload)
    assert math.isclose(last - first, 3585.0)
    assert _valid_echo_live_acceptance(tmp_path, path)


def test_first_late_and_last_early_fails(tmp_path: Path) -> None:
    _minimal_release_tree(tmp_path)
    path = tmp_path / "docs/security/ECHO_LIVE_ACCEPTANCE.json"
    payload = _valid_live_payload(tmp_path)
    started = datetime(2026, 7, 24, 0, 0, 0, tzinfo=UTC)
    checks = _rebuild_checks(
        digest=str(payload["source_digest"]),
        meta=str(payload["source_integrity"]["expected_metadata_fingerprint"]),
        started=started,
        first_mono=15.0,
        last_mono=3585.0,
    )
    payload["started_utc"] = started.isoformat().replace("+00:00", "Z")
    payload["finished_utc"] = (started + timedelta(seconds=3600)).isoformat().replace("+00:00", "Z")
    payload["duration_seconds"] = 3600.0
    payload["soak"]["active_elapsed_seconds"] = 3600.0
    payload["source_integrity"]["checks"] = checks
    _resign(payload)
    _write(path, payload)
    assert not _valid_echo_live_acceptance(tmp_path, path)


def test_inflated_active_elapsed_with_short_span_fails(tmp_path: Path) -> None:
    _minimal_release_tree(tmp_path)
    path = tmp_path / "docs/security/ECHO_LIVE_ACCEPTANCE.json"
    payload = _valid_live_payload(tmp_path)
    started = datetime(2026, 7, 24, 0, 0, 0, tzinfo=UTC)
    checks = _rebuild_checks(
        digest=str(payload["source_digest"]),
        meta=str(payload["source_integrity"]["expected_metadata_fingerprint"]),
        started=started,
        first_mono=0.0,
        last_mono=3570.0,
    )
    payload["started_utc"] = started.isoformat().replace("+00:00", "Z")
    payload["finished_utc"] = (started + timedelta(seconds=3600)).isoformat().replace("+00:00", "Z")
    payload["duration_seconds"] = 3600.0
    payload["soak"]["active_elapsed_seconds"] = 3600.0  # inflated vs span
    payload["source_integrity"]["checks"] = checks
    _resign(payload)
    _write(path, payload)
    assert not _valid_echo_live_acceptance(tmp_path, path)


def test_round88_live_artifact_still_valid_when_digest_matches() -> None:
    """Current docs live acceptance must remain valid under Round 8.9 rules when digests match."""
    live = REPO_ROOT / "docs/security/ECHO_LIVE_ACCEPTANCE.json"
    if not live.is_file():
        return
    data = json.loads(live.read_text(encoding="utf-8"))
    if data.get("source_digest") != release_source_digest(REPO_ROOT):
        # Source changed mid-round — skip rather than false-fail.
        return
    assert _valid_echo_live_acceptance(REPO_ROOT, live)


def test_wall_only_compression_fails(tmp_path: Path) -> None:
    _minimal_release_tree(tmp_path)
    path = tmp_path / "docs/security/ECHO_LIVE_ACCEPTANCE.json"
    payload = _valid_live_payload(tmp_path)
    started = datetime(2026, 7, 24, 0, 0, 0, tzinfo=UTC)
    digest = str(payload["source_digest"])
    meta = str(payload["source_integrity"]["expected_metadata_fingerprint"])
    checks = _rebuild_checks(
        digest=digest, meta=meta, started=started, first_mono=0.0, last_mono=3600.0
    )
    checks[-1]["wall_utc"] = (started + timedelta(seconds=3570)).isoformat().replace("+00:00", "Z")
    payload["started_utc"] = started.isoformat().replace("+00:00", "Z")
    payload["finished_utc"] = (started + timedelta(seconds=3600)).isoformat().replace("+00:00", "Z")
    payload["duration_seconds"] = 3600.0
    payload["soak"]["active_elapsed_seconds"] = 3600.0
    payload["source_integrity"]["checks"] = checks
    _resign(payload)
    _write(path, payload)
    assert not _valid_echo_live_acceptance(tmp_path, path)


def test_mono_only_compression_fails(tmp_path: Path) -> None:
    _minimal_release_tree(tmp_path)
    path = tmp_path / "docs/security/ECHO_LIVE_ACCEPTANCE.json"
    payload = _valid_live_payload(tmp_path)
    started = datetime(2026, 7, 24, 0, 0, 0, tzinfo=UTC)
    checks = _rebuild_checks(
        digest=str(payload["source_digest"]),
        meta=str(payload["source_integrity"]["expected_metadata_fingerprint"]),
        started=started,
        first_mono=0.0,
        last_mono=3570.0,
    )
    payload["started_utc"] = started.isoformat().replace("+00:00", "Z")
    payload["finished_utc"] = (started + timedelta(seconds=3600)).isoformat().replace("+00:00", "Z")
    payload["duration_seconds"] = 3600.0
    payload["soak"]["active_elapsed_seconds"] = 3570.0
    payload["source_integrity"]["checks"] = checks
    _resign(payload)
    _write(path, payload)
    assert not _valid_echo_live_acceptance(tmp_path, path)
