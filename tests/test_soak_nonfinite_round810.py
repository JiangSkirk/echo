from __future__ import annotations

import math
from pathlib import Path

from js.echo.ledger.release_gates import _valid_echo_live_acceptance
from tests.test_soak_source_integrity_round85 import _minimal_release_tree, _valid_live_payload
from tests.test_soak_source_integrity_round88 import _resign, _write


def _base(tmp_path: Path) -> tuple[Path, dict]:
    _minimal_release_tree(tmp_path)
    path = tmp_path / "docs/security/ECHO_LIVE_ACCEPTANCE.json"
    payload = _valid_live_payload(tmp_path)
    return path, payload


def test_duration_nonfinite_fails(tmp_path: Path) -> None:
    path, payload = _base(tmp_path)
    payload["duration_seconds"] = math.inf
    _resign(payload)
    _write(path, payload)
    # strict JSON path: write inf via Python json may emit Infinity
    path.write_text(
        path.read_text(encoding="utf-8").replace("Infinity", "1e9999"), encoding="utf-8"
    )
    assert not _valid_echo_live_acceptance(tmp_path, path)


def test_active_elapsed_nonfinite_fails(tmp_path: Path) -> None:
    path, payload = _base(tmp_path)
    payload["soak"]["active_elapsed_seconds"] = math.nan
    # Bypass resign JSON issues by mutating after write with invalid token
    _resign(payload)
    _write(path, payload)
    text = path.read_text(encoding="utf-8").replace(
        '"active_elapsed_seconds": 3600.0', '"active_elapsed_seconds": NaN'
    )
    path.write_text(text, encoding="utf-8")
    assert not _valid_echo_live_acceptance(tmp_path, path)


def test_sample_coverage_nonfinite_fails(tmp_path: Path) -> None:
    path, payload = _base(tmp_path)
    _resign(payload)
    _write(path, payload)
    text = path.read_text(encoding="utf-8").replace(
        '"sample_coverage_seconds": 3600.0',
        '"sample_coverage_seconds": Infinity',
        1,
    )
    path.write_text(text, encoding="utf-8")
    assert not _valid_echo_live_acceptance(tmp_path, path)


def test_rss_field_nonfinite_fails(tmp_path: Path) -> None:
    path, payload = _base(tmp_path)
    processes = payload["resources"]["processes"]
    assert isinstance(processes, dict)
    for name in ("js_agent", "js_work"):
        processes[name]["peak_rss_mib"] = 12.0
    _resign(payload)
    _write(path, payload)
    text = path.read_text(encoding="utf-8").replace(
        '"peak_rss_mib": 12.0', '"peak_rss_mib": -Infinity', 1
    )
    path.write_text(text, encoding="utf-8")
    assert not _valid_echo_live_acceptance(tmp_path, path)


def test_monotonic_nonfinite_fails(tmp_path: Path) -> None:
    path, payload = _base(tmp_path)
    _resign(payload)
    _write(path, payload)
    text = path.read_text(encoding="utf-8")
    text = text.replace('"monotonic_s": 0.0', '"monotonic_s": NaN', 1)
    path.write_text(text, encoding="utf-8")
    assert not _valid_echo_live_acceptance(tmp_path, path)


def test_growth_and_both_coverage_nonfinite_fail(tmp_path: Path) -> None:
    path, payload = _base(tmp_path)
    _resign(payload)
    _write(path, payload)
    text = path.read_text(encoding="utf-8")
    # Second sample_coverage_seconds (Work) if present; else mutate growth field.
    if text.count('"sample_coverage_seconds": 3600.0') >= 2:
        text = text.replace(
            '"sample_coverage_seconds": 3600.0',
            '"sample_coverage_seconds": Infinity',
            2,
        )
        # undo first replacement leave second
        text = text.replace(
            '"sample_coverage_seconds": Infinity',
            '"sample_coverage_seconds": 3600.0',
            1,
        )
    elif '"growth_mib_per_minute"' in text:
        text = text.replace(
            '"growth_mib_per_minute": 0.0',
            '"growth_mib_per_minute": 1e9999',
            1,
        )
    else:
        text = text.replace(
            '"max_growth_mib_per_minute":',
            '"max_growth_mib_per_minute": Infinity, "_x":',
            1,
        )
    path.write_text(text, encoding="utf-8")
    assert not _valid_echo_live_acceptance(tmp_path, path)
