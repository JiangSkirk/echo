from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from js.echo.ledger.release_gates import (
    REQUIRED_FINAL_LOCAL_GATES,
    _valid_echo_live_acceptance,
    get_local_gate_spec,
)
from tests.test_soak_source_integrity_round85 import (
    _minimal_release_tree,
    _resign_live_payload,
    _valid_live_payload,
)


def _write_payload(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_round815_targeted_gate_is_the_required_current_gate() -> None:
    assert "pytest_targeted_round815" in REQUIRED_FINAL_LOCAL_GATES
    assert "pytest_targeted_round813" not in REQUIRED_FINAL_LOCAL_GATES
    spec = get_local_gate_spec("pytest_targeted_round815", evidence_dir=Path("/tmp/evidence"))
    expected_tests = {
        "tests/test_baseline_provenance_round815.py",
        "tests/test_release_validator_resource_round815.py",
        "tests/test_source_integrity_preflight_round815.py",
        "tests/work/test_work_output_staging_round815.py",
        "tests/work/test_work_report_rollback_round815.py",
        "tests/work/test_work_shared_office_snapshot_round815.py",
    }
    assert expected_tests.issubset(set(spec.argv))


def _artifact(tmp_path: Path) -> tuple[Path, dict[str, Any]]:
    _minimal_release_tree(tmp_path)
    path = tmp_path / "docs/security/ECHO_LIVE_ACCEPTANCE.json"
    payload = _valid_live_payload(tmp_path)
    _write_payload(path, payload)
    assert _valid_echo_live_acceptance(tmp_path, path)
    return path, payload


def _delete_path(payload: dict[str, Any], path: Sequence[str]) -> None:
    target: Any = payload
    for component in path[:-1]:
        target = target[component]
    del target[path[-1]]


@pytest.mark.parametrize(
    "field_path",
    [
        ("max_rss_bytes",),
        ("max_rss_growth_mib_per_minute",),
        ("max_state_bytes",),
        ("resources", "samples"),
        ("resources", "recorded_sample_count"),
        ("resources", "processes", "js_agent", "sample_count"),
        ("resources", "processes", "js_agent", "required_sample_count"),
        ("resources", "processes", "js_agent", "sample_coverage_seconds"),
        ("resources", "processes", "js_agent", "peak_rss_mib"),
        ("resources", "processes", "js_agent", "start_rss_mib"),
        ("resources", "processes", "js_agent", "final_rss_mib"),
        ("resources", "processes", "js_agent", "growth_mib_per_minute"),
        ("resources", "processes", "js_agent", "tail_growth_mib_per_minute"),
        ("resources", "processes", "js_agent", "plateau_growth_mib"),
        ("resources", "processes", "js_agent", "max_sample_gap_seconds"),
        ("resources", "processes", "js_agent", "sample_integrity_ok"),
        ("resources", "processes", "js_agent", "stability_window_start_seconds"),
        ("resources", "processes", "js_agent", "minute_medians"),
        ("resources", "processes", "js_agent", "peak_within_limit"),
        ("resources", "processes", "js_agent", "growth_within_limit"),
        ("resources", "max_plateau_growth_mib"),
        ("resources", "sample_interval_seconds"),
        ("resources", "max_sample_gap_seconds"),
        ("resources", "min_sample_ratio"),
        ("storage_stability",),
        ("storage_stability", "samples"),
        ("storage_stability", "products", "js_agent", "sample_count"),
        ("storage_stability", "products", "js_agent", "required_sample_count"),
        ("storage_stability", "products", "js_agent", "sample_coverage_seconds"),
        ("storage_stability", "products", "js_agent", "peak_total_mib"),
        ("storage_stability", "products", "js_agent", "start_total_mib"),
        ("storage_stability", "products", "js_agent", "final_total_mib"),
        ("storage_stability", "products", "js_agent", "total_growth_mib_per_minute"),
        ("storage_stability", "products", "js_agent", "partition_growth_mib_per_minute"),
        ("storage_stability", "products", "js_agent", "total_plateau_growth_mib"),
        ("storage_stability", "products", "js_agent", "partition_plateau_growth_mib"),
        ("storage_stability", "products", "js_agent", "max_sample_gap_seconds"),
        ("storage_stability", "products", "js_agent", "sample_integrity_ok"),
        ("storage_stability", "products", "js_agent", "component_growth"),
        ("storage_stability", "products", "js_agent", "bounds_within_limit"),
        ("storage_stability", "products", "js_agent", "growth_within_limit"),
        ("storage_stability", "max_total_growth_mib_per_minute"),
        ("storage_stability", "max_partition_growth_mib_per_minute"),
        ("storage_stability", "max_total_plateau_growth_mib"),
        ("storage_stability", "max_partition_plateau_growth_mib"),
        ("storage_stability", "max_active_session_partitions_per_owner"),
    ],
)
def test_live_artifact_rejects_missing_canonical_resource_field(
    tmp_path: Path,
    field_path: tuple[str, ...],
) -> None:
    path, payload = _artifact(tmp_path)
    _delete_path(payload, field_path)
    _write_payload(path, payload)

    assert not _valid_echo_live_acceptance(tmp_path, path)


@pytest.mark.parametrize(
    ("field_path", "value"),
    [
        (("resources", "processes", "js_agent", "peak_rss_mib"), 999_999.0),
        (("resources", "processes", "js_agent", "growth_mib_per_minute"), 999_999.0),
        (("resources", "processes", "js_agent", "plateau_growth_mib"), 999_999.0),
        (("resources", "processes", "js_agent", "peak_within_limit"), 1),
        (("storage_stability", "products", "js_agent", "peak_total_mib"), 999_999.0),
        (
            ("storage_stability", "products", "js_agent", "total_growth_mib_per_minute"),
            999_999.0,
        ),
        (
            ("storage_stability", "products", "js_agent", "partition_plateau_growth_mib"),
            999_999.0,
        ),
        (("storage_stability", "products", "js_agent", "growth_within_limit"), 1),
    ],
)
def test_live_artifact_rejects_tampered_resource_summary(
    tmp_path: Path,
    field_path: tuple[str, ...],
    value: object,
) -> None:
    path, payload = _artifact(tmp_path)
    target: Any = payload
    for component in field_path[:-1]:
        target = target[component]
    target[field_path[-1]] = value
    _write_payload(path, payload)

    assert not _valid_echo_live_acceptance(tmp_path, path)


def test_live_artifact_rejects_tampered_minute_bucket(tmp_path: Path) -> None:
    path, payload = _artifact(tmp_path)
    payload["resources"]["processes"]["js_agent"]["minute_medians"][0]["rss_mib"] += 1
    _write_payload(path, payload)

    assert not _valid_echo_live_acceptance(tmp_path, path)


def test_live_artifact_rejects_boolean_minute_bucket(tmp_path: Path) -> None:
    path, payload = _artifact(tmp_path)
    payload["resources"]["processes"]["js_agent"]["minute_medians"][0]["rss_mib"] = True
    _write_payload(path, payload)

    assert not _valid_echo_live_acceptance(tmp_path, path)


def test_live_artifact_rejects_boolean_or_gapped_raw_samples(tmp_path: Path) -> None:
    path, payload = _artifact(tmp_path)
    samples = payload["resources"]["samples"]
    samples[0]["rss_bytes"]["js_agent"] = True
    samples.pop(len(samples) // 2)
    payload["storage_stability"]["samples"] = samples
    _resign_live_payload(payload)
    _write_payload(path, payload)

    assert not _valid_echo_live_acceptance(tmp_path, path)


def test_live_artifact_rejects_threshold_mismatch(tmp_path: Path) -> None:
    path, payload = _artifact(tmp_path)
    payload["resources"]["max_rss_bytes"] += 1
    _write_payload(path, payload)

    assert not _valid_echo_live_acceptance(tmp_path, path)


@pytest.mark.parametrize(
    "field_path",
    [
        ("elapsed_seconds",),
        ("rss_bytes", "js_agent"),
        ("process_counts", "js_agent"),
        ("storage", "js_agent", "total_bytes"),
        ("storage", "js_agent", "partition_storage_bytes"),
        ("storage", "js_agent", "max_active_session_partitions_per_owner"),
        ("storage", "js_agent", "retention_checkpoint_errors"),
        ("storage", "js_agent", "incomplete_retirements"),
        ("storage", "js_agent", "component_bytes"),
    ],
)
def test_live_artifact_rejects_missing_raw_sample_field(
    tmp_path: Path,
    field_path: tuple[str, ...],
) -> None:
    path, payload = _artifact(tmp_path)
    sample = payload["resources"]["samples"][0]
    target: Any = sample
    for component in field_path[:-1]:
        target = target[component]
    del target[field_path[-1]]
    payload["storage_stability"]["samples"] = payload["resources"]["samples"]
    _resign_live_payload(payload)
    _write_payload(path, payload)

    assert not _valid_echo_live_acceptance(tmp_path, path)


def test_live_artifact_recomputes_peak_from_resigned_raw_samples(tmp_path: Path) -> None:
    path, payload = _artifact(tmp_path)
    samples = payload["resources"]["samples"]
    samples[len(samples) // 2]["rss_bytes"]["js_agent"] = 600 * 1024 * 1024
    payload["storage_stability"]["samples"] = samples
    _resign_live_payload(payload)
    _write_payload(path, payload)

    assert not _valid_echo_live_acceptance(tmp_path, path)


def test_live_artifact_recomputes_storage_peak_from_resigned_raw_samples(
    tmp_path: Path,
) -> None:
    path, payload = _artifact(tmp_path)
    samples = payload["resources"]["samples"]
    evidence = samples[len(samples) // 2]["storage"]["js_agent"]
    evidence["total_bytes"] = 600 * 1024 * 1024
    evidence["component_bytes"]["other"] = 596 * 1024 * 1024
    payload["storage_stability"]["samples"] = samples
    _resign_live_payload(payload)
    _write_payload(path, payload)

    assert not _valid_echo_live_acceptance(tmp_path, path)
