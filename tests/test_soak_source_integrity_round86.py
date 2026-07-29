from __future__ import annotations

import json
from pathlib import Path

from js.echo.ledger.release_gates import _valid_echo_live_acceptance, _valid_echo_slo_benchmark
from scripts.build_evidence_manifest import build_evidence_manifests
from scripts.echo_architecture_benchmark import _summary
from tests.echo.ledger.test_release_gates import _write_valid_stable_artifacts
from tests.test_soak_source_integrity_round85 import _minimal_release_tree, _valid_live_payload


def test_live_v3_recomputes_integrity_chain_and_process_tree(tmp_path: Path) -> None:
    _minimal_release_tree(tmp_path)
    path = tmp_path / "docs" / "security" / "ECHO_LIVE_ACCEPTANCE.json"
    payload = _valid_live_payload(tmp_path)
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert _valid_echo_live_acceptance(tmp_path, path)

    payload["source_integrity"]["check_count"] += 1
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert not _valid_echo_live_acceptance(tmp_path, path)

    payload = _valid_live_payload(tmp_path)
    payload["process_tree"]["children"]["js_work"]["ppid"] = 999
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert not _valid_echo_live_acceptance(tmp_path, path)


def test_summary_clamps_rounded_p95_to_max() -> None:
    summary = _summary([0.0004, 0.00049])
    assert float(summary["p95_ms"]) <= float(summary["max_ms"])


def test_slo_validator_rejects_p95_above_max(tmp_path: Path) -> None:
    _write_valid_stable_artifacts(tmp_path)
    path = tmp_path / "docs" / "security" / "ECHO_SLO_BENCHMARK.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    latency = payload["modes"]["echo"]["api_full_agent"]["latency"]
    latency["max_ms"] = float(latency["p95_ms"]) - 0.1
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert not _valid_echo_slo_benchmark(path)


def test_evidence_manifest_separates_history_and_failures(tmp_path: Path) -> None:
    (tmp_path / "current.json").write_text("current", encoding="utf-8")
    (tmp_path / "failure").mkdir()
    (tmp_path / "failure" / "receipt.json").write_text("failed", encoding="utf-8")
    (tmp_path / "historical").mkdir()
    (tmp_path / "historical" / "old.json").write_text("old", encoding="utf-8")

    current, historical = build_evidence_manifests(tmp_path)
    assert "current.json" in current.read_text(encoding="utf-8")
    assert "failure/" not in current.read_text(encoding="utf-8")
    assert "historical/" not in current.read_text(encoding="utf-8")
    assert historical is not None
    assert "old.json" in historical.read_text(encoding="utf-8")
