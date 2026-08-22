from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

from js.echo.ledger import release_gates as gates

if TYPE_CHECKING:
    import pytest


_SOURCE_DIGEST = "a" * 64
_METADATA_FINGERPRINT = "c" * 64
_COUNTER_KEYS = (
    "mode_switches",
    "app_restarts",
    "sidecar_recoveries",
    "ws_cancel_cycles",
    "r4_ops",
    "r6_ops",
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical_sha256(payload: dict[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _rechain_overlay(overlay: dict[str, Any]) -> None:
    chain = bytes(32)
    for heartbeat in overlay["heartbeats"]:
        heartbeat["prev_chain"] = chain.hex()
        unsigned = {key: value for key, value in heartbeat.items() if key != "chain"}
        chain = hashlib.sha256(
            json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).digest()
        heartbeat["chain"] = chain.hex()
    overlay["chain_root"] = chain.hex()


def _overlay_report(evidence: Path, bindings: dict[str, str]) -> dict[str, Any]:
    targets = {
        "mode_switches": 30,
        "app_restarts": 6,
        "sidecar_recoveries": 3,
        "ws_cancel_cycles": 30,
        "r4_ops": 12,
        "r6_ops": 12,
    }
    zeroes = dict.fromkeys(_COUNTER_KEYS, 0)
    base = datetime(2026, 8, 11, tzinfo=UTC)
    chain = bytes(32)
    heartbeats: list[dict[str, Any]] = []
    for index in range(721):
        elapsed = float(index * 5)
        counters = zeroes if index == 0 else targets
        payload: dict[str, Any] = {
            "index": index + 1,
            "monotonic_s": elapsed,
            "wall_utc": (base + timedelta(seconds=elapsed)).strftime(
                "%Y-%m-%dT%H:%M:%S.%fZ"
            ),
            "note": "overlay_start" if index == 0 else ("cycle_1_ok" if index == 1 else "soak_tick"),
            "counters": dict(counters),
            "source_digest": _SOURCE_DIGEST,
            "prev_chain": chain.hex(),
        }
        chain = hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).digest()
        payload["chain"] = chain.hex()
        heartbeats.append(payload)
    app = evidence / "desktop-build/artifacts/JS Agent.app"
    harness = (
        evidence
        / "harness/JS Agent UI Test Harness.app/Contents/MacOS/js-agent-ui-test-harness"
    )
    manifest = evidence / "desktop-build/manifest.json"
    return {
        "schema_version": "js-agent-tauri-overlay-v1",
        "ok": True,
        "started_utc": base.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "finished_utc": (base + timedelta(seconds=3600)).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ"
        ),
        "duration_seconds": 3600.0,
        "elapsed_seconds": 3600.0,
        "source_digest": _SOURCE_DIGEST,
        "metadata_fingerprint": _METADATA_FINGERPRINT,
        "acceptance_pid": 1234,
        "targets": targets,
        "counters": targets,
        "targets_met": True,
        "cycles": 1,
        "heartbeats": heartbeats,
        "heartbeat_count": len(heartbeats),
        "max_heartbeat_gap_s": 5.0,
        "max_heartbeat_gap_limit_s": 15.0,
        "chain_root": chain.hex(),
        "errors": [],
        "app_path": str(app.resolve()),
        "harness_exec": str(harness.resolve()),
        "desktop_manifest_path": str(manifest.resolve()),
        "desktop_manifest_sha256": bindings["desktop_manifest_sha256"],
        "app_tree_sha256": bindings["app_tree_sha256"],
        "app_sha256": bindings["app_sha256"],
    }


def _combined_report(
    *, core_raw: Path, overlay_raw: Path, overlay: dict[str, Any]
) -> dict[str, Any]:
    combined: dict[str, Any] = {
        "schema_version": "js-agent-supervised-soak-v1",
        "ok": True,
        "started_utc": overlay["started_utc"],
        "finished_utc": overlay["finished_utc"],
        "duration_seconds": 3600.0,
        "elapsed_seconds": 3600.0,
        "source_digest": _SOURCE_DIGEST,
        "metadata_fingerprint": _METADATA_FINGERPRINT,
        "core": {
            "exit_code": 0,
            "raw_sha256": _sha256(core_raw),
            "ok": True,
        },
        "overlay": {
            "exit_code": 0,
            "raw_sha256": _sha256(overlay_raw),
            "ok": True,
            "targets": overlay["targets"],
            "counters": overlay["counters"],
            "targets_met": True,
            "cycles": overlay["cycles"],
            "heartbeat_count": overlay["heartbeat_count"],
            "max_heartbeat_gap_s": overlay["max_heartbeat_gap_s"],
            "max_heartbeat_gap_limit_s": overlay["max_heartbeat_gap_limit_s"],
            "chain_root": overlay["chain_root"],
            "desktop_manifest_sha256": overlay["desktop_manifest_sha256"],
            "app_tree_sha256": overlay["app_tree_sha256"],
            "app_sha256": overlay["app_sha256"],
        },
    }
    combined["combined_sha256"] = _canonical_sha256(combined)
    return combined


def _fixture(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> tuple[Path, Path, Path, dict[str, Any], dict[str, str]]:
    root = (tmp_path / "repo").resolve()
    evidence = (tmp_path / "evidence").resolve()
    root.mkdir()
    manifest = evidence / "desktop-build/manifest.json"
    manifest.parent.mkdir(parents=True)
    manifest.write_bytes(b"fresh-manifest")
    bindings = {
        "app_sha256": "1" * 64,
        "app_tree_sha256": "2" * 64,
        "desktop_manifest_sha256": _sha256(manifest),
        "bundle_identifier": "com.titan.js-agent",
    }
    core_raw = evidence / "soak/echo_core_soak.raw.json"
    _write_json(core_raw, {"fixture": "valid-core"})
    overlay = _overlay_report(evidence, bindings)
    overlay_raw = evidence / "soak/tauri_overlay.raw.json"
    _write_json(overlay_raw, overlay)
    combined = _combined_report(core_raw=core_raw, overlay_raw=overlay_raw, overlay=overlay)
    combined_path = evidence / "soak/supervised_soak.combined.json"
    _write_json(combined_path, combined)

    monkeypatch.setattr(gates, "release_source_digest", lambda _root: _SOURCE_DIGEST)
    monkeypatch.setattr(
        gates,
        "release_source_surface_metadata_fingerprint",
        lambda _root: _METADATA_FINGERPRINT,
    )
    monkeypatch.setattr(gates, "_valid_echo_live_acceptance", lambda _root, path: path == core_raw)
    monkeypatch.setattr(
        "scripts.run_tauri_webview_gate._manifest_bindings",
        lambda **_kwargs: dict(bindings),
    )
    return root, evidence, combined_path, combined, bindings


def test_soak_receipt_artifact_is_sanitized_combined_without_changing_gate_argv(
    tmp_path: Path,
) -> None:
    root = (tmp_path / "repo").resolve()
    evidence = (tmp_path / "evidence").resolve()
    root.mkdir()
    spec = gates.get_local_gate_spec("soak_3600", evidence_dir=evidence)
    assert spec is not None
    original_argv = (
        ".venv/bin/python",
        "-u",
        "scripts/run_supervised_soak.py",
        "--duration-seconds",
        "3600",
        "--concurrency",
        "2",
        "--output",
        f"{gates._REPO_ROOT_TOKEN}/docs/security/ECHO_LIVE_ACCEPTANCE.json",
        "--evidence-dir",
        gates._EVIDENCE_DIR_TOKEN,
        "--app-path",
        f"{gates._EVIDENCE_DIR_TOKEN}/desktop-build/artifacts/JS Agent.app",
        "--harness-path",
        f"{gates._EVIDENCE_DIR_TOKEN}/harness/JS Agent UI Test Harness.app",
    )
    assert spec.argv == original_argv

    artifact = gates._artifact_path_from_argv(
        original_argv,
        spec,
        root=root,
        evidence_dir=evidence,
        source_digest=_SOURCE_DIGEST,
    )

    assert artifact == evidence / "soak/supervised_soak.combined.json"


def test_formal_validator_recomputes_combined_raw_chain_and_desktop_bindings(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root, evidence, combined_path, combined, _ = _fixture(monkeypatch, tmp_path)
    spec = gates.get_local_gate_spec("soak_3600", evidence_dir=evidence)
    assert spec is not None

    assert gates._valid_supervised_soak_artifact(
        root=root,
        evidence_dir=evidence,
        path=combined_path,
        expected_source_digest=_SOURCE_DIGEST,
    )
    assert gates._valid_gate_artifact(
        spec,
        root=root,
        evidence_dir=evidence,
        argv=spec.argv,
        source_digest=_SOURCE_DIGEST,
        artifact_sha256=_sha256(combined_path),
    )

    serialized = combined_path.read_text(encoding="utf-8")
    assert str(tmp_path) not in serialized
    assert "nonce" not in serialized.lower()
    assert "pid" not in serialized.lower()

    combined["overlay"]["app_tree_sha256"] = "9" * 64
    combined["combined_sha256"] = _canonical_sha256(
        {key: value for key, value in combined.items() if key != "combined_sha256"}
    )
    _write_json(combined_path, combined)
    assert not gates._valid_supervised_soak_artifact(
        root=root,
        evidence_dir=evidence,
        path=combined_path,
        expected_source_digest=_SOURCE_DIGEST,
    )


def test_formal_validator_rejects_resealed_overlay_chain_tampering(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root, evidence, combined_path, combined, _ = _fixture(monkeypatch, tmp_path)
    overlay_path = evidence / "soak/tauri_overlay.raw.json"
    overlay = json.loads(overlay_path.read_text(encoding="utf-8"))
    overlay["heartbeats"][10]["chain"] = "f" * 64
    _write_json(overlay_path, overlay)
    combined["overlay"]["raw_sha256"] = _sha256(overlay_path)
    combined["combined_sha256"] = _canonical_sha256(
        {key: value for key, value in combined.items() if key != "combined_sha256"}
    )
    _write_json(combined_path, combined)

    assert not gates._valid_supervised_soak_artifact(
        root=root,
        evidence_dir=evidence,
        path=combined_path,
        expected_source_digest=_SOURCE_DIGEST,
    )


def test_formal_validator_rejects_rechained_compressed_wall_clock(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root, evidence, combined_path, combined, _ = _fixture(monkeypatch, tmp_path)
    overlay_path = evidence / "soak/tauri_overlay.raw.json"
    overlay = json.loads(overlay_path.read_text(encoding="utf-8"))
    for heartbeat in overlay["heartbeats"]:
        heartbeat["wall_utc"] = overlay["started_utc"]
    _rechain_overlay(overlay)
    _write_json(overlay_path, overlay)
    combined["overlay"]["raw_sha256"] = _sha256(overlay_path)
    combined["overlay"]["chain_root"] = overlay["chain_root"]
    combined["combined_sha256"] = _canonical_sha256(
        {key: value for key, value in combined.items() if key != "combined_sha256"}
    )
    _write_json(combined_path, combined)

    assert not gates._valid_supervised_soak_artifact(
        root=root,
        evidence_dir=evidence,
        path=combined_path,
        expected_source_digest=_SOURCE_DIGEST,
    )
