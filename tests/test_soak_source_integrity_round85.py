"""Round 8.5 Task E: soak source-integrity + acceptance_pid binding."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import math
import os
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import ModuleType

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from js.echo.ledger.release_gates import (
    _valid_echo_live_acceptance,
    release_source_digest,
    release_source_surface_metadata_fingerprint,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "echo_live_acceptance.py"


def _harness_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("echo_live_acceptance_integrity_test", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _minimal_release_tree(root: Path) -> None:
    for relative in (
        "LICENSE",
        "README.md",
        "ORIGIN_LEDGER.md",
        "THIRD_PARTY_NOTICES.md",
        "pyproject.toml",
        "uv.lock",
        "Dockerfile",
        ".gitignore",
    ):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"{relative}\n", encoding="utf-8")
    for dirname in ("js", "js_work", "scripts", "tests", "benchmarks", "resources", ".github"):
        (root / dirname).mkdir(parents=True, exist_ok=True)
    (root / "js" / "marker.py").write_text("x = 1\n", encoding="utf-8")
    (root / ".github" / "CODEOWNERS").write_text("* @echo\n", encoding="utf-8")
    for relative in (
        "docs/adr/0001-echo-ledger-boundary.md",
        "docs/echo/ECHO_10_ROUND_AUDIT.md",
        "docs/echo/ECHO_FINAL_REPLACEMENT_REPORT.md",
        "docs/echo/ECHO_SELF_DEVELOPED_BOUNDARY.md",
        "docs/echo/ECHO_UNIFIED_EXECUTION_CONTRACT.md",
        "docs/rfc/echo-ledger-major-change-template.md",
        "docs/security/ECHO_BASELINE_65CC545.json",
        "docs/security/LICENSE_SCAN.md",
        "docs/security/SBOM.spdx.json",
    ):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"{relative}\n", encoding="utf-8")


def test_release_source_surface_metadata_fingerprint_stable_then_changes_on_mtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from js.echo.ledger import release_gates as rg

    _minimal_release_tree(tmp_path)
    monkeypatch.setattr(
        rg,
        "_RELEASE_SOURCE_DIGEST_SURFACES",
        (
            Path("LICENSE"),
            Path("js"),
            Path("pyproject.toml"),
        ),
    )
    monkeypatch.setattr(rg, "_RELEASE_SOURCE_DIGEST_EXCLUDE", frozenset())

    first = release_source_surface_metadata_fingerprint(tmp_path)
    second = release_source_surface_metadata_fingerprint(tmp_path)
    assert first == second
    assert len(first) == 64
    assert all(ch in "0123456789abcdef" for ch in first)

    target = tmp_path / "js" / "marker.py"
    time.sleep(0.02)
    target.write_text("x = 2\n# grown\n", encoding="utf-8")
    os.utime(target, ns=(time.time_ns(), time.time_ns()))
    third = release_source_surface_metadata_fingerprint(tmp_path)
    assert third != first


def test_run_soak_aborts_on_source_digest_drift(monkeypatch: pytest.MonkeyPatch) -> None:
    harness = _harness_module()
    products = [object()]
    digest_calls = {"n": 0}
    stable_meta = "a" * 64
    digests = ["b" * 64, "b" * 64, "c" * 64]

    def fake_digest(_root: Path) -> str:
        idx = min(digest_calls["n"], len(digests) - 1)
        digest_calls["n"] += 1
        return digests[idx]

    def fake_meta(_root: Path) -> str:
        return stable_meta

    def fake_soak_one(product: object, index: int, provider_port: int) -> dict[str, object]:
        del product, provider_port
        identity = f"product:request-{index}"
        return {
            "product": "product",
            "request_id": f"request-{index}",
            "expected_identity": identity,
            "http_status": 200,
            "http_identity": identity,
            "ws_identity": identity,
            "terminal_frames": ["done"],
            "ws_errors": 0,
        }

    monkeypatch.setattr(harness, "release_source_digest", fake_digest)
    monkeypatch.setattr(harness, "release_source_surface_metadata_fingerprint", fake_meta)
    monkeypatch.setattr(harness, "RESOURCE_SAMPLE_INTERVAL_SECONDS", 0.05)
    monkeypatch.setattr(harness, "_soak_one", fake_soak_one)
    monkeypatch.setattr(
        harness,
        "_provider_stats",
        lambda _port: {
            "chat_calls": 1,
            "interactive_calls": 1,
            "background_calls": 0,
            "identities": {},
            "primary_identities": {},
        },
    )
    monkeypatch.setattr(
        harness,
        "_provider_evidence",
        lambda _stats: {"classification_complete": True},
    )

    with pytest.raises(harness.AcceptanceError, match="source digest drift during soak") as caught:
        harness._run_soak(
            products,
            provider_port=9,
            duration_seconds=2.0,
            concurrency=1,
        )

    soak_result = getattr(caught.value, "soak_result", None)
    assert isinstance(soak_result, dict)
    integrity = soak_result["source_integrity"]
    assert integrity["drifted"] is True
    assert integrity["ok"] is False
    assert integrity["check_count"] >= 2


def test_live_acceptance_short_mode_binds_pid_and_source_integrity(tmp_path: Path) -> None:
    output = tmp_path / "live-acceptance.json"
    import subprocess

    proc = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--duration-seconds",
            "1",
            "--concurrency",
            "1",
            "--output",
            str(output),
        ],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        timeout=90,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    report = json.loads(output.read_text(encoding="utf-8"))
    assert isinstance(report.get("acceptance_pid"), int)
    assert not isinstance(report["acceptance_pid"], bool)
    assert report["acceptance_pid"] > 0
    integrity = report["source_integrity"]
    assert integrity["ok"] is True
    assert integrity["drifted"] is False
    assert isinstance(integrity["check_count"], int) and integrity["check_count"] > 0
    assert integrity["expected_digest"] == report["source_digest"]
    assert integrity["final_digest"] == release_source_digest(REPO_ROOT)
    assert integrity["expected_metadata_fingerprint"] == integrity["final_metadata_fingerprint"]
    assert len(integrity["expected_metadata_fingerprint"]) == 64


def _resign_live_payload(payload: dict[str, object]) -> None:
    private_key = Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(b"js-agent-round87-soak-integrity-signing-key-v1").digest()
    )
    public_raw = private_key.public_key().public_bytes_raw()
    integrity = payload["source_integrity"]
    assert isinstance(integrity, dict)
    checks = integrity["checks"]
    assert isinstance(checks, list)
    source_root = bytes(32)
    for index, check in enumerate(checks, start=1):
        assert isinstance(check, dict)
        check["index"] = index
        canonical = json.dumps(
            {
                "index": index,
                "metadata_fingerprint": check["metadata_fingerprint"],
                "monotonic_s": check["monotonic_s"],
                "source_digest": check["source_digest"],
                "wall_utc": check.get("wall_utc"),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        source_root = hashlib.sha256(source_root + canonical).digest()
    resources = payload["resources"]
    storage = payload["storage_stability"]
    assert isinstance(resources, dict) and isinstance(storage, dict)
    resource_samples = resources["samples"]
    storage_samples = storage["samples"]
    resource_root = hashlib.sha256(
        json.dumps(
            resource_samples,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode()
    ).hexdigest()
    storage_root = hashlib.sha256(
        json.dumps(
            storage_samples,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode()
    ).hexdigest()
    binding_version = "echo-live-resource-samples-v1"
    binding = {
        "binding_version": binding_version,
        "resource_sample_count": len(resource_samples),
        "resource_sample_root": resource_root,
        "storage_sample_count": len(storage_samples),
        "storage_sample_root": storage_root,
    }
    chain_root = hashlib.sha256(
        source_root
        + json.dumps(binding, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    integrity.update(
        {
            "check_count": len(checks),
            "source_check_chain_root": source_root.hex(),
            "resource_sample_count": len(resource_samples),
            "resource_sample_root": resource_root,
            "storage_sample_count": len(storage_samples),
            "storage_sample_root": storage_root,
            "chain_root": chain_root,
            "chain_binding": binding_version,
            "chain_root_signature_b64": base64.b64encode(
                private_key.sign(chain_root.encode("ascii"))
            ).decode(),
            "pubkey_fingerprint": hashlib.sha256(public_raw).hexdigest(),
        }
    )


def _valid_live_payload(root: Path) -> dict[str, object]:
    from scripts import echo_live_acceptance as live

    private_key = Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(b"js-agent-round87-soak-integrity-signing-key-v1").digest()
    )
    public_raw = private_key.public_key().public_bytes_raw()
    frozen_path = root / "docs" / "security" / "ECHO_SOAK_INTEGRITY_PUBKEY.json"
    frozen_path.parent.mkdir(parents=True, exist_ok=True)
    frozen_path.write_text(
        json.dumps(
            {
                "schema_version": "echo-soak-integrity-pubkey-v1",
                "algorithm": "Ed25519",
                "public_key_b64": base64.b64encode(public_raw).decode(),
                "fingerprint_sha256": hashlib.sha256(public_raw).hexdigest(),
            }
        ),
        encoding="utf-8",
    )
    digest = release_source_digest(root)
    meta = release_source_surface_metadata_fingerprint(root)
    duration = 3600.0
    check_count = math.floor(duration / 5) + 1
    started = datetime(2026, 7, 24, 0, 0, 0, tzinfo=UTC)
    checks: list[dict[str, object]] = []
    chain_root = bytes(32)
    for index in range(1, check_count + 1):
        check = {
            "index": index,
            "source_digest": digest,
            "metadata_fingerprint": meta,
            "monotonic_s": float((index - 1) * 5),
            "wall_utc": (started + timedelta(seconds=(index - 1) * 5))
            .isoformat()
            .replace("+00:00", "Z"),
        }
        checks.append(check)
        canonical = json.dumps(check, sort_keys=True, separators=(",", ":")).encode()
        chain_root = hashlib.sha256(chain_root + canonical).digest()
    mib = 1024 * 1024
    resource_samples = [
        {
            "elapsed_seconds": float(second),
            "rss_bytes": {
                "js_agent": 100 * mib,
                "js_work": 120 * mib,
            },
            "process_counts": {"js_agent": 1, "js_work": 1},
            "storage": {
                product: {
                    "total_bytes": 32 * mib,
                    "file_count": 10,
                    "partition_storage_bytes": 4 * mib,
                    "partition_file_count": 2,
                    "max_active_session_partitions_per_owner": 4,
                    "retired_session_partition_count": 0,
                    "retention_checkpoint_bytes": 0,
                    "retention_checkpoint_errors": [],
                    "incomplete_retirements": [],
                    "incomplete_retirement_markers": [],
                    "component_bytes": {
                        "audit": 0,
                        "compression_feedback": 0,
                        "learning": 0,
                        "lifecycle": 0,
                        "memory_enhanced": 0,
                        "metacognition": 0,
                        "prompt_optimization": 0,
                        "quality": 0,
                        "review_capsules": 0,
                        "token_stats": 0,
                        "echo_partitions": 4 * mib,
                        "events": 0,
                        "other": 28 * mib,
                    },
                }
                for product in ("js_agent", "js_work")
            },
        }
        for second in range(0, 3601, 5)
    ]
    resource_summary = live._summarize_resource_samples(
        resource_samples,
        duration_seconds=duration,
        max_rss_bytes=live.DEFAULT_MAX_RSS_BYTES,
        max_growth_mib_per_minute=live.DEFAULT_MAX_RSS_GROWTH_MIB_PER_MINUTE,
        required_processes=("js_agent", "js_work"),
    )
    resource_summary["processes"]["js_agent"]["pid"] = 4301
    resource_summary["processes"]["js_work"]["pid"] = 4302
    storage_summary = live._summarize_storage_samples(
        resource_samples,
        duration_seconds=duration,
        max_state_bytes=live.DEFAULT_MAX_STATE_BYTES,
        required_products=("js_agent", "js_work"),
    )
    payload: dict[str, object] = {
        "schema_version": "echo-live-acceptance-v4",
        "started_utc": started.isoformat().replace("+00:00", "Z"),
        "finished_utc": (started + timedelta(seconds=duration + 1))
        .isoformat()
        .replace("+00:00", "Z"),
        "source_digest": digest,
        "acceptance_pid": 4242,
        "process_tree": {
            "wrapper": {"pid": 4241, "ppid": 1, "create_time": started.timestamp() - 1},
            "acceptance": {"pid": 4242, "ppid": 4241, "create_time": started.timestamp()},
            "children": {
                name: {
                    "pid": 4300 + index,
                    "ppid": 4242,
                    "create_time": started.timestamp() + 1 + index,
                }
                for index, name in enumerate(("fake-provider", "js_agent", "js_work"))
            },
        },
        "ok": True,
        "duration_seconds": duration,
        "concurrency": 4,
        "max_state_bytes": live.DEFAULT_MAX_STATE_BYTES,
        "max_session_partitions_per_owner": live.DEFAULT_MAX_SESSION_PARTITIONS_PER_OWNER,
        "max_rss_bytes": live.DEFAULT_MAX_RSS_BYTES,
        "max_rss_growth_mib_per_minute": live.DEFAULT_MAX_RSS_GROWTH_MIB_PER_MINUTE,
        "network": "local-only",
        "products": {
            product: {
                "status_primary_healthy": True,
                "chat": True,
                "stream": True,
                "tool_continue": True,
                "attachment": True,
                "cross_owner_rejected": True,
                "secret_rejected": True,
                "cancel": True,
                "provider_error_single_terminal": True,
                "storage_within_limit": True,
            }
            for product in ("js_agent", "js_work")
        },
        "provider": {"classification_complete": True},
        "soak": {
            "requested_seconds": duration,
            "active_elapsed_seconds": duration,
            "sample_count": 100,
            "success": 100,
            "failures": 0,
            "crosstalk": 0,
            "http_5xx": 0,
            "terminal": {"done": 100, "error": 0},
        },
        "resources": resource_summary,
        "storage_stability": storage_summary,
        "source_integrity": {
            "ok": True,
            "drifted": False,
            "check_count": check_count,
            "expected_digest": digest,
            "final_digest": digest,
            "expected_metadata_fingerprint": meta,
            "final_metadata_fingerprint": meta,
            "checks": checks,
            "chain_root": chain_root.hex(),
            "chain_root_signature_b64": "",
            "pubkey_fingerprint": "",
        },
        "cleanup": {
            "all_processes_stopped": True,
            "graceful": True,
            "errors": [],
            "children": {
                child: {
                    "stopped": True,
                    "forced_kill": False,
                    "stop_error": None,
                }
                for child in ("fake-provider", "js_agent", "js_work")
            },
        },
    }
    _resign_live_payload(payload)
    return payload


def test_valid_echo_live_acceptance_rejects_pid_and_integrity_faults(
    tmp_path: Path,
) -> None:
    _minimal_release_tree(tmp_path)
    artifact = tmp_path / "docs" / "security" / "ECHO_LIVE_ACCEPTANCE.json"
    artifact.parent.mkdir(parents=True, exist_ok=True)

    payload = _valid_live_payload(tmp_path)
    artifact.write_text(json.dumps(payload), encoding="utf-8")
    assert _valid_echo_live_acceptance(tmp_path, artifact)

    payload = _valid_live_payload(tmp_path)
    payload["acceptance_pid"] = True
    artifact.write_text(json.dumps(payload), encoding="utf-8")
    assert not _valid_echo_live_acceptance(tmp_path, artifact)

    payload = _valid_live_payload(tmp_path)
    payload["acceptance_pid"] = 0
    artifact.write_text(json.dumps(payload), encoding="utf-8")
    assert not _valid_echo_live_acceptance(tmp_path, artifact)

    payload = _valid_live_payload(tmp_path)
    payload.pop("source_integrity")
    artifact.write_text(json.dumps(payload), encoding="utf-8")
    assert not _valid_echo_live_acceptance(tmp_path, artifact)

    payload = _valid_live_payload(tmp_path)
    integrity = payload["source_integrity"]
    assert isinstance(integrity, dict)
    integrity["drifted"] = True
    integrity["ok"] = False
    artifact.write_text(json.dumps(payload), encoding="utf-8")
    assert not _valid_echo_live_acceptance(tmp_path, artifact)

    payload = _valid_live_payload(tmp_path)
    integrity = payload["source_integrity"]
    assert isinstance(integrity, dict)
    integrity["check_count"] = 1
    artifact.write_text(json.dumps(payload), encoding="utf-8")
    assert not _valid_echo_live_acceptance(tmp_path, artifact)
