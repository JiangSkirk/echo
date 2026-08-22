from __future__ import annotations

import base64
import copy
import hashlib
import importlib.metadata
import json
import pathlib
import platform
import subprocess
import sys
from functools import lru_cache

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from js.echo.ledger.release_gates import (
    _canonical_external_approval_payload,
    _has_unresolved_artifact_marker,
    _valid_echo_live_acceptance,
    _valid_echo_slo_benchmark,
    release_source_digest,
    verify_echo_ip_boundary,
    verify_release_readiness,
)
from js.echo.ledger.slo_contract import SLO_CONTRACT

_OLD_BASELINE_COMMIT = "65cc545e3ec893f5bab62d356514643f14456a58"
_OLD_BASELINE_TREE = "679b1172facba3f13af6b32e70bd6b815138ef13"
_OLD_BASELINE_SOURCE_DIGEST = "3774de07b6652deeef91535a11730da860bf2d8572a81374c07d0b258b4effe5"
_OLD_BASELINE_UV_LOCK_SHA256 = "ff448bc032a8bf5dc4dd85ddaf3e1b495a95acd1f9ac9a5a7dae83dd94a0c1c8"
_OLD_BASELINE_IMPORT_ROOT_SHA256 = (
    "52ca898f824bc6698dce23993fa86adfa9c3a56125f799eeda72ebcb8b5991f0"
)
_OLD_BASELINE_CORPUS_SHA256 = "1830b820b332faa5ef506b2fe3567d4dd8bf4fdcf2a3ed6a6fb682e9d9d0e039"
_TOKENIZER_METHOD = "tiktoken_cl100k_base_canonical_json"
_TOKENIZER_ENCODING = "cl100k_base"


def _attach_old_commit_object_store(root: pathlib.Path) -> None:
    """Make the real immutable old commit readable from a disposable test repository."""
    source_root = pathlib.Path(__file__).resolve().parents[3]
    object_path = subprocess.run(
        ["git", "rev-parse", "--path-format=absolute", "--git-path", "objects"],
        cwd=source_root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    subprocess.run(["git", "init", "--quiet"], cwd=root, check=True)
    alternates = root / ".git" / "objects" / "info" / "alternates"
    alternates.parent.mkdir(parents=True, exist_ok=True)
    alternates.write_text(str(pathlib.Path(object_path).resolve()) + "\n", encoding="utf-8")


def _old_baseline_payload(
    root: pathlib.Path,
    *,
    baseline_script_sha256: str,
    tokenizer_sha256: str,
) -> dict[str, object]:
    measured_root = pathlib.Path("/detached/echo-old-baseline")
    import_root = measured_root / "js" / "__init__.py"
    markers = [f"benchmark long history message {index}" for index in range(40)]
    marker_counts = dict.fromkeys(markers, 1)
    marker_sha256 = hashlib.sha256(
        json.dumps(markers, ensure_ascii=False, separators=(",", ":")).encode()
    ).hexdigest()
    empty_marker_sha256 = hashlib.sha256(b"[]").hexdigest()
    run_summaries: list[dict[str, object]] = []
    for group in range(1, 6):
        long_receipts = [
            {
                "message_count": 42,
                "history_marker_count": 40,
                "history_marker_counts": marker_counts,
                "history_marker_sha256": marker_sha256,
                "message_identity_sha256": hashlib.sha256(
                    f"long-message-{group}-{index}".encode()
                ).hexdigest(),
                "provider_payload_sha256": hashlib.sha256(
                    f"long-payload-{group}-{index}".encode()
                ).hexdigest(),
            }
            for index in range(50)
        ]
        short_receipts = [
            {
                "message_count": 2,
                "history_marker_count": 0,
                "history_marker_counts": {},
                "history_marker_sha256": empty_marker_sha256,
                "message_identity_sha256": hashlib.sha256(
                    f"short-message-{group}-{index}".encode()
                ).hexdigest(),
                "provider_payload_sha256": hashlib.sha256(
                    f"short-payload-{group}-{index}".encode()
                ).hexdigest(),
            }
            for index in range(50)
        ]
        run_summaries.append(
            {
                "group": group,
                "api_full_agent": {
                    "mean_ms": 45.0,
                    "p50_ms": 45.0,
                    "p95_ms": 50.0,
                    "max_ms": 50.0,
                },
                "prompt_tokens": {
                    "source": "tokenizer",
                    "method": _TOKENIZER_METHOD,
                    "p50": 10_000.0,
                    "p95": 10_000.0,
                },
                "short_prompt_tokens": {
                    "source": "tokenizer",
                    "method": _TOKENIZER_METHOD,
                    "p50": 500.0,
                    "p95": 500.0,
                },
                "long_provider_payload_evidence": long_receipts,
                "short_provider_payload_evidence": short_receipts,
                "failures": [],
            }
        )
    executable = pathlib.Path(sys.executable).resolve()
    platform_identity = platform.platform(aliased=True, terse=False)
    provenance = {
        "schema_version": "echo-old-baseline-provenance-v2",
        "commit": _OLD_BASELINE_COMMIT,
        "tree": _OLD_BASELINE_TREE,
        "source_digest_algorithm": "ECHO-RELEASE-SOURCE-V2",
        "source_digest": _OLD_BASELINE_SOURCE_DIGEST,
        "uv_lock_sha256": _OLD_BASELINE_UV_LOCK_SHA256,
        "measured_root": str(measured_root),
        "import_root": str(import_root),
        "harness_root": str(root.resolve()),
        "baseline_script_sha256": baseline_script_sha256,
        "harness_sha256": baseline_script_sha256,
        "import_root_sha256": _OLD_BASELINE_IMPORT_ROOT_SHA256,
        "workload": {
            "history_message_count": 40,
            "history_words_per_message": 80,
            "corpus_sha256": _OLD_BASELINE_CORPUS_SHA256,
        },
        "tokenizer": {
            "method": _TOKENIZER_METHOD,
            "encoding": _TOKENIZER_ENCODING,
            "tiktoken_version": importlib.metadata.version("tiktoken"),
            "resource_digest_algorithm": "ECHO-TOKENIZER-TREE-V1",
            "resource_root": str((root / "resources" / "tokenizer").resolve()),
            "resource_tree_sha256": tokenizer_sha256,
        },
        "interpreter": {
            "implementation": platform.python_implementation(),
            "version": platform.python_version(),
            "executable_sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
        },
        "platform": {
            "identity": platform_identity,
            "identity_sha256": hashlib.sha256(platform_identity.encode()).hexdigest(),
        },
    }
    return {
        "schema_version": "echo-old-baseline-v2",
        "source": "independent_clean_commit_export",
        "commit": _OLD_BASELINE_COMMIT,
        "tree": _OLD_BASELINE_TREE,
        "source_digest": _OLD_BASELINE_SOURCE_DIGEST,
        "provenance": provenance,
        "iterations": 50,
        "warmup": 10,
        "runs": 5,
        "paid_provider_calls": 0,
        "failures": [],
        "script_sha256": baseline_script_sha256,
        "import_root": str(import_root),
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
        },
        "methodology": "deterministic external-harness fixture",
        "limitations": "local fake-provider fixture",
        "api_full_agent": {
            "mean_ms": 45.0,
            "p50_ms": 45.0,
            "p95_ms": 50.0,
            "max_ms": 50.0,
            "group_p95_ms": [50.0] * 5,
        },
        "prompt_tokens": {
            "source": "tokenizer",
            "method": _TOKENIZER_METHOD,
            "p50": 10_000.0,
            "p95": 10_000.0,
        },
        "short_prompt_tokens": {
            "source": "tokenizer",
            "method": _TOKENIZER_METHOD,
            "p50": 500.0,
            "p95": 500.0,
        },
        "run_summaries": run_summaries,
    }


def _valid_concurrency_probe() -> dict[str, object]:
    workers = 50
    rounds = 3
    receipts: list[dict[str, object]] = []
    events: list[dict[str, object]] = []
    sequence = 0
    for round_index in range(rounds):
        for worker_index in range(workers):
            marker = f"benchmark-concurrency:{round_index}:{worker_index}"
            secret = f"benchmark-isolation-secret:{round_index}:{worker_index}"
            session_id = f"echo-concurrency-{round_index}-{worker_index}"
            expected_response = f"{marker}|{secret}"
            receipts.append(
                {
                    "round": round_index,
                    "worker": worker_index,
                    "session_id": session_id,
                    "status_code": 200,
                    "expected_response": expected_response,
                    "observed_session_id": session_id,
                    "observed_response": expected_response,
                }
            )
            sequence += 1
            events.append(
                {
                    "sequence": sequence,
                    "phase": "start",
                    "request_id": marker,
                }
            )
        for worker_index in range(workers):
            sequence += 1
            events.append(
                {
                    "sequence": sequence,
                    "phase": "end",
                    "request_id": f"benchmark-concurrency:{round_index}:{worker_index}",
                }
            )
    receipt_payload = {
        "request_receipts": receipts,
        "provider_call_events": events,
    }
    return {
        "evidence_schema_version": "echo-concurrency-evidence-v1",
        "submitted_concurrency": workers,
        "rounds": rounds,
        "total_requests": workers * rounds,
        "completed_ok": workers * rounds,
        "http_5xx_count": 0,
        "crosstalk_count": 0,
        "isolation_checks": workers * rounds,
        "runtime_peak_inflight": workers,
        "overlap_layer": "real_gated_provider_calls",
        "execution_model": "single_process_async_asgi",
        "peak_rss_mb": 100.0,
        "delta_rss_mb": 5.0,
        "latency": {"n": workers * rounds, "p95_ms": 1.0, "max_ms": 1.0},
        "failures": [],
        **receipt_payload,
        "receipt_sha256": hashlib.sha256(
            json.dumps(
                receipt_payload,
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest(),
    }


def _bind_concurrency_receipts(probe: dict[str, object]) -> None:
    receipt_payload = {
        "request_receipts": probe["request_receipts"],
        "provider_call_events": probe["provider_call_events"],
    }
    probe["receipt_sha256"] = hashlib.sha256(
        json.dumps(
            receipt_payload,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()


def _set_concurrency_peak(probe: dict[str, object], peak: int) -> None:
    workers = int(probe["submitted_concurrency"])
    rounds = int(probe["rounds"])
    events: list[dict[str, object]] = []
    sequence = 0
    for round_index in range(rounds):
        for batch_start in range(0, workers, peak):
            batch = range(batch_start, min(workers, batch_start + peak))
            for worker_index in batch:
                sequence += 1
                events.append(
                    {
                        "sequence": sequence,
                        "phase": "start",
                        "request_id": f"benchmark-concurrency:{round_index}:{worker_index}",
                    }
                )
            for worker_index in batch:
                sequence += 1
                events.append(
                    {
                        "sequence": sequence,
                        "phase": "end",
                        "request_id": f"benchmark-concurrency:{round_index}:{worker_index}",
                    }
                )
    probe["provider_call_events"] = events
    probe["runtime_peak_inflight"] = peak
    _bind_concurrency_receipts(probe)


def _valid_ws_stream_timing() -> dict[str, object]:
    sample_count = SLO_CONTRACT.benchmark_measured
    receipts = [
        {
            "send_monotonic_ns": 1_000_000_000 + index * 10_000_000,
            "clock": "time.perf_counter_ns",
            "frame_offsets_ms": {
                "status": 0.1,
                "thinking": 1.0,
                "first_text_token": 5.0,
                "usage": 7.0,
                "terminal": 8.0,
            },
            "frame_types": [
                "status",
                "thinking",
                "token",
                "token",
                "token",
                "usage",
                "done",
            ],
            "terminal_count": 1,
            "terminal_type": "done",
        }
        for index in range(sample_count)
    ]

    def summary(value: float) -> dict[str, float | int]:
        return {
            "n": sample_count,
            "min_ms": value,
            "mean_ms": value,
            "p50_ms": value,
            "p95_ms": value,
            "max_ms": value,
        }

    return {
        "evidence_schema_version": "echo-ws-stream-timing-v1",
        "clock": "time.perf_counter_ns",
        "configured_cadence_ms": {
            "first_text_token": 5.0,
            "inter_text_token": 1.0,
        },
        "first_text_token_semantics": "first non-empty websocket token frame after send",
        "timing_receipts": receipts,
        "status_latency": summary(0.1),
        "thinking_latency": summary(1.0),
        "first_text_token_latency": summary(5.0),
        "usage_latency": summary(7.0),
        "terminal_latency": summary(8.0),
        "provider_stream_event_calls": sample_count,
        "provider_stream_completed": sample_count,
        "provider_stream_cancelled": 0,
        "failures": [],
        "resilience": {
            "single_terminal_all_ok": True,
            "slow_consumer": {
                "ok": True,
                "consumer_pause_ms": 10.0,
                "bounded_max_frames": 7,
                "received_frame_count": 7,
                "terminal_count": 1,
                "terminal_type": "done",
            },
            "disconnect": {
                "ok": True,
                "status_received": True,
                "provider_started": True,
                "provider_cancelled": True,
                "terminal_frames_after_disconnect": 0,
                "bounded_wait_ms": 10.0,
                "max_wait_ms": 1_000.0,
            },
        },
    }


@lru_cache(maxsize=1)
def _cached_compaction_semantics() -> dict[str, object]:
    import scripts.echo_architecture_benchmark as benchmark

    expected = [
        benchmark._compaction_semantics(entry) for entry in benchmark._compaction_fixture_entries()
    ]
    expected_sampled = [expected[index] for index in benchmark.COMPACTION_SAMPLE_INDICES]
    expected_tail = expected[-benchmark.COMPACTION_RETAIN_RECORDS :]
    receipt: dict[str, object] = {
        "schema_version": benchmark.COMPACTION_RECEIPT_VERSION,
        "semantic_verification_outside_timed_interval": True,
        "expected_logical_record_count": benchmark.COMPACTION_LOGICAL_RECORD_COUNT,
        "logical_record_count": benchmark.COMPACTION_LOGICAL_RECORD_COUNT,
        "expected_active_record_count": benchmark.COMPACTION_ACTIVE_RECORD_COUNT,
        "active_record_count": benchmark.COMPACTION_ACTIVE_RECORD_COUNT,
        "active_record_types": ["snapshot_anchor"]
        + ["decision"] * benchmark.COMPACTION_RETAIN_RECORDS,
        "expected_retained_record_count": benchmark.COMPACTION_RETAIN_RECORDS,
        "retained_record_count": benchmark.COMPACTION_RETAIN_RECORDS,
        "archive_chain_verified": True,
        "archive_chain_errors": [],
        "archive_generation_count": 1,
        "archive_generation": 1,
        "archive_cumulative_record_count": benchmark.COMPACTION_LOGICAL_RECORD_COUNT,
        "archive_cumulative_tombstone_count": 1,
        "archive_ref_sha256": "a" * 64,
        "tombstones": [benchmark.COMPACTION_EFFECT_ID],
        "tombstone_sha256": benchmark._canonical_sha256([benchmark.COMPACTION_EFFECT_ID]),
        "archived_effect_lookup_ok": True,
        "expected_logical_payload_sha256": benchmark._canonical_sha256(expected),
        "logical_payload_sha256": benchmark._canonical_sha256(expected),
        "logical_payload_equivalent": True,
        "sample_indices": list(benchmark.COMPACTION_SAMPLE_INDICES),
        "expected_sampled_payload_sha256": benchmark._canonical_sha256(expected_sampled),
        "sampled_payload_sha256": benchmark._canonical_sha256(expected_sampled),
        "sampled_payload_equivalent": True,
        "expected_active_payload_sha256": benchmark._canonical_sha256(expected_tail),
        "active_payload_sha256": benchmark._canonical_sha256(expected_tail),
        "active_payload_equivalent": True,
        "post_compaction_bad_tail_recovery_ok": True,
        "corrupt_tail_quarantine_count": 1,
        "active_journal_sha256": "b" * 64,
        "archive_sha256": "c" * 64,
        "ok": True,
    }
    receipt["receipt_sha256"] = benchmark._compaction_receipt_sha256(receipt)
    return receipt


def _valid_recovery_probe(variant: int = 0) -> dict[str, object]:
    import scripts.echo_architecture_benchmark as benchmark

    semantics = copy.deepcopy(_cached_compaction_semantics())
    semantics["active_journal_sha256"] = format(variant + 1, "x") * 64
    semantics["receipt_sha256"] = benchmark._compaction_receipt_sha256(semantics)
    return {
        "journal_replay_10k_record_count": 10_000,
        "journal_replay_10k_records_s": 0.1,
        "bad_tail_recovery_ok": True,
        "compaction_record_count": 101,
        "compaction_latency_ms": 5.0,
        "compaction_ok": True,
        "compaction_semantic_receipt_sha256": semantics["receipt_sha256"],
        "compaction_semantics": semantics,
    }


def _write_valid_stable_artifacts(root: pathlib.Path) -> None:
    _attach_old_commit_object_store(root)
    security_dir = root / "docs" / "security"
    security_dir.mkdir(parents=True, exist_ok=True)
    (security_dir / "SBOM.spdx.json").write_text(
        """
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "fixture",
  "packages": [
    {
      "SPDXID": "SPDXRef-Package-js-agent",
      "name": "js-agent",
      "licenseDeclared": "MIT"
    }
  ]
}
""".strip()
        + "\n",
        encoding="utf-8",
    )
    (security_dir / "LICENSE_SCAN.md").write_text(
        "\n".join(
            [
                "# License Scan",
                "",
                "Status: COMPLETE_LOCAL_SCAN_EXTERNAL_REVIEW_REQUIRED",
                "",
                "- Packages scanned: 1",
                "",
                "| Package | Version | License metadata |",
                "| --- | --- | --- |",
                "| `js-agent` | `0.1.5` | MIT |",
                "",
            ]
        ),
        encoding="utf-8",
    )
    benchmark_script = root / "scripts" / "echo_architecture_benchmark.py"
    benchmark_script.parent.mkdir(parents=True, exist_ok=True)
    benchmark_script.write_text("# deterministic benchmark fixture\n", encoding="utf-8")
    benchmark_script_sha256 = hashlib.sha256(benchmark_script.read_bytes()).hexdigest()
    baseline_script = root / "benchmarks" / "old_architecture_baseline.py"
    baseline_script.parent.mkdir(parents=True, exist_ok=True)
    baseline_script.write_text("# deterministic clean-export baseline fixture\n", encoding="utf-8")
    baseline_script_sha256 = hashlib.sha256(baseline_script.read_bytes()).hexdigest()
    tokenizer_fixture = root / "resources" / "tokenizer" / "fixture.bin"
    tokenizer_fixture.parent.mkdir(parents=True, exist_ok=True)
    tokenizer_fixture.write_bytes(b"deterministic tokenizer fixture\n")
    from js.echo.ledger.release_gates import tokenizer_resource_digest

    baseline_path = security_dir / "ECHO_BASELINE_65CC545.json"
    baseline_path.write_text(
        json.dumps(
            _old_baseline_payload(
                root,
                baseline_script_sha256=baseline_script_sha256,
                tokenizer_sha256=tokenizer_resource_digest(root),
            ),
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    baseline_sha256 = hashlib.sha256(baseline_path.read_bytes()).hexdigest()
    benchmark_path = security_dir / "ECHO_SLO_BENCHMARK.json"
    benchmark_path.write_text(
        """
{
  "metadata": {
    "iterations": 50,
    "warmup": 10,
    "runs": 5,
    "benchmark_script_sha256": "BENCHMARK_SCRIPT_SHA256",
    "slo_contract": {
      "version": "js-agent-slo-v1",
      "full_request_p95_ms": 45.0,
      "wrapper_p95_ms": 2.5,
      "journal_append_p95_ms": 10.0,
      "replay_10k_seconds": 2.0,
      "compaction_ms": 250.0,
      "concurrency_workers": 50,
      "concurrency_rounds": 3,
      "max_rss_mb": 500.0,
      "benchmark_groups": 5,
      "benchmark_warmup": 10,
      "benchmark_measured": 50,
      "long_context_min_reduction_pct": 15.0,
      "short_context_max_increase_pct": 5.0
    }
  },
  "modes": {
    "echo": {
      "api_full_agent": {"latency": {"n": 50, "p95_ms": 1.0}},
      "api_wrapper_only": {"latency": {"n": 50, "p95_ms": 1.0}},
      "ws_message_wrapper": {"latency": {"n": 50, "p95_ms": 1.0}},
      "ws_stream_wrapper": {"latency": {"n": 50, "p95_ms": 1.0}}
    }
  },
  "comparisons": {},
  "token_comparison": {
    "api_full_agent_prompt_p95_echo": 8115.0,
    "api_full_agent_prompt_p95_limit": 9000.0,
    "api_full_agent_prompt_within_limit": true,
    "token_source": "tokenizer"
  },
  "recovery_probes": {
    "journal_replay_10k_record_count": 10000,
    "journal_replay_10k_records_s": 0.1,
    "bad_tail_recovery_ok": true,
    "compaction_ok": true,
    "compaction_latency_ms": 5.0
  },
  "concurrency_probe": {
    "submitted_concurrency": 50,
    "rounds": 3,
    "total_requests": 150,
    "completed_ok": 150,
    "http_5xx_count": 0,
    "crosstalk_count": 0,
    "isolation_checks": 150,
    "overlap_layer": "real_gated_provider_calls",
    "execution_model": "single_process_async_asgi",
    "runtime_peak_inflight": 50,
    "peak_rss_mb": 100.0,
    "delta_rss_mb": 5.0
  },
  "baseline_comparison": {
    "valid": true,
    "source": "independent_clean_commit_export",
    "baseline_commit": "65cc545e3ec893f5bab62d356514643f14456a58",
    "iterations": 50,
    "warmup": 10,
    "runs": 5,
    "paid_provider_calls": 0,
    "api_full_agent": {
      "old_p95_ms": 50.0,
      "echo_p95_ms": 40.0,
      "p95_delta_pct": -20.0
    },
    "prompt_tokens": {
      "source": "tokenizer",
      "method": "tiktoken_cl100k_base_canonical_json",
      "old_p50": 10000.0,
      "echo_p50": 8000.0,
      "p50_reduction_pct": 20.0,
      "old_p95": 10000.0,
      "echo_p95": 8000.0,
      "reduction_pct": 20.0
    },
    "short_prompt_tokens": {
      "source": "tokenizer",
      "method": "tiktoken_cl100k_base_canonical_json",
      "old_p50": 500.0,
      "echo_p50": 500.0,
      "p50_increase_pct": 0.0,
      "old_p95": 500.0,
      "echo_p95": 500.0,
      "p95_increase_pct": 0.0
    }
  },
  "security_matrix": {"ok": true, "passed": 25, "total": 25}
}
""".strip()
        + "\n",
        encoding="utf-8",
    )
    from js.echo.ledger.release_gates import (
        _TOKENIZER_TREE_DIGEST_VERSION,
        tokenizer_resource_digest,
    )
    from tests.test_isolated_product_e2e_round85 import _valid_payload
    from tests.test_soak_source_integrity_round85 import _valid_live_payload

    # Seed frozen signing keys and E2E files before binding source digests.
    _valid_live_payload(root)
    e2e_path = security_dir / "ECHO_ISOLATED_VENV_E2E.json"
    _e2e_json_path, e2e_payload = _valid_payload(root)
    source_digest = release_source_digest(root)
    e2e_payload["source_digest"] = source_digest
    for step in e2e_payload["results"]:
        if isinstance(step, dict):
            step["source_digest"] = source_digest
    e2e_path.write_text(json.dumps(e2e_payload, indent=2) + "\n", encoding="utf-8")
    _e2e_json_path.write_text(json.dumps(e2e_payload, indent=2) + "\n", encoding="utf-8")

    benchmark_data = json.loads(benchmark_path.read_text(encoding="utf-8"))
    benchmark_data["metadata"]["slo_contract"] = SLO_CONTRACT.as_dict()
    benchmark_data["source_digest"] = source_digest
    benchmark_data["metadata"]["source_digest"] = source_digest
    benchmark_data["metadata"]["benchmark_script_sha256"] = benchmark_script_sha256
    benchmark_data["metadata"]["tokenizer_tree_digest_version"] = (
        _TOKENIZER_TREE_DIGEST_VERSION.decode("ascii").rstrip("\0")
    )
    benchmark_data["metadata"]["tokenizer_resource_sha256"] = tokenizer_resource_digest(root)
    benchmark_data["journal_append_probe"] = {
        "durability": "flush_fsync",
        "latency": {"n": 50, "p95_ms": 1.0},
    }
    latency_p95 = {
        "api_full_agent": 40.0,
        "api_wrapper_only": 1.0,
        "ws_message_wrapper": 1.0,
        "ws_stream_wrapper": 1.0,
    }
    concurrency = _valid_concurrency_probe()
    benchmark_data["concurrency_probe"] = concurrency
    timing = _valid_ws_stream_timing()
    benchmark_data["modes"]["echo"]["ws_stream_timing"] = copy.deepcopy(timing)
    benchmark_data["modes"]["echo"]["ws_stream_timing"]["first_text_token_latency"][
        "group_p95_ms"
    ] = [5.0] * SLO_CONTRACT.benchmark_groups
    benchmark_data["modes"]["echo"]["ws_stream_timing"]["terminal_latency"]["group_p95_ms"] = [
        8.0
    ] * SLO_CONTRACT.benchmark_groups
    group_recoveries = [_valid_recovery_probe(index) for index in range(5)]
    recovery = copy.deepcopy(group_recoveries[0])
    benchmark_data["recovery_probes"] = copy.deepcopy(recovery)
    benchmark_data["run_summaries"] = [
        {
            "group": group,
            "latency_p95_ms": latency_p95,
            "long_prompt_tokens": {
                "p50": 8_000.0,
                "p95": 8_000.0,
                "source": "tokenizer",
                "method": "tiktoken_cl100k_base_canonical_json",
            },
            "short_prompt_tokens": {
                "p50": 500.0,
                "p95": 500.0,
                "source": "tokenizer",
                "method": "tiktoken_cl100k_base_canonical_json",
            },
            "ws_stream_timing": copy.deepcopy(timing),
            "journal_append_p95_ms": 1.0,
            "recovery": copy.deepcopy(group_recoveries[group - 1]),
            "concurrency": copy.deepcopy(concurrency),
        }
        for group in range(1, 6)
    ]
    benchmark_data["aggregate"] = {
        "group_count": 5,
        "latency_p95_median_ms": latency_p95,
        "latency_p95_runs_ms": {scenario: [value] * 5 for scenario, value in latency_p95.items()},
        "ws_first_token_p95_median_ms": 5.0,
        "ws_first_token_p95_runs_ms": [5.0] * 5,
        "ws_terminal_p95_median_ms": 8.0,
        "ws_terminal_p95_runs_ms": [8.0] * 5,
        "long_prompt_tokens": {
            "p50_median": 8_000.0,
            "p95_median": 8_000.0,
            "source": "tokenizer",
            "method": "tiktoken_cl100k_base_canonical_json",
        },
        "short_prompt_tokens": {
            "p50_median": 500.0,
            "p95_median": 500.0,
            "source": "tokenizer",
            "method": "tiktoken_cl100k_base_canonical_json",
        },
        "journal_append_p95_max_ms": 1.0,
        "replay_10k_record_count_min": 10_000,
        "replay_10k_max_seconds": 0.1,
        "bad_tail_all_ok": True,
        "compaction_max_ms": 5.0,
        "compaction_all_ok": True,
        "compaction_semantics_all_ok": True,
        "compaction_semantic_receipt_sha256s": [
            group_recovery["compaction_semantic_receipt_sha256"]
            for group_recovery in group_recoveries
        ],
    }
    benchmark_data["baseline_comparison"]["baseline_artifact"] = baseline_path.name
    benchmark_data["baseline_comparison"]["baseline_artifact_sha256"] = baseline_sha256
    benchmark_data["baseline_comparison"]["baseline_script_sha256"] = baseline_script_sha256
    benchmark_path.write_text(json.dumps(benchmark_data, indent=2) + "\n", encoding="utf-8")
    benchmark_sha256 = hashlib.sha256(benchmark_path.read_bytes()).hexdigest()
    echo_dir = root / "docs" / "echo"
    echo_dir.mkdir(parents=True, exist_ok=True)
    for name in ("ECHO_10_ROUND_AUDIT.md", "ECHO_FINAL_REPLACEMENT_REPORT.md"):
        (echo_dir / name).write_text(
            f"# Fixture\n\nBenchmark SHA-256: `{benchmark_sha256}`\n",
            encoding="utf-8",
        )


def _write_valid_live_acceptance(root: pathlib.Path) -> pathlib.Path:
    from tests.test_soak_source_integrity_round85 import _valid_live_payload

    path = root / "docs" / "security" / "ECHO_LIVE_ACCEPTANCE.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = _valid_live_payload(root)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return path


def test_release_source_digest_version_and_surfaces_cover_release_inputs() -> None:
    """Digest algorithm version and surfaces must cover wheel/sdist/SLO inputs."""
    from js.echo.ledger import release_gates as rg

    assert rg._RELEASE_SOURCE_DIGEST_VERSION.startswith(b"ECHO-RELEASE-SOURCE-V2")
    assert rg._RELEASE_SOURCE_DIGEST_VERSION != b"ECHO-RELEASE-SOURCE-V1\0"
    assert rg._TOKENIZER_TREE_DIGEST_VERSION.startswith(b"ECHO-TOKENIZER-TREE-V1")
    surfaces = {path.as_posix() for path in rg._RELEASE_SOURCE_DIGEST_SURFACES}
    required = {
        "desktop",
        "resources",
        "benchmarks",
        "LICENSE",
        "README.md",
        "ORIGIN_LEDGER.md",
        "THIRD_PARTY_NOTICES.md",
        "js",
        "js_work",
        "pyproject.toml",
        "uv.lock",
        "scripts",
        "tests",
    }
    missing = sorted(required - surfaces)
    assert not missing, f"digest surfaces missing release inputs: {missing}"
    # Evidence that binds TO the digest must not be hashed into it.
    excludes = {path.as_posix() for path in rg._RELEASE_SOURCE_DIGEST_EXCLUDE}
    assert "docs/security/ECHO_SLO_BENCHMARK.json" in excludes
    assert "docs/security/ECHO_LIVE_ACCEPTANCE.json" in excludes
    assert "docs/echo/ECHO_10_ROUND_AUDIT.md" in excludes
    assert "docs/echo/ECHO_FINAL_REPLACEMENT_REPORT.md" in excludes
    # No duplicate nested file listings alongside parent dirs.
    assert "benchmarks/baseline.json" not in surfaces
    assert len(surfaces) == len(set(surfaces))


def test_audit_report_updates_do_not_change_runtime_source_digest(
    tmp_path: pathlib.Path,
) -> None:
    """Generated audit markdown must stay outside the runtime digest cycle."""
    from js.echo.ledger import release_gates as rg

    # Minimal digest surfaces
    for relative in (
        "LICENSE",
        "README.md",
        "ORIGIN_LEDGER.md",
        "THIRD_PARTY_NOTICES.md",
        "pyproject.toml",
    ):
        (tmp_path / relative).write_text("x\n", encoding="utf-8")
    (tmp_path / "js").mkdir()
    (tmp_path / "js" / "x.py").write_text("x=1\n", encoding="utf-8")
    (tmp_path / "js_work").mkdir()
    (tmp_path / "js_work" / "x.py").write_text("x=1\n", encoding="utf-8")
    (tmp_path / "scripts").mkdir()
    (tmp_path / "tests").mkdir()
    (tmp_path / "benchmarks").mkdir()
    (tmp_path / "resources").mkdir()
    (tmp_path / "docs" / "echo").mkdir(parents=True)
    audit = tmp_path / "docs" / "echo" / "ECHO_10_ROUND_AUDIT.md"
    audit.write_text("Benchmark SHA-256: `aaa`\n", encoding="utf-8")
    (tmp_path / "docs" / "echo" / "ECHO_FINAL_REPLACEMENT_REPORT.md").write_text(
        "Benchmark SHA-256: `aaa`\n", encoding="utf-8"
    )
    before = release_source_digest(tmp_path)
    audit.write_text("Benchmark SHA-256: `bbb`\nchanged\n", encoding="utf-8")
    after = release_source_digest(tmp_path)
    assert before == after
    assert "docs/echo/ECHO_10_ROUND_AUDIT.md" in {
        path.as_posix() for path in rg._RELEASE_SOURCE_DIGEST_EXCLUDE
    }


def test_echo_slo_rejects_missing_or_stale_source_digest(tmp_path: pathlib.Path) -> None:
    _write_valid_stable_artifacts(tmp_path)
    path = tmp_path / "docs" / "security" / "ECHO_SLO_BENCHMARK.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data.pop("source_digest", None)
    data["metadata"].pop("source_digest", None)
    path.write_text(json.dumps(data), encoding="utf-8")
    assert not _valid_echo_slo_benchmark(path)

    data["source_digest"] = "0" * 64
    data["metadata"]["source_digest"] = "0" * 64
    path.write_text(json.dumps(data), encoding="utf-8")
    assert not _valid_echo_slo_benchmark(path)


def test_readiness_rejects_false_green_isolated_e2e(tmp_path: pathlib.Path) -> None:
    for relative in (
        "ORIGIN_LEDGER.md",
        "THIRD_PARTY_NOTICES.md",
        ".github/CODEOWNERS",
        "docs/adr/0001-echo-ledger-boundary.md",
        "docs/rfc/echo-ledger-major-change-template.md",
        "docs/echo/ECHO_SELF_DEVELOPED_BOUNDARY.md",
        "docs/echo/ECHO_UNIFIED_EXECUTION_CONTRACT.md",
        "docs/echo/ECHO_10_ROUND_AUDIT.md",
        "docs/echo/ECHO_FINAL_REPLACEMENT_REPORT.md",
    ):
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("ok\n", encoding="utf-8")
    _write_valid_stable_artifacts(tmp_path)
    digest = hashlib.sha256(
        (tmp_path / "docs" / "security" / "ECHO_SLO_BENCHMARK.json").read_bytes()
    ).hexdigest()
    for relative in (
        "docs/echo/ECHO_10_ROUND_AUDIT.md",
        "docs/echo/ECHO_FINAL_REPLACEMENT_REPORT.md",
    ):
        (tmp_path / relative).write_text(f"Benchmark SHA-256: `{digest}`\n", encoding="utf-8")
    e2e = tmp_path / "docs" / "security" / "ECHO_ISOLATED_VENV_E2E.json"
    e2e.write_text(
        json.dumps(
            {
                "ok": True,
                "source_digest": "deadbeef",
                "artifacts": {
                    "wheel": {"sha256": "a" * 64},
                    "sdist": {"sha256": "b" * 64},
                },
                "results": [
                    {
                        "step": "wheel: server",
                        "ok": True,
                        "exit_code": 0,
                        "detail": {"chat_status": 403, "ws_terminal": "error"},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    report = verify_release_readiness(tmp_path, require_live_acceptance=False)
    assert "isolated_venv_e2e_invalid" in report.internal_blockers
    assert report.internal_ready is False


def test_live_acceptance_gate_rejects_failed_and_stale_evidence(
    tmp_path: pathlib.Path,
) -> None:
    (tmp_path / "js").mkdir()
    source = tmp_path / "js" / "runtime.py"
    source.write_text("VERSION = 1\n", encoding="utf-8")
    artifact = _write_valid_live_acceptance(tmp_path)
    assert _valid_echo_live_acceptance(tmp_path, artifact)

    payload = json.loads(artifact.read_text(encoding="utf-8"))
    payload["ok"] = False
    artifact.write_text(json.dumps(payload), encoding="utf-8")
    assert not _valid_echo_live_acceptance(tmp_path, artifact)

    artifact = _write_valid_live_acceptance(tmp_path)
    source.write_text("VERSION = 2\n", encoding="utf-8")
    assert not _valid_echo_live_acceptance(tmp_path, artifact)


def test_development_readiness_can_exclude_live_acceptance_without_weakening_default(
    tmp_path: pathlib.Path,
) -> None:
    _write_required_internal_evidence(tmp_path)
    _write_valid_stable_artifacts(tmp_path)

    strict_report = verify_release_readiness(tmp_path)
    development_report = verify_release_readiness(
        tmp_path,
        require_live_acceptance=False,
    )

    assert "echo_live_acceptance_missing" in strict_report.internal_blockers
    assert "echo_live_acceptance_missing" not in development_report.internal_blockers
    assert development_report.internal_ready


def _write_required_internal_evidence(root: pathlib.Path) -> None:
    (root / "uv.lock").write_text("version = 1\n", encoding="utf-8")
    for relative in (
        "ORIGIN_LEDGER.md",
        "THIRD_PARTY_NOTICES.md",
        ".github/CODEOWNERS",
        "docs/adr/0001-echo-ledger-boundary.md",
        "docs/rfc/echo-ledger-major-change-template.md",
        "docs/echo/ECHO_SELF_DEVELOPED_BOUNDARY.md",
        "docs/echo/ECHO_UNIFIED_EXECUTION_CONTRACT.md",
    ):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("ok\n", encoding="utf-8")


def _write_signed_external_approval(
    root: pathlib.Path,
    *,
    evidence_name: str,
    reviewer: str,
    private_key: Ed25519PrivateKey,
    signed_evidence_name: str | None = None,
    signature: bytes | None = None,
    scope_commit: str | None = None,
) -> pathlib.Path:
    relative_path = {
        "legal_fto_review": "docs/security/LEGAL_FTO_REVIEW.md",
        "clean_room_reviewer": "docs/security/CLEAN_ROOM_REVIEW.md",
        "external_security_audit": "docs/security/EXTERNAL_SECURITY_AUDIT.md",
        "redteam_report": "docs/security/REDTEAM_REPORT.md",
    }[evidence_name]
    fields = {
        "Status": "APPROVED",
        "Reviewer": reviewer,
        "Date": "2026-07-12",
        "Evidence-Name": signed_evidence_name or evidence_name,
        "Scope-Commit": scope_commit or _git(root, "rev-parse", "--verify", "HEAD^{commit}"),
        "SBOM-SHA256": hashlib.sha256(
            (root / "docs/security/SBOM.spdx.json").read_bytes()
        ).hexdigest(),
        "UV-Lock-SHA256": hashlib.sha256((root / "uv.lock").read_bytes()).hexdigest(),
        "Approval-Reference": "EXT-2026-0712-001",
    }
    detached_signature = signature or private_key.sign(_canonical_external_approval_payload(fields))
    fields["Signature"] = base64.b64encode(detached_signature).decode("ascii")
    path = root / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "\n".join(f"{key}: {value}" for key, value in fields.items()) + "\n",
        encoding="utf-8",
    )
    return path


def _set_trusted_reviewer_key(
    monkeypatch,
    *,
    reviewer: str,
    private_key: Ed25519PrivateKey,
) -> None:
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    monkeypatch.setenv(
        "JS_ECHO_TRUSTED_REVIEW_KEYS",
        json.dumps({reviewer: base64.b64encode(public_key).decode("ascii")}),
    )


def _git(root: pathlib.Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _commit_release_candidate(root: pathlib.Path) -> str:
    _git(root, "init", "--quiet")
    _git(root, "config", "user.email", "echo-release-test@example.invalid")
    _git(root, "config", "user.name", "Echo Release Test")
    _git(root, "add", "--all")
    _git(root, "commit", "--quiet", "-m", "release candidate")
    return _git(root, "rev-parse", "--verify", "HEAD^{commit}")


def _write_complete_signed_approval_set(
    root: pathlib.Path,
    monkeypatch,
) -> tuple[str, Ed25519PrivateKey]:
    reviewer = "external-reviewer"
    private_key = Ed25519PrivateKey.generate()
    _write_required_internal_evidence(root)
    _write_valid_stable_artifacts(root)
    _write_valid_live_acceptance(root)
    _commit_release_candidate(root)
    _set_trusted_reviewer_key(
        monkeypatch,
        reviewer=reviewer,
        private_key=private_key,
    )
    for evidence_name in (
        "legal_fto_review",
        "clean_room_reviewer",
        "external_security_audit",
        "redteam_report",
    ):
        _write_signed_external_approval(
            root,
            evidence_name=evidence_name,
            reviewer=reviewer,
            private_key=private_key,
        )
    return reviewer, private_key


def test_echo_slo_artifact_rejects_claimed_success_with_high_latency(
    tmp_path: pathlib.Path,
) -> None:
    _write_valid_stable_artifacts(tmp_path)
    path = tmp_path / "docs" / "security" / "ECHO_SLO_BENCHMARK.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["aggregate"]["latency_p95_median_ms"]["api_full_agent"] = 99_999.0
    path.write_text(json.dumps(data), encoding="utf-8")

    assert not _valid_echo_slo_benchmark(path)


def test_echo_slo_artifact_rejects_a_different_contract_version(
    tmp_path: pathlib.Path,
) -> None:
    _write_valid_stable_artifacts(tmp_path)
    path = tmp_path / "docs" / "security" / "ECHO_SLO_BENCHMARK.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["metadata"]["slo_contract"]["version"] = "drifted-contract"
    path.write_text(json.dumps(data), encoding="utf-8")

    assert not _valid_echo_slo_benchmark(path)


@pytest.mark.parametrize(
    ("scenario", "p95_ms"),
    [
        ("api_full_agent", 45.001),
        ("api_wrapper_only", 2.501),
        ("ws_message_wrapper", 2.501),
        ("ws_stream_wrapper", 2.501),
    ],
)
def test_echo_slo_artifact_enforces_versioned_latency_contract(
    tmp_path: pathlib.Path,
    scenario: str,
    p95_ms: float,
) -> None:
    _write_valid_stable_artifacts(tmp_path)
    path = tmp_path / "docs" / "security" / "ECHO_SLO_BENCHMARK.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["aggregate"]["latency_p95_median_ms"][scenario] = p95_ms
    path.write_text(json.dumps(data), encoding="utf-8")

    assert not _valid_echo_slo_benchmark(path)


def test_echo_slo_artifact_rejects_missing_concurrency_evidence(
    tmp_path: pathlib.Path,
) -> None:
    _write_valid_stable_artifacts(tmp_path)
    path = tmp_path / "docs" / "security" / "ECHO_SLO_BENCHMARK.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data.pop("concurrency_probe")
    path.write_text(json.dumps(data), encoding="utf-8")

    assert not _valid_echo_slo_benchmark(path)


@pytest.mark.parametrize("runtime_peak", [49, 2])
@pytest.mark.parametrize("location", ["top_level", "group"])
def test_echo_slo_artifact_rejects_runtime_peak_below_worker_floor(
    tmp_path: pathlib.Path,
    runtime_peak: int,
    location: str,
) -> None:
    _write_valid_stable_artifacts(tmp_path)
    path = tmp_path / "docs" / "security" / "ECHO_SLO_BENCHMARK.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    if location == "top_level":
        _set_concurrency_peak(data["concurrency_probe"], runtime_peak)
    else:
        _set_concurrency_peak(data["run_summaries"][2]["concurrency"], runtime_peak)
    path.write_text(json.dumps(data), encoding="utf-8")

    assert not _valid_echo_slo_benchmark(path)


@pytest.mark.parametrize("location", ["top_level", "group"])
def test_echo_slo_artifact_rejects_boolean_runtime_peak(
    tmp_path: pathlib.Path,
    location: str,
) -> None:
    _write_valid_stable_artifacts(tmp_path)
    path = tmp_path / "docs" / "security" / "ECHO_SLO_BENCHMARK.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    if location == "top_level":
        data["concurrency_probe"]["runtime_peak_inflight"] = True
    else:
        data["run_summaries"][2]["concurrency"]["runtime_peak_inflight"] = True
    path.write_text(json.dumps(data), encoding="utf-8")

    assert not _valid_echo_slo_benchmark(path)


def test_echo_slo_artifact_rejects_top_level_group_concurrency_mismatch(
    tmp_path: pathlib.Path,
) -> None:
    _write_valid_stable_artifacts(tmp_path)
    path = tmp_path / "docs" / "security" / "ECHO_SLO_BENCHMARK.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["concurrency_probe"]["peak_rss_mb"] = 101.0
    path.write_text(json.dumps(data), encoding="utf-8")

    assert not _valid_echo_slo_benchmark(path)


def test_echo_slo_artifact_recomputes_concurrency_from_bound_receipts(
    tmp_path: pathlib.Path,
) -> None:
    _write_valid_stable_artifacts(tmp_path)
    path = tmp_path / "docs" / "security" / "ECHO_SLO_BENCHMARK.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    concurrency = data["run_summaries"][2]["concurrency"]
    receipt = concurrency["request_receipts"][0]
    receipt["observed_response"] = "cross-owner response"
    _bind_concurrency_receipts(concurrency)
    path.write_text(json.dumps(data), encoding="utf-8")

    assert not _valid_echo_slo_benchmark(path)


@pytest.mark.parametrize("location", ["top_level", "group"])
def test_echo_slo_artifact_rejects_missing_ws_timing_receipt(
    tmp_path: pathlib.Path,
    location: str,
) -> None:
    _write_valid_stable_artifacts(tmp_path)
    path = tmp_path / "docs/security/ECHO_SLO_BENCHMARK.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    if location == "top_level":
        data["modes"]["echo"].pop("ws_stream_timing")
    else:
        data["run_summaries"][2].pop("ws_stream_timing")
    path.write_text(json.dumps(data), encoding="utf-8")

    assert not _valid_echo_slo_benchmark(path)


@pytest.mark.parametrize(
    ("aggregate_field", "summary_field"),
    [
        ("ws_first_token_p95_median_ms", "first_text_token_latency"),
        ("ws_terminal_p95_median_ms", "terminal_latency"),
    ],
)
def test_echo_slo_artifact_enforces_separate_stream_latency_limits(
    tmp_path: pathlib.Path,
    aggregate_field: str,
    summary_field: str,
) -> None:
    _write_valid_stable_artifacts(tmp_path)
    path = tmp_path / "docs/security/ECHO_SLO_BENCHMARK.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["aggregate"][aggregate_field] = 45.001
    data["modes"]["echo"]["ws_stream_timing"][summary_field]["p95_ms"] = 45.001
    path.write_text(json.dumps(data), encoding="utf-8")

    assert not _valid_echo_slo_benchmark(path)


def test_echo_slo_artifact_recomputes_ws_timing_summaries_from_receipts(
    tmp_path: pathlib.Path,
) -> None:
    _write_valid_stable_artifacts(tmp_path)
    path = tmp_path / "docs/security/ECHO_SLO_BENCHMARK.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    timing = data["run_summaries"][2]["ws_stream_timing"]
    timing["timing_receipts"][0]["frame_offsets_ms"]["first_text_token"] = 6.0
    path.write_text(json.dumps(data), encoding="utf-8")

    assert not _valid_echo_slo_benchmark(path)


@pytest.mark.parametrize(
    ("path_parts", "value"),
    [
        (("timing_receipts", 0, "send_monotonic_ns"), True),
        (("resilience", "slow_consumer", "received_frame_count"), 6),
        (("resilience", "disconnect", "terminal_frames_after_disconnect"), 1),
        (("provider_stream_cancelled",), True),
    ],
)
def test_echo_slo_artifact_rejects_malformed_ws_timing_detail(
    tmp_path: pathlib.Path,
    path_parts: tuple[str | int, ...],
    value: object,
) -> None:
    _write_valid_stable_artifacts(tmp_path)
    path = tmp_path / "docs/security/ECHO_SLO_BENCHMARK.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    target = data["run_summaries"][2]["ws_stream_timing"]
    for part in path_parts[:-1]:
        target = target[part]
    target[path_parts[-1]] = value
    path.write_text(json.dumps(data), encoding="utf-8")

    assert not _valid_echo_slo_benchmark(path)


def test_echo_slo_artifact_rejects_ws_aggregate_run_mismatch(
    tmp_path: pathlib.Path,
) -> None:
    _write_valid_stable_artifacts(tmp_path)
    path = tmp_path / "docs/security/ECHO_SLO_BENCHMARK.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["aggregate"]["ws_first_token_p95_runs_ms"][2] = 6.0
    path.write_text(json.dumps(data), encoding="utf-8")

    assert not _valid_echo_slo_benchmark(path)


@pytest.mark.parametrize("location", ["top_level", "group"])
def test_echo_slo_artifact_rejects_wrong_compaction_active_count(
    tmp_path: pathlib.Path,
    location: str,
) -> None:
    _write_valid_stable_artifacts(tmp_path)
    path = tmp_path / "docs/security/ECHO_SLO_BENCHMARK.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    recovery = (
        data["recovery_probes"] if location == "top_level" else data["run_summaries"][2]["recovery"]
    )
    recovery["compaction_record_count"] = 999
    path.write_text(json.dumps(data), encoding="utf-8")

    assert not _valid_echo_slo_benchmark(path)


def test_echo_slo_artifact_recomputes_compaction_semantic_digest(
    tmp_path: pathlib.Path,
) -> None:
    import scripts.echo_architecture_benchmark as benchmark

    _write_valid_stable_artifacts(tmp_path)
    path = tmp_path / "docs/security/ECHO_SLO_BENCHMARK.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    recovery = data["run_summaries"][2]["recovery"]
    receipt = recovery["compaction_semantics"]
    receipt["logical_payload_sha256"] = "d" * 64
    receipt["receipt_sha256"] = benchmark._compaction_receipt_sha256(receipt)
    recovery["compaction_semantic_receipt_sha256"] = receipt["receipt_sha256"]
    data["aggregate"]["compaction_semantic_receipt_sha256s"][2] = receipt["receipt_sha256"]
    path.write_text(json.dumps(data), encoding="utf-8")

    assert not _valid_echo_slo_benchmark(path)


def test_echo_slo_artifact_rejects_compaction_receipt_digest_mismatch(
    tmp_path: pathlib.Path,
) -> None:
    _write_valid_stable_artifacts(tmp_path)
    path = tmp_path / "docs/security/ECHO_SLO_BENCHMARK.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["run_summaries"][2]["recovery"]["compaction_semantic_receipt_sha256"] = "f" * 64
    path.write_text(json.dumps(data), encoding="utf-8")

    assert not _valid_echo_slo_benchmark(path)


def test_echo_slo_artifact_rejects_compaction_aggregate_mismatch(
    tmp_path: pathlib.Path,
) -> None:
    _write_valid_stable_artifacts(tmp_path)
    path = tmp_path / "docs/security/ECHO_SLO_BENCHMARK.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    digests = data["aggregate"]["compaction_semantic_receipt_sha256s"]
    digests[0], digests[1] = digests[1], digests[0]
    data["aggregate"]["compaction_max_ms"] = 4.0
    path.write_text(json.dumps(data), encoding="utf-8")

    assert not _valid_echo_slo_benchmark(path)


def test_echo_slo_artifact_rejects_fewer_than_five_groups(
    tmp_path: pathlib.Path,
) -> None:
    _write_valid_stable_artifacts(tmp_path)
    path = tmp_path / "docs" / "security" / "ECHO_SLO_BENCHMARK.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["run_summaries"] = data["run_summaries"][:4]
    data["aggregate"]["group_count"] = 4
    path.write_text(json.dumps(data), encoding="utf-8")

    assert not _valid_echo_slo_benchmark(path)


def test_echo_slo_artifact_rejects_slow_durable_journal_append(
    tmp_path: pathlib.Path,
) -> None:
    _write_valid_stable_artifacts(tmp_path)
    path = tmp_path / "docs" / "security" / "ECHO_SLO_BENCHMARK.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["aggregate"]["journal_append_p95_max_ms"] = 10.001
    path.write_text(json.dumps(data), encoding="utf-8")

    assert not _valid_echo_slo_benchmark(path)


def test_echo_slo_artifact_rejects_inconsistent_baseline_claim(
    tmp_path: pathlib.Path,
) -> None:
    _write_valid_stable_artifacts(tmp_path)
    path = tmp_path / "docs" / "security" / "ECHO_SLO_BENCHMARK.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["baseline_comparison"]["prompt_tokens"]["reduction_pct"] = 99.0
    path.write_text(json.dumps(data), encoding="utf-8")

    assert not _valid_echo_slo_benchmark(path)


def test_echo_slo_artifact_requires_long_context_p50_reduction(
    tmp_path: pathlib.Path,
) -> None:
    _write_valid_stable_artifacts(tmp_path)
    path = tmp_path / "docs" / "security" / "ECHO_SLO_BENCHMARK.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    tokens = data["baseline_comparison"]["prompt_tokens"]
    tokens["echo_p50"] = 9_000.0
    tokens["p50_reduction_pct"] = 10.0
    path.write_text(json.dumps(data), encoding="utf-8")

    assert not _valid_echo_slo_benchmark(path)


def test_echo_slo_artifact_rejects_short_context_regression_over_five_percent(
    tmp_path: pathlib.Path,
) -> None:
    _write_valid_stable_artifacts(tmp_path)
    path = tmp_path / "docs" / "security" / "ECHO_SLO_BENCHMARK.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    tokens = data["baseline_comparison"]["short_prompt_tokens"]
    tokens["echo_p95"] = 550.0
    tokens["p95_increase_pct"] = 10.0
    path.write_text(json.dumps(data), encoding="utf-8")

    assert not _valid_echo_slo_benchmark(path)


def test_echo_slo_artifact_rejects_modified_detached_baseline(
    tmp_path: pathlib.Path,
) -> None:
    _write_valid_stable_artifacts(tmp_path)
    baseline = tmp_path / "docs" / "security" / "ECHO_BASELINE_65CC545.json"
    baseline.write_text(baseline.read_text(encoding="utf-8") + "\n", encoding="utf-8")

    benchmark = tmp_path / "docs" / "security" / "ECHO_SLO_BENCHMARK.json"
    assert not _valid_echo_slo_benchmark(benchmark)


@pytest.mark.parametrize(
    "mutation",
    [
        "missing_provenance",
        "provenance_schema",
        "provenance_commit",
        "git_tree",
        "measured_source_digest",
        "measured_uv_lock",
        "measured_js_import_bytes",
        "external_harness",
        "tokenizer_resource",
        "tokenizer_version",
        "workload_corpus",
        "interpreter_identity",
        "platform_identity",
        "import_escape",
        "all_group_history_markers",
        "measured_sample_count",
        "group_failures",
        "group_paid_provider_calls",
        "aggregate_group_closure",
    ],
)
def test_echo_slo_artifact_rejects_tampered_old_baseline_provenance(
    tmp_path: pathlib.Path,
    mutation: str,
) -> None:
    """A rebound artifact hash must not turn unverified old-code claims into release evidence."""
    _write_valid_stable_artifacts(tmp_path)
    benchmark_path = tmp_path / "docs" / "security" / "ECHO_SLO_BENCHMARK.json"
    baseline_path = tmp_path / "docs" / "security" / "ECHO_BASELINE_65CC545.json"
    assert _valid_echo_slo_benchmark(benchmark_path)

    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    provenance = baseline["provenance"]
    if mutation == "missing_provenance":
        del baseline["provenance"]
    elif mutation == "provenance_schema":
        provenance["schema_version"] = "echo-old-baseline-provenance-v1"
    elif mutation == "provenance_commit":
        provenance["commit"] = "0" * 40
    elif mutation == "git_tree":
        baseline["tree"] = "0" * 40
        provenance["tree"] = "0" * 40
    elif mutation == "measured_source_digest":
        baseline["source_digest"] = "0" * 64
        provenance["source_digest"] = "0" * 64
    elif mutation == "measured_uv_lock":
        provenance["uv_lock_sha256"] = "0" * 64
    elif mutation == "measured_js_import_bytes":
        provenance["import_root_sha256"] = "0" * 64
    elif mutation == "external_harness":
        provenance["harness_sha256"] = "0" * 64
    elif mutation == "tokenizer_resource":
        provenance["tokenizer"]["resource_tree_sha256"] = "0" * 64
    elif mutation == "tokenizer_version":
        provenance["tokenizer"]["tiktoken_version"] = "0.0.0"
    elif mutation == "workload_corpus":
        provenance["workload"]["corpus_sha256"] = "0" * 64
    elif mutation == "interpreter_identity":
        provenance["interpreter"]["version"] = "0.0.0"
    elif mutation == "platform_identity":
        provenance["platform"]["identity"] = "tampered-platform"
        provenance["platform"]["identity_sha256"] = hashlib.sha256(b"tampered-platform").hexdigest()
    elif mutation == "import_escape":
        escaped = str((tmp_path / "js" / "__init__.py").resolve())
        baseline["import_root"] = escaped
        provenance["import_root"] = escaped
    elif mutation == "all_group_history_markers":
        receipt = baseline["run_summaries"][4]["long_provider_payload_evidence"][49]
        receipt["history_marker_count"] = 39
        receipt["history_marker_counts"].pop("benchmark long history message 39")
    elif mutation == "measured_sample_count":
        baseline["run_summaries"][2]["short_provider_payload_evidence"].pop()
    elif mutation == "group_failures":
        baseline["run_summaries"][1]["failures"] = ["long HTTP 500"]
    elif mutation == "group_paid_provider_calls":
        baseline["run_summaries"][3]["paid_provider_calls"] = 1
    elif mutation == "aggregate_group_closure":
        baseline["run_summaries"][0]["api_full_agent"]["p95_ms"] = 49.0
    else:  # pragma: no cover - the parameter list is closed above.
        raise AssertionError(mutation)

    baseline_path.write_text(json.dumps(baseline, indent=2) + "\n", encoding="utf-8")
    benchmark = json.loads(benchmark_path.read_text(encoding="utf-8"))
    benchmark["baseline_comparison"]["baseline_artifact_sha256"] = hashlib.sha256(
        baseline_path.read_bytes()
    ).hexdigest()
    rebound_source_digest = release_source_digest(tmp_path)
    benchmark["source_digest"] = rebound_source_digest
    benchmark["metadata"]["source_digest"] = rebound_source_digest
    benchmark_path.write_text(json.dumps(benchmark, indent=2) + "\n", encoding="utf-8")

    assert not _valid_echo_slo_benchmark(benchmark_path)


def test_echo_slo_artifact_rejects_modified_baseline_script(
    tmp_path: pathlib.Path,
) -> None:
    _write_valid_stable_artifacts(tmp_path)
    script = tmp_path / "benchmarks" / "old_architecture_baseline.py"
    script.write_text(script.read_text(encoding="utf-8") + "# changed\n", encoding="utf-8")

    benchmark = tmp_path / "docs" / "security" / "ECHO_SLO_BENCHMARK.json"
    assert not _valid_echo_slo_benchmark(benchmark)


def test_echo_slo_artifact_rejects_modified_benchmark_script(
    tmp_path: pathlib.Path,
) -> None:
    _write_valid_stable_artifacts(tmp_path)
    script = tmp_path / "scripts" / "echo_architecture_benchmark.py"
    script.write_text(script.read_text(encoding="utf-8") + "# changed\n", encoding="utf-8")

    benchmark = tmp_path / "docs" / "security" / "ECHO_SLO_BENCHMARK.json"
    assert not _valid_echo_slo_benchmark(benchmark)


def test_release_gate_rejects_audit_reports_bound_to_an_old_benchmark(
    tmp_path: pathlib.Path,
) -> None:
    _write_valid_stable_artifacts(tmp_path)
    benchmark = tmp_path / "docs" / "security" / "ECHO_SLO_BENCHMARK.json"
    benchmark.write_text(benchmark.read_text(encoding="utf-8") + "\n", encoding="utf-8")

    report = verify_release_readiness(tmp_path)

    assert not report.internal_ready
    assert "echo_audit_reports_stale" in report.internal_blockers


def test_release_gate_recognizes_required_internal_evidence(
    tmp_path: pathlib.Path,
) -> None:
    root = tmp_path
    _write_required_internal_evidence(root)
    _write_valid_stable_artifacts(root)
    _write_valid_live_acceptance(root)

    report = verify_release_readiness(root)

    assert report.internal_ready
    assert "origin_ledger" in report.passed
    assert "third_party_notices" in report.passed
    assert "codeowners" in report.passed
    assert "adr" in report.passed
    assert "rfc_template" in report.passed
    assert "echo_self_developed_boundary" in report.passed
    assert "echo_unified_execution_contract" in report.passed
    assert "echo_kernel_core" in report.passed
    assert "echo_recovery_probe" in report.passed
    assert "echo_local_sandbox_adapter" in report.passed
    assert "echo_ip_boundary" in report.passed


def test_release_gate_keeps_external_reviews_as_explicit_blockers(
    tmp_path: pathlib.Path,
) -> None:
    root = tmp_path
    _write_required_internal_evidence(root)
    _write_valid_stable_artifacts(root)
    _write_valid_live_acceptance(root)

    report = verify_release_readiness(root)

    assert not report.stable_ready
    assert report.external_blockers
    # Only fix legal suffixes / current unresolved state — never claim external pass.
    _allowed_suffixes = ("_pending", "_missing", "_invalid")
    assert all(
        any(blocker.endswith(suffix) for suffix in _allowed_suffixes)
        for blocker in report.external_blockers
    )
    for name in (
        "legal_fto_review",
        "clean_room_reviewer",
        "external_security_audit",
        "redteam_report",
    ):
        assert name not in report.passed
        assert any(blocker.startswith(f"{name}_") for blocker in report.external_blockers)
    assert "sbom_spdx" in report.passed
    assert "license_scan" in report.passed
    assert "echo_slo_benchmark" in report.passed
    assert "echo_live_acceptance_60m" in report.passed
    assert "sbom_spdx_missing" not in report.external_blockers
    assert "license_scan_missing" not in report.external_blockers
    assert "echo_slo_benchmark_missing" not in report.external_blockers
    assert "echo_slo_benchmark_pending" not in report.external_blockers


def test_release_gate_reports_missing_internal_evidence(tmp_path: pathlib.Path) -> None:
    report = verify_release_readiness(tmp_path)

    assert not report.internal_ready
    assert "origin_ledger_missing" in report.internal_blockers
    assert "codeowners_missing" in report.internal_blockers


def test_release_gate_requires_25_case_matrix_and_real_sandbox() -> None:
    root = pathlib.Path(__file__).resolve().parents[3]

    report = verify_release_readiness(root)

    assert "security_matrix_25" in report.passed
    assert "real_sandbox_backend" in report.passed


def test_echo_ip_boundary_blocks_disallowed_project_api_shape(
    tmp_path: pathlib.Path,
) -> None:
    code_path = tmp_path / "js" / "echo" / "bad.py"
    code_path.parent.mkdir(parents=True)
    code_path.write_text("class StateGraph:\n    pass\n", encoding="utf-8")

    report = verify_echo_ip_boundary(tmp_path)

    assert not report.ok
    assert any("StateGraph" in finding for finding in report.findings)


def test_echo_ip_boundary_blocks_clean_room_matrix_tokens(
    tmp_path: pathlib.Path,
) -> None:
    code_path = tmp_path / "js" / "echo" / "bad.py"
    code_path.parent.mkdir(parents=True)
    code_path.write_text(
        "\n".join(
            [
                "START = object()",
                "END = object()",
                "def add_node(name): return name",
                "def add_edge(left, right): return left, right",
                "def compile(graph): return graph",
                "def handoff(agent): return agent",
                "def guardrail(value): return value",
                "tripwire = True",
                "class Workflow: pass",
                "class Conversation: pass",
                "class Runtime: pass",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    report = verify_echo_ip_boundary(tmp_path)

    assert not report.ok
    for token in (
        "START",
        "END",
        "add_node",
        "add_edge",
        "compile",
        "handoff",
        "guardrail",
        "tripwire",
        "Workflow",
        "Conversation",
        "Runtime",
    ):
        assert any(token in finding for finding in report.findings)


def test_echo_ip_boundary_blocks_unverifiable_self_developed_claim(
    tmp_path: pathlib.Path,
) -> None:
    doc_path = tmp_path / "docs" / "echo" / "bad.md"
    doc_path.parent.mkdir(parents=True)
    doc_path.write_text("Echo 2.0 是 100% 自研并且无侵权。\n", encoding="utf-8")

    report = verify_echo_ip_boundary(tmp_path)

    assert not report.ok
    assert any("unverifiable self-developed claim" in finding for finding in report.findings)


def test_echo_ip_boundary_allows_clean_room_avoidance_matrix(
    tmp_path: pathlib.Path,
) -> None:
    doc_path = tmp_path / "docs" / "security" / "ECHO_2_CLEAN_ROOM.md"
    doc_path.parent.mkdir(parents=True)
    doc_path.write_text(
        "Avoid `StateGraph`, `AgentWorkflow`, and `CodeAgent` API shapes.\n",
        encoding="utf-8",
    )

    report = verify_echo_ip_boundary(tmp_path)

    assert report.ok


def test_ip_boundary_handoff_vault_narrow_exemption_passes(
    tmp_path: pathlib.Path,
) -> None:
    """handoff_vault.py 中合法内部 handoff 命名应通过。"""
    code_path = tmp_path / "js" / "echo" / "handoff_vault.py"
    code_path.parent.mkdir(parents=True)
    code_path.write_text(
        'HANDOFF_VAULT_MAC_DOMAIN = b"js-agent:handoff-vault:v1\\0"\n',
        encoding="utf-8",
    )

    report = verify_echo_ip_boundary(tmp_path)

    assert report.ok, f"handoff_vault.py internal handoff should pass: {report.findings}"


def test_ip_boundary_handoff_vault_still_blocks_other_tokens(
    tmp_path: pathlib.Path,
) -> None:
    """handoff_vault.py 中出现 StateGraph/Workflow/guardrail 仍应失败。"""
    code_path = tmp_path / "js" / "echo" / "handoff_vault.py"
    code_path.parent.mkdir(parents=True)
    code_path.write_text(
        'HANDOFF_VAULT_MAC_DOMAIN = b"js-agent:handoff-vault:v1\\0"\n'
        "class StateGraph:\n    pass\n",
        encoding="utf-8",
    )

    report = verify_echo_ip_boundary(tmp_path)

    assert not report.ok
    assert any("StateGraph" in f for f in report.findings)


def test_ip_boundary_other_files_handoff_still_fails(
    tmp_path: pathlib.Path,
) -> None:
    """其他文件出现 handoff 仍应失败。"""
    code_path = tmp_path / "js" / "echo" / "other.py"
    code_path.parent.mkdir(parents=True)
    code_path.write_text("def handoff(agent): return agent\n", encoding="utf-8")

    report = verify_echo_ip_boundary(tmp_path)

    assert not report.ok
    assert any("handoff" in f for f in report.findings)


def test_ip_boundary_token_exemption_has_documented_reason() -> None:
    """例外有明确原因注释，不能扩展成整文件 allowlist。"""
    from js.echo.ledger.release_gates import _TOKEN_EXEMPTIONS

    key = ("js/echo/handoff_vault.py", "handoff")
    assert key in _TOKEN_EXEMPTIONS
    reason = _TOKEN_EXEMPTIONS[key]
    assert "internal" in reason.lower() or "vault" in reason.lower()
    assert "framework" in reason.lower() or "not" in reason.lower()


def test_release_gate_accepts_external_evidence_only_when_approved(
    tmp_path: pathlib.Path,
    monkeypatch,
) -> None:
    _write_complete_signed_approval_set(tmp_path, monkeypatch)

    report = verify_release_readiness(tmp_path)

    assert report.stable_ready


def test_release_gate_rejects_approval_bound_to_previous_head(
    tmp_path: pathlib.Path,
    monkeypatch,
) -> None:
    _write_complete_signed_approval_set(tmp_path, monkeypatch)
    source = tmp_path / "js/echo/new_release_code.py"
    source.parent.mkdir(parents=True)
    source.write_text("RELEASE_VALUE = 1\n", encoding="utf-8")
    # Refresh digest-bound artifacts so only external approvals go stale.
    _write_valid_stable_artifacts(tmp_path)
    _write_valid_live_acceptance(tmp_path)
    digest = hashlib.sha256(
        (tmp_path / "docs" / "security" / "ECHO_SLO_BENCHMARK.json").read_bytes()
    ).hexdigest()
    for relative in (
        "docs/echo/ECHO_10_ROUND_AUDIT.md",
        "docs/echo/ECHO_FINAL_REPLACEMENT_REPORT.md",
    ):
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"Benchmark SHA-256: `{digest}`\n", encoding="utf-8")
    _git(
        tmp_path,
        "add",
        "js/echo/new_release_code.py",
        "docs/security/ECHO_LIVE_ACCEPTANCE.json",
        "docs/security/ECHO_SLO_BENCHMARK.json",
        "docs/security/ECHO_ISOLATED_VENV_E2E.json",
        "docs/echo/ECHO_10_ROUND_AUDIT.md",
        "docs/echo/ECHO_FINAL_REPLACEMENT_REPORT.md",
    )
    _git(tmp_path, "commit", "--quiet", "-m", "change release source")

    report = verify_release_readiness(tmp_path)

    assert report.internal_ready
    assert not report.stable_ready
    assert "legal_fto_review_pending" in report.external_blockers


def test_release_gate_rejects_approval_when_git_head_is_unavailable(
    tmp_path: pathlib.Path,
    monkeypatch,
) -> None:
    reviewer = "external-reviewer"
    private_key = Ed25519PrivateKey.generate()
    _write_required_internal_evidence(tmp_path)
    _write_valid_stable_artifacts(tmp_path)
    _write_valid_live_acceptance(tmp_path)
    _set_trusted_reviewer_key(
        monkeypatch,
        reviewer=reviewer,
        private_key=private_key,
    )
    for evidence_name in (
        "legal_fto_review",
        "clean_room_reviewer",
        "external_security_audit",
        "redteam_report",
    ):
        _write_signed_external_approval(
            tmp_path,
            evidence_name=evidence_name,
            reviewer=reviewer,
            private_key=private_key,
            scope_commit="a" * 40,
        )

    report = verify_release_readiness(tmp_path)

    assert report.internal_ready
    assert not report.stable_ready
    assert "legal_fto_review_pending" in report.external_blockers


def test_release_gate_rejects_uncommitted_release_surface(
    tmp_path: pathlib.Path,
    monkeypatch,
) -> None:
    _write_complete_signed_approval_set(tmp_path, monkeypatch)
    source = tmp_path / "js/echo/uncommitted_release_code.py"
    source.parent.mkdir(parents=True)
    source.write_text("UNCOMMITTED_VALUE = 1\n", encoding="utf-8")

    report = verify_release_readiness(tmp_path)

    assert not report.internal_ready
    assert "echo_live_acceptance_invalid" in report.internal_blockers
    assert not report.stable_ready
    assert "legal_fto_review_pending" in report.external_blockers


def test_release_gate_allows_dirty_non_release_file(
    tmp_path: pathlib.Path,
    monkeypatch,
) -> None:
    _write_complete_signed_approval_set(tmp_path, monkeypatch)
    (tmp_path / "local-notes.txt").write_text("development notes\n", encoding="utf-8")

    report = verify_release_readiness(tmp_path)

    assert report.stable_ready


def test_release_gate_fails_closed_without_trusted_reviewer_keys(
    tmp_path: pathlib.Path,
    monkeypatch,
) -> None:
    _write_complete_signed_approval_set(tmp_path, monkeypatch)
    monkeypatch.delenv("JS_ECHO_TRUSTED_REVIEW_KEYS", raising=False)

    report = verify_release_readiness(tmp_path)

    assert not report.stable_ready
    assert "legal_fto_review_pending" in report.external_blockers


def test_release_gate_rejects_tampered_signed_approval_fields(
    tmp_path: pathlib.Path,
    monkeypatch,
) -> None:
    _write_complete_signed_approval_set(tmp_path, monkeypatch)
    approval = tmp_path / "docs/security/LEGAL_FTO_REVIEW.md"
    approval.write_text(
        approval.read_text(encoding="utf-8").replace(
            "Approval-Reference: EXT-2026-0712-001",
            "Approval-Reference: EXT-2026-0712-TAMPERED",
        ),
        encoding="utf-8",
    )

    report = verify_release_readiness(tmp_path)

    assert not report.stable_ready
    assert "legal_fto_review_pending" in report.external_blockers


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("Status", "REVOKED"),
        ("Reviewer", "unknown-reviewer"),
        ("Date", "2026-07-13"),
        ("Evidence-Name", "another-evidence"),
        ("Scope-Commit", "b" * 40),
        ("SBOM-SHA256", "b" * 64),
        ("UV-Lock-SHA256", "b" * 64),
        ("Approval-Reference", "EXT-2026-0712-TAMPERED"),
        ("Signature", base64.b64encode(b"x" * 64).decode("ascii")),
    ),
)
def test_release_gate_rejects_every_tampered_approval_field(
    tmp_path: pathlib.Path,
    monkeypatch,
    field: str,
    replacement: str,
) -> None:
    _write_complete_signed_approval_set(tmp_path, monkeypatch)
    approval = tmp_path / "docs/security/LEGAL_FTO_REVIEW.md"
    approval.write_text(
        approval.read_text(encoding="utf-8").replace(
            f"{field}: " + _approval_field_value(approval, field),
            f"{field}: {replacement}",
        ),
        encoding="utf-8",
    )

    report = verify_release_readiness(tmp_path)

    assert not report.stable_ready
    assert "legal_fto_review_pending" in report.external_blockers


def _approval_field_value(path: pathlib.Path, field: str) -> str:
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith(f"{field}: "):
            return line.removeprefix(f"{field}: ")
    raise AssertionError(f"approval field {field} was not found")


def test_release_gate_rejects_cross_report_signature_replay(
    tmp_path: pathlib.Path,
    monkeypatch,
) -> None:
    reviewer, private_key = _write_complete_signed_approval_set(tmp_path, monkeypatch)
    for evidence_name in (
        "clean_room_reviewer",
        "external_security_audit",
        "redteam_report",
    ):
        _write_signed_external_approval(
            tmp_path,
            evidence_name=evidence_name,
            reviewer=reviewer,
            private_key=private_key,
            signed_evidence_name="legal_fto_review",
        )

    report = verify_release_readiness(tmp_path)

    assert not report.stable_ready
    assert "clean_room_reviewer_pending" in report.external_blockers


def test_release_gate_allows_json_metric_fields_containing_pending(
    tmp_path: pathlib.Path,
) -> None:
    path = tmp_path / "artifact.json"
    path.write_text(
        '{"pending_effect_count":0,"claimed_effect_count":0,"ok":true}\n',
        encoding="utf-8",
    )

    assert not _has_unresolved_artifact_marker(path)


def test_release_gate_rejects_blank_external_approval_fields(
    tmp_path: pathlib.Path,
) -> None:
    for relative in (
        "ORIGIN_LEDGER.md",
        "THIRD_PARTY_NOTICES.md",
        ".github/CODEOWNERS",
        "docs/adr/0001-echo-ledger-boundary.md",
        "docs/rfc/echo-ledger-major-change-template.md",
        "docs/echo/ECHO_SELF_DEVELOPED_BOUNDARY.md",
        "docs/echo/ECHO_UNIFIED_EXECUTION_CONTRACT.md",
    ):
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("ok\n", encoding="utf-8")

    for relative in (
        "docs/security/LEGAL_FTO_REVIEW.md",
        "docs/security/CLEAN_ROOM_REVIEW.md",
        "docs/security/EXTERNAL_SECURITY_AUDIT.md",
        "docs/security/REDTEAM_REPORT.md",
    ):
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("Status: APPROVED\nReviewer:\nDate:\n", encoding="utf-8")

    report = verify_release_readiness(tmp_path)

    assert not report.stable_ready
    assert "legal_fto_review_pending" in report.external_blockers
    assert "clean_room_reviewer_pending" in report.external_blockers


def test_release_gate_requires_echo_slo_benchmark_artifact(
    tmp_path: pathlib.Path,
) -> None:
    for relative in (
        "ORIGIN_LEDGER.md",
        "THIRD_PARTY_NOTICES.md",
        ".github/CODEOWNERS",
        "docs/adr/0001-echo-ledger-boundary.md",
        "docs/rfc/echo-ledger-major-change-template.md",
        "docs/echo/ECHO_SELF_DEVELOPED_BOUNDARY.md",
        "docs/echo/ECHO_UNIFIED_EXECUTION_CONTRACT.md",
        "docs/security/SBOM.spdx.json",
        "docs/security/LICENSE_SCAN.md",
    ):
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("ok\n", encoding="utf-8")

    report = verify_release_readiness(tmp_path)

    assert "echo_slo_benchmark_missing" in report.external_blockers


def test_release_gate_rejects_invalid_stable_artifacts(tmp_path: pathlib.Path) -> None:
    for relative in (
        "ORIGIN_LEDGER.md",
        "THIRD_PARTY_NOTICES.md",
        ".github/CODEOWNERS",
        "docs/adr/0001-echo-ledger-boundary.md",
        "docs/rfc/echo-ledger-major-change-template.md",
        "docs/echo/ECHO_SELF_DEVELOPED_BOUNDARY.md",
        "docs/echo/ECHO_UNIFIED_EXECUTION_CONTRACT.md",
    ):
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("ok\n", encoding="utf-8")
    security_dir = tmp_path / "docs" / "security"
    security_dir.mkdir(parents=True, exist_ok=True)
    (security_dir / "SBOM.spdx.json").write_text('{"spdxVersion":"SPDX-2.3"}\n')
    (security_dir / "LICENSE_SCAN.md").write_text("Status: COMPLETE\n")
    (security_dir / "ECHO_SLO_BENCHMARK.json").write_text('{"security_matrix":{}}\n')

    report = verify_release_readiness(tmp_path)

    assert "sbom_spdx_invalid" in report.external_blockers
    assert "license_scan_invalid" in report.external_blockers
    assert "echo_slo_benchmark_invalid" in report.external_blockers


def test_release_gate_rejects_slo_artifact_without_recovery_metrics(
    tmp_path: pathlib.Path,
) -> None:
    for relative in (
        "ORIGIN_LEDGER.md",
        "THIRD_PARTY_NOTICES.md",
        ".github/CODEOWNERS",
        "docs/adr/0001-echo-ledger-boundary.md",
        "docs/rfc/echo-ledger-major-change-template.md",
        "docs/echo/ECHO_SELF_DEVELOPED_BOUNDARY.md",
        "docs/echo/ECHO_UNIFIED_EXECUTION_CONTRACT.md",
    ):
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("ok\n", encoding="utf-8")
    security_dir = tmp_path / "docs" / "security"
    security_dir.mkdir(parents=True, exist_ok=True)
    _write_valid_stable_artifacts(tmp_path)
    (security_dir / "ECHO_SLO_BENCHMARK.json").write_text(
        '{"modes":{"echo":{}},"token_comparison":{"api_full_agent_prompt_within_limit":true},"security_matrix":{"ok":true,"passed":25,"total":25}}\n',
        encoding="utf-8",
    )

    report = verify_release_readiness(tmp_path)

    assert "echo_slo_benchmark_invalid" in report.external_blockers
