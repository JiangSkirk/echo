from __future__ import annotations

import copy
import os
import subprocess
from collections import Counter
from pathlib import Path


def test_release_smoke_all_includes_echo_mode_matrix() -> None:
    import scripts.release_smoke as release_smoke

    assert "echo" in release_smoke.CHECKS
    assert "work" in release_smoke.CHECKS
    assert release_smoke.parse_args(["--all"]).all


def test_release_smoke_has_explicit_stable_gate() -> None:
    import scripts.release_smoke as release_smoke

    args = release_smoke.parse_args(["--all", "--stable"])

    assert args.all
    assert args.stable


def test_release_smoke_stable_gate_blocks_unapproved_release() -> None:
    import scripts.release_smoke as release_smoke

    try:
        release_smoke.check_stable_release_gate(Path(__file__).resolve().parents[3])
    except release_smoke.SmokeError as exc:
        text = str(exc)
        assert "stable release blockers" in text
        # Legal suffix / unresolved external state only — never claim external pass.
        for name in (
            "legal_fto_review_",
            "clean_room_reviewer_",
            "external_security_audit_",
            "redteam_report_",
        ):
            assert name in text
        assert "sbom_spdx_missing" not in text
        assert "license_scan_missing" not in text
    else:  # pragma: no cover - this repository should not self-approve stable release.
        raise AssertionError("stable release gate unexpectedly passed")


def test_echo_architecture_benchmark_has_explicit_slo_gate() -> None:
    import scripts.echo_architecture_benchmark as benchmark

    args = benchmark.parse_args(["--enforce-slo"])

    assert args.enforce_slo


def test_echo_architecture_benchmark_reuses_embedded_clean_export_baseline() -> None:
    import scripts.echo_architecture_benchmark as benchmark

    normalized = benchmark._normalize_baseline_payload(
        {
            "baseline_comparison": {
                "valid": True,
                "baseline_commit": "65cc545",
                "iterations": 50,
                "warmup": 10,
                "runs": 5,
                "paid_provider_calls": 0,
                "api_full_agent": {"old_mean_ms": 41.0, "old_p95_ms": 45.0},
                "prompt_tokens": {
                    "source": "tokenizer",
                    "method": benchmark.TOKENIZER_METHOD,
                    "old_p50": 8_800.0,
                    "old_p95": 8_800.0,
                },
                "short_prompt_tokens": {
                    "source": "tokenizer",
                    "method": benchmark.TOKENIZER_METHOD,
                    "old_p50": 4_200.0,
                    "old_p95": 4_200.0,
                },
            }
        }
    )

    assert normalized["commit"] == "65cc545"
    assert normalized["api_full_agent"]["p95_ms"] == 45.0
    assert normalized["prompt_tokens"]["p95"] == 8_800.0
    assert normalized["short_prompt_tokens"]["p50"] == 4_200.0


def test_echo_architecture_wrapper_benchmark_uses_real_echo_runtime(tmp_path: Path) -> None:
    import scripts.echo_architecture_benchmark as benchmark

    mode = benchmark.MODES[0]
    settings = benchmark._settings(tmp_path, mode)
    agent = benchmark._make_mock_agent(settings)

    with benchmark._build_chat_client(settings, agent) as stack:
        response = stack.client.post(
            "/api/chat",
            json={"message": "benchmark", "session_id": "wrapper-session"},
        )

    assert response.status_code == 200
    assert response.json()["response"] == "mock response"
    assert agent.echo_turn_calls == 1


def test_echo_long_context_provider_payload_contains_expected_bounded_markers_once(
    tmp_path: Path,
    monkeypatch,
) -> None:
    import js.web.auth as auth_mod
    import scripts.echo_architecture_benchmark as benchmark

    captured_messages = []
    original_chat = benchmark.DeterministicProvider.chat
    sentinel_origins = {"http://sentinel.example"}
    sentinel_origins_env = "http://sentinel.example"
    monkeypatch.setenv("JS_ECHO_ENGINE", "sentinel-engine")
    monkeypatch.setenv("JS_ALLOWED_ORIGINS", sentinel_origins_env)
    monkeypatch.setattr(auth_mod, "_ALLOWED_ORIGINS", sentinel_origins)
    monkeypatch.setattr(auth_mod, "_ALLOWED_ORIGINS_ENV", sentinel_origins_env)

    async def capture_chat(self, messages, model, tools=None, temperature=0.7, max_tokens=None):
        captured_messages.append(list(messages))
        return await original_chat(
            self,
            messages,
            model,
            tools,
            temperature,
            max_tokens,
        )

    monkeypatch.setattr(benchmark.DeterministicProvider, "chat", capture_chat)

    mode = benchmark.MODES[0]
    with benchmark._isolated_benchmark_environment(mode):
        result = benchmark._run_api_full_agent(
            tmp_path,
            mode,
            iterations=1,
            warmup=0,
        )

    assert captured_messages, result["failures"]
    observed = Counter(
        marker
        for message in captured_messages[-1]
        if isinstance(message.content, str)
        for marker in (
            f"benchmark long history message {index}"
            for index in range(26, 40)
        )
        if marker in message.content.split(" context ", maxsplit=1)[0]
    )
    expected = Counter(
        {
            f"benchmark long history message {index}": 1
            for index in range(26, 40)
        }
    )

    assert result["failures"] == []
    assert observed == expected
    assert os.environ["JS_ECHO_ENGINE"] == "sentinel-engine"
    assert os.environ["JS_ALLOWED_ORIGINS"] == sentinel_origins_env
    assert auth_mod._ALLOWED_ORIGINS is sentinel_origins
    assert sentinel_origins_env == auth_mod._ALLOWED_ORIGINS_ENV


def test_echo_benchmark_router_consumes_runtime_model_permits(tmp_path: Path) -> None:
    import scripts.echo_architecture_benchmark as benchmark

    mode = benchmark.MODES[0]
    with benchmark._isolated_benchmark_environment(mode):
        result = benchmark._run_api_short_agent(
            tmp_path,
            mode,
            iterations=1,
            warmup=0,
        )

    assert result["provider_chat_calls"] == 1
    assert result["failures"] == []


def test_echo_long_context_prompt_tokens_exceed_short_context(tmp_path: Path) -> None:
    import scripts.echo_architecture_benchmark as benchmark

    mode = benchmark.MODES[0]
    with benchmark._isolated_benchmark_environment(mode):
        long_result = benchmark._run_api_full_agent(
            tmp_path / "long",
            mode,
            iterations=1,
            warmup=0,
        )
    with benchmark._isolated_benchmark_environment(mode):
        short_result = benchmark._run_api_short_agent(
            tmp_path / "short",
            mode,
            iterations=1,
            warmup=0,
        )

    assert long_result["prompt_tokens"]["p50"] > short_result["prompt_tokens"]["p50"]


def test_echo_fake_provider_records_long_context_marker_and_payload_digests(
    tmp_path: Path,
) -> None:
    import scripts.echo_architecture_benchmark as benchmark

    mode = benchmark.MODES[0]
    with benchmark._isolated_benchmark_environment(mode):
        result = benchmark._run_api_full_agent(
            tmp_path,
            mode,
            iterations=1,
            warmup=0,
        )

    evidence = result.get("provider_payload_evidence")
    assert isinstance(evidence, list)
    assert len(evidence) == 1
    assert evidence[0]["history_marker_count"] == 14
    assert len(evidence[0]["history_marker_sha256"]) == 64
    assert len(evidence[0]["message_identity_sha256"]) == 64
    validation = result["provider_payload_validation"]
    assert validation["seeded_history_message_count"] == 40
    assert validation["expected_provider_history_message_count"] == 14
    assert validation["dropped_by_context_vault_count"] == 26
    assert evidence[0]["history_marker_sha256"] == validation["expected_history_marker_sha256"]


def test_echo_long_context_gate_rejects_missing_and_foreign_markers(
    tmp_path: Path,
    monkeypatch,
) -> None:
    import scripts.echo_architecture_benchmark as benchmark

    corrupted = benchmark._benchmark_history()
    corrupted[-1] = {
        "role": "assistant",
        "content": "benchmark long history message 999 " + ("context " * 80),
    }
    monkeypatch.setattr(benchmark, "_benchmark_history", lambda: corrupted)

    mode = benchmark.MODES[0]
    with benchmark._isolated_benchmark_environment(mode):
        result = benchmark._run_api_full_agent(
            tmp_path,
            mode,
            iterations=1,
            warmup=0,
        )

    assert any("history markers" in failure for failure in result["failures"])


def test_echo_slo_gate_rejects_equal_long_and_short_prompt_tokens() -> None:
    import scripts.echo_architecture_benchmark as benchmark

    result = {
        "modes": {
            "echo": {
                "api_full_agent": {
                    "latency": {"n": 1, "p95_ms": 1.0},
                    "prompt_tokens": {"p50": 1_661.0, "p95": 1_661.0},
                },
                "api_short_agent": {
                    "prompt_tokens": {"p50": 1_661.0, "p95": 1_661.0},
                },
                "api_wrapper_only": {"latency": {"n": 1, "p95_ms": 1.0}},
                "ws_message_wrapper": {"latency": {"n": 1, "p95_ms": 1.0}},
                "ws_stream_wrapper": {"latency": {"n": 1, "p95_ms": 1.0}},
            }
        },
        "token_comparison": {
            "api_full_agent_prompt_p95_echo": 1_661.0,
            "api_full_agent_prompt_p95_limit": 9_000.0,
            "api_full_agent_prompt_within_limit": True,
            "api_short_prompt_p50_echo": 1_661.0,
            "api_short_prompt_p95_echo": 1_661.0,
            "token_source": "tokenizer",
        },
    }

    failures = benchmark.evaluate_slo_failures(result)

    assert any("long-context prompt tokens" in failure for failure in failures)


def test_old_architecture_baseline_authenticates_chat_requests(tmp_path: Path) -> None:
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    import js
    from benchmarks import old_architecture_baseline as baseline
    from js.agent import JSAgent
    from js.config import JSSettings, MemoryConfig, SecurityConfig
    from js.models.providers import ChatMessage, ChatResponse
    from js.models.stream_events import StreamEvent
    from js.web.auth import AuthManager
    from js.web.routers.chat import router as chat_router

    runtime = baseline.MeasuredRuntime(
        root=Path(js.__file__).resolve().parents[1],
        import_root=str(Path(js.__file__).resolve()),
        FastAPI=FastAPI,
        TestClient=TestClient,
        JSAgent=JSAgent,
        JSSettings=JSSettings,
        MemoryConfig=MemoryConfig,
        SecurityConfig=SecurityConfig,
        ChatMessage=ChatMessage,
        ChatResponse=ChatResponse,
        StreamEvent=StreamEvent,
        AuthManager=AuthManager,
        chat_router=chat_router,
    )
    settings = baseline._settings(runtime, tmp_path)
    stats = baseline.ProviderStats()
    agent = runtime.JSAgent(settings)
    agent.router = baseline.FakeRouter(baseline.FakeProvider(runtime, stats))

    with baseline._client(runtime, settings, agent) as stack:
        response = stack.client.post(
            "/api/chat",
            json={"message": "benchmark", "session_id": "baseline-auth"},
        )

    assert response.status_code != 403


def test_echo_architecture_benchmark_runs_true_concurrent_rounds(tmp_path: Path) -> None:
    import scripts.echo_architecture_benchmark as benchmark

    result = benchmark._run_concurrency_probe(
        tmp_path,
        benchmark.MODES[0],
        workers=4,
        rounds=2,
    )

    assert result["submitted_concurrency"] == 4
    assert result["rounds"] == 2
    assert result["total_requests"] == 8
    assert result["completed_ok"] == 8
    assert result["http_5xx_count"] == 0
    assert result["crosstalk_count"] == 0
    assert result["runtime_peak_inflight"] >= 2
    assert result["isolation_checks"] == 8
    assert result["overlap_layer"] == "real_gated_provider_calls"
    assert result["execution_model"] == "single_process_async_asgi"


def test_echo_ws_stream_timing_records_send_to_first_text_and_terminal(
    tmp_path: Path,
) -> None:
    import scripts.echo_architecture_benchmark as benchmark

    probe = getattr(benchmark, "_run_ws_stream_timing_probe", None)
    assert callable(probe), "benchmark lacks a provider-cadence WS timing probe"

    mode = benchmark.MODES[0]
    with benchmark._isolated_benchmark_environment(mode):
        result = probe(
            tmp_path,
            mode,
            iterations=2,
            warmup=0,
        )

    assert result.get("provider_stream_event_calls") == 2
    assert result.get("configured_cadence_ms") == {
        "first_text_token": 5.0,
        "inter_text_token": 1.0,
    }
    receipts = result.get("timing_receipts")
    assert isinstance(receipts, list) and len(receipts) == 2
    for receipt in receipts:
        assert isinstance(receipt.get("send_monotonic_ns"), int)
        offsets = receipt.get("frame_offsets_ms")
        assert isinstance(offsets, dict)
        assert 0.0 <= offsets["status"] <= offsets["thinking"]
        assert offsets["thinking"] <= offsets["first_text_token"]
        assert offsets["first_text_token"] <= offsets["usage"] <= offsets["terminal"]
        assert receipt["terminal_count"] == 1
        assert receipt["terminal_type"] == "done"
        assert receipt["frame_types"] == [
            "status",
            "thinking",
            "token",
            "token",
            "token",
            "usage",
            "done",
        ]
    assert result["first_text_token_latency"]["n"] == 2
    assert result["terminal_latency"]["n"] == 2


def test_echo_ws_stream_timing_has_bounded_consumer_disconnect_and_terminal_probes(
    tmp_path: Path,
) -> None:
    import scripts.echo_architecture_benchmark as benchmark

    probe = getattr(benchmark, "_run_ws_stream_timing_probe", None)
    assert callable(probe), "benchmark lacks bounded WS resilience probes"
    mode = benchmark.MODES[0]
    with benchmark._isolated_benchmark_environment(mode):
        result = probe(
            tmp_path,
            mode,
            iterations=1,
            warmup=0,
        )

    resilience = result.get("resilience")
    assert isinstance(resilience, dict)
    assert resilience["single_terminal_all_ok"] is True
    assert resilience["slow_consumer"] == {
        "ok": True,
        "consumer_pause_ms": 10.0,
        "bounded_max_frames": 7,
        "received_frame_count": 7,
        "terminal_count": 1,
        "terminal_type": "done",
    }
    assert resilience["disconnect"]["ok"] is True
    assert resilience["disconnect"]["status_received"] is True
    assert resilience["disconnect"]["provider_started"] is True
    assert resilience["disconnect"]["provider_cancelled"] is True
    assert resilience["disconnect"]["terminal_frames_after_disconnect"] == 0
    assert resilience["disconnect"]["bounded_wait_ms"] <= 1_000.0


def _stream_slo_mutation_result(*, first_text_p95_ms: float, terminal_p95_ms: float):
    import scripts.echo_architecture_benchmark as benchmark

    timing = {
        "first_text_token_latency": {"n": 1, "p95_ms": first_text_p95_ms},
        "terminal_latency": {"n": 1, "p95_ms": terminal_p95_ms},
        "timing_receipts": [
            {
                "send_monotonic_ns": 1,
                "frame_offsets_ms": {
                    "status": 0.1,
                    "thinking": 0.2,
                    "first_text_token": first_text_p95_ms,
                    "usage": max(first_text_p95_ms, terminal_p95_ms - 0.1),
                    "terminal": terminal_p95_ms,
                },
                "terminal_count": 1,
                "terminal_type": "done",
            }
        ],
        "resilience": {
            "single_terminal_all_ok": True,
            "slow_consumer": {"ok": True},
            "disconnect": {"ok": True},
        },
    }
    return {
        "modes": {
            "echo": {
                **{
                    name: {"latency": {"n": 1, "p95_ms": 1.0}}
                    for name in benchmark.SLO_THRESHOLDS
                },
                "ws_stream_timing": timing,
            }
        },
        "aggregate": {
            "group_count": 5,
            "latency_p95_median_ms": dict.fromkeys(benchmark.SLO_THRESHOLDS, 1.0),
            "ws_first_token_p95_median_ms": first_text_p95_ms,
            "ws_terminal_p95_median_ms": terminal_p95_ms,
        },
        "token_comparison": {},
    }


def test_echo_slo_gate_rejects_slow_first_text_token_separately() -> None:
    import scripts.echo_architecture_benchmark as benchmark

    result = _stream_slo_mutation_result(first_text_p95_ms=45.001, terminal_p95_ms=44.0)

    failures = benchmark.evaluate_slo_failures(result)

    assert any("first text token" in failure for failure in failures)
    assert not any("terminal p95" in failure for failure in failures)


def test_echo_slo_gate_rejects_slow_stream_terminal_separately() -> None:
    import scripts.echo_architecture_benchmark as benchmark

    result = _stream_slo_mutation_result(first_text_p95_ms=44.0, terminal_p95_ms=45.001)

    failures = benchmark.evaluate_slo_failures(result)

    assert any("terminal p95" in failure for failure in failures)
    assert not any("first text token" in failure for failure in failures)


def test_echo_recovery_probe_binds_compacted_semantics_outside_timed_interval(
    tmp_path: Path,
) -> None:
    import scripts.echo_architecture_benchmark as benchmark

    result = benchmark._run_recovery_probes(tmp_path)

    receipt = result.get("compaction_semantics")
    assert isinstance(receipt, dict)
    assert receipt["schema_version"] == "echo-compaction-semantic-receipt-v1"
    assert receipt["semantic_verification_outside_timed_interval"] is True
    assert receipt["logical_record_count"] == 1_002
    assert receipt["expected_logical_record_count"] == 1_002
    assert receipt["active_record_count"] == 101
    assert receipt["expected_active_record_count"] == 101
    assert receipt["active_record_types"] == ["snapshot_anchor"] + ["decision"] * 100
    assert receipt["archive_chain_verified"] is True
    assert receipt["archive_generation_count"] == 1
    assert receipt["tombstones"] == ["benchmark-effect-1"]
    assert receipt["archived_effect_lookup_ok"] is True
    assert receipt["logical_payload_equivalent"] is True
    assert receipt["sampled_payload_equivalent"] is True
    assert receipt["post_compaction_bad_tail_recovery_ok"] is True
    assert receipt["corrupt_tail_quarantine_count"] == 1
    assert receipt["ok"] is True
    assert len(receipt["active_journal_sha256"]) == 64
    assert len(receipt["archive_sha256"]) == 64
    assert len(receipt["receipt_sha256"]) == 64


def _compaction_slo_mutation_result(recovery: dict[str, object]) -> dict[str, object]:
    return {
        "aggregate": {
            "group_count": 5,
            "compaction_all_ok": True,
            "compaction_max_ms": 1.0,
            "replay_10k_record_count_min": 10_000,
            "replay_10k_max_seconds": 0.1,
            "bad_tail_all_ok": True,
        },
        "recovery_probes": recovery,
    }


def test_echo_slo_gate_rejects_compaction_count_999() -> None:
    import scripts.echo_architecture_benchmark as benchmark

    recovery: dict[str, object] = {
        "compaction_ok": True,
        "compaction_latency_ms": 1.0,
        "compaction_record_count": 999,
        "compaction_semantics": {"ok": True},
    }

    failures = benchmark.evaluate_slo_failures(_compaction_slo_mutation_result(recovery))

    assert any("compaction semantic" in failure for failure in failures)


def test_echo_slo_gate_rejects_compaction_payload_corruption(tmp_path: Path) -> None:
    import scripts.echo_architecture_benchmark as benchmark

    recovery = benchmark._run_recovery_probes(tmp_path)
    corrupted = copy.deepcopy(recovery)
    receipt = corrupted.get("compaction_semantics")
    assert isinstance(receipt, dict)
    receipt["sampled_payload_sha256"] = "0" * 64

    failures = benchmark.evaluate_slo_failures(_compaction_slo_mutation_result(corrupted))

    assert any("compaction semantic" in failure for failure in failures)


def test_echo_concurrency_probe_isolated_across_event_loops(tmp_path: Path) -> None:
    import scripts.echo_architecture_benchmark as benchmark

    first = benchmark._run_concurrency_probe(
        tmp_path / "first",
        benchmark.MODES[0],
        workers=12,
        rounds=1,
    )
    second = benchmark._run_concurrency_probe(
        tmp_path / "second",
        benchmark.MODES[0],
        workers=12,
        rounds=1,
    )

    assert first["completed_ok"] == 12
    assert second["completed_ok"] == 12
    assert second["failures"] == []


def test_echo_benchmark_defaults_to_five_identical_measurement_groups() -> None:
    import scripts.echo_architecture_benchmark as benchmark

    args = benchmark.parse_args([])

    assert args.runs == 5
    assert args.warmup == 10
    assert args.iterations == 50


def test_echo_benchmark_aggregates_the_median_of_group_p95_values() -> None:
    import scripts.echo_architecture_benchmark as benchmark

    def run_result(p95_ms: float) -> dict[str, object]:
        scenarios = {
            name: {"latency": {"n": 50, "p95_ms": p95_ms}}
            for name in benchmark.SLO_THRESHOLDS
        }
        scenarios["api_full_agent"]["prompt_tokens"] = {
            "p50": 3_000.0,
            "p95": 3_100.0,
            "source": "tokenizer",
            "method": benchmark.TOKENIZER_METHOD,
        }
        scenarios["api_short_agent"] = {
            "prompt_tokens": {
                "p50": 500.0,
                "p95": 510.0,
                "source": "tokenizer",
                "method": benchmark.TOKENIZER_METHOD,
            }
        }
        return {
            "modes": {"echo": scenarios},
            "journal_append_probe": {"latency": {"p95_ms": 1.0}},
            "recovery_probes": {
                "journal_replay_10k_record_count": 10_000,
                "journal_replay_10k_records_s": 0.1,
                "bad_tail_recovery_ok": True,
                "compaction_ok": True,
                "compaction_latency_ms": 10.0,
            },
            "concurrency_probe": {
                "submitted_concurrency": 50,
                "rounds": 3,
                "total_requests": 150,
                "completed_ok": 150,
                "http_5xx_count": 0,
                "crosstalk_count": 0,
                "isolation_checks": 150,
                "runtime_peak_inflight": 2,
                "peak_rss_mb": 100.0,
                "overlap_layer": "real_gated_provider_calls",
                "execution_model": "single_process_async_asgi",
            },
        }

    summaries, aggregate = benchmark._aggregate_run_summaries(
        [run_result(value) for value in (9.0, 3.0, 7.0, 1.0, 5.0)]
    )

    assert len(summaries) == 5
    assert aggregate["group_count"] == 5
    assert aggregate["latency_p95_median_ms"]["api_full_agent"] == 5.0
    assert aggregate["journal_append_p95_max_ms"] == 1.0


def test_echo_benchmark_token_comparison_checks_long_and_short_percentiles() -> None:
    import scripts.echo_architecture_benchmark as benchmark

    comparison = {
        "valid": True,
        "api_full_agent": {
            "old_p95_ms": 50.0,
            "echo_p95_ms": 40.0,
            "p95_delta_pct": -20.0,
        },
        "prompt_tokens": {
            "source": "tokenizer",
            "method": benchmark.TOKENIZER_METHOD,
            "old_p50": 10_000.0,
            "echo_p50": 8_000.0,
            "p50_reduction_pct": 20.0,
            "old_p95": 10_000.0,
            "echo_p95": 8_000.0,
            "reduction_pct": 20.0,
        },
        "short_prompt_tokens": {
            "source": "tokenizer",
            "method": benchmark.TOKENIZER_METHOD,
            "old_p50": 500.0,
            "echo_p50": 520.0,
            "p50_increase_pct": 4.0,
            "old_p95": 500.0,
            "echo_p95": 520.0,
            "p95_increase_pct": 4.0,
        },
    }

    assert benchmark._evaluate_baseline_comparison(comparison) == []
    comparison["short_prompt_tokens"]["echo_p95"] = 550.0
    comparison["short_prompt_tokens"]["p95_increase_pct"] = 10.0

    failures = benchmark._evaluate_baseline_comparison(comparison)

    assert any("short-context p95" in failure for failure in failures)


def test_echo_architecture_benchmark_restores_environment(
    tmp_path: Path,
    monkeypatch,
) -> None:
    import js.web.auth as auth_mod
    import scripts.echo_architecture_benchmark as benchmark

    monkeypatch.setenv("JS_ECHO_ENGINE", "sentinel-engine")
    monkeypatch.setenv("JS_ALLOWED_ORIGINS", "sentinel-origin")
    sentinel_origins = {"sentinel-origin"}
    monkeypatch.setattr(auth_mod, "_ALLOWED_ORIGINS", sentinel_origins)

    benchmark._run_concurrency_probe(
        tmp_path,
        benchmark.MODES[0],
        workers=2,
        rounds=1,
    )

    assert os.environ["JS_ECHO_ENGINE"] == "sentinel-engine"
    assert os.environ["JS_ALLOWED_ORIGINS"] == "sentinel-origin"
    assert auth_mod._ALLOWED_ORIGINS is sentinel_origins


def test_echo_architecture_slo_fails_closed_without_concurrency_evidence() -> None:
    import scripts.echo_architecture_benchmark as benchmark

    result = {
        "modes": {
            "echo": {
                name: {"latency": {"n": 1, "p95_ms": 1.0}}
                for name in benchmark.SLO_THRESHOLDS
            }
        },
        "token_comparison": {
            "api_full_agent_prompt_p95_echo": 1.0,
            "api_full_agent_prompt_p95_limit": 9_000.0,
            "api_full_agent_prompt_within_limit": True,
            "token_source": "tokenizer",
        },
        "recovery_probes": {
            "journal_replay_10k_record_count": 10_000,
            "journal_replay_10k_records_s": 0.1,
            "bad_tail_recovery_ok": True,
            "compaction_ok": True,
            "compaction_latency_ms": 1.0,
        },
    }

    failures = benchmark.evaluate_slo_failures(result)

    assert any("concurrency" in failure for failure in failures)


def test_echo_architecture_benchmark_slo_gate_blocks_slow_echo() -> None:
    import scripts.echo_architecture_benchmark as benchmark

    result = {
        "modes": {
            "echo": {
                "api_full_agent": {"latency": {"p95_ms": 999.0}},
                "api_wrapper_only": {"latency": {"p95_ms": 1.0}},
                "ws_message_wrapper": {"latency": {"p95_ms": 1.0}},
                "ws_stream_wrapper": {"latency": {"p95_ms": 1.0}},
            }
        },
        "comparisons": {},
        "token_comparison": {
            "api_full_agent_prompt_p95_echo": 8115.0,
            "api_full_agent_prompt_within_limit": True,
        },
    }

    failures = benchmark.evaluate_slo_failures(result)

    assert any("api_full_agent" in failure for failure in failures)


def test_echo_architecture_benchmark_slo_gate_blocks_prompt_budget_excess() -> None:
    import scripts.echo_architecture_benchmark as benchmark

    result = {
        "modes": {
            "echo": {
                "api_full_agent": {"latency": {"n": 1, "p95_ms": 10.0}},
                "api_wrapper_only": {"latency": {"n": 1, "p95_ms": 1.0}},
                "ws_message_wrapper": {"latency": {"n": 1, "p95_ms": 1.0}},
                "ws_stream_wrapper": {"latency": {"n": 1, "p95_ms": 1.0}},
            }
        },
        "comparisons": {},
        "token_comparison": {
            "api_full_agent_prompt_p95_echo": 9500.0,
            "api_full_agent_prompt_p95_limit": 9000.0,
            "api_full_agent_prompt_within_limit": False,
            "token_source": "tokenizer",
        },
    }

    failures = benchmark.evaluate_slo_failures(result)

    assert any("prompt p95" in failure for failure in failures)


def test_echo_ledger_smoke_runs_multiple_turns(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"

    proc = subprocess.run(
        [
            ".venv/bin/python",
            "scripts/echo_ledger_smoke.py",
            "--turns",
            "3",
            "--state-dir",
            str(state_dir),
        ],
        cwd=Path(__file__).resolve().parents[3],
        text=True,
        capture_output=True,
        check=False,
    )

    assert proc.returncode == 0, proc.stderr
    assert "echo_ledger_smoke ok" in proc.stdout
    assert "records=27" in proc.stdout
    assert (state_dir / "echo" / "ledger" / "chat.jsonl").is_file()
