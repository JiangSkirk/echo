from __future__ import annotations

from js.echo.ledger.slo import SLOSnapshot, evaluate_slo_snapshot


def test_preview_slo_snapshot_passes_within_thresholds() -> None:
    snapshot = SLOSnapshot(
        api_chat_mock_p95_ms=20,
        api_wrapper_p95_ms=1,
        ws_message_wrapper_p95_ms=1,
        ws_stream_wrapper_p95_ms=1,
        ws_first_token_p95_ms=20,
        journal_append_p95_ms=3,
        crash_replay_10k_records_s=1,
        compaction_latency_ms=100,
        sandbox_cold_start_p95_ms=100,
        memory_idle_overhead_mb=80,
        concurrent_50_peak_memory_mb=200,
        plugin_oom_containment_rate=1.0,
        security_blocking_pass_rate=1.0,
    )

    report = evaluate_slo_snapshot(snapshot, stage="preview")

    assert report.ok
    assert report.failures == ()


def test_stable_slo_snapshot_blocks_regression() -> None:
    snapshot = SLOSnapshot(
        api_chat_mock_p95_ms=60,
        api_wrapper_p95_ms=3,
        ws_message_wrapper_p95_ms=3,
        ws_stream_wrapper_p95_ms=3,
        ws_first_token_p95_ms=80,
        journal_append_p95_ms=12,
        crash_replay_10k_records_s=30,
        compaction_latency_ms=300,
        sandbox_cold_start_p95_ms=400,
        memory_idle_overhead_mb=170,
        concurrent_50_peak_memory_mb=540,
        plugin_oom_containment_rate=0.99,
        security_blocking_pass_rate=1.0,
    )

    report = evaluate_slo_snapshot(snapshot, stage="stable")

    assert not report.ok
    assert "api_chat_mock_p95_ms" in report.failures
    assert "plugin_oom_containment_rate" in report.failures


def test_preview_cannot_relax_the_versioned_product_contract() -> None:
    snapshot = SLOSnapshot(
        api_chat_mock_p95_ms=45.001,
        api_wrapper_p95_ms=2.501,
        ws_message_wrapper_p95_ms=2.501,
        ws_stream_wrapper_p95_ms=2.501,
        ws_first_token_p95_ms=45.001,
        journal_append_p95_ms=10.001,
        crash_replay_10k_records_s=2.001,
        compaction_latency_ms=250.001,
        sandbox_cold_start_p95_ms=100,
        memory_idle_overhead_mb=80,
        concurrent_50_peak_memory_mb=500.001,
        plugin_oom_containment_rate=1.0,
        security_blocking_pass_rate=1.0,
    )

    report = evaluate_slo_snapshot(snapshot, stage="preview")

    assert not report.ok
    assert set(report.failures) >= {
        "api_chat_mock_p95_ms",
        "api_wrapper_p95_ms",
        "ws_message_wrapper_p95_ms",
        "ws_stream_wrapper_p95_ms",
        "journal_append_p95_ms",
        "crash_replay_10k_records_s",
        "compaction_latency_ms",
        "concurrent_50_peak_memory_mb",
    }
