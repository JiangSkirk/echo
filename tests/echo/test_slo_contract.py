from __future__ import annotations

from js.echo.slo_contract import SLO_CONTRACT, SLO_CONTRACT_VERSION


def test_slo_contract_matches_product_requirement() -> None:
    assert SLO_CONTRACT_VERSION == "js-agent-slo-v2"
    assert SLO_CONTRACT.full_request_p95_ms == 45.0
    assert SLO_CONTRACT.wrapper_p95_ms == 2.5
    # The older ledger SLO already audited 45 ms for first-token latency.
    # Version 2 makes that exact value authoritative for the first *text* token
    # and uses the same non-relaxed ceiling for the separate terminal receipt.
    assert SLO_CONTRACT.ws_first_token_p95_ms == 45.0
    assert SLO_CONTRACT.ws_terminal_p95_ms == 45.0
    assert SLO_CONTRACT.journal_append_p95_ms == 10.0
    assert SLO_CONTRACT.replay_10k_seconds == 2.0
    assert SLO_CONTRACT.compaction_ms == 250.0
    assert SLO_CONTRACT.concurrency_workers == 50
    assert SLO_CONTRACT.concurrency_rounds == 3
    assert SLO_CONTRACT.max_rss_mb == 500.0
    assert SLO_CONTRACT.benchmark_groups == 5
    assert SLO_CONTRACT.benchmark_warmup == 10
    assert SLO_CONTRACT.benchmark_measured == 50
    assert SLO_CONTRACT.long_context_min_reduction_pct == 15.0
    assert SLO_CONTRACT.short_context_max_increase_pct == 5.0


def test_all_runtime_gates_import_the_same_contract() -> None:
    import scripts.echo_architecture_benchmark as benchmark
    import scripts.release_smoke as release_smoke
    from js.echo.ledger import release_gates
    from js.echo.ledger import slo as ledger_slo

    assert benchmark.SLO_CONTRACT is SLO_CONTRACT
    assert release_smoke.SLO_CONTRACT is SLO_CONTRACT
    assert release_gates.SLO_CONTRACT is SLO_CONTRACT
    assert ledger_slo.SLO_CONTRACT is SLO_CONTRACT
    assert benchmark.SLO_THRESHOLDS == {
        "api_full_agent": {"p95_ms": 45.0},
        "api_wrapper_only": {"p95_ms": 2.5},
        "ws_message_wrapper": {"p95_ms": 2.5},
        "ws_stream_wrapper": {"p95_ms": 2.5},
    }
