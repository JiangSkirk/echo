"""Single versioned performance contract for JS Agent and JS Agent Work."""

from __future__ import annotations

from dataclasses import asdict, dataclass

SLO_CONTRACT_VERSION = "js-agent-slo-v2"


@dataclass(frozen=True)
class SLOContract:
    """Product-level limits shared by benchmarks, status, smoke, and release gates."""

    version: str = SLO_CONTRACT_VERSION
    full_request_p95_ms: float = 45.0
    # Wrapper path is sub-2ms on quiet hosts; macOS timer jitter after long
    # pytest suites routinely lands 2.05–2.15ms median p95. Keep the budget
    # tight enough to catch regressions while absorbing measurement noise.
    wrapper_p95_ms: float = 2.5
    # The legacy ledger SLO audited 45 ms as the first-token ceiling.  Version
    # 2 makes the meaning precise: this is the first non-empty text token, not
    # an earlier status/thinking frame.  Terminal latency is gated separately
    # at the same existing ceiling, so adding TTFT evidence cannot relax the
    # prior product-level latency expectation.
    ws_first_token_p95_ms: float = 45.0
    ws_terminal_p95_ms: float = 45.0
    journal_append_p95_ms: float = 10.0
    replay_10k_seconds: float = 2.0
    compaction_ms: float = 250.0
    concurrency_workers: int = 50
    concurrency_rounds: int = 3
    max_rss_mb: float = 500.0
    benchmark_groups: int = 5
    benchmark_warmup: int = 10
    benchmark_measured: int = 50
    long_context_min_reduction_pct: float = 15.0
    short_context_max_increase_pct: float = 5.0

    def as_dict(self) -> dict[str, str | float | int]:
        """Return the canonical JSON-ready representation."""

        return asdict(self)

    def benchmark_latency_thresholds(self) -> dict[str, dict[str, float]]:
        """Return scenario thresholds without duplicating product limits."""

        return {
            "api_full_agent": {"p95_ms": self.full_request_p95_ms},
            "api_wrapper_only": {"p95_ms": self.wrapper_p95_ms},
            "ws_message_wrapper": {"p95_ms": self.wrapper_p95_ms},
            "ws_stream_wrapper": {"p95_ms": self.wrapper_p95_ms},
        }


SLO_CONTRACT = SLOContract()
