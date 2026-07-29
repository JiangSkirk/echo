from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from .slo_contract import SLO_CONTRACT

Stage = Literal["preview", "stable"]


@dataclass(frozen=True)
class SLOSnapshot:
    api_chat_mock_p95_ms: float
    api_wrapper_p95_ms: float
    ws_message_wrapper_p95_ms: float
    ws_stream_wrapper_p95_ms: float
    ws_first_token_p95_ms: float
    journal_append_p95_ms: float
    crash_replay_10k_records_s: float
    compaction_latency_ms: float
    sandbox_cold_start_p95_ms: float
    memory_idle_overhead_mb: float
    concurrent_50_peak_memory_mb: float
    plugin_oom_containment_rate: float
    security_blocking_pass_rate: float


@dataclass(frozen=True)
class SLOReport:
    stage: Stage
    ok: bool
    failures: tuple[str, ...]


_THRESHOLDS: dict[Stage, dict[str, float]] = {
    "preview": {
        "api_chat_mock_p95_ms": SLO_CONTRACT.full_request_p95_ms,
        "api_wrapper_p95_ms": SLO_CONTRACT.wrapper_p95_ms,
        "ws_message_wrapper_p95_ms": SLO_CONTRACT.wrapper_p95_ms,
        "ws_stream_wrapper_p95_ms": SLO_CONTRACT.wrapper_p95_ms,
        "ws_first_token_p95_ms": SLO_CONTRACT.ws_first_token_p95_ms,
        "journal_append_p95_ms": SLO_CONTRACT.journal_append_p95_ms,
        "crash_replay_10k_records_s": SLO_CONTRACT.replay_10k_seconds,
        "compaction_latency_ms": SLO_CONTRACT.compaction_ms,
        "sandbox_cold_start_p95_ms": 800,
        "memory_idle_overhead_mb": 180,
        "concurrent_50_peak_memory_mb": SLO_CONTRACT.max_rss_mb,
        "plugin_oom_containment_rate": 1.0,
        "security_blocking_pass_rate": 1.0,
    },
    "stable": {
        "api_chat_mock_p95_ms": SLO_CONTRACT.full_request_p95_ms,
        "api_wrapper_p95_ms": SLO_CONTRACT.wrapper_p95_ms,
        "ws_message_wrapper_p95_ms": SLO_CONTRACT.wrapper_p95_ms,
        "ws_stream_wrapper_p95_ms": SLO_CONTRACT.wrapper_p95_ms,
        "ws_first_token_p95_ms": SLO_CONTRACT.ws_first_token_p95_ms,
        "journal_append_p95_ms": SLO_CONTRACT.journal_append_p95_ms,
        "crash_replay_10k_records_s": SLO_CONTRACT.replay_10k_seconds,
        "compaction_latency_ms": SLO_CONTRACT.compaction_ms,
        "sandbox_cold_start_p95_ms": 300,
        "memory_idle_overhead_mb": 150,
        "concurrent_50_peak_memory_mb": SLO_CONTRACT.max_rss_mb,
        "plugin_oom_containment_rate": 1.0,
        "security_blocking_pass_rate": 1.0,
    },
}


def evaluate_slo_snapshot(snapshot: SLOSnapshot, *, stage: Stage) -> SLOReport:
    thresholds = _THRESHOLDS[stage]
    failures: list[str] = []
    for field, threshold in thresholds.items():
        value = getattr(snapshot, field)
        if field.endswith("_rate"):
            if value < threshold:
                failures.append(field)
        elif value > threshold:
            failures.append(field)
    return SLOReport(stage=stage, ok=not failures, failures=tuple(failures))
