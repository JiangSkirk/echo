"""Metrics collection with Prometheus and OpenTelemetry."""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any

from opentelemetry import trace
from prometheus_client import Counter, Histogram

from js.utils.log import get_logger

logger = get_logger("js.utils.metrics")

tracer = trace.get_tracer("js.agent")


class MetricsCollector:
    """Centralized Prometheus metrics collector."""

    def __init__(self) -> None:
        self.agent_runs_total = Counter(
            "agent_runs_total",
            "Total number of agent runs started",
        )
        self.tool_calls_total = Counter(
            "tool_calls_total",
            "Total number of tool calls",
            ["tool_name"],
        )
        self.tool_errors_total = Counter(
            "tool_errors_total",
            "Total number of tool execution errors",
            ["tool_name"],
        )
        self.model_requests_total = Counter(
            "model_requests_total",
            "Total number of model API requests",
            ["model", "provider"],
        )
        self.model_errors_total = Counter(
            "model_errors_total",
            "Total number of model API errors",
            ["model", "provider"],
        )
        self.approval_requests_total = Counter(
            "approval_requests_total",
            "Total number of approval requests",
            ["tool_name", "mode", "outcome"],
        )
        self.search_requests_total = Counter(
            "search_requests_total",
            "Total number of search requests",
            ["engine"],
        )
        self.tool_latency_seconds = Histogram(
            "tool_latency_seconds",
            "Tool execution latency in seconds",
            ["tool_name"],
        )
        self.model_latency_seconds = Histogram(
            "model_latency_seconds",
            "Model API latency in seconds",
            ["model", "provider"],
        )
        self.agent_turn_duration_seconds = Histogram(
            "agent_turn_duration_seconds",
            "Agent turn duration in seconds",
        )
        # Skill metrics
        self.skill_usage_total = Counter(
            "skill_usage_total",
            "Total number of skill executions",
            ["skill_id", "skill_type", "source"],
        )
        self.skill_latency_seconds = Histogram(
            "skill_latency_seconds",
            "Skill execution latency in seconds",
            ["skill_id", "skill_type"],
        )
        self.skill_success_rate_gauge = Histogram(
            "skill_success_rate",
            "Skill success rate distribution",
            ["skill_id"],
            buckets=[0.0, 0.25, 0.5, 0.75, 0.9, 0.95, 1.0],
        )
        # Memory metrics
        self.memory_store_latency_seconds = Histogram(
            "memory_store_latency_seconds",
            "Memory store operation latency in seconds",
            ["operation"],
        )
        self.memory_retrieve_latency_seconds = Histogram(
            "memory_retrieve_latency_seconds",
            "Memory retrieve/search latency in seconds",
            ["operation"],
        )
        self.memory_search_fallback_total = Counter(
            "memory_search_fallback_total",
            "Total number of memory search fallbacks to keyword",
            ["reason"],
        )


_metrics = MetricsCollector()


def get_metrics() -> MetricsCollector:
    return _metrics


@contextmanager
def start_span(
    name: str,
    attributes: dict[str, Any] | None = None,
) -> Any:
    """Start an OpenTelemetry span, failing open on any error."""
    try:
        with tracer.start_as_current_span(name) as span:
            if attributes and span is not None:
                for key, value in attributes.items():
                    try:
                        span.set_attribute(key, value)
                    except Exception:
                        logger.warning('Operation failed', exc_info=True)
            yield span
    except Exception:
        yield None


