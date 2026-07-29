"""Metrics collection with Prometheus and OpenTelemetry (optional)."""

from __future__ import annotations

from collections.abc import Generator
from contextlib import contextmanager
from typing import Any

try:
    from opentelemetry import trace
    from prometheus_client import Counter, Gauge, Histogram

    tracer = trace.get_tracer("js.agent")
    _METRICS_AVAILABLE = True
except ImportError:
    _METRICS_AVAILABLE = False

    class _DummyCounter:
        """No-op counter when prometheus_client is unavailable."""

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        def inc(self, *args: Any, **kwargs: Any) -> None:
            pass

        def labels(self, *args: Any, **kwargs: Any) -> _DummyCounter:
            return self

    class _DummyGauge:
        """No-op gauge when prometheus_client is unavailable."""

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        def set(self, *args: Any, **kwargs: Any) -> None:
            pass

    class _DummyHistogram:
        """No-op histogram when prometheus_client is unavailable."""

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        def observe(self, *args: Any, **kwargs: Any) -> None:
            pass

        def labels(self, *args: Any, **kwargs: Any) -> _DummyHistogram:
            return self

    Counter = _DummyCounter  # type: ignore[misc,assignment]
    Gauge = _DummyGauge  # type: ignore[misc,assignment]
    Histogram = _DummyHistogram  # type: ignore[misc,assignment]

from js.utils.log import get_logger

logger = get_logger("js.utils.metrics")


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
        self.tool_batches_total = Counter(
            "tool_batches_total",
            "Total number of tool call batches",
            ["all_failed", "tool_count"],
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
        self.skill_promotion_events_total = Counter(
            "skill_promotion_events_total",
            "Skill promotion gate decisions (pass/fail per step)",
            ["decision", "failed_step"],
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
        # Governor metrics
        self.governor_memory_percent = Gauge(
            "governor_memory_percent",
            "System memory usage percent",
        )
        self.governor_cpu_percent = Gauge(
            "governor_cpu_percent",
            "Process CPU usage percent",
        )
        self.governor_active_agents = Gauge(
            "governor_active_agents",
            "Number of busy agents",
        )
        self.governor_idle_agents = Gauge(
            "governor_idle_agents",
            "Number of idle agents",
        )
        self.governor_in_flight_tasks = Gauge(
            "governor_in_flight_tasks",
            "Number of in-flight tasks",
        )
        self.governor_reaped_total = Counter(
            "governor_reaped_total",
            "Total number of idle agents reaped",
        )


_metrics = MetricsCollector()


def get_metrics() -> MetricsCollector:
    return _metrics


@contextmanager
def start_span(
    name: str,
    attributes: dict[str, Any] | None = None,
) -> Generator[Any, None, None]:
    """Start an OpenTelemetry span, failing open on any error."""
    if not _METRICS_AVAILABLE:
        yield None
        return
    try:
        with tracer.start_as_current_span(name) as span:
            if attributes and span is not None:
                for key, value in attributes.items():
                    try:
                        span.set_attribute(key, value)
                    except Exception:
                        logger.warning("Operation failed", exc_info=True)
            yield span
    except Exception as exc:
        # Failing open: log but **never** suppress the original exception.
        # Using ``yield`` inside an ``except`` block of a @contextmanager
        # generator triggers ``RuntimeError: generator didn't stop after
        # throw()`` — we must re-raise instead.
        if isinstance(exc, PermissionError):
            logger.debug("Span exited with expected permission error: %s", type(exc).__name__)
        else:
            logger.warning("Span cleanup failed", exc_info=True)
        raise
