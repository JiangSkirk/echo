"""Metrics collection with Prometheus and OpenTelemetry."""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any

from opentelemetry import trace
from prometheus_client import Counter, Histogram, make_wsgi_app

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
                        pass
            yield span
    except Exception:
        yield None


def get_metrics_app() -> Any:
    """Return WSGI app for /metrics endpoint."""
    return make_wsgi_app()
