"""Metrics API router — per-provider SLO metrics.

Extracted from ``server.py``.  Surfaces provider health, request counts and
approximate latency percentiles (read from Prometheus histogram buckets).
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends

from js.utils.log import get_logger
from js.web.auth import require_auth_dep
from js.web.deps import get_agent

logger = get_logger("js.web.metrics")
router = APIRouter(tags=["metrics"])


@router.get("/api/metrics/providers")
async def provider_metrics(auth: dict[str, Any] = Depends(require_auth_dep)) -> dict[str, Any]:
    """Return per-provider SLO metrics: health, latency percentiles, circuit state."""
    agent = get_agent()
    health = await agent.router.health_check()

    # Pull Prometheus samples for provider metrics
    from prometheus_client import REGISTRY
    def _latency_stats(model: str, provider: str) -> dict[str, float]:
        """Read P50/P95/P99 from histogram buckets (approximate)."""
        stats = {"count": 0.0, "sum": 0.0, "p50": 0.0, "p95": 0.0, "p99": 0.0}
        try:
            for family in REGISTRY.collect():
                if family.name == "model_latency_seconds":
                    for sample in family.samples:
                        if sample.labels.get("model") == model and sample.labels.get("provider") == provider:
                            if sample.name.endswith("_count"):
                                stats["count"] = sample.value
                            elif sample.name.endswith("_sum"):
                                stats["sum"] = sample.value
                            elif sample.name.endswith("_bucket"):
                                # Find buckets for p50/p95/p99 approximations
                                le = sample.labels.get("le", "")
                                if le not in ("+Inf", ""):
                                    try:
                                        bound = float(le)
                                        if bound <= 0.5 and sample.value > 0:
                                            stats["p50"] = bound
                                        if bound <= 2.0 and sample.value > 0:
                                            stats["p95"] = bound
                                        if bound <= 5.0 and sample.value > 0:
                                            stats["p99"] = bound
                                    except ValueError:
                                        logger.warning('Operation failed', exc_info=True)
        except Exception:
            logger.warning('Operation failed', exc_info=True)
        return stats

    providers: list[dict[str, Any]] = []
    for p in agent.settings.providers:
        for m in p.models:
            lat = _latency_stats(m.id, p.name)
            providers.append({
                "name": p.name,
                "model": m.id,
                "healthy": health.get(p.name, False),
                "latency_p50_ms": round(lat["p50"] * 1000, 1) if lat["p50"] else None,
                "latency_p95_ms": round(lat["p95"] * 1000, 1) if lat["p95"] else None,
                "latency_p99_ms": round(lat["p99"] * 1000, 1) if lat["p99"] else None,
                "request_count": int(lat["count"]),
            })

    overall_healthy = any(p["healthy"] for p in providers)
    return {
        "overall_healthy": overall_healthy,
        "degraded": agent.degraded,
        "providers": providers,
    }
