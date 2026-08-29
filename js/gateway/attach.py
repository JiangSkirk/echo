"""Attach one GatewayService onto the agent so cron and HTTP share it."""

from __future__ import annotations

from typing import Any

from js.gateway.service import GatewayService


def attach_gateway_service(agent: Any) -> GatewayService:
    existing = getattr(agent, "gateway_service", None)
    if isinstance(existing, GatewayService):
        return existing
    settings = getattr(agent, "settings", None)
    if settings is None:
        raise RuntimeError("agent has no settings; cannot attach gateway")
    service = GatewayService(settings)
    agent.gateway_service = service
    return service
