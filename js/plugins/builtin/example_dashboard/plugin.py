"""Example plugin demonstrating the JS Plugin SDK."""

from __future__ import annotations

import time
from typing import Any

from js.plugins.sdk import JSPlugin, PluginContext, ToolContribution


class DashboardPlugin(JSPlugin):
    """Example plugin that adds a system-dashboard tool."""

    manifest: Any = None  # Set by manager from plugin.json

    def __init__(self) -> None:
        self.start_time = time.time()
        self._ctx: PluginContext | None = None

    def setup(self, ctx: PluginContext) -> None:
        self._ctx = ctx
        ctx.logger.info("DashboardPlugin setup complete")

    def teardown(self) -> None:
        if self._ctx:
            self._ctx.logger.info("DashboardPlugin teardown")

    def get_tools(self) -> list[ToolContribution]:
        return [
            ToolContribution(
                name="system_dashboard",
                description="Get a quick overview of system health: uptime, memory, providers.",
                parameters={},
                dangerous=False,
            ),
        ]

    def health(self) -> dict[str, Any]:
        return {
            "status": "ok",
            "uptime_seconds": time.time() - self.start_time,
        }
