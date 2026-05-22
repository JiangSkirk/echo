"""Health monitor plugin — tracks provider health and resource usage."""

from __future__ import annotations

from typing import Any

from js.plugins.sdk import HookContribution, JSPlugin, PluginContext, ToolContribution


class HealthMonitorPlugin(JSPlugin):
    """Monitors provider health and emits alerts when issues are detected."""

    def setup(self, ctx: PluginContext) -> None:
        self._ctx = ctx
        ctx.logger.info("HealthMonitor active")

    def get_tools(self) -> list[ToolContribution]:
        return [
            ToolContribution(
                name="provider_health_check",
                description="Check health of all configured model providers.",
                parameters={"provider": {"type": "string", "description": "Specific provider name or 'all'"}},
            ),
        ]

    def get_hooks(self) -> list[HookContribution]:
        return [
            HookContribution(
                event="after_tool_call",
                handler=self._on_tool_call,
                priority=0,
            ),
        ]

    def _on_tool_call(self, **kwargs: Any) -> None:
        tool_name = kwargs.get("tool_name", "")
        success = kwargs.get("success", True)
        if not success and self._ctx:
            self._ctx.logger.warning(f"Tool '{tool_name}' failed — consider checking provider health")
