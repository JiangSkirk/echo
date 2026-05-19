"""Adapter to convert MCP tools to JS tools."""

from __future__ import annotations

from typing import Any

from js.mcp.client import MCPClient
from js.tools.registry import ToolParam, ToolRegistry, ToolResult, ToolSpec


class MCPToolAdapter:
    """Adapts MCP server tools into JS's tool registry."""

    def __init__(self, client: MCPClient) -> None:
        self.client = client

    async def register_all(self, registry: ToolRegistry) -> None:
        """Discover and register all MCP tools."""
        await self.client.connect()
        for mcp_tool in self.client.list_tools():
            spec = self._convert_spec(mcp_tool)
            registry.register(spec, self._make_handler(mcp_tool.name))

    def _convert_spec(self, mcp_tool: Any) -> ToolSpec:
        from js.mcp.client import MCPTool
        t: MCPTool = mcp_tool
        params: list[ToolParam] = []
        schema = t.input_schema
        if "properties" in schema:
            required = set(schema.get("required", []))
            for name, prop in schema["properties"].items():
                params.append(ToolParam(
                    name=name,
                    type=prop.get("type", "string"),
                    description=prop.get("description", ""),
                    required=name in required,
                    enum=prop.get("enum"),
                ))
        return ToolSpec(
            name=f"mcp_{t.name}",
            description=t.description,
            parameters=params,
        )

    def _make_handler(self, tool_name: str) -> Any:
        async def handler(**kwargs: Any) -> ToolResult:
            result = await self.client.call_tool(tool_name, kwargs)
            return ToolResult(success=not result.startswith("Error"), output=result)
        return handler
