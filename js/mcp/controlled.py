"""Controlled MCP connector foundation for Echo.

This layer deliberately does not auto-start untrusted MCP servers. It imports
tool schemas from an explicit manifest, marks every imported tool dangerous,
and leaves remote execution disabled unless a future policy grants it.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from js.tools.registry import ToolParam, ToolRegistry, ToolResult, ToolSpec

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")


@dataclass(frozen=True)
class ControlledMCPTool:
    server_id: str
    name: str
    public_name: str
    description: str
    input_schema: dict[str, Any]
    read_only: bool


@dataclass(frozen=True)
class ControlledMCPServer:
    server_id: str
    transport: str
    command: tuple[str, ...]
    url: str
    tools: tuple[ControlledMCPTool, ...]


@dataclass(frozen=True)
class ControlledMCPManifest:
    version: int
    servers: tuple[ControlledMCPServer, ...]


def _validate_name(kind: str, value: str) -> str:
    if not _SAFE_ID.match(value):
        raise ValueError(f"Invalid MCP {kind} name: {value!r}")
    return value


def _params_from_schema(schema: dict[str, Any]) -> list[ToolParam]:
    params: list[ToolParam] = []
    properties = schema.get("properties", {})
    required = set(schema.get("required", []))
    if not isinstance(properties, dict):
        return params
    for raw_name, raw_prop in properties.items():
        name = _validate_name("parameter", str(raw_name))
        prop = raw_prop if isinstance(raw_prop, dict) else {}
        params.append(
            ToolParam(
                name=name,
                type=str(prop.get("type", "string")),
                description=str(prop.get("description", "")),
                required=name in required,
                enum=prop.get("enum") if isinstance(prop.get("enum"), list) else None,
            )
        )
    return params


def _validated_stdio_command(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise ValueError("MCP stdio transport requires a non-empty command list")
    if any(not isinstance(item, str) or not item.strip() or "\x00" in item for item in value):
        raise ValueError("MCP command must contain non-empty strings without NUL bytes")
    return tuple(value)


def _validated_sse_url(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("MCP SSE transport requires an HTTPS URL")
    parsed = urlsplit(value)
    if (
        parsed.scheme.lower() != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise ValueError("MCP SSE transport requires a credential-free HTTPS URL")
    hostname = parsed.hostname.rstrip(".").lower()
    if hostname == "localhost" or hostname.endswith(".localhost"):
        raise ValueError("MCP SSE transport cannot target a local host")
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        if not address.is_global:
            raise ValueError("MCP SSE transport cannot target a non-global address")
    return value


def load_mcp_manifest(path: Path | str) -> ControlledMCPManifest:
    manifest_path = Path(path).expanduser().resolve()
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    version = int(data.get("version", 1))
    servers: list[ControlledMCPServer] = []
    for raw_server in data.get("servers", []):
        if not isinstance(raw_server, dict) or not raw_server.get("enabled", False):
            continue
        server_id = _validate_name("server", str(raw_server.get("id", "")))
        transport = str(raw_server.get("transport", "stdio"))
        if transport not in {"stdio", "sse"}:
            raise ValueError(f"Invalid MCP transport: {transport!r}")
        command = (
            _validated_stdio_command(raw_server.get("command"))
            if transport == "stdio"
            else ()
        )
        url = _validated_sse_url(raw_server.get("url")) if transport == "sse" else ""
        allow_execute = bool(raw_server.get("allow_execute", False))
        if allow_execute:
            raise ValueError(
                "MCP execution requires a configured isolated runtime adapter; "
                "schema-only manifests must keep allow_execute disabled"
            )
        tools: list[ControlledMCPTool] = []
        for raw_tool in raw_server.get("tools", []):
            if not isinstance(raw_tool, dict):
                continue
            if bool(raw_tool.get("allow_execute", False)):
                raise ValueError(
                    "MCP execution requires a configured isolated runtime adapter; "
                    "schema-only tools must keep allow_execute disabled"
                )
            tool_name = _validate_name("tool", str(raw_tool.get("name", "")))
            public_name = f"mcp_{server_id}_{tool_name}"
            tools.append(
                ControlledMCPTool(
                    server_id=server_id,
                    name=tool_name,
                    public_name=public_name,
                    description=str(raw_tool.get("description", "")),
                    input_schema=raw_tool.get("input_schema", {})
                    if isinstance(raw_tool.get("input_schema", {}), dict)
                    else {},
                    read_only=bool(raw_tool.get("read_only", False)),
                )
            )
        servers.append(
            ControlledMCPServer(
                server_id=server_id,
                transport=transport,
                command=command,
                url=url,
                tools=tuple(tools),
            )
        )
    return ControlledMCPManifest(version=version, servers=tuple(servers))


class ControlledMCPConnector:
    """Register manifest-declared MCP tools behind Echo's tool gate."""

    def __init__(self, manifest: ControlledMCPManifest) -> None:
        self.manifest = manifest

    def register_tools(self, registry: ToolRegistry) -> None:
        for server in self.manifest.servers:
            for tool in server.tools:
                registry.register(self._spec(tool), self._handler(tool))

    def _spec(self, tool: ControlledMCPTool) -> ToolSpec:
        return ToolSpec(
            name=tool.public_name,
            description=tool.description or f"MCP tool {tool.server_id}/{tool.name}",
            parameters=_params_from_schema(tool.input_schema),
            dangerous=True,
            read_only=tool.read_only,
        )

    def _handler(self, tool: ControlledMCPTool) -> Any:
        async def _disabled_handler(**_kwargs: Any) -> ToolResult:
            return ToolResult(
                success=False,
                error="MCP execution disabled by Echo MCP policy",
                metadata={"mcp_server": tool.server_id, "mcp_tool": tool.name},
            )

        return _disabled_handler


__all__ = [
    "ControlledMCPConnector",
    "ControlledMCPManifest",
    "ControlledMCPServer",
    "ControlledMCPTool",
    "load_mcp_manifest",
]
