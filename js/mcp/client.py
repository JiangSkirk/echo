"""MCP client supporting stdio and sse transports."""

from __future__ import annotations

import asyncio
import json
import subprocess
from dataclasses import dataclass
from typing import Any

import httpx

from js.utils.log import get_logger

logger = get_logger("js.mcp")


@dataclass
class MCPTool:
    name: str
    description: str
    input_schema: dict[str, Any]


@dataclass
class MCPResource:
    uri: str
    name: str
    mime_type: str


class MCPClient:
    """Client for communicating with MCP servers."""

    def __init__(self, command: list[str] | None = None, url: str | None = None) -> None:
        self.command = command
        self.url = url
        self._proc: subprocess.Popen[str] | None = None
        self._http: httpx.AsyncClient | None = None
        self._transport: str = "stdio" if command else "sse"
        self._req_id = 0
        self._tools: list[MCPTool] = []
        self._resources: list[MCPResource] = []

    async def connect(self) -> None:
        if self._transport == "stdio":
            await self._connect_stdio()
        else:
            await self._connect_sse()

    async def _connect_stdio(self) -> None:
        if not self.command:
            raise ValueError("No command provided for stdio transport")
        cmd = self.command
        assert cmd is not None
        self._proc = await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            ),
        )
        # Initialize
        await self._send_stdio({
            "jsonrpc": "2.0",
            "id": self._next_id(),
            "method": "initialize",
            "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "js", "version": "0.1.0"}},
        })
        await self._list_tools_stdio()

    async def _connect_sse(self) -> None:
        if not self.url:
            raise ValueError("No URL provided for sse transport")
        self._http = httpx.AsyncClient(base_url=self.url, timeout=30.0)
        await self._list_tools_sse()

    def _next_id(self) -> int:
        self._req_id += 1
        return self._req_id

    async def _send_stdio(self, msg: dict[str, Any]) -> dict[str, Any] | None:
        if not self._proc or not self._proc.stdin or not self._proc.stdout:
            return None
        line = json.dumps(msg) + "\n"
        # Run blocking I/O in thread pool to avoid freezing the event loop
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._proc.stdin.write, line)
        await loop.run_in_executor(None, self._proc.stdin.flush)
        response = await loop.run_in_executor(None, self._proc.stdout.readline)
        if response:
            try:
                return json.loads(response)  # type: ignore[no-any-return]
            except json.JSONDecodeError:
                logger.error(f"Invalid JSON from MCP: {response!r}")
                return None
        return None

    async def _list_tools_stdio(self) -> None:
        result = await self._send_stdio({
            "jsonrpc": "2.0",
            "id": self._next_id(),
            "method": "tools/list",
            "params": {},
        })
        if result and "result" in result:
            for t in result["result"].get("tools", []):
                self._tools.append(MCPTool(
                    name=t["name"],
                    description=t.get("description", ""),
                    input_schema=t.get("inputSchema", {}),
                ))

    async def _list_tools_sse(self) -> None:
        if not self._http:
            return
        try:
            resp = await self._http.get("/tools")
            resp.raise_for_status()
            data = resp.json()
            for t in data.get("tools", []):
                self._tools.append(MCPTool(
                    name=t["name"],
                    description=t.get("description", ""),
                    input_schema=t.get("inputSchema", {}),
                ))
        except Exception as e:
            logger.error(f"Failed to list tools via SSE: {e}")
            raise

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> str:
        if self._transport == "stdio":
            return await self._call_tool_stdio(name, arguments)
        return await self._call_tool_sse(name, arguments)

    async def _call_tool_stdio(self, name: str, arguments: dict[str, Any]) -> str:
        result = await self._send_stdio({
            "jsonrpc": "2.0",
            "id": self._next_id(),
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        })
        if result and "result" in result:
            content = result["result"].get("content", [])
            return "\n".join(c.get("text", "") for c in content if c.get("type") == "text")
        return json.dumps(result.get("error", {})) if result else "Unknown error"

    async def _call_tool_sse(self, name: str, arguments: dict[str, Any]) -> str:
        if not self._http:
            return "Not connected"
        try:
            resp = await self._http.post("/tools/call", json={"name": name, "arguments": arguments})
            data = resp.json()
            content = data.get("content", [])
            return "\n".join(c.get("text", "") for c in content if c.get("type") == "text")
        except Exception as e:
            return f"Error: {e}"

    def list_tools(self) -> list[MCPTool]:
        return self._tools

    async def disconnect(self) -> None:
        if self._proc:
            self._proc.terminate()
            self._proc = None
        if self._http:
            await self._http.aclose()
            self._http = None
