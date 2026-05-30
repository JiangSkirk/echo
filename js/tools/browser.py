"""Simple browser/fetch tool for web content retrieval."""

from __future__ import annotations

import ipaddress
from typing import Any
from urllib.parse import urlparse

import httpx

from js import __version__
from js.config import ToolLimits
from js.security.guard import BehaviorGuard
from js.tools.registry import ToolParam, ToolResult, ToolSpec


class BrowserTool:
    """Fetch and extract web content."""

    def __init__(self, limits: ToolLimits, guard: BehaviorGuard) -> None:
        self.limits = limits
        self.guard = guard
        self._client: httpx.AsyncClient | None = None

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(self.limits.browser_timeout),
                follow_redirects=False,  # Prevent redirect-based SSRF bypass
                headers={
                    "User-Agent": f"JS-Agent/{__version__} (Research Bot)",
                },
            )
        return self._client

    def get_specs(self) -> list[ToolSpec]:
        return [
            ToolSpec(
                name="browser_fetch",
                description="Fetch content from a URL. Returns text content up to max chars.",
                parameters=[
                    ToolParam("url", "string", "URL to fetch"),
                    ToolParam("max_chars", "integer", "Max characters to return", required=False),
                ],
            ),
        ]

    async def fetch(self, url: str, max_chars: int | None = None) -> ToolResult:
        max_chars = max_chars if max_chars is not None else self.limits.file_read_max_chars

        # Basic URL validation
        if not url.startswith(("http://", "https://")):
            return ToolResult(success=False, error="URL must start with http:// or https://")

        parsed = urlparse(url)
        hostname = parsed.hostname or ""

        # Block private/internal IPs using ipaddress module (covers IPv4, IPv6, octal, hex, decimal)
        try:
            addr = ipaddress.ip_address(hostname)
            if addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_multicast or addr.is_unspecified:
                return ToolResult(success=False, error="Private/internal URLs are blocked for security")
        except ValueError:
            # Not an IP address — check localhost-like hostnames
            if hostname.lower() in ("localhost", "0.0.0.0", "::", "::1"):
                return ToolResult(success=False, error="Private/internal URLs are blocked for security")

        try:
            client = self._get_client()
            response = await client.get(url)
            if response.is_redirect:
                return ToolResult(success=False, error="Redirects are not followed for security")
            response.raise_for_status()

            content = response.text
            if len(content) > max_chars:
                content = content[:max_chars] + "\n... [truncated]"

            return ToolResult(
                success=True,
                output=content,
                metadata={
                    "status_code": response.status_code,
                    "content_type": response.headers.get("content-type", "unknown"),
                    "url": str(response.url),
                },
            )
        except httpx.HTTPStatusError as e:
            return ToolResult(success=False, error=f"HTTP error {e.response.status_code}")
        except httpx.RequestError as e:
            return ToolResult(success=False, error=f"Request failed: {e}")
        except Exception as e:
            return ToolResult(success=False, error=f"Fetch error: {e}")

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()

    def register_all(self, registry: Any) -> None:
        specs = self.get_specs()
        registry.register(specs[0], self.fetch)
