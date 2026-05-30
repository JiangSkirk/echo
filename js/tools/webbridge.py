"""Kimi WebBridge integration for real browser control.

Requires the kimi-webbridge daemon running at http://127.0.0.1:10086.
Provides tools for navigating, interacting with, and capturing real browser tabs
with full JavaScript execution and user login sessions.
"""

from __future__ import annotations

import asyncio
import ipaddress
from typing import Any
from urllib.parse import urlparse

import httpx

from js.tools.registry import ToolParam, ToolResult, ToolSpec

_DAEMON_URL = "http://127.0.0.1:10086/command"
_DEFAULT_TIMEOUT = 30.0


def _check_url_safe(url: str) -> tuple[bool, str]:
    """Block private/internal URLs to prevent SSRF.

    Returns (is_safe, reason_if_blocked).
    """
    if not url.startswith(("http://", "https://")):
        return False, "URL must start with http:// or https://"

    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    try:
        addr = ipaddress.ip_address(hostname)
        if addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_multicast or addr.is_unspecified:
            return False, "Private/internal URLs are blocked for security"
    except ValueError:
        if hostname.lower() in ("localhost", "0.0.0.0", "::", "::1"):
            return False, "Private/internal URLs are blocked for security"

    return True, ""


class WebBridgeTool:
    """Wrapper around Kimi WebBridge daemon API."""

    def __init__(self) -> None:
        self._client: httpx.AsyncClient | None = None
        self._available: bool | None = None  # Lazy health check

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=httpx.Timeout(_DEFAULT_TIMEOUT))
        return self._client

    async def health_check(self) -> bool:
        """Check whether the WebBridge daemon is reachable.

        Uses a lightweight POST to /command (list_tabs) because the daemon
        does not expose a dedicated /_health endpoint.
        """
        if self._available is not None:
            return self._available
        try:
            client = self._get_client()
            resp = await client.post(
                _DAEMON_URL,
                json={"action": "list_tabs", "args": {}, "session": "__health__"},
                timeout=5.0,
            )
            self._available = resp.status_code == 200 and resp.json().get("ok") is True
        except Exception:
            self._available = False
        return self._available

    async def _call(self, action: str, args: dict[str, Any], session: str = "js-agent") -> dict[str, Any]:
        """Send a command to the WebBridge daemon with retry."""
        client = self._get_client()
        last_error: Exception | None = None
        for attempt in range(3):
            try:
                resp = await client.post(
                    _DAEMON_URL,
                    json={"action": action, "args": args, "session": session},
                )
                resp.raise_for_status()
                raw: dict[str, Any] = resp.json()
                result: dict[str, Any] = raw.get("data", {})
                return result
            except (httpx.ConnectError, httpx.ReadTimeout) as e:
                last_error = e
                if attempt < 2:
                    wait = 2 ** attempt
                    import logging
                    logging.getLogger("js.tools.webbridge").warning(
                        f"WebBridge call {action} failed (attempt {attempt + 1}), retrying in {wait}s: {e}"
                    )
                    await asyncio.sleep(wait)
            except httpx.HTTPStatusError as e:
                # 5xx errors from the daemon may be transient; retry once quickly
                last_error = e
                if attempt < 2 and e.response.status_code >= 500:
                    await asyncio.sleep(1)
                    continue
                raise
            except Exception:
                raise
        raise last_error or RuntimeError(f"WebBridge call {action} failed after 3 attempts")

    def get_specs(self) -> list[ToolSpec]:
        return [
            ToolSpec(
                name="web_navigate",
                description=(
                    "Navigate the browser to a URL. Use new_tab=true for the first navigation. "
                    "Returns the current URL and tab ID."
                ),
                parameters=[
                    ToolParam("url", "string", "URL to navigate to"),
                    ToolParam("new_tab", "boolean", "Open in a new tab (recommended for first call)", required=False),
                    ToolParam("session", "string", "Browser session name for isolation", required=False),
                ],
            ),
            ToolSpec(
                name="web_snapshot",
                description=(
                    "Capture the accessibility tree of the current page. "
                    "Returns a text representation with @e references for clickable elements. "
                    "Use this to understand page structure before clicking or filling."
                ),
                parameters=[
                    ToolParam("session", "string", "Browser session name", required=False),
                ],
                read_only=True,
            ),
            ToolSpec(
                name="web_click",
                description=(
                    "Click an element on the page. Use @e references from web_snapshot, "
                    "or a CSS selector."
                ),
                parameters=[
                    ToolParam("selector", "string", "Element selector (@e ref or CSS selector)"),
                    ToolParam("session", "string", "Browser session name", required=False),
                ],
            ),
            ToolSpec(
                name="web_fill",
                description=(
                    "Fill an input field or textarea with text. Works on <input>, <textarea>, "
                    "and contenteditable elements."
                ),
                parameters=[
                    ToolParam("selector", "string", "Element selector (@e ref or CSS selector)"),
                    ToolParam("value", "string", "Text to fill"),
                    ToolParam("session", "string", "Browser session name", required=False),
                ],
            ),
            ToolSpec(
                name="web_screenshot",
                description=(
                    "Take a screenshot of the current page or a specific element. "
                    "Returns the file path of the saved image."
                ),
                parameters=[
                    ToolParam("selector", "string", "Optional CSS selector to screenshot a specific element", required=False),
                    ToolParam("session", "string", "Browser session name", required=False),
                ],
                read_only=True,
            ),
            ToolSpec(
                name="web_evaluate",
                description=(
                    "Execute JavaScript code in the browser context. Supports async/await. "
                    "Return value is serialized as JSON."
                ),
                parameters=[
                    ToolParam("code", "string", "JavaScript code to execute"),
                    ToolParam("session", "string", "Browser session name", required=False),
                ],
            ),
            ToolSpec(
                name="web_find_tab",
                description=(
                    "Find an already-open tab by URL or domain. "
                    "Use active=true to select the tab the user is currently viewing."
                ),
                parameters=[
                    ToolParam("url", "string", "URL or domain to match"),
                    ToolParam("active", "boolean", "Select the currently active tab", required=False),
                    ToolParam("session", "string", "Browser session name", required=False),
                ],
            ),
            ToolSpec(
                name="web_list_tabs",
                description="List all open tabs in the session.",
                parameters=[
                    ToolParam("session", "string", "Browser session name", required=False),
                ],
                read_only=True,
            ),
            ToolSpec(
                name="web_extract_text",
                description=(
                    "Extract visible text content from the current page using JavaScript. "
                    "This is a fallback when web_snapshot returns an empty or sparse accessibility tree. "
                    "Returns headings, links, buttons, and body text found on the page. "
                    "Use this for JavaScript-heavy sites (Douyin, TikTok, React/Vue SPAs) where the accessibility tree is incomplete."
                ),
                parameters=[
                    ToolParam("max_chars", "integer", "Max characters to return (default 8000)", required=False),
                    ToolParam("session", "string", "Browser session name", required=False),
                ],
                read_only=True,
            ),
        ]

    # ------------------------------------------------------------------
    # Handlers
    # ------------------------------------------------------------------

    async def navigate(self, url: str, new_tab: bool = True, session: str = "js-agent") -> ToolResult:
        safe, reason = _check_url_safe(url)
        if not safe:
            return ToolResult(success=False, error=f"URL blocked: {reason}")
        try:
            data = await self._call("navigate", {"url": url, "newTab": new_tab}, session=session)
            if not data.get("success"):
                return ToolResult(success=False, error=data.get("error", "Navigation failed"))
            return ToolResult(
                success=True,
                output=f"Navigated to {data.get('url', url)} (tab {data.get('tabId')})",
                metadata={"url": data.get("url"), "tabId": data.get("tabId")},
            )
        except httpx.ConnectError:
            return ToolResult(success=False, error="WebBridge daemon not running. Install with: curl -fsSL https://cdn.kimi.com/webbridge/install.sh | bash")
        except Exception as e:
            return ToolResult(success=False, error=f"Navigate error: {e}")

    def _format_tree(self, nodes: list[Any] | dict[str, Any], indent: int = 0) -> str:
        """Format accessibility tree nodes to plain text.

        WebBridge returns a mix of object arrays and nested arrays.
        We flatten arrays and process each node recursively.
        """
        lines: list[str] = []

        # Handle nested arrays by flattening one level
        if isinstance(nodes, list):
            for item in nodes:
                if isinstance(item, (list, dict)):
                    lines.append(self._format_tree(item, indent))
            return "\n".join(lines)

        if not isinstance(nodes, dict):
            return ""

        role = nodes.get("role", "")
        name = nodes.get("name", "")
        ref = nodes.get("ref", "")
        parts = [role] if role else []
        if name:
            parts.append(f'"{name}"')
        if ref:
            parts.append(ref)
        if parts:
            lines.append("  " * indent + " ".join(parts))

        children = nodes.get("children")
        if children is not None:
            lines.append(self._format_tree(children, indent + 1))

        return "\n".join(lines)

    async def snapshot(self, session: str = "js-agent") -> ToolResult:
        try:
            data = await self._call("snapshot", {}, session=session)
            url = data.get("url", "")
            title = data.get("title", "")
            tree = data.get("tree", [])
            tree_text = self._format_tree(tree) if isinstance(tree, list) else str(tree)
            output = f"URL: {url}\nTitle: {title}\n\n{tree_text}"
            return ToolResult(success=True, output=output, metadata={"url": url, "title": title})
        except httpx.ConnectError:
            return ToolResult(success=False, error="WebBridge daemon not running.")
        except Exception as e:
            return ToolResult(success=False, error=f"Snapshot error: {e}")

    async def click(self, selector: str, session: str = "js-agent") -> ToolResult:
        try:
            data = await self._call("click", {"selector": selector}, session=session)
            if not data.get("success"):
                return ToolResult(success=False, error=data.get("error", "Click failed"))
            return ToolResult(
                success=True,
                output=f"Clicked <{data.get('tag', 'element')}> {data.get('text', '')}",
                metadata={"tag": data.get("tag"), "text": data.get("text")},
            )
        except httpx.ConnectError:
            return ToolResult(success=False, error="WebBridge daemon not running.")
        except Exception as e:
            return ToolResult(success=False, error=f"Click error: {e}")

    async def fill(self, selector: str, value: str, session: str = "js-agent") -> ToolResult:
        try:
            data = await self._call("fill", {"selector": selector, "value": value}, session=session)
            if not data.get("success"):
                return ToolResult(success=False, error=data.get("error", "Fill failed"))
            return ToolResult(
                success=True,
                output=f"Filled <{data.get('tag', 'input')}> using {data.get('mode', 'value')} mode",
                metadata={"tag": data.get("tag"), "mode": data.get("mode")},
            )
        except httpx.ConnectError:
            return ToolResult(success=False, error="WebBridge daemon not running.")
        except Exception as e:
            return ToolResult(success=False, error=f"Fill error: {e}")

    async def screenshot(self, selector: str = "", session: str = "js-agent") -> ToolResult:
        try:
            args: dict[str, Any] = {}
            if selector:
                args["selector"] = selector
            data = await self._call("screenshot", args, session=session)
            path = data.get("path", "")
            size = data.get("sizeBytes", 0)
            if not path:
                return ToolResult(success=False, error=data.get("error", "Screenshot failed"))
            return ToolResult(
                success=True,
                output=f"Screenshot saved: {path} ({size} bytes)",
                metadata={"path": path, "sizeBytes": size, "format": data.get("format"), "mimeType": data.get("mimeType")},
            )
        except httpx.ConnectError:
            return ToolResult(success=False, error="WebBridge daemon not running.")
        except Exception as e:
            return ToolResult(success=False, error=f"Screenshot error: {e}")

    async def evaluate(self, code: str, session: str = "js-agent") -> ToolResult:
        try:
            data = await self._call("evaluate", {"code": code}, session=session)
            result_type = data.get("type", "unknown")
            result_value = data.get("value")
            output = f"Type: {result_type}\nValue: {result_value}"
            return ToolResult(success=True, output=output, metadata={"type": result_type, "value": result_value})
        except httpx.ConnectError:
            return ToolResult(success=False, error="WebBridge daemon not running.")
        except Exception as e:
            return ToolResult(success=False, error=f"Evaluate error: {e}")

    async def find_tab(self, url: str, active: bool = False, session: str = "js-agent") -> ToolResult:
        is_safe, reason = _check_url_safe(url)
        if not is_safe:
            return ToolResult(success=False, error=reason)
        try:
            data = await self._call("find_tab", {"url": url, "active": active}, session=session)
            if not data.get("success"):
                return ToolResult(success=False, error=data.get("error", "No matching tab found"))
            return ToolResult(
                success=True,
                output=f"Found tab: {data.get('url')} (tab {data.get('tabId')})",
                metadata={"url": data.get("url"), "tabId": data.get("tabId")},
            )
        except httpx.ConnectError:
            return ToolResult(success=False, error="WebBridge daemon not running.")
        except Exception as e:
            return ToolResult(success=False, error=f"Find tab error: {e}")

    async def list_tabs(self, session: str = "js-agent") -> ToolResult:
        try:
            data = await self._call("list_tabs", {}, session=session)
            if not data.get("success"):
                return ToolResult(success=False, error=data.get("error", "List tabs failed"))
            tabs = data.get("tabs", [])
            lines = [f"{t.get('tabId')}: {t.get('title', '')} ({t.get('url', '')}) {'[active]' if t.get('active') else ''}" for t in tabs]
            return ToolResult(success=True, output="\n".join(lines) if lines else "No tabs open", metadata={"tabs": tabs})
        except httpx.ConnectError:
            return ToolResult(success=False, error="WebBridge daemon not running.")
        except Exception as e:
            return ToolResult(success=False, error=f"List tabs error: {e}")

    async def extract_text(self, max_chars: int = 8000, session: str = "js-agent") -> ToolResult:
        """Extract visible text from the page using JavaScript. Fallback for sparse accessibility trees."""
        js_code = """
        (function() {
            const results = [];
            // Headings
            document.querySelectorAll('h1, h2, h3, h4, h5, h6').forEach(el => {
                const text = el.innerText?.trim();
                if (text) results.push('# ' + text);
            });
            // Links with text
            document.querySelectorAll('a').forEach(el => {
                const text = el.innerText?.trim();
                if (text && text.length > 1) results.push('[Link] ' + text + (el.href ? ' (' + el.href + ')' : ''));
            });
            // Buttons
            document.querySelectorAll('button, [role=\"button\"]').forEach(el => {
                const text = el.innerText?.trim() || el.getAttribute('aria-label')?.trim();
                if (text && text.length > 0) results.push('[Button] ' + text);
            });
            // Inputs with placeholders
            document.querySelectorAll('input[placeholder], textarea[placeholder]').forEach(el => {
                const ph = el.getAttribute('placeholder')?.trim();
                if (ph) results.push('[Input] placeholder: ' + ph);
            });
            // Paragraphs and divs with meaningful text
            const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, null, false);
            const textNodes = [];
            let node;
            while (node = walker.nextNode()) {
                const text = node.textContent?.trim();
                if (text && text.length > 2 && text.length < 500) {
                    const parent = node.parentElement;
                    if (parent && ['SCRIPT', 'STYLE', 'NOSCRIPT'].indexOf(parent.tagName) === -1) {
                        textNodes.push(text);
                    }
                }
            }
            // Deduplicate and limit
            const unique = [...new Set(textNodes)].slice(0, 200);
            results.push('--- Body text ---');
            results.push(...unique);
            return results.join('\\n');
        })()
        """
        try:
            data = await self._call("evaluate", {"code": js_code}, session=session)
            result_type = data.get("type", "unknown")
            result_value = data.get("value", "")
            if result_type == "string" and result_value:
                text = result_value
                if len(text) > max_chars:
                    text = text[:max_chars] + "\n... [truncated]"
                return ToolResult(success=True, output=text, metadata={"type": result_type, "length": len(result_value)})
            return ToolResult(success=False, error=f"Extract text returned type={result_type}, no content")
        except httpx.ConnectError:
            return ToolResult(success=False, error="WebBridge daemon not running.")
        except Exception as e:
            return ToolResult(success=False, error=f"Extract text error: {e}")

    def register_all(self, registry: Any) -> None:
        """Register all WebBridge tools with the agent's tool registry."""
        specs = self.get_specs()
        handlers = {
            "web_navigate": self.navigate,
            "web_snapshot": self.snapshot,
            "web_click": self.click,
            "web_fill": self.fill,
            "web_screenshot": self.screenshot,
            "web_evaluate": self.evaluate,
            "web_find_tab": self.find_tab,
            "web_list_tabs": self.list_tabs,
            "web_extract_text": self.extract_text,
        }
        for spec in specs:
            handler = handlers.get(spec.name)
            if handler:
                registry.register(spec, handler)

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()
