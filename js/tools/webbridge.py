"""Kimi WebBridge integration for real browser control.

Requires the kimi-webbridge daemon running at http://127.0.0.1:10086.
Provides tools for navigating, interacting with, and capturing real browser tabs
with full JavaScript execution and user login sessions.
"""

from __future__ import annotations

import asyncio
import os
import secrets
from pathlib import Path
from typing import Any

import httpx

from js.security.net_guard import OutboundURLError, resolve_and_validate
from js.tools.registry import ToolParam, ToolResult, ToolSpec
from js.utils.log import get_logger

logger = get_logger("js.tools.webbridge")

_DAEMON_URL = "http://127.0.0.1:10086/command"
_DEFAULT_TIMEOUT = 30.0

# Environment variable that lets the daemon and the agent share an explicit
# token.  When unset, a random per-install token is generated and persisted.
_TOKEN_ENV = "JS_WEBRIDGE_TOKEN"
_TOKEN_FILENAME = "webbridge_token"


def _load_or_create_token(state_dir: Path | None) -> str:
    """Resolve the WebBridge daemon auth token.

    Precedence:
      1. ``JS_WEBRIDGE_TOKEN`` environment variable (explicit alignment).
      2. A random token persisted at ``<state_dir>/webbridge_token`` (0600).
      3. An ephemeral random token if no persistence location is available.

    There is deliberately NO fallback to a fixed/shared default token — a
    hardcoded secret is no secret at all.
    """
    env_token = os.environ.get(_TOKEN_ENV, "").strip()
    if env_token:
        return env_token

    if state_dir is None:
        return secrets.token_urlsafe(32)

    token_path = Path(state_dir) / _TOKEN_FILENAME
    try:
        if token_path.exists():
            existing = token_path.read_text(encoding="utf-8").strip()
            if existing:
                return existing
    except OSError:
        logger.warning("Failed to read WebBridge token file", exc_info=True)

    token = secrets.token_urlsafe(32)
    try:
        Path(state_dir).mkdir(parents=True, exist_ok=True)
        # O_CREAT with mode 0600 so the secret is never world/group-readable.
        fd = os.open(str(token_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, token.encode("utf-8"))
        finally:
            os.close(fd)
        os.chmod(token_path, 0o600)
    except OSError:
        logger.warning("Failed to persist WebBridge token; using ephemeral token", exc_info=True)
    return token


_JS_LINE_COMMENT_RE = None  # lazily compiled in _normalize_js_for_scan


def _normalize_js_for_scan(code: str) -> str:
    """Normalize JS source for security scanning.

    Steps: strip comments (quote-aware), decode \\uXXXX/\\xXX escapes, and
    fold adjacent string-literal concatenations (``"ev"+"al"`` → ``"eval"``).
    Purely heuristic — see the residual-risk note in ``_scan_js_code``.
    """
    import re

    # 1. Strip comments with a small quote-aware state machine so that
    #    comment markers inside string literals survive.
    out: list[str] = []
    idx = 0
    quote: str | None = None
    length = len(code)
    while idx < length:
        ch = code[idx]
        nxt = code[idx + 1] if idx + 1 < length else ""
        if quote is not None:
            out.append(ch)
            if ch == "\\" and idx + 1 < length:
                out.append(code[idx + 1])
                idx += 2
                continue
            if ch == quote:
                quote = None
            idx += 1
            continue
        if ch in "'\"`":
            quote = ch
            out.append(ch)
            idx += 1
            continue
        if ch == "/" and nxt == "*":
            end = code.find("*/", idx + 2)
            idx = length if end == -1 else end + 2
            continue
        if ch == "/" and nxt == "/":
            end = code.find("\n", idx + 2)
            idx = length if end == -1 else end
            continue
        out.append(ch)
        idx += 1
    stripped = "".join(out)

    # 2. Decode hex/unicode escapes (both raw and string-embedded forms).
    stripped = re.sub(
        r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), stripped
    )
    stripped = re.sub(
        r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), stripped
    )

    # 3. Fold adjacent string-literal concatenations, repeatedly.
    concat_re = re.compile(
        r"""(['"`])([^'"`]*)\1\s*\+\s*(['"`])([^'"`]*)\3"""
    )
    previous = None
    while previous != stripped:
        previous = stripped
        stripped = concat_re.sub(lambda m: m.group(1) + m.group(2) + m.group(4) + m.group(1), stripped)
    return stripped


def _resolve_url_safe(url: str) -> tuple[bool, str, list[str]]:
    """Block private/internal URLs to prevent SSRF.

    Returns (is_safe, reason_if_blocked, validated_ips).  Resolves the host so
    numeric-IP, wildcard-DNS and rebinding bypasses are caught, not just literal
    IPs.  The validated IP list is returned so callers can pin connections or
    pass the IPs to downstream services (e.g. the WebBridge daemon) to prevent
    DNS rebinding between validation and the actual request.
    """
    try:
        validated_ips = resolve_and_validate(url, allow_loopback=False, allow_private=False)
    except OutboundURLError as exc:
        return False, str(exc), []
    return True, "", validated_ips


class WebBridgeTool:
    """Wrapper around Kimi WebBridge daemon API."""

    def __init__(self, state_dir: Path | None = None) -> None:
        self._client: httpx.AsyncClient | None = None
        self._available: bool | None = None  # Lazy health check
        self._token = _load_or_create_token(state_dir)
        # Set when the daemon rejects our token — WebBridge is then disabled
        # until the operator aligns the tokens.
        self._token_mismatch = False

    _TOKEN_HELP = (
        "WebBridge daemon rejected the auth token. The agent now generates a "
        f"random token; align the daemon by setting the {_TOKEN_ENV} environment "
        "variable (or the daemon's token file) to the same value on both sides."
    )

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=httpx.Timeout(_DEFAULT_TIMEOUT))
        return self._client

    @staticmethod
    def _is_auth_rejection(resp: httpx.Response) -> bool:
        """Heuristically detect a token/auth rejection from the daemon."""
        if resp.status_code in (401, 403):
            return True
        try:
            body = resp.json()
        except Exception:
            return False
        if body.get("ok") is False:
            err = str(body.get("error", "")).lower()
            return any(kw in err for kw in ("token", "auth", "unauthor", "forbidden"))
        return False

    async def health_check(self) -> bool:
        """Check whether the WebBridge daemon is reachable AND token-aligned.

        Uses a lightweight POST to /command (list_tabs) because the daemon
        does not expose a dedicated /_health endpoint.
        """
        if self._available is not None:
            return self._available
        try:
            client = self._get_client()
            resp = await client.post(
                _DAEMON_URL,
                json={"action": "list_tabs", "args": {}, "session": "__health__", "token": self._token},
                timeout=5.0,
            )
            if self._is_auth_rejection(resp):
                self._token_mismatch = True
                self._available = False
                logger.warning(self._TOKEN_HELP)
            else:
                self._available = resp.status_code == 200 and resp.json().get("ok") is True
        except Exception:
            self._available = False
        return self._available

    async def _call(self, action: str, args: dict[str, Any], session: str = "js-agent") -> dict[str, Any]:
        """Send a command to the WebBridge daemon with retry."""
        if self._token_mismatch:
            raise RuntimeError(self._TOKEN_HELP)
        client = self._get_client()
        last_error: Exception | None = None
        for attempt in range(3):
            try:
                resp = await client.post(
                    _DAEMON_URL,
                    json={"action": action, "args": args, "session": session, "token": self._token},
                )
                if self._is_auth_rejection(resp):
                    self._token_mismatch = True
                    self._available = False
                    logger.warning(self._TOKEN_HELP)
                    raise RuntimeError(self._TOKEN_HELP)
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
                dangerous=True,
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
                    "or a CSS selector. DANGEROUS: interacts with the real browser."
                ),
                parameters=[
                    ToolParam("selector", "string", "Element selector (@e ref or CSS selector)"),
                    ToolParam("session", "string", "Browser session name", required=False),
                ],
                dangerous=True,
            ),
            ToolSpec(
                name="web_fill",
                description=(
                    "Fill an input field or textarea with text. Works on <input>, <textarea>, "
                    "and contenteditable elements. DANGEROUS: interacts with the real browser."
                ),
                parameters=[
                    ToolParam("selector", "string", "Element selector (@e ref or CSS selector)"),
                    ToolParam("value", "string", "Text to fill"),
                    ToolParam("session", "string", "Browser session name", required=False),
                ],
                dangerous=True,
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
                    "Return value is serialized as JSON. DANGEROUS: runs arbitrary JS in the "
                    "user's real browser with active login sessions. Requires explicit approval."
                ),
                parameters=[
                    ToolParam("code", "string", "JavaScript code to execute"),
                    ToolParam("session", "string", "Browser session name", required=False),
                ],
                dangerous=True,
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
                dangerous=True,
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
        safe, reason, validated_ips = _resolve_url_safe(url)
        if not safe:
            return ToolResult(success=False, error=f"URL blocked: {reason}")
        try:
            # Pass validated IPs to the daemon so it can pin the connection
            # and avoid DNS rebinding between our check and the actual request.
            data = await self._call(
                "navigate",
                {"url": url, "newTab": new_tab, "validated_ips": validated_ips},
                session=session,
            )
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

    # Dangerous JS patterns that could exfiltrate data or execute arbitrary code
    _JS_DANGEROUS_PATTERNS = [
        (r"\beval\s*\(", "eval() execution"),
        (r"\bnew\s+Function\s*\(", "Function() constructor"),
        (r"\bsetTimeout\s*\(\s*['\"`][^'\"`]*['\"`]", "setTimeout with string"),
        (r"\bsetInterval\s*\(\s*['\"`][^'\"`]*['\"`]", "setInterval with string"),
        (r"\bdocument\.cookie\b", "document.cookie access"),
        (r"\blocalStorage\b", "localStorage access"),
        (r"\bsessionStorage\b", "sessionStorage access"),
        (r"\bfetch\s*\(", "fetch() network call"),
        (r"\bXMLHttpRequest\b", "XMLHttpRequest network call"),
        (r"\bWebSocket\b", "WebSocket network call"),
        (r"\bimportScripts\s*\(", "importScripts() import"),
        (r"\bnavigator\.sendBeacon\b", "sendBeacon data exfiltration"),
        # Bracket-notation bypasses: window["fetch"], this["eval"], etc.
        (r'''\[['"\`](?:eval|fetch|Function|XMLHttpRequest|WebSocket|importScripts|sendBeacon)['"\`]\]''',
         "bracket-notation dangerous API access"),
        # Constructor chain attacks: []["constructor"]["constructor"]
        (r'''\[['"\`]constructor['"\`]\]''',
         "constructor property access — potential sandbox escape"),
        # String concatenation obfuscation of dangerous names
        (r'''['"\`][ef][ev][at][lc][ch]['"\`]\s*\+''', "string concat obfuscation of 'eval'/'fetch'"),
        # Indirect eval via property access: window.eval, this.eval, globalThis.eval
        (r"\b(?:window|this|globalThis|self|top|parent)\.eval\b", "indirect eval access"),
        # Indirect fetch via property access
        (r"\b(?:window|this|globalThis|self|top|parent)\.fetch\b", "indirect fetch access"),
        # Reflect-based dynamic invocation: Reflect.apply(eval, ...),
        # Reflect.construct(Function, ...)
        (r"\bReflect\s*\.\s*(?:apply|construct|defineProperty)\b", "Reflect dynamic invocation"),
        # with(...) scope manipulation — classic eval-hiding primitive
        (r"\bwith\s*\(", "with statement scope manipulation"),
        # Hex / unicode escape sequences often used to hide eval/fetch
        (r"\\x[0-9a-fA-F]{2}", "hex escape obfuscation"),
        (r"\\u[0-9a-fA-F]{4}", "unicode escape obfuscation"),
        # Template literal obfuscation: `${`ev`+`al`}` or similar
        (r"\$\{\s*['\"`][^'\"`]{1,6}['\"`]\s*\+", "template literal obfuscation"),
        # Spread into Function constructor: Function(...["e","v","a","l"])
        (r"Function\s*\(\s*\.\.\.", "Function constructor with spread"),
        # fromCharCode obfuscation: String.fromCharCode(101,118,97,108)
        (r"fromCharCode\s*\(", "fromCharCode obfuscation"),
        # Dynamic script injection
        (r"document\.(createElement|head|body)\b.*\bscript\b", "dynamic script injection"),
        # location manipulation for data exfiltration
        (r"\blocation\.(href|assign|replace)\b", "location manipulation"),
        # Form submission exfiltration
        (r"document\.(createElement|body).*\bform\b.*\.submit\b", "form submission exfiltration"),
    ]

    def _scan_js_code(self, code: str) -> str | None:
        """Static analysis for dangerous JS patterns.

        The raw source is scanned first (so obfuscation markers like
        ``\\uXXXX`` escapes are rejected even when they decode to something
        benign), then a normalized form is scanned as well: comments are
        stripped, ``\\uXXXX``/``\\xXX`` escapes are decoded, and adjacent
        string-literal concatenations are folded.  This defeats the classic
        ev/*x*/al, \\u0065val and "ev"+"al" bypass families.

        Residual risk: this is regex heuristics, not a JS parser.  A
        determined attacker with full grammar-level obfuscation (computed
        property names from non-literal expressions, getter tricks, tagged
        templates) may still slip through.  The scan is one layer; the
        ``dangerous=True`` approval gate is the primary control.
        """
        import re
        for pattern, description in self._JS_DANGEROUS_PATTERNS:
            if re.search(pattern, code, re.IGNORECASE):
                return f"Blocked dangerous JS pattern: {description}"
        # Additional check: atob() for base64 decode of obfuscated code
        if re.search(r'\batob\s*\(', code, re.IGNORECASE):
            return "Blocked atob() — base64 decode may hide malicious code"
        # Additional check: btoa() could be used to encode exfiltrated data
        if re.search(r'\bbtoa\s*\(', code, re.IGNORECASE):
            return "Blocked btoa() — base64 encode may hide exfiltrated data"
        normalized = _normalize_js_for_scan(code)
        if normalized != code:
            for pattern, description in self._JS_DANGEROUS_PATTERNS:
                if re.search(pattern, normalized, re.IGNORECASE):
                    return f"Blocked dangerous JS pattern after normalization: {description}"
            if re.search(r'\batob\s*\(', normalized, re.IGNORECASE):
                return "Blocked atob() after normalization"
            if re.search(r'\bbtoa\s*\(', normalized, re.IGNORECASE):
                return "Blocked btoa() after normalization"
        return None

    async def evaluate(self, code: str, session: str = "js-agent") -> ToolResult:
        scan = self._scan_js_code(code)
        if scan:
            return ToolResult(success=False, error=f"JS security scan failed: {scan}")
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
        is_safe, reason, validated_ips = _resolve_url_safe(url)
        if not is_safe:
            return ToolResult(success=False, error=reason)
        try:
            data = await self._call(
                "find_tab",
                {"url": url, "active": active, "validated_ips": validated_ips},
                session=session,
            )
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
