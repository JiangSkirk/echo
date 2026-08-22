"""Run the Desktop browser probe in an isolated real asyncio process."""

from __future__ import annotations

import asyncio
import json
import re
import sys
from typing import Any
from urllib.parse import urlsplit

from playwright.async_api import async_playwright

_TOKEN_PATTERN = re.compile(r"[0-9a-f]{64}\Z")


def _read_request() -> tuple[str, str, bool]:
    raw = sys.stdin.buffer.readline(4097)
    if not raw.endswith(b"\n") or len(raw) > 4096 or sys.stdin.buffer.read(1):
        raise ValueError("invalid browser probe request")
    payload = json.loads(raw)
    if not isinstance(payload, dict) or set(payload) != {
        "inject_failure",
        "token",
        "url",
    }:
        raise ValueError("invalid browser probe request")
    url = payload.get("url")
    token = payload.get("token")
    inject_failure = payload.get("inject_failure")
    if not isinstance(url, str) or not isinstance(token, str):
        raise ValueError("invalid browser probe request")
    if not isinstance(inject_failure, bool) or _TOKEN_PATTERN.fullmatch(token) is None:
        raise ValueError("invalid browser probe request")
    parsed = urlsplit(url)
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path != "/"
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("invalid browser probe request")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("invalid browser probe request") from exc
    if port is None or not 1 <= port <= 65535:
        raise ValueError("invalid browser probe request")
    return url, token, inject_failure


async def _probe(url: str, token: str, *, inject_failure: bool) -> dict[str, Any]:
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=True)
        context = None
        try:
            context = await browser.new_context()
            page = await context.new_page()
            await page.goto(f"{url}#bootstrap={token}")
            await page.wait_for_function("window.location.hash === ''")
            status = await page.evaluate(
                "fetch('/api/status').then(async response => "
                "({status: response.status, body: await response.json()}))"
            )
            cookies = await context.cookies()
            parent_cookie = next(
                cookie for cookie in cookies if cookie["name"] == "js_appshell_session"
            )
            cookie_visible = "js_appshell_session" in await page.evaluate(
                "document.cookie"
            )
            if inject_failure:
                raise RuntimeError("injected post-bootstrap browser failure")
            return {
                "cookie_http_only": parent_cookie["httpOnly"] is True,
                "cookie_visible": cookie_visible,
                "fragment_cleared": True,
                "product_id": status["body"]["product_id"],
                "status": status["status"],
            }
        finally:
            try:
                if context is not None:
                    await context.close()
            finally:
                await browser.close()


def main() -> int:
    try:
        url, token, inject_failure = _read_request()
        result = asyncio.run(_probe(url, token, inject_failure=inject_failure))
    except Exception:
        print("async desktop browser probe failed", file=sys.stderr)
        return 70
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
