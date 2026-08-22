"""Tests for browser tool."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx
import pytest

import js.tools.browser as browser_module
from js.config import SecurityConfig, ToolLimits
from js.security.guard import BehaviorGuard
from js.tools.browser import BrowserTool


class TestBrowserTool:
    @pytest.fixture
    def browser(self) -> BrowserTool:
        limits = ToolLimits()
        guard = BehaviorGuard(SecurityConfig(), Path("/tmp"))
        return BrowserTool(limits, guard)

    @pytest.mark.asyncio
    async def test_private_url_blocked(self, browser: BrowserTool) -> None:
        result = await browser.fetch("http://127.0.0.1:8080/admin")
        assert not result.success
        assert "blocked" in result.error.lower()

    @pytest.mark.asyncio
    async def test_invalid_url_blocked(self, browser: BrowserTool) -> None:
        result = await browser.fetch("ftp://example.com/file")
        assert not result.success
        assert "http://" in result.error or "https://" in result.error

    @pytest.mark.asyncio
    async def test_fetch_real(self, browser: BrowserTool) -> None:
        result = await browser.fetch("https://httpbin.org/get", max_chars=2000)
        # May fail in CI, so just check structure
        assert isinstance(result.success, bool)


class _FakeStreamResponse:
    """Minimal stand-in for an httpx streaming response."""

    def __init__(
        self,
        chunks: list[bytes],
        status_code: int = 200,
        headers: dict[str, str] | None = None,
    ) -> None:
        self._chunks = chunks
        self.status_code = status_code
        self.headers = headers or {"content-type": "text/plain; charset=utf-8"}
        self.url = httpx.URL("http://example.com/")
        self.encoding = "utf-8"

    @property
    def is_redirect(self) -> bool:
        return self.status_code in (301, 302, 303, 307, 308)

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            request = httpx.Request("GET", self.url)
            raise httpx.HTTPStatusError("error", request=request, response=self)  # type: ignore[arg-type]

    async def aiter_bytes(self) -> Any:
        for chunk in self._chunks:
            yield chunk

    async def __aenter__(self) -> _FakeStreamResponse:
        return self

    async def __aexit__(self, *args: Any) -> bool:
        return False


class _FakeClient:
    def __init__(self, response: _FakeStreamResponse) -> None:
        self._response = response

    async def __aenter__(self) -> _FakeClient:
        return self

    async def __aexit__(self, *args: Any) -> bool:
        return False

    def stream(self, method: str, url: str) -> _FakeStreamResponse:
        return self._response


class TestBrowserToolStreaming:
    @pytest.fixture
    def browser(self) -> BrowserTool:
        limits = ToolLimits()
        guard = BehaviorGuard(SecurityConfig(), Path("/tmp"))
        return BrowserTool(limits, guard)

    def _patch_transport(
        self,
        monkeypatch: pytest.MonkeyPatch,
        response: _FakeStreamResponse,
    ) -> dict[str, Any]:
        captured: dict[str, Any] = {}

        def fake_client(**kwargs: Any) -> _FakeClient:
            captured.update(kwargs)
            return _FakeClient(response)

        monkeypatch.setattr(
            browser_module, "resolve_and_validate", lambda url, **kw: ["93.184.216.34"]
        )
        monkeypatch.setattr(httpx, "AsyncClient", fake_client)
        return captured

    @pytest.mark.asyncio
    async def test_fetch_streams_and_truncates(
        self, browser: BrowserTool, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # A multibyte character split across chunk boundaries must survive.
        chunks = ["你".encode()[:1], "你".encode()[1:], b" world"]
        self._patch_transport(monkeypatch, _FakeStreamResponse(chunks))

        result = await browser.fetch("http://example.com/", max_chars=100)

        assert result.success
        assert result.output == "你 world"

        self._patch_transport(monkeypatch, _FakeStreamResponse([b"abcdef"]))
        result = await browser.fetch("http://example.com/", max_chars=3)
        assert result.success
        assert result.output == "abc\n... [truncated]"

    @pytest.mark.asyncio
    async def test_fetch_aborts_over_size_limit(
        self, browser: BrowserTool, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(browser_module, "MAX_RESPONSE_BYTES", 10)
        self._patch_transport(monkeypatch, _FakeStreamResponse([b"aaaaaa", b"bbbbbb"]))

        result = await browser.fetch("http://example.com/")

        assert not result.success
        assert "size limit" in result.error

    @pytest.mark.asyncio
    async def test_fetch_disables_trust_env_and_redirects(
        self, browser: BrowserTool, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured = self._patch_transport(monkeypatch, _FakeStreamResponse([b"ok"]))

        result = await browser.fetch("http://example.com/")

        assert result.success
        assert captured["trust_env"] is False
        assert captured["follow_redirects"] is False

    @pytest.mark.asyncio
    async def test_fetch_redirect_still_blocked(
        self, browser: BrowserTool, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._patch_transport(monkeypatch, _FakeStreamResponse([b""], status_code=302))

        result = await browser.fetch("http://example.com/")

        assert not result.success
        assert "redirect" in result.error.lower()
