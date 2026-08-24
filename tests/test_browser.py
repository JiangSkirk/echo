"""Tests for browser tool."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import httpx
import pytest

import js.tools.browser as browser_module
from js.config import SecurityConfig, ToolLimits
from js.echo.capability import LeaseDenied
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


class TestBrowserNetworkCellRouting:
    @pytest.fixture
    def browser(self) -> BrowserTool:
        limits = ToolLimits()
        guard = BehaviorGuard(SecurityConfig(), Path("/tmp"))
        return BrowserTool(limits, guard)

    @staticmethod
    def _forbid_local_network(monkeypatch: pytest.MonkeyPatch) -> None:
        def local_dns_forbidden(*_args: object, **_kwargs: object) -> list[str]:
            raise AssertionError("local DNS validation must not run with Network Cell backend")

        def local_http_forbidden(*_args: object, **_kwargs: object) -> object:
            raise AssertionError("local HTTP client must not run with Network Cell backend")

        monkeypatch.setattr(browser_module, "resolve_and_validate", local_dns_forbidden)
        monkeypatch.setattr(httpx, "AsyncClient", local_http_forbidden)

    @pytest.mark.asyncio
    async def test_backend_uses_to_thread_and_projects_committed_result(
        self,
        browser: BrowserTool,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        self._forbid_local_network(monkeypatch)
        original_to_thread = asyncio.to_thread
        thread_calls: list[tuple[object, tuple[object, ...]]] = []
        backend_calls: list[dict[str, Any]] = []

        async def traced_to_thread(
            func: object, /, *args: object, **kwargs: object
        ) -> object:
            thread_calls.append((func, args))
            return await original_to_thread(func, *args, **kwargs)  # type: ignore[arg-type]

        def backend(payload: dict[str, Any]) -> dict[str, Any]:
            backend_calls.append(payload)
            return {
                "status": "COMMITTED",
                "output": "via-network-cell",
                "content_hash": "sha256:" + "a" * 64,
                "final_url": "https://example.com/final",
                # Backend internals must never enter the model-visible result.
                "token": "MUST-NOT-LEAK",
                "permit": {"idempotency_key": "private"},
            }

        monkeypatch.setattr(asyncio, "to_thread", traced_to_thread)
        browser.cell_backend = backend  # type: ignore[attr-defined]

        result = await browser.fetch("https://example.com/start", max_chars=17)

        assert result.success
        assert result.output == "via-network-cell"
        assert thread_calls and thread_calls[0][0] is backend
        assert backend_calls == [
            {
                "tool": "net.fetch",
                "url": "https://example.com/start",
                "max_chars": 17,
            }
        ]
        assert result.metadata.get("cell") == "net"
        assert result.metadata.get("content_hash") == "sha256:" + "a" * 64
        assert result.metadata.get("url") == "https://example.com/final"
        assert "MUST-NOT-LEAK" not in repr(result)
        assert "idempotency_key" not in repr(result)

    @pytest.mark.asyncio
    async def test_denied_backend_fails_closed_without_local_fallback(
        self,
        browser: BrowserTool,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        self._forbid_local_network(monkeypatch)
        calls: list[dict[str, Any]] = []

        def backend(payload: dict[str, Any]) -> dict[str, Any]:
            calls.append(payload)
            return {
                "status": "DENIED",
                "error": "policy denied",
                "output": "must-not-be-projected",
            }

        browser.cell_backend = backend  # type: ignore[attr-defined]
        result = await browser.fetch("https://example.com/denied", max_chars=9)

        assert not result.success
        assert result.output == ""
        assert "denied" in result.error.lower()
        assert calls and calls[0]["max_chars"] == 9
        assert "must-not-be-projected" not in repr(result)

    @pytest.mark.asyncio
    @pytest.mark.parametrize("failure", [LeaseDenied("denied"), RuntimeError("cell died")])
    async def test_backend_exception_fails_closed_without_local_fallback(
        self,
        browser: BrowserTool,
        monkeypatch: pytest.MonkeyPatch,
        failure: Exception,
    ) -> None:
        self._forbid_local_network(monkeypatch)
        calls = 0

        def backend(_payload: dict[str, Any]) -> dict[str, Any]:
            nonlocal calls
            calls += 1
            raise failure

        browser.cell_backend = backend  # type: ignore[attr-defined]
        result = await browser.fetch("https://example.com/failure", max_chars=31)

        assert not result.success
        assert result.output == ""
        assert "cell" in result.error.lower() or "safety" in result.error.lower()
        assert calls == 1
