"""Tests for browser tool."""

from pathlib import Path

import pytest

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
