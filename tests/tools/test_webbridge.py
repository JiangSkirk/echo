"""Tests for Kimi WebBridge tool integration."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import httpx
import pytest

from js.tools.registry import ToolRegistry
from js.tools.webbridge import WebBridgeTool


@pytest.fixture
def webbridge() -> WebBridgeTool:
    return WebBridgeTool()


@pytest.fixture
def registry() -> ToolRegistry:
    from pathlib import Path

    from js.config import SecurityConfig, ToolLimits
    from js.security.guard import BehaviorGuard
    guard = BehaviorGuard(config=SecurityConfig(), workspace=Path("/tmp"))
    limits = ToolLimits()
    return ToolRegistry(limits, guard)


class TestWebBridgeRegistration:
    """Test tool registration."""

    def test_register_all(self, webbridge: WebBridgeTool, registry: ToolRegistry) -> None:
        webbridge.register_all(registry)
        names = {t.name for t in registry.list_tools()}
        expected = {
            "web_navigate",
            "web_snapshot",
            "web_click",
            "web_fill",
            "web_screenshot",
            "web_evaluate",
            "web_find_tab",
            "web_list_tabs",
        }
        assert expected <= names

    def test_snapshot_read_only(self, webbridge: WebBridgeTool, registry: ToolRegistry) -> None:
        webbridge.register_all(registry)
        spec = registry.get("web_snapshot")
        assert spec is not None
        assert spec.read_only is True

    def test_screenshot_read_only(self, webbridge: WebBridgeTool, registry: ToolRegistry) -> None:
        webbridge.register_all(registry)
        spec = registry.get("web_screenshot")
        assert spec is not None
        assert spec.read_only is True


class TestWebBridgeHandlersOffline:
    """Test handlers when daemon is not running."""

    async def test_navigate_offline(self, webbridge: WebBridgeTool) -> None:
        with patch.object(webbridge, "_call", side_effect=httpx.ConnectError("Connection refused")):
            result = await webbridge.navigate("https://example.com")
        assert result.success is False
        assert "not running" in result.error

    async def test_snapshot_offline(self, webbridge: WebBridgeTool) -> None:
        with patch.object(webbridge, "_call", side_effect=httpx.ConnectError("Connection refused")):
            result = await webbridge.snapshot()
        assert result.success is False
        assert "not running" in result.error

    async def test_click_offline(self, webbridge: WebBridgeTool) -> None:
        with patch.object(webbridge, "_call", side_effect=httpx.ConnectError("Connection refused")):
            result = await webbridge.click("@e1")
        assert result.success is False
        assert "not running" in result.error

    async def test_fill_offline(self, webbridge: WebBridgeTool) -> None:
        with patch.object(webbridge, "_call", side_effect=httpx.ConnectError("Connection refused")):
            result = await webbridge.fill("@e1", "hello")
        assert result.success is False
        assert "not running" in result.error

    async def test_screenshot_offline(self, webbridge: WebBridgeTool) -> None:
        with patch.object(webbridge, "_call", side_effect=httpx.ConnectError("Connection refused")):
            result = await webbridge.screenshot()
        assert result.success is False
        assert "not running" in result.error

    async def test_evaluate_offline(self, webbridge: WebBridgeTool) -> None:
        with patch.object(webbridge, "_call", side_effect=httpx.ConnectError("Connection refused")):
            result = await webbridge.evaluate("document.title")
        assert result.success is False
        assert "not running" in result.error

    async def test_find_tab_offline(self, webbridge: WebBridgeTool) -> None:
        with patch.object(webbridge, "_call", side_effect=httpx.ConnectError("Connection refused")):
            result = await webbridge.find_tab("https://example.com")
        assert result.success is False
        assert "not running" in result.error

    async def test_list_tabs_offline(self, webbridge: WebBridgeTool) -> None:
        with patch.object(webbridge, "_call", side_effect=httpx.ConnectError("Connection refused")):
            result = await webbridge.list_tabs()
        assert result.success is False
        assert "not running" in result.error


class TestWebBridgeHandlersOnline:
    """Test handlers with mocked daemon responses."""

    async def test_navigate_success(self, webbridge: WebBridgeTool) -> None:
        with patch.object(webbridge, "_call", new_callable=AsyncMock, return_value={
            "success": True, "url": "https://example.com", "tabId": 42,
        }):
            result = await webbridge.navigate("https://example.com")
        assert result.success is True
        assert "example.com" in result.output
        assert result.metadata["tabId"] == 42

    async def test_navigate_failure(self, webbridge: WebBridgeTool) -> None:
        with patch.object(webbridge, "_call", new_callable=AsyncMock, return_value={
            "success": False, "error": "Navigation failed",
        }):
            result = await webbridge.navigate("http://bad-url.example")
        assert result.success is False
        assert "Navigation failed" in result.error

    async def test_navigate_blocked_url(self, webbridge: WebBridgeTool) -> None:
        result = await webbridge.navigate("bad-url")
        assert result.success is False
        assert "URL blocked" in result.error

    async def test_snapshot_success(self, webbridge: WebBridgeTool) -> None:
        with patch.object(webbridge, "_call", new_callable=AsyncMock, return_value={
            "url": "https://example.com", "title": "Example", "tree": "- button @e1\n- link @e2",
        }):
            result = await webbridge.snapshot()
        assert result.success is True
        assert "Example" in result.output
        assert "@e1" in result.output

    async def test_click_success(self, webbridge: WebBridgeTool) -> None:
        with patch.object(webbridge, "_call", new_callable=AsyncMock, return_value={
            "success": True, "tag": "button", "text": "Submit",
        }):
            result = await webbridge.click("@e1")
        assert result.success is True
        assert "button" in result.output
        assert "Submit" in result.output

    async def test_fill_success(self, webbridge: WebBridgeTool) -> None:
        with patch.object(webbridge, "_call", new_callable=AsyncMock, return_value={
            "success": True, "tag": "input", "mode": "value",
        }):
            result = await webbridge.fill("@e1", "hello world")
        assert result.success is True
        assert "input" in result.output
        assert "value" in result.output

    async def test_screenshot_success(self, webbridge: WebBridgeTool) -> None:
        with patch.object(webbridge, "_call", new_callable=AsyncMock, return_value={
            "path": "/tmp/screenshot.png", "sizeBytes": 12345, "format": "png", "mimeType": "image/png",
        }):
            result = await webbridge.screenshot()
        assert result.success is True
        assert "/tmp/screenshot.png" in result.output
        assert result.metadata["sizeBytes"] == 12345

    async def test_evaluate_success(self, webbridge: WebBridgeTool) -> None:
        with patch.object(webbridge, "_call", new_callable=AsyncMock, return_value={
            "type": "string", "value": "Hello",
        }):
            result = await webbridge.evaluate("document.title")
        assert result.success is True
        assert "string" in result.output
        assert "Hello" in result.output

    async def test_find_tab_success(self, webbridge: WebBridgeTool) -> None:
        with patch.object(webbridge, "_call", new_callable=AsyncMock, return_value={
            "success": True, "url": "https://example.com/page", "tabId": 7,
        }):
            result = await webbridge.find_tab("https://example.com")
        assert result.success is True
        assert "example.com/page" in result.output
        assert result.metadata["tabId"] == 7

    async def test_find_tab_failure(self, webbridge: WebBridgeTool) -> None:
        with patch.object(webbridge, "_call", new_callable=AsyncMock, return_value={
            "success": False, "error": "no open tab found",
        }):
            result = await webbridge.find_tab("https://example.com")
        assert result.success is False
        assert "no open tab found" in result.error

    async def test_list_tabs_success(self, webbridge: WebBridgeTool) -> None:
        with patch.object(webbridge, "_call", new_callable=AsyncMock, return_value={
            "success": True,
            "tabs": [
                {"tabId": 1, "url": "https://a.com", "title": "A", "active": True},
                {"tabId": 2, "url": "https://b.com", "title": "B", "active": False},
            ],
        }):
            result = await webbridge.list_tabs()
        assert result.success is True
        assert "A" in result.output
        assert "B" in result.output
        assert "[active]" in result.output

    async def test_list_tabs_empty(self, webbridge: WebBridgeTool) -> None:
        with patch.object(webbridge, "_call", new_callable=AsyncMock, return_value={
            "success": True, "tabs": [],
        }):
            result = await webbridge.list_tabs()
        assert result.success is True
        assert "No tabs open" in result.output
