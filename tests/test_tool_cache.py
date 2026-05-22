"""Tests for ToolRegistry result caching (TTL + LRU eviction)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from js.config import SecurityConfig, ToolLimits
from js.security.guard import BehaviorGuard
from js.tools.registry import ToolRegistry, ToolResult, ToolSpec


@pytest.fixture
def registry(tmp_path: Path) -> ToolRegistry:
    limits = ToolLimits(max_concurrent_tools=4)
    guard = BehaviorGuard(SecurityConfig(), tmp_path)
    return ToolRegistry(limits, guard)


@pytest.fixture
def read_tool(registry: ToolRegistry) -> str:
    spec = ToolSpec(
        name="file_read",
        description="Read a file",
        parameters=[],
        read_only=True,
    )
    handler = AsyncMock(return_value=ToolResult(success=True, output="hello"))
    registry.register(spec, handler)
    return "file_read"


@pytest.fixture
def write_tool(registry: ToolRegistry) -> str:
    spec = ToolSpec(
        name="file_write",
        description="Write a file",
        parameters=[],
        read_only=False,
    )
    handler = AsyncMock(return_value=ToolResult(success=True, output="done"))
    registry.register(spec, handler)
    return "file_write"


# ---------------------------------------------------------------------------
# Cache key determinism
# ---------------------------------------------------------------------------


class TestCacheKey:
    def test_cache_key_stable(self, registry: ToolRegistry) -> None:
        key1 = registry._cache_key("tool", {"b": 2, "a": 1})
        key2 = registry._cache_key("tool", {"a": 1, "b": 2})
        assert key1 == key2

    def test_cache_key_different_tools(self, registry: ToolRegistry) -> None:
        key1 = registry._cache_key("tool_a", {"x": 1})
        key2 = registry._cache_key("tool_b", {"x": 1})
        assert key1 != key2


# ---------------------------------------------------------------------------
# Cacheability
# ---------------------------------------------------------------------------


class TestIsCacheable:
    def test_read_only_tool_cacheable(self, registry: ToolRegistry, read_tool: str) -> None:
        assert registry._is_cacheable(read_tool) is True

    def test_write_tool_not_cacheable(self, registry: ToolRegistry, write_tool: str) -> None:
        assert registry._is_cacheable(write_tool) is False

    def test_unknown_tool_not_cacheable(self, registry: ToolRegistry) -> None:
        assert registry._is_cacheable("nonexistent") is False

    def test_heuristic_names_cacheable(self, registry: ToolRegistry) -> None:
        for name in ("file_list", "file_search", "browser_fetch", "web_search"):
            spec = ToolSpec(name=name, description="test", parameters=[], read_only=False)
            registry.register(spec, AsyncMock())
            assert registry._is_cacheable(name) is True


# ---------------------------------------------------------------------------
# TTL expiration
# ---------------------------------------------------------------------------


class TestCacheTTL:
    def test_get_cached_fresh(self, registry: ToolRegistry) -> None:
        result = ToolResult(success=True, output="data")
        key = ("file_read", '{"path":"/tmp/a"}')
        registry._set_cached(key, result)
        cached = registry._get_cached(key)
        assert cached is not None
        assert cached.output == "data"

    def test_get_cached_expired(self, registry: ToolRegistry) -> None:
        result = ToolResult(success=True, output="data")
        key = ("file_read", '{"path":"/tmp/a"}')
        registry._set_cached(key, result)
        # Artificially age the entry beyond TTL
        registry._result_cache[key] = (result, 0.0)  # timestamp = epoch
        cached = registry._get_cached(key)
        assert cached is None
        assert key not in registry._result_cache

    def test_get_cached_miss(self, registry: ToolRegistry) -> None:
        cached = registry._get_cached(("unknown", "{}"))
        assert cached is None


# ---------------------------------------------------------------------------
# LRU eviction
# ---------------------------------------------------------------------------


class TestCacheLRU:
    def test_eviction_oldest_removed(self, registry: ToolRegistry) -> None:
        registry._cache_max_size = 3
        for i in range(4):
            key = ("file_read", f'{{"idx":{i}}}')
            registry._set_cached(key, ToolResult(success=True, output=str(i)))

        # Oldest entry (idx=0) should have been evicted
        assert registry._get_cached(("file_read", '{"idx":0}')) is None
        # Newer entries still present
        assert registry._get_cached(("file_read", '{"idx":1}')) is not None
        assert registry._get_cached(("file_read", '{"idx":3}')) is not None

    def test_capacity_respected(self, registry: ToolRegistry) -> None:
        registry._cache_max_size = 2
        for i in range(5):
            key = ("file_read", f'{{"idx":{i}}}')
            registry._set_cached(key, ToolResult(success=True, output=str(i)))
        assert len(registry._result_cache) == 2


# ---------------------------------------------------------------------------
# End-to-end cache in execute()
# ---------------------------------------------------------------------------


class TestExecuteCaching:
    @pytest.mark.asyncio
    async def test_cache_hit_skips_handler(self, registry: ToolRegistry, read_tool: str) -> None:
        handler = registry._handlers[read_tool]
        # Prime cache
        await registry.execute("run-1", read_tool, {"path": "/tmp/a"})
        assert handler.call_count == 1

        # Second call — cache hit
        result = await registry.execute("run-1", read_tool, {"path": "/tmp/a"})
        assert handler.call_count == 1  # Handler not called again
        assert result.success is True
        assert result.output == "hello"

    @pytest.mark.asyncio
    async def test_cache_miss_calls_handler(self, registry: ToolRegistry, read_tool: str) -> None:
        handler = registry._handlers[read_tool]
        result = await registry.execute("run-1", read_tool, {"path": "/tmp/a"})
        assert handler.call_count == 1
        assert result.output == "hello"

    @pytest.mark.asyncio
    async def test_uncacheable_tool_no_cache(self, registry: ToolRegistry, write_tool: str) -> None:
        handler = registry._handlers[write_tool]
        await registry.execute("run-1", write_tool, {"path": "/tmp/a", "content": "x"})
        await registry.execute("run-1", write_tool, {"path": "/tmp/a", "content": "x"})
        # write_tool is not cacheable → handler called every time
        assert handler.call_count == 2

    @pytest.mark.asyncio
    async def test_failed_result_not_cached(self, registry: ToolRegistry) -> None:
        spec = ToolSpec(name="fail_tool", description="Fails", parameters=[], read_only=True)
        handler = AsyncMock(return_value=ToolResult(success=False, error="boom"))
        registry.register(spec, handler)

        await registry.execute("run-1", "fail_tool", {})
        await registry.execute("run-1", "fail_tool", {})
        assert handler.call_count == 2  # Not cached because it failed

    @pytest.mark.asyncio
    async def test_different_args_separate_cache(self, registry: ToolRegistry, read_tool: str) -> None:
        handler = registry._handlers[read_tool]
        await registry.execute("run-1", read_tool, {"path": "/tmp/a"})
        await registry.execute("run-1", read_tool, {"path": "/tmp/b"})
        assert handler.call_count == 2


# ---------------------------------------------------------------------------
# Cache stats
# ---------------------------------------------------------------------------


class TestCacheStats:
    def test_stats_reflects_call_count(self, registry: ToolRegistry, read_tool: str) -> None:
        # Call count is incremented during execute() only
        assert registry.get_stats().get(read_tool, 0) == 0
