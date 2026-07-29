"""Tests for ToolRegistry result caching (TTL + LRU eviction)."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import pytest

from js.config import SecurityConfig, ToolLimits
from js.security.guard import BehaviorGuard
from js.tools.files import FileTools
from js.tools.registry import ToolExecutionContext, ToolRegistry, ToolResult, ToolSpec


@pytest.fixture
def registry(tmp_path: Path) -> ToolRegistry:
    limits = ToolLimits(max_concurrent_tools=4)
    guard = BehaviorGuard(SecurityConfig(), tmp_path)
    return ToolRegistry(limits, guard)


@pytest.fixture
def delete_enabled_registry(tmp_path: Path) -> ToolRegistry:
    limits = ToolLimits(max_concurrent_tools=4)
    guard = BehaviorGuard(SecurityConfig(allow_workspace_delete=True), tmp_path)
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

    def test_cache_key_isolated_by_owner_and_run(self, registry: ToolRegistry) -> None:
        def context(owner: str, run_id: str) -> ToolExecutionContext:
            return ToolExecutionContext(
                owner_key_hash=owner,
                run_id=run_id,
                tool_name="file_read",
                args_hash="args",
                fs_roots=("/workspace",),
                network_policy="deny",
                max_bytes=100,
                max_duration_ms=100,
                resource_scope="session:s1",
            )

        arguments = {"path": "shared.txt"}
        key_a = registry._cache_key("file_read", arguments, context("owner-a", "run-1"))
        key_b = registry._cache_key("file_read", arguments, context("owner-b", "run-1"))
        key_next_run = registry._cache_key(
            "file_read", arguments, context("owner-a", "run-2")
        )

        assert len({key_a, key_b, key_next_run}) == 3

    def test_cache_returns_a_copy(self, registry: ToolRegistry) -> None:
        key = ("file_read", "scope")
        registry._set_cached(key, ToolResult(success=True, output="safe", metadata={"x": 1}))

        first = registry._get_cached(key)
        assert first is not None
        first.output = "mutated"
        first.metadata["x"] = 2

        second = registry._get_cached(key)
        assert second is not None
        assert second.output == "safe"
        assert second.metadata == {"x": 1}


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

    def test_backward_wall_clock_cannot_extend_ttl(
        self, registry: ToolRegistry, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A clock rollback must not prolong a stale cached filesystem result."""
        key = ("file_read", '{"path":"/tmp/a"}')
        monotonic_now = 100.0
        wall_clock_now = 1_000_000.0
        monkeypatch.setattr("js.tools.registry.time.monotonic", lambda: monotonic_now)
        monkeypatch.setattr("js.tools.registry.time.time", lambda: wall_clock_now)
        registry._set_cached(key, ToolResult(success=True, output="old"))

        monotonic_now += registry._cache_ttl_seconds + 1.0
        wall_clock_now -= 86_400.0

        assert registry._get_cached(key) is None


async def _execute_echo_authorized(
    registry: ToolRegistry,
    echo_tool_context: Any,
    *,
    run_id: str,
    tool_name: str,
    arguments: dict[str, Any],
    fs_root: Path,
    owner_key_hash: str = "owner-a",
) -> ToolResult:
    """Run a tool through the signed Echo lease boundary used in production."""
    return await registry.execute(
        run_id,
        tool_name,
        arguments,
        execution_context=echo_tool_context(
            run_id=run_id,
            tool_name=tool_name,
            arguments=arguments,
            owner_key_hash=owner_key_hash,
            resource_scope="session-a",
            fs_roots=(str(fs_root),),
            registry=registry,
        ),
    )


def _register_file_tools(registry: ToolRegistry, workspace: Path) -> None:
    FileTools(workspace, registry.limits, registry.guard).register_all(registry)


# ---------------------------------------------------------------------------
# Filesystem mutations invalidate same-scope read results
# ---------------------------------------------------------------------------


class TestFilesystemMutationInvalidation:
    @pytest.mark.asyncio
    async def test_successful_write_refreshes_cached_read_list_and_search(
        self,
        registry: ToolRegistry,
        tmp_path: Path,
        echo_tool_context: Any,
    ) -> None:
        """Removing mutation invalidation would return the old bytes and directory metadata."""
        _register_file_tools(registry, tmp_path)
        (tmp_path / "a.txt").write_text("old", encoding="utf-8")

        for tool_name, arguments in (
            ("file_read", {"path": "a.txt"}),
            ("file_list", {"path": "."}),
            ("file_search", {"pattern": "*.txt", "path": "."}),
        ):
            result = await _execute_echo_authorized(
                registry,
                echo_tool_context,
                run_id="run-a",
                tool_name=tool_name,
                arguments=arguments,
                fs_root=tmp_path,
            )
            assert result.success is True

        mutation = await _execute_echo_authorized(
            registry,
            echo_tool_context,
            run_id="run-a",
            tool_name="file_write",
            arguments={"path": "a.txt", "content": "fresh value"},
            fs_root=tmp_path,
        )

        read = await _execute_echo_authorized(
            registry,
            echo_tool_context,
            run_id="run-a",
            tool_name="file_read",
            arguments={"path": "a.txt"},
            fs_root=tmp_path,
        )
        listed = await _execute_echo_authorized(
            registry,
            echo_tool_context,
            run_id="run-a",
            tool_name="file_list",
            arguments={"path": "."},
            fs_root=tmp_path,
        )
        searched = await _execute_echo_authorized(
            registry,
            echo_tool_context,
            run_id="run-a",
            tool_name="file_search",
            arguments={"pattern": "*.txt", "path": "."},
            fs_root=tmp_path,
        )

        assert mutation.success is True
        assert read.output == "fresh value"
        assert listed.output == "📄 a.txt (11 bytes)"
        assert searched.output == "a.txt"

    @pytest.mark.asyncio
    async def test_successful_delete_refreshes_cached_read_list_and_search(
        self,
        delete_enabled_registry: ToolRegistry,
        tmp_path: Path,
        echo_tool_context: Any,
    ) -> None:
        """Removing mutation invalidation would publish a deleted file as present."""
        registry = delete_enabled_registry
        _register_file_tools(registry, tmp_path)
        (tmp_path / "a.txt").write_text("old", encoding="utf-8")

        for tool_name, arguments in (
            ("file_read", {"path": "a.txt"}),
            ("file_list", {"path": "."}),
            ("file_search", {"pattern": "*.txt", "path": "."}),
        ):
            await _execute_echo_authorized(
                registry,
                echo_tool_context,
                run_id="run-a",
                tool_name=tool_name,
                arguments=arguments,
                fs_root=tmp_path,
            )

        deleted = await _execute_echo_authorized(
            registry,
            echo_tool_context,
            run_id="run-a",
            tool_name="file_delete",
            arguments={"path": "a.txt"},
            fs_root=tmp_path,
        )
        read = await _execute_echo_authorized(
            registry,
            echo_tool_context,
            run_id="run-a",
            tool_name="file_read",
            arguments={"path": "a.txt"},
            fs_root=tmp_path,
        )
        listed = await _execute_echo_authorized(
            registry,
            echo_tool_context,
            run_id="run-a",
            tool_name="file_list",
            arguments={"path": "."},
            fs_root=tmp_path,
        )
        searched = await _execute_echo_authorized(
            registry,
            echo_tool_context,
            run_id="run-a",
            tool_name="file_search",
            arguments={"pattern": "*.txt", "path": "."},
            fs_root=tmp_path,
        )

        assert deleted.success is True
        assert read.success is False
        assert listed.output == ""
        assert searched.output == "No matches found"

    @pytest.mark.asyncio
    async def test_successful_move_refreshes_cached_read_list_and_search(
        self,
        registry: ToolRegistry,
        tmp_path: Path,
        echo_tool_context: Any,
    ) -> None:
        """A future non-read-only file_move must invalidate read results too."""
        _register_file_tools(registry, tmp_path)
        (tmp_path / "a.txt").write_text("old", encoding="utf-8")

        async def move(source: str, destination: str) -> ToolResult:
            (tmp_path / source).replace(tmp_path / destination)
            return ToolResult(success=True, output="moved")

        registry.register(
            ToolSpec(
                name="file_move",
                description="Move a workspace file",
                parameters=[],
                dangerous=True,
            ),
            move,
        )
        for tool_name, arguments in (
            ("file_read", {"path": "a.txt"}),
            ("file_list", {"path": "."}),
            ("file_search", {"pattern": "*.txt", "path": "."}),
        ):
            await _execute_echo_authorized(
                registry,
                echo_tool_context,
                run_id="run-a",
                tool_name=tool_name,
                arguments=arguments,
                fs_root=tmp_path,
            )

        moved = await _execute_echo_authorized(
            registry,
            echo_tool_context,
            run_id="run-a",
            tool_name="file_move",
            arguments={"source": "a.txt", "destination": "b.txt"},
            fs_root=tmp_path,
        )
        read = await _execute_echo_authorized(
            registry,
            echo_tool_context,
            run_id="run-a",
            tool_name="file_read",
            arguments={"path": "a.txt"},
            fs_root=tmp_path,
        )
        listed = await _execute_echo_authorized(
            registry,
            echo_tool_context,
            run_id="run-a",
            tool_name="file_list",
            arguments={"path": "."},
            fs_root=tmp_path,
        )
        searched = await _execute_echo_authorized(
            registry,
            echo_tool_context,
            run_id="run-a",
            tool_name="file_search",
            arguments={"pattern": "*.txt", "path": "."},
            fs_root=tmp_path,
        )

        assert moved.success is True
        assert read.success is False
        assert listed.output == "📄 b.txt (3 bytes)"
        assert searched.output == "b.txt"

    @pytest.mark.asyncio
    async def test_failed_mutation_keeps_current_same_scope_read_result(
        self, registry: ToolRegistry, echo_tool_context: Any, tmp_path: Path
    ) -> None:
        """A failed mutation must not publish a new or stale read result."""
        reads = 0

        async def read(path: str) -> ToolResult:
            nonlocal reads
            reads += 1
            return ToolResult(success=True, output=f"current:{path}")

        async def fail_write(path: str) -> ToolResult:
            return ToolResult(success=False, error=f"cannot write {path}")

        registry.register(ToolSpec("file_read", "read", [], read_only=True), read)
        registry.register(ToolSpec("file_write", "write", []), fail_write)
        arguments = {"path": "a.txt"}
        first = await _execute_echo_authorized(
            registry,
            echo_tool_context,
            run_id="run-a",
            tool_name="file_read",
            arguments=arguments,
            fs_root=tmp_path,
        )
        failed = await _execute_echo_authorized(
            registry,
            echo_tool_context,
            run_id="run-a",
            tool_name="file_write",
            arguments=arguments,
            fs_root=tmp_path,
        )
        second = await _execute_echo_authorized(
            registry,
            echo_tool_context,
            run_id="run-a",
            tool_name="file_read",
            arguments=arguments,
            fs_root=tmp_path,
        )

        assert first.output == "current:a.txt"
        assert failed.success is False
        assert second.output == "current:a.txt"
        assert reads == 1

    @pytest.mark.asyncio
    async def test_mutation_does_not_share_or_clear_another_owner_or_run_cache(
        self, registry: ToolRegistry, echo_tool_context: Any, tmp_path: Path
    ) -> None:
        """Invalidation is scoped; another owner or run cannot reuse this run's result."""
        reads: dict[tuple[str, str], int] = {}

        async def read(path: str) -> ToolResult:
            from js.tools.registry import current_tool_execution_context

            context = current_tool_execution_context()
            assert context is not None
            scope = (context.owner_key_hash, context.run_id)
            reads[scope] = reads.get(scope, 0) + 1
            return ToolResult(success=True, output=f"{scope[0]}:{scope[1]}:{reads[scope]}:{path}")

        async def write(path: str) -> ToolResult:
            return ToolResult(success=True, output=f"wrote:{path}")

        registry.register(ToolSpec("file_read", "read", [], read_only=True), read)
        registry.register(ToolSpec("file_write", "write", []), write)
        arguments = {"path": "a.txt"}
        owner_a = await _execute_echo_authorized(
            registry,
            echo_tool_context,
            run_id="run-a",
            tool_name="file_read",
            arguments=arguments,
            fs_root=tmp_path,
            owner_key_hash="owner-a",
        )
        owner_b = await _execute_echo_authorized(
            registry,
            echo_tool_context,
            run_id="run-b",
            tool_name="file_read",
            arguments=arguments,
            fs_root=tmp_path,
            owner_key_hash="owner-b",
        )
        mutation = await _execute_echo_authorized(
            registry,
            echo_tool_context,
            run_id="run-a",
            tool_name="file_write",
            arguments=arguments,
            fs_root=tmp_path,
            owner_key_hash="owner-a",
        )
        owner_b_again = await _execute_echo_authorized(
            registry,
            echo_tool_context,
            run_id="run-b",
            tool_name="file_read",
            arguments=arguments,
            fs_root=tmp_path,
            owner_key_hash="owner-b",
        )

        assert owner_a.output == "owner-a:run-a:1:a.txt"
        assert owner_b.output == "owner-b:run-b:1:a.txt"
        assert mutation.success is True
        assert owner_b_again.output == "owner-b:run-b:1:a.txt"


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
    async def test_cache_hit_skips_handler(
        self, registry: ToolRegistry, read_tool: str, echo_tool_context: Any
    ) -> None:
        handler = registry._handlers[read_tool]
        arguments = {"path": "/tmp/a"}
        # Prime cache
        await registry.execute(
            "run-1",
            read_tool,
            arguments,
            execution_context=echo_tool_context(
                run_id="run-1",
                tool_name=read_tool,
                arguments=arguments,
                fs_roots=("/tmp",),
                registry=registry,
            ),
        )
        assert handler.call_count == 1

        # Second call — cache hit
        result = await registry.execute(
            "run-1",
            read_tool,
            arguments,
            execution_context=echo_tool_context(
                run_id="run-1",
                tool_name=read_tool,
                arguments=arguments,
                fs_roots=("/tmp",),
                registry=registry,
            ),
        )
        assert handler.call_count == 1  # Handler not called again
        assert result.success is True
        assert result.output == "hello"

    @pytest.mark.asyncio
    async def test_cache_miss_calls_handler(
        self, registry: ToolRegistry, read_tool: str, echo_tool_context: Any
    ) -> None:
        handler = registry._handlers[read_tool]
        arguments = {"path": "/tmp/a"}
        result = await registry.execute(
            "run-1",
            read_tool,
            arguments,
            execution_context=echo_tool_context(
                run_id="run-1",
                tool_name=read_tool,
                arguments=arguments,
                fs_roots=("/tmp",),
                registry=registry,
            ),
        )
        assert handler.call_count == 1
        assert result.output == "hello"

    @pytest.mark.asyncio
    async def test_uncacheable_tool_no_cache(
        self, registry: ToolRegistry, write_tool: str, echo_tool_context: Any
    ) -> None:
        handler = registry._handlers[write_tool]
        arguments = {"path": "/tmp/a", "content": "x"}
        for _ in range(2):
            await registry.execute(
                "run-1",
                write_tool,
                arguments,
                execution_context=echo_tool_context(
                    run_id="run-1",
                    tool_name=write_tool,
                    arguments=arguments,
                    fs_roots=("/tmp",),
                    registry=registry,
                ),
            )
        # write_tool is not cacheable → handler called every time
        assert handler.call_count == 2

    @pytest.mark.asyncio
    async def test_failed_result_not_cached(
        self, registry: ToolRegistry, echo_tool_context: Any
    ) -> None:
        spec = ToolSpec(name="fail_tool", description="Fails", parameters=[], read_only=True)
        handler = AsyncMock(return_value=ToolResult(success=False, error="boom"))
        registry.register(spec, handler)

        for _ in range(2):
            await registry.execute(
                "run-1",
                "fail_tool",
                {},
                execution_context=echo_tool_context(
                    run_id="run-1",
                    tool_name="fail_tool",
                    arguments={},
                    fs_roots=("/tmp",),
                    registry=registry,
                ),
            )
        assert handler.call_count == 2  # Not cached because it failed

    @pytest.mark.asyncio
    async def test_different_args_separate_cache(
        self, registry: ToolRegistry, read_tool: str, echo_tool_context: Any
    ) -> None:
        handler = registry._handlers[read_tool]
        for arguments in ({"path": "/tmp/a"}, {"path": "/tmp/b"}):
            await registry.execute(
                "run-1",
                read_tool,
                arguments,
                execution_context=echo_tool_context(
                    run_id="run-1",
                    tool_name=read_tool,
                    arguments=arguments,
                    fs_roots=("/tmp",),
                    registry=registry,
                ),
            )
        assert handler.call_count == 2


# ---------------------------------------------------------------------------
# Cache stats
# ---------------------------------------------------------------------------


class TestCacheStats:
    def test_stats_reflects_call_count(self, registry: ToolRegistry, read_tool: str) -> None:
        # Call count is incremented during execute() only
        assert registry.get_stats().get(read_tool, 0) == 0
