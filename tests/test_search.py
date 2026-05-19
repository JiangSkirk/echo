"""Tests for search engines."""

import pytest

from js.search.engines import DuckDuckGoEngine, SearchManager


class TestDuckDuckGoEngine:
    @pytest.fixture
    def engine(self) -> DuckDuckGoEngine:
        return DuckDuckGoEngine(timeout=10.0)

    @pytest.mark.asyncio
    async def test_health_check(self, engine: DuckDuckGoEngine) -> None:
        result = await engine.health_check()
        assert isinstance(result, bool)

    @pytest.mark.asyncio
    async def test_search(self, engine: DuckDuckGoEngine) -> None:
        results = await engine.search("Python programming", max_results=3)
        # May fail in CI, check structure
        assert isinstance(results, list)
        for r in results:
            assert r.title
            assert r.url


class TestSearchManager:
    def test_fallback(self) -> None:
        manager = SearchManager()
        manager.register(DuckDuckGoEngine(), default=True)
        assert manager._default is not None
