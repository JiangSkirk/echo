"""Tests for search engines."""

import pytest

from js.search.engines import DuckDuckGoEngine, SearchManager, SearchResult


class TestDuckDuckGoEngine:
    @pytest.fixture
    def engine(self) -> DuckDuckGoEngine:
        return DuckDuckGoEngine(timeout=2.0)

    @pytest.mark.asyncio
    async def test_health_check(self, engine: DuckDuckGoEngine) -> None:
        try:
            result = await engine.health_check()
            assert isinstance(result, bool)
        finally:
            await engine.close()

    @pytest.mark.asyncio
    async def test_search(self, engine: DuckDuckGoEngine) -> None:
        try:
            results = await engine.search("Python programming", max_results=3)
            # May fail in CI, check structure
            assert isinstance(results, list)
            for r in results:
                assert r.title
                assert r.url
        finally:
            await engine.close()

    def test_parse_html_standard_layout(self, engine: DuckDuckGoEngine) -> None:
        html = """
        <div class="result results_links_deep highlight_a">
            <a href="https://example.com/page1" class="result__a">Example Page Title</a>
            <div class="result__snippet">This is a detailed snippet about the page.</div>
        </div>
        <div class="result">
            <a href="https://example.org/page2">Another Page</a>
            <div class="result__snippet">Another snippet with sufficient length.</div>
        </div>
        """
        results = engine._parse_html(html, 5)
        assert len(results) == 2
        assert results[0].title == "Example Page Title"
        assert results[0].url == "https://example.com/page1"
        assert "detailed snippet" in results[0].snippet
        assert results[1].title == "Another Page"

    def test_parse_html_lite_layout(self, engine: DuckDuckGoEngine) -> None:
        """Lite layout spreads each result across multiple <tr> rows."""
        html = """
        <table>
        <tr><td class="result-snippet"><a href="https://lite1.com">Lite Result 1</a></td></tr>
        <tr><td class="result-snippet">Description for result one is quite long and detailed.</td></tr>
        <tr><td class="result-snippet"><a href="https://lite2.com">Lite Result 2</a></td></tr>
        <tr><td class="result-snippet">Description for result two is also very long.</td></tr>
        </table>
        """
        results = engine._parse_html(html, 5)
        assert len(results) == 2
        assert results[0].title == "Lite Result 1"
        assert "Description for result one" in results[0].snippet
        assert results[1].title == "Lite Result 2"
        assert "Description for result two" in results[1].snippet

    def test_parse_html_skips_internal_links(self, engine: DuckDuckGoEngine) -> None:
        html = """
        <div class="result">
            <a href="https://duckduckgo.com/l/?uddg=...">Redirect</a>
        </div>
        <div class="result">
            <a href="https://real-site.com/article">Real Article</a>
            <span>Real description here that is long enough.</span>
        </div>
        """
        results = engine._parse_html(html, 5)
        assert len(results) == 1
        assert results[0].title == "Real Article"

    def test_parse_html_empty(self, engine: DuckDuckGoEngine) -> None:
        assert engine._parse_html("", 5) == []
        assert engine._parse_html("<html><body><h1>No results</h1></body></html>", 5) == []

    def test_parse_html_respects_max_results(self, engine: DuckDuckGoEngine) -> None:
        html = """
        <div class="result"><a href="https://a.com">A</a><span>Desc A is long enough.</span></div>
        <div class="result"><a href="https://b.com">B</a><span>Desc B is long enough.</span></div>
        <div class="result"><a href="https://c.com">C</a><span>Desc C is long enough.</span></div>
        """
        results = engine._parse_html(html, 2)
        assert len(results) == 2

    @pytest.mark.asyncio
    async def test_search_manager_closes_engines(self) -> None:
        manager = SearchManager()
        engine = DuckDuckGoEngine(timeout=2.0)
        manager.register(engine, default=True)
        await manager.close()


class TestSearchManager:
    def test_fallback(self) -> None:
        manager = SearchManager()
        manager.register(DuckDuckGoEngine(timeout=2.0), default=True)
        assert manager._default is not None

    def test_fallback_empty_results_from_first_engine(self) -> None:
        """If first engine returns [] (success but no results), fallback to next."""

        class EmptyEngine:
            async def search(self, query: str, max_results: int = 5) -> list[SearchResult]:
                return []

            async def health_check(self) -> bool:
                return True

            async def close(self) -> None:
                pass

        class RealEngine:
            async def search(self, query: str, max_results: int = 5) -> list[SearchResult]:
                return [SearchResult(title="Test", url="https://test.com", snippet="snippet", source="test")]

            async def health_check(self) -> bool:
                return True

            async def close(self) -> None:
                pass

        manager = SearchManager()
        manager.register(EmptyEngine())  # type: ignore[arg-type]
        manager.register(RealEngine())  # type: ignore[arg-type]

        import asyncio

        async def _run() -> list[SearchResult]:
            return await manager.search("query")

        results = asyncio.run(_run())
        assert len(results) == 1
        assert results[0].title == "Test"
