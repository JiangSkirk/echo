"""Tests for search engines."""

from unittest.mock import AsyncMock

import httpx
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
        except RuntimeError:
            # Network failure in CI is acceptable; engines now raise on failure
            pytest.skip("DuckDuckGo unavailable in this environment")
        finally:
            await engine.close()

    @pytest.mark.asyncio
    async def test_fixed_search_endpoint_is_resolved_and_connection_pinned(
        self,
        engine: DuckDuckGoEngine,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        resolved_urls: list[str] = []

        def resolve(url: str, **_kwargs):
            resolved_urls.append(url)
            return ["93.184.216.34"]

        response = httpx.Response(
            200,
            text="<html></html>",
            request=httpx.Request("GET", "https://lite.duckduckgo.com/lite/"),
        )
        monkeypatch.setattr("js.search.engines.resolve_and_validate", resolve)
        monkeypatch.setattr("js.search.engines.asyncio.sleep", AsyncMock())
        monkeypatch.setattr("httpx.AsyncClient.get", AsyncMock(return_value=response))

        try:
            await engine._search_via_lite("echo", 1)
        finally:
            await engine.close()

        assert resolved_urls == ["https://lite.duckduckgo.com/lite/"]

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

    def test_parse_html_decodes_duckduckgo_redirects(self, engine: DuckDuckGoEngine) -> None:
        html = """
        <div class="result">
            <a class="result__a" href="https://duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Farticle&amp;rut=abc">
                Redirected Result
            </a>
            <div class="result__snippet">Useful redirected result snippet.</div>
        </div>
        """
        results = engine._parse_html(html, 5)
        assert len(results) == 1
        assert results[0].title == "Redirected Result"
        assert results[0].url == "https://example.com/article"

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

    def test_empty_results_returned_directly(self) -> None:
        """A successful engine returning [] should return empty, not fallback."""

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
        assert len(results) == 0  # Empty results from successful engine are preserved

    def test_fallback_on_engine_exception(self) -> None:
        """If an engine throws an exception, fallback to the next engine."""

        class FailingEngine:
            async def search(self, query: str, max_results: int = 5) -> list[SearchResult]:
                raise RuntimeError("Engine down")

            async def health_check(self) -> bool:
                return False

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
        manager.register(FailingEngine())  # type: ignore[arg-type]
        manager.register(RealEngine())  # type: ignore[arg-type]

        import asyncio

        async def _run() -> list[SearchResult]:
            return await manager.search("query")

        results = asyncio.run(_run())
        assert len(results) == 1
        assert results[0].title == "Test"
