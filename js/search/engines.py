"""Search engines with unified interface."""

from __future__ import annotations

import asyncio
import html as html_module
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from urllib.parse import parse_qs, unquote, urlparse

import httpx

from js.utils.log import get_logger
from js.utils.metrics import get_metrics

logger = get_logger("js.search")


@dataclass
class SearchResult:
    title: str
    url: str
    snippet: str
    source: str


class SearchEngine(ABC):
    """Abstract base for search engines."""

    @abstractmethod
    async def search(self, query: str, max_results: int = 5) -> list[SearchResult]:
        ...

    @abstractmethod
    async def health_check(self) -> bool:
        ...


class DuckDuckGoEngine(SearchEngine):
    """DuckDuckGo search via html interface (no API key required)."""

    _USER_AGENT = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )

    def __init__(self, timeout: float = 15.0) -> None:
        self.timeout = timeout
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(timeout),
            follow_redirects=True,
            headers={"User-Agent": self._USER_AGENT},
        )

    async def close(self) -> None:
        await self._client.aclose()

    async def search(self, query: str, max_results: int = 5) -> list[SearchResult]:
        await asyncio.sleep(1)  # Rate-limit delay

        for attempt in range(3):  # initial + 2 retries
            try:
                resp = await self._client.get(
                    "https://html.duckduckgo.com/html/",
                    params={"q": query},
                )
                if resp.status_code == 200:
                    return self._parse_html(resp.text, max_results)

                # Do not retry permanent client errors (except 429 Too Many Requests)
                if 400 <= resp.status_code < 500 and resp.status_code != 429:
                    logger.warning(
                        f"DuckDuckGo returned {resp.status_code}, not retrying"
                    )
                    break

                logger.warning(
                    f"DuckDuckGo returned {resp.status_code}, "
                    f"attempt {attempt + 1}/3"
                )
            except Exception as e:
                logger.warning(
                    f"DuckDuckGo request failed: {type(e).__name__}: {e}, "
                    f"attempt {attempt + 1}/3"
                )

            if attempt < 2:
                await asyncio.sleep(2 ** attempt)  # 1s, 2s exponential backoff

        # Fallback to DuckDuckGo Lite
        lite_results = await self._search_via_lite(query, max_results)
        if lite_results:
            return lite_results
        raise RuntimeError("DuckDuckGo search failed after all retries")

    async def _search_via_lite(self, query: str, max_results: int) -> list[SearchResult]:
        """Fallback using DuckDuckGo Lite."""
        await asyncio.sleep(1)
        try:
            resp = await self._client.get(
                "https://lite.duckduckgo.com/lite/",
                params={"q": query},
            )
            if resp.status_code != 200:
                logger.warning(f"DuckDuckGo Lite returned {resp.status_code}")
                raise RuntimeError(f"DuckDuckGo Lite returned {resp.status_code}")
            return self._parse_html(resp.text, max_results)
        except Exception as e:
            logger.error(
                f"DuckDuckGo lite fallback failed: {type(e).__name__}: {e}"
            )
            raise RuntimeError(f"DuckDuckGo search failed: {e}") from e

    def _parse_html(self, html: str, max_results: int) -> list[SearchResult]:
        import re
        results: list[SearchResult] = []

        # Remove scripts and styles to avoid false matches
        html = re.sub(r"<(script|style)[^>]*>.*?</\1>", "", html, flags=re.S | re.I)

        # Strategy 1: Find result blocks: <div> containers whose class attribute
        # starts with the word "result" (e.g. "result", "result results_links").
        block_starts = [
            m.start()
            for m in re.finditer(
                r'<div[^>]*class="(?:[^"]*\s)?result(?:\s[^"]*)?"[^>]*>',
                html,
                re.I,
            )
        ]

        # Strategy 2: If no result blocks found, try table-row layout (lite/mobile).
        # In Lite mode each result spans multiple <tr> rows (title, snippet, ...).
        # We merge consecutive <tr> rows until the next one that contains an
        # external link, which signals the start of a new result.
        if not block_starts:
            tr_starts = [m.start() for m in re.finditer(r"<tr[^>]*>", html, re.I)]
            merged: list[int] = []
            idx = 0
            while idx < len(tr_starts):
                s = tr_starts[idx]
                e = tr_starts[idx + 1] if idx + 1 < len(tr_starts) else len(html)
                row = html[s:e]
                has_link = any(
                    u.startswith("http") and "duckduckgo.com" not in u
                    for m2 in re.finditer(r'<a[^>]*href="([^"]+)"[^>]*>.*?</a>', row, re.S)
                    for u in [m2.group(1)]
                )
                if has_link:
                    merged.append(s)
                    idx += 1
                elif merged:
                    # Belongs to previous result — extend its end boundary
                    idx += 1
                else:
                    idx += 1
            block_starts = merged

        # Strategy 3: If still no blocks, try generic article/section containers
        if not block_starts:
            block_starts = [
                m.start()
                for m in re.finditer(
                    r"<article[^>]*>|<section[^>]*>",
                    html,
                    re.I,
                )
            ]

        for i, start in enumerate(block_starts):
            end = block_starts[i + 1] if i + 1 < len(block_starts) else len(html)
            block = html[start:end]

            # Within each block, pick the first <a> tag that points to an
            # external URL (skip internal DuckDuckGo navigation links).
            for link_match in re.finditer(
                r'<a[^>]*href="([^"]+)"[^>]*>(.*?)</a>', block, re.S
            ):
                url = self._normalize_result_url(link_match.group(1))
                title = re.sub(r"<[^>]+>", "", link_match.group(2)).strip()
                title = html_module.unescape(title)

                if not url.startswith("http") or "duckduckgo.com" in url or not title:
                    continue

                # Snippet: first substantial text chunk after the title link
                after = block[link_match.end() :]
                snippet = ""
                for text_match in re.finditer(r">([^<]{10,})<", after, re.S):
                    candidate = re.sub(r"<[^>]+>", "", text_match.group(1)).strip()
                    candidate = html_module.unescape(candidate)
                    if candidate and candidate != title:
                        snippet = candidate
                        break

                results.append(
                    SearchResult(
                        title=title,
                        url=url,
                        snippet=snippet,
                        source="duckduckgo",
                    )
                )
                break  # Only one result per block

            if len(results) >= max_results:
                break

        return results

    @staticmethod
    def _normalize_result_url(raw_url: str) -> str:
        """Return the external target URL from direct or DuckDuckGo redirect links."""
        url = html_module.unescape(raw_url)
        parsed = urlparse(url)

        # DuckDuckGo HTML commonly wraps outbound links as /l/?uddg=<encoded-url>.
        # Decode those so real search results are not mistaken for internal links.
        if parsed.path.startswith("/l/") or parsed.netloc.endswith("duckduckgo.com"):
            target = parse_qs(parsed.query).get("uddg", [""])[0]
            if target:
                return unquote(target)
        return url

    async def health_check(self) -> bool:
        try:
            resp = await self._client.get("https://duckduckgo.com", timeout=5.0)
            return resp.status_code == 200
        except Exception:
            return False


class TavilyEngine(SearchEngine):
    """Tavily AI search (requires API key, higher quality)."""

    def __init__(self, api_key: str, timeout: float = 15.0) -> None:
        self.api_key = api_key
        self.timeout = timeout
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(timeout),
            headers={"Authorization": f"Bearer {api_key}"},
        )

    async def close(self) -> None:
        await self._client.aclose()

    async def search(self, query: str, max_results: int = 5) -> list[SearchResult]:
        try:
            try:
                get_metrics().search_requests_total.labels(engine="tavily").inc()
            except Exception:
                logger.warning('Operation failed', exc_info=True)
            resp = await self._client.post(
                "https://api.tavily.com/search",
                json={
                    "query": query,
                    "max_results": max_results,
                    "search_depth": "basic",
                    "include_answer": False,
                },
            )
            resp.raise_for_status()
            data = resp.json()
            results: list[SearchResult] = []
            for r in data.get("results", []):
                results.append(SearchResult(
                    title=r.get("title", ""),
                    url=r.get("url", ""),
                    snippet=r.get("content", ""),
                    source="tavily",
                ))
            return results
        except Exception as e:
            logger.error(f"Tavily search failed: {e}")
            raise RuntimeError(f"Tavily search failed: {e}") from e

    async def health_check(self) -> bool:
        try:
            resp = await self._client.post(
                "https://api.tavily.com/search",
                json={"query": "test", "max_results": 1},
                timeout=5.0,
            )
            return resp.status_code == 200
        except Exception:
            return False


class SerperEngine(SearchEngine):
    """Serper.dev Google search (requires API key)."""

    def __init__(self, api_key: str, timeout: float = 15.0) -> None:
        self.api_key = api_key
        self.timeout = timeout
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(timeout),
            headers={"X-API-KEY": api_key, "Content-Type": "application/json"},
        )

    async def close(self) -> None:
        await self._client.aclose()

    async def search(self, query: str, max_results: int = 5) -> list[SearchResult]:
        try:
            try:
                get_metrics().search_requests_total.labels(engine="serper").inc()
            except Exception:
                logger.warning('Operation failed', exc_info=True)
            resp = await self._client.post(
                "https://google.serper.dev/search",
                json={"q": query, "num": max_results},
            )
            resp.raise_for_status()
            data = resp.json()
            results: list[SearchResult] = []
            for r in data.get("organic", []):
                results.append(SearchResult(
                    title=r.get("title", ""),
                    url=r.get("link", ""),
                    snippet=r.get("snippet", ""),
                    source="serper",
                ))
            return results
        except Exception as e:
            logger.error(f"Serper search failed: {e}")
            raise RuntimeError(f"Serper search failed: {e}") from e

    async def health_check(self) -> bool:
        try:
            resp = await self._client.post(
                "https://google.serper.dev/search",
                json={"q": "test", "num": 1},
                timeout=5.0,
            )
            return resp.status_code == 200
        except Exception:
            return False


class BingEngine(SearchEngine):
    """Bing web search fallback (no API key required)."""

    _USER_AGENT = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )

    def __init__(self, timeout: float = 15.0) -> None:
        self.timeout = timeout
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(timeout),
            follow_redirects=True,
            headers={
                "User-Agent": self._USER_AGENT,
                "Accept-Language": "en-US,en;q=0.9",
            },
        )

    async def close(self) -> None:
        await self._client.aclose()

    async def search(self, query: str, max_results: int = 5) -> list[SearchResult]:
        # Prioritize cn.bing.com for China-region users; fall back to www.bing.com
        for domain in ("https://cn.bing.com", "https://www.bing.com"):
            for attempt in range(2):
                try:
                    resp = await self._client.get(
                        f"{domain}/search",
                        params={"q": query},
                        headers={
                            "User-Agent": self._USER_AGENT,
                            "Accept-Language": "zh-CN,zh;q=0.9",
                        },
                    )
                    if resp.status_code == 200:
                        parsed = self._parse_html(resp.text, max_results)
                        # Sanity check: if all results are from unrelated domains, try fallback
                        if parsed and not all(
                            any(bad in r.url for bad in ("minhaconexao", "speedtest", "bilibili.com"))
                            for r in parsed
                        ):
                            return parsed
                        logger.warning(f"Bing ({domain}) returned suspicious results, trying fallback")
                    else:
                        logger.warning(f"Bing ({domain}) returned {resp.status_code}, attempt {attempt + 1}/2")
                except Exception as e:
                    logger.warning(f"Bing ({domain}) request failed: {type(e).__name__}: {e}, attempt {attempt + 1}/2")
                if attempt < 1:
                    await asyncio.sleep(2)
        raise RuntimeError("Bing search failed")

    def _parse_html(self, html: str, max_results: int) -> list[SearchResult]:
        import re
        results: list[SearchResult] = []
        html = re.sub(r"<(script|style)[^>]*>.*?</\1>", "", html, flags=re.S | re.I)
        # Bing results: <li class="b_algo"> containers
        for block in re.findall(r'<li class="b_algo"[^>]*>(.*?)</li>', html, re.S | re.I):
            # Skip blocks that contain only stylesheets/icons (no real result)
            if block.count("<link ") > block.count("<a "):
                continue
            title_match = re.search(r'<h2[^>]*>.*?<a[^>]+href="([^"]+)"[^>]*>(.*?)</a>.*?</h2>', block, re.S | re.I)
            if not title_match:
                continue
            url = html_module.unescape(title_match.group(1))
            # Skip Bing internal / redirect URLs
            if url.startswith("/") or "bing.com" in url.lower():
                continue
            title = re.sub(r"<[^>]+>", "", title_match.group(2))
            snippet_match = re.search(r'<p[^>]*>(.*?)</p>', block, re.S | re.I)
            snippet = re.sub(r"<[^>]+>", "", snippet_match.group(1)) if snippet_match else ""
            if url and title:
                results.append(SearchResult(title=title.strip(), url=url, snippet=snippet.strip(), source="bing"))
            if len(results) >= max_results:
                break
        return results

    async def health_check(self) -> bool:
        try:
            resp = await self._client.get("https://cn.bing.com", timeout=5.0)
            return resp.status_code == 200
        except Exception:
            return False


class SearchCache:
    """Simple in-memory TTL cache for search results."""

    def __init__(self, ttl_seconds: float = 300.0) -> None:
        self._ttl = ttl_seconds
        self._store: dict[str, tuple[list[SearchResult], float]] = {}

    def _key(self, query: str, max_results: int) -> str:
        return f"{query.lower().strip()}:{max_results}"

    def get(self, query: str, max_results: int) -> list[SearchResult] | None:
        key = self._key(query, max_results)
        entry = self._store.get(key)
        if entry is None:
            return None
        results, timestamp = entry
        if time.time() - timestamp > self._ttl:
            self._store.pop(key, None)
            return None
        return results

    def set(self, query: str, max_results: int, results: list[SearchResult]) -> None:
        self._store[self._key(query, max_results)] = (results, time.time())

    def clear(self) -> None:
        self._store.clear()


class SearchManager:
    """Manages multiple search engines with fallback and caching."""

    def __init__(self, cache_ttl: float = 300.0) -> None:
        self.engines: list[SearchEngine] = []
        self._default: SearchEngine | None = None
        self._cache = SearchCache(ttl_seconds=cache_ttl)

    def register(self, engine: SearchEngine, default: bool = False) -> None:
        self.engines.append(engine)
        if default or self._default is None:
            self._default = engine

    async def close(self) -> None:
        for engine in self.engines:
            close_method = getattr(engine, "close", None)
            if close_method:
                await close_method()
        self._cache.clear()

    async def search(self, query: str, max_results: int = 5) -> list[SearchResult]:
        """Search with caching and fallback across all engines."""
        # Check cache first
        cached = self._cache.get(query, max_results)
        if cached is not None:
            logger.debug(f"Search cache hit for query: {query[:40]}")
            return cached

        errors: list[str] = []
        for engine in self.engines:
            try:
                results = await engine.search(query, max_results)
                # Cache and return even empty results — a legitimate empty result
                # is different from an engine failure. Only fallback on exception.
                self._cache.set(query, max_results, results)
                return results
            except Exception as e:
                errors.append(f"{type(engine).__name__}: {e}")

        logger.error(f"All search engines failed: {errors}")
        return []

    async def health_check(self) -> dict[str, bool]:
        return {
            type(e).__name__: await e.health_check()
            for e in self.engines
        }
