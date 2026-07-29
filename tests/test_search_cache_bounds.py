"""F-06: SearchCache must be bounded LRU+TTL with query/max_results guards."""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError

import pytest

from js.search.engines import SearchCache, SearchManager, SearchResult, validate_search_max_results


def _results(n: int = 1) -> list[SearchResult]:
    return [
        SearchResult(title=f"t{i}", url=f"https://example.com/{i}", snippet="s", source="test")
        for i in range(n)
    ]


def test_lru_evicts_oldest_when_at_capacity() -> None:
    cache = SearchCache(ttl_seconds=60.0, max_entries=2)
    cache.set("a", 5, _results())
    cache.set("b", 5, _results())
    cache.set("c", 5, _results())
    assert cache.get("a", 5) is None
    assert cache.get("b", 5) is not None
    assert cache.get("c", 5) is not None
    assert cache.size() <= 2


def test_lru_promotes_on_access_before_eviction() -> None:
    """After get(), the accessed key is newest and must survive the next insert."""
    cache = SearchCache(ttl_seconds=60.0, max_entries=2)
    cache.set("a", 5, _results())
    cache.set("b", 5, _results())
    assert cache.get("a", 5) is not None  # promote a over b
    cache.set("c", 5, _results())
    assert cache.get("b", 5) is None
    assert cache.get("a", 5) is not None
    assert cache.get("c", 5) is not None


def test_ttl_expires_on_get_and_set() -> None:
    cache = SearchCache(ttl_seconds=0.05, max_entries=10)
    cache.set("q", 3, _results())
    time.sleep(0.08)
    assert cache.get("q", 3) is None
    cache.set("fresh", 3, _results())
    assert cache.size() == 1


def test_ttl_uses_monotonic_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    mono = {"now": 1000.0}
    monkeypatch.setattr(time, "monotonic", lambda: mono["now"])
    # Wall clock jumping must not drive TTL.
    monkeypatch.setattr(time, "time", lambda: 9_999_999.0)

    cache = SearchCache(ttl_seconds=10.0, max_entries=5)
    cache.set("q", 3, _results())
    mono["now"] = 1005.0
    assert cache.get("q", 3) is not None
    mono["now"] = 1010.0  # age == ttl → expired
    assert cache.get("q", 3) is None


def test_ttl_expires_at_exact_age_boundary(monkeypatch: pytest.MonkeyPatch) -> None:
    mono = {"now": 100.0}
    monkeypatch.setattr(time, "monotonic", lambda: mono["now"])
    cache = SearchCache(ttl_seconds=5.0, max_entries=5)
    cache.set("q", 3, _results())
    mono["now"] = 104.999
    assert cache.get("q", 3) is not None
    mono["now"] = 105.0
    assert cache.get("q", 3) is None


def test_ttl_seconds_rejects_bool_and_non_numeric() -> None:
    for bad in (True, False, "30", None):
        with pytest.raises(ValueError, match="ttl_seconds"):
            SearchCache(ttl_seconds=bad, max_entries=5)  # type: ignore[arg-type]


def test_duplicate_key_refreshes_without_growing() -> None:
    cache = SearchCache(ttl_seconds=60.0, max_entries=5)
    cache.set("same", 5, _results(1))
    cache.set("same", 5, _results(2))
    assert cache.size() == 1
    hit = cache.get("same", 5)
    assert hit is not None
    assert len(hit) == 2


def test_empty_results_are_cacheable() -> None:
    cache = SearchCache(ttl_seconds=60.0, max_entries=5)
    cache.set("empty", 5, [])
    assert cache.get("empty", 5) == []


def test_overlong_query_rejected() -> None:
    cache = SearchCache(ttl_seconds=60.0, max_entries=5, max_query_chars=16)
    with pytest.raises(ValueError, match="query"):
        cache.set("x" * 20, 5, _results())
    with pytest.raises(ValueError, match="query"):
        cache.get("x" * 20, 5)


def test_size_params_reject_bool_float_string() -> None:
    for bad in (True, 1.5, "8"):
        with pytest.raises(ValueError, match="max_entries"):
            SearchCache(ttl_seconds=60.0, max_entries=bad)  # type: ignore[arg-type]
        with pytest.raises(ValueError, match="max_query_chars"):
            SearchCache(ttl_seconds=60.0, max_entries=5, max_query_chars=bad)  # type: ignore[arg-type]
        with pytest.raises(ValueError, match="max_results"):
            validate_search_max_results(bad)


def test_mutating_returned_results_does_not_poison_cache() -> None:
    cache = SearchCache(ttl_seconds=60.0, max_entries=5)
    original = _results(1)
    cache.set("q", 5, original)
    original.clear()  # mutating the caller's list must not affect the cache

    hit = cache.get("q", 5)
    assert hit is not None
    assert len(hit) == 1
    assert hit[0].title == "t0"

    with pytest.raises(FrozenInstanceError):
        hit[0].title = "poisoned"  # type: ignore[misc]

    hit.clear()
    hit.append(SearchResult(title="x", url="u", snippet="s", source="t"))

    again = cache.get("q", 5)
    assert again is not None
    assert len(again) == 1
    assert again[0].title == "t0"


@pytest.mark.asyncio
async def test_manager_validates_max_results_range() -> None:
    manager = SearchManager(cache_ttl=60.0, cache_max_entries=8)

    class _Stub:
        async def search(self, query: str, max_results: int = 5) -> list[SearchResult]:
            return _results(max_results)

        async def health_check(self) -> bool:
            return True

        async def close(self) -> None:
            return None

    manager.register(_Stub())  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="max_results"):
        await manager.search("ok", max_results=11)
    with pytest.raises(ValueError, match="query"):
        await manager.search("q" * 2000, max_results=5)
    out = await manager.search("ok", max_results=3)
    assert len(out) == 3


def test_concurrent_set_get_keeps_structure() -> None:
    cache = SearchCache(ttl_seconds=60.0, max_entries=50)
    errors: list[BaseException] = []

    def worker(i: int) -> None:
        try:
            for j in range(20):
                cache.set(f"q-{i}-{j % 5}", 5, _results())
                cache.get(f"q-{i}-{j % 5}", 5)
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(worker, range(8)))
    assert not errors
    assert cache.size() <= 50
