"""Tests for ClawHub registry client."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from js.skills.clawhub import ClawHubClient

_INDEX_URL = "https://raw.githubusercontent.com/example/skills/main/clawhub.json"


class TestClawHubClient:
    @pytest.fixture(autouse=True)
    def _no_live_dns(self) -> Any:
        with (
            patch(
                "js.skills.clawhub.resolve_and_validate",
                return_value=["203.0.113.10"],
            ),
            patch(
                "js.skills.clawhub.current_tool_execution_context",
                return_value=SimpleNamespace(
                    tool_name="control_clawhub_discover",
                    network_policy="allow",
                    network_hosts=("api.github.com", "raw.githubusercontent.com"),
                ),
            ),
        ):
            yield

    @pytest.fixture
    def client(self, tmp_path: Path) -> ClawHubClient:
        return ClawHubClient(tmp_path, index_url=_INDEX_URL)

    @pytest.mark.parametrize(
        "index_url",
        [
            "file:///etc/passwd",
            "https://example.com/clawhub.json",
            "https://raw.githubusercontent.com.evil.test/index.json",
            "http://raw.githubusercontent.com/openclaw/skills/main/clawhub.json",
        ],
    )
    def test_registry_index_is_restricted_to_the_pinned_https_origin(
        self,
        tmp_path: Path,
        index_url: str,
    ) -> None:
        with pytest.raises(ValueError, match="ClawHub index"):
            ClawHubClient(tmp_path, index_url=index_url)

    @pytest.mark.anyio
    async def test_registry_fetch_validates_and_pins_dns_without_proxy_env(
        self,
        tmp_path: Path,
    ) -> None:
        client = ClawHubClient(
            tmp_path,
            index_url="https://raw.githubusercontent.com/openclaw/skills/main/clawhub.json",
        )
        response = httpx.Response(
            200,
            json={"skills": [{"id": "safe", "source": "https://github.com/x/safe.git"}]},
            request=httpx.Request(
                "GET",
                "https://raw.githubusercontent.com/openclaw/skills/main/clawhub.json",
            ),
        )
        fake_http = AsyncMock()
        fake_http.__aenter__.return_value = fake_http
        fake_http.__aexit__.return_value = None
        fake_http.get.return_value = response

        with (
            patch(
                "js.skills.clawhub.resolve_and_validate",
                return_value=["203.0.113.10"],
            ) as resolve,
            patch("js.skills.clawhub.PinnedTransport") as pinned,
            patch("js.skills.clawhub.httpx.AsyncClient", return_value=fake_http) as http,
        ):
            index = await client.fetch_index(force=True)

        assert index[0]["id"] == "safe"
        resolve.assert_called_once_with(
            client.index_url,
            allow_loopback=False,
            allow_private=False,
        )
        pinned.assert_called_once_with("203.0.113.10", verify=True)
        assert http.call_args.kwargs["trust_env"] is False
        assert http.call_args.kwargs["follow_redirects"] is False

    @pytest.mark.anyio
    async def test_registry_without_echo_network_context_stays_offline(
        self,
        tmp_path: Path,
    ) -> None:
        client = ClawHubClient(tmp_path)
        with (
            patch(
                "js.skills.clawhub.current_tool_execution_context",
                return_value=None,
            ),
            patch("js.skills.clawhub.httpx.AsyncClient") as http,
        ):
            index = await client.fetch_index(force=True)

        assert index
        assert all(item["id"].startswith("openclaw:") for item in index)
        http.assert_not_called()

    @pytest.mark.anyio
    async def test_fetch_index_mock(self, client: ClawHubClient) -> None:
        request = httpx.Request("GET", _INDEX_URL)
        mock_response = httpx.Response(
            200,
            json={
                "version": "1.0",
                "skills": [
                    {
                        "id": "pdf-tool",
                        "name": "PDF Tool",
                        "source": "https://github.com/x/pdf-tool.git",
                    },
                ],
            },
            request=request,
        )
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_response):
            index = await client.fetch_index()
        assert len(index) == 1
        assert index[0]["id"] == "pdf-tool"

    def test_search_index(self, client: ClawHubClient) -> None:
        client._index = [
            {"id": "pdf-tool", "name": "PDF Helper", "description": "Work with PDFs"},
            {"id": "csv-tool", "name": "CSV Helper", "description": "Work with CSVs"},
        ]
        results = client.search_index("pdf")
        assert len(results) == 1
        assert results[0]["id"] == "pdf-tool"

    def test_get_skill_source(self, client: ClawHubClient) -> None:
        client._index = [
            {"id": "pdf-tool", "source": "https://github.com/x/pdf-tool.git"}
        ]
        assert client.get_skill_source("pdf-tool") == "https://github.com/x/pdf-tool.git"
        assert client.get_skill_source("missing") is None

    @pytest.mark.anyio
    async def test_cache_fallback(self, client: ClawHubClient, tmp_path: Path) -> None:
        import os
        import time

        # Pre-populate cache with old data and backdated mtime
        cache_path = tmp_path / "clawhub_cache.json"
        cache_path.write_text('{"skills": [{"id": "cached"}], "fetched_at": 1}')
        past = time.time() - 7200
        os.utime(cache_path, (past, past))
        client.cache_path = cache_path
        client._cache_ttl = 3600  # cache is expired

        # Fresh fetch
        request = httpx.Request("GET", _INDEX_URL)
        mock_response = httpx.Response(
            200,
            json={
                "skills": [
                    {
                        "id": "fresh",
                        "source": "https://github.com/example/fresh.git",
                    }
                ]
            },
            request=request,
        )
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_response):
            index = await client.fetch_index()
        assert any(s["id"] == "fresh" for s in index)

    @pytest.mark.anyio
    async def test_github_search_fallback(self, client: ClawHubClient, tmp_path: Path) -> None:
        """When primary index 404s, fall back to GitHub Search API."""
        # No cache
        client.cache_path = tmp_path / "no_cache.json"
        client._cache_ttl = 0

        # Primary index 404
        primary_request = httpx.Request("GET", _INDEX_URL)
        primary_404 = httpx.Response(404, text="Not Found", request=primary_request)

        # GitHub Search API mock
        gh_request = httpx.Request("GET", "https://api.github.com/search/repositories")
        gh_response = httpx.Response(
            200,
            json={
                "total_count": 2,
                "items": [
                    {
                        "full_name": "user/skill-one",
                        "name": "skill-one",
                        "description": "First skill",
                        "html_url": "https://github.com/user/skill-one",
                        "stargazers_count": 42,
                        "owner": {"login": "user"},
                    },
                    {
                        "full_name": "user/skill-two",
                        "name": "skill-two",
                        "description": "Second skill",
                        "html_url": "https://github.com/user/skill-two",
                        "stargazers_count": 10,
                        "owner": {"login": "user"},
                    },
                ],
            },
            request=gh_request,
        )

        call_count = 0
        async def mock_get(self: Any, *args: Any, **kwargs: Any) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            url = str(args[0]) if args else kwargs.get("url", "")
            if url == _INDEX_URL:
                return primary_404
            elif "github.com" in url:
                return gh_response
            return httpx.Response(404, request=httpx.Request("GET", url))

        with patch("httpx.AsyncClient.get", new=mock_get):
            index = await client.fetch_index(force=True)

        assert len(index) == 2
        assert index[0]["id"] == "user:skill-one"
        assert index[0]["source"] == "https://github.com/user/skill-one.git"
        assert index[0]["stars"] == 42
        assert index[1]["id"] == "user:skill-two"

    def test_search_github_results(self, client: ClawHubClient) -> None:
        """Search across GitHub-fetched index entries."""
        client._index = [
            {"id": "user:pdf-tool", "name": "PDF Tool", "description": "Work with PDFs", "tags": ["openclaw"]},
            {"id": "user:csv-tool", "name": "CSV Tool", "description": "Work with CSVs", "tags": ["openclaw"]},
        ]
        results = client.search_index("pdf")
        assert len(results) == 1
        assert results[0]["id"] == "user:pdf-tool"

    def test_cache_write_does_not_follow_symlink(
        self,
        client: ClawHubClient,
        tmp_path: Path,
    ) -> None:
        victim = tmp_path / "victim.json"
        victim.write_text("do-not-overwrite", encoding="utf-8")
        client.cache_path.symlink_to(victim)
        client._index = [
            {
                "id": "safe",
                "name": "Safe",
                "source": "https://github.com/example/safe.git",
            }
        ]
        client._last_fetch = 1.0

        client._save_cached_index()

        assert victim.read_text(encoding="utf-8") == "do-not-overwrite"
        assert not client.cache_path.is_symlink()

    def test_cached_index_drops_non_github_sources(
        self,
        client: ClawHubClient,
    ) -> None:
        client.cache_path.write_text(
            '{"skills": ['
            '{"id": "bad", "source": "https://evil.test/skill.git"},'
            '{"id": "good", "source": "https://github.com/example/good.git"}'
            '], "fetched_at": 1}',
            encoding="utf-8",
        )

        loaded = client._load_cached_index()

        assert [item["id"] for item in loaded] == ["good"]
