"""Tests for ClawHub registry client."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from js.skills.clawhub import ClawHubClient


class TestClawHubClient:
    @pytest.fixture
    def client(self, tmp_path: Path) -> ClawHubClient:
        return ClawHubClient(tmp_path, index_url="https://example.com/clawhub.json")

    @pytest.mark.anyio
    async def test_fetch_index_mock(self, client: ClawHubClient) -> None:
        request = httpx.Request("GET", "https://example.com/clawhub.json")
        mock_response = httpx.Response(
            200,
            json={
                "version": "1.0",
                "skills": [
                    {"id": "pdf-tool", "name": "PDF Tool", "source": "git+https://github.com/x/pdf-tool"},
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
        client._index = [{"id": "pdf-tool", "source": "git+https://github.com/x/pdf-tool"}]
        assert client.get_skill_source("pdf-tool") == "git+https://github.com/x/pdf-tool"
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
        request = httpx.Request("GET", "https://example.com/clawhub.json")
        mock_response = httpx.Response(200, json={"skills": [{"id": "fresh"}]}, request=request)
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
        primary_request = httpx.Request("GET", "https://example.com/clawhub.json")
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
            if "example.com/clawhub" in url:
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
