"""Tests for ClawHub registry client."""

from __future__ import annotations

from pathlib import Path
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
