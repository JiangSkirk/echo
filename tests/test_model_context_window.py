"""Tests for real-time model context window detection and cloud model discovery."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from js.models.discovery import LocalModelDiscovery
from js.models.provider_manager import ProviderManager


class TestLocalModelContextDetection:
    """Verify local provider models get accurate context windows from APIs."""

    @pytest.fixture
    def discovery(self) -> LocalModelDiscovery:
        return LocalModelDiscovery(timeout=1.0)

    def test_local_discovery_exposes_no_raw_network_probe(
        self,
        discovery: LocalModelDiscovery,
    ) -> None:
        assert not hasattr(discovery, "_lmstudio_context_lengths")
        assert not hasattr(discovery, "_ollama_context_lengths")
        assert not hasattr(discovery, "_probe")

    def test_infer_with_lmstudio_override(self, discovery: LocalModelDiscovery) -> None:
        """When LM Studio v0 API provides context, it overrides name inference."""
        # Simulate _parse_models with v0 context overrides
        v1_data = {
            "data": [
                {"id": "qwen3.5-122b-a10b", "object": "model"},
            ]
        }
        overrides = {"qwen3.5-122b-a10b": 262144}
        models = discovery._parse_models(v1_data, "lmstudio", overrides)
        assert len(models) == 1
        assert models[0].context_window == 262144

    def test_infer_without_override_uses_name(self, discovery: LocalModelDiscovery) -> None:
        """Without API context, name-based inference is used."""
        v1_data = {
            "data": [
                {"id": "qwen3.5-122b-a10b", "object": "model"},
            ]
        }
        models = discovery._parse_models(v1_data, "lmstudio")
        assert len(models) == 1
        # qwen3 family default is 131072
        assert models[0].context_window == 131072

    def test_v1_api_context_length_field(self, discovery: LocalModelDiscovery) -> None:
        """Some OpenAI-compatible APIs expose context_length in /v1/models."""
        v1_data = {
            "data": [
                {"id": "custom-model", "context_length": 65536},
            ]
        }
        models = discovery._parse_models(v1_data, "custom")
        assert models[0].context_window == 65536

    def test_context_override_priority(self, discovery: LocalModelDiscovery) -> None:
        """Priority: v0 override > v1 context_length > name inference."""
        v1_data = {
            "data": [
                {"id": "my-model", "context_length": 8192},
            ]
        }
        # v0 override should win
        models = discovery._parse_models(v1_data, "lmstudio", {"my-model": 262144})
        assert models[0].context_window == 262144

        # v1 context_length should win over name inference
        models2 = discovery._parse_models(v1_data, "custom")
        assert models2[0].context_window == 8192


class TestCloudModelDiscovery:
    """Verify cloud provider model lists can be refreshed from API."""

    @pytest.mark.asyncio
    async def test_provider_manager_discovers_with_context(self) -> None:
        """ProviderManager.discover_models returns context_window when available."""
        # Mock the v0 API for LM Studio
        v0_response = MagicMock()
        v0_response.status_code = 200
        v0_response.json.return_value = {
            "data": [
                {"id": "test-model", "state": "loaded", "max_context_length": 262144}
            ]
        }

        # Mock the v1 API
        v1_response = MagicMock()
        v1_response.status_code = 200
        v1_response.raise_for_status = MagicMock()
        v1_response.json.return_value = {
            "data": [
                {"id": "test-model", "object": "model"}
            ]
        }

        with patch("httpx.AsyncClient.get", side_effect=[v0_response, v1_response]):
            result = await ProviderManager.discover_models(
                "http://127.0.0.1:1234/v1", api_key="lm-studio"
            )

        assert "error" not in result
        assert len(result["models"]) == 1
        assert result["models"][0]["context_window"] == 262144

    @pytest.mark.asyncio
    async def test_provider_manager_falls_back_to_name_inference(self) -> None:
        """When API provides no context, name inference is used."""
        v1_response = MagicMock()
        v1_response.status_code = 200
        v1_response.raise_for_status = MagicMock()
        v1_response.json.return_value = {
            "data": [
                {"id": "qwen3-32b", "object": "model"}
            ]
        }

        with patch("httpx.AsyncClient.get", return_value=v1_response):
            result = await ProviderManager.discover_models(
                "http://example.com/v1", api_key="test"
            )

        assert result["models"][0]["context_window"] == 131072

    @pytest.mark.asyncio
    async def test_provider_manager_handles_api_error(self) -> None:
        """Graceful error when API is unreachable."""
        result = await ProviderManager.discover_models(
            "http://127.0.0.1:9999/v1", api_key="test"
        )
        assert "error" in result


class TestGenericLocalProvider:
    """Verify any OpenAI-compatible local endpoint is supported."""

    def test_lan_scanner_is_physically_absent(self) -> None:
        """Broad LAN scanning cannot be reached through the compatibility class."""
        discovery = LocalModelDiscovery(timeout=0.5)
        assert not hasattr(discovery, "scan_lan")

    def test_infer_context_accurate_for_known_models(self) -> None:
        """Context inference covers major model families accurately."""
        d = LocalModelDiscovery(timeout=1.0)
        # Qwen series
        assert d._infer_context_window("qwen3-8b") == 131072
        assert d._infer_context_window("qwen2.5-72b-instruct") == 131072
        # Llama series
        assert d._infer_context_window("llama-3-8b-instruct") == 131072
        assert d._infer_context_window("llama-2-7b-chat") == 4096
        # Mistral
        assert d._infer_context_window("mistral-7b-instruct-v0.3") == 32768
        # DeepSeek
        assert d._infer_context_window("deepseek-v4-flash") == 1_000_000
        assert d._infer_context_window("deepseek-v4-pro") == 1_000_000
        assert d._infer_context_window("deepseek-v3.2") == 131072
        assert d._infer_context_window("deepseek-chat") == 65536
        assert d._infer_context_window("deepseek-reasoner") == 65536
        assert d._infer_context_window("deepseek-coder") == 65536
        # Claude
        assert d._infer_context_window("claude-3-5-sonnet") == 200000
        # GPT
        assert d._infer_context_window("gpt-4o") == 128000
        # Context markers in name
        assert d._infer_context_window("my-model-256k-awq") == 262144
        assert d._infer_context_window("my-model-32k-q4") == 32768
        # Unknown fallback
        assert d._infer_context_window("some-random-model") == 32768
