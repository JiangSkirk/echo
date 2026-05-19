"""Tests for local model discovery."""

from pathlib import Path

import pytest

from js.config import JSSettings
from js.discovery.local_models import LocalModelDiscovery


class TestLocalModelDiscovery:
    @pytest.fixture
    def discovery(self) -> LocalModelDiscovery:
        return LocalModelDiscovery(timeout=1.0)

    @pytest.mark.asyncio
    async def test_discover_all_no_servers(self, discovery: LocalModelDiscovery) -> None:
        results = await discovery.discover_all()
        # Should return empty since no local servers are running in test env
        assert isinstance(results, list)
        await discovery.close()

    def test_infer_context_window(self, discovery: LocalModelDiscovery) -> None:
        assert discovery._infer_context_window("llama-3-8b-128k") == 131072
        assert discovery._infer_context_window("qwen3-32b") == 128000
        assert discovery._infer_context_window("unknown") == 32768

    @pytest.mark.asyncio
    async def test_apply_to_settings(self, discovery: LocalModelDiscovery, tmp_path: Path) -> None:
        settings = JSSettings()
        settings.workspace = tmp_path / "workspace"
        settings.state_dir = tmp_path / "state"
        settings.workspace.mkdir(parents=True, exist_ok=True)
        settings.state_dir.mkdir(parents=True, exist_ok=True)
        updated = await discovery.apply_to_settings(settings)
        assert isinstance(updated.providers, list)
        await discovery.close()
