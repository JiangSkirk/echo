"""Tests for cloud provider presets and LAN discovery."""

from __future__ import annotations

from js.models.cloud_providers import (
    ALL_PRESETS,
    build_provider_config,
    get_preset,
    list_presets,
)


class TestCloudProviderPresets:
    def test_all_presets_have_models(self):
        for preset in ALL_PRESETS:
            assert len(preset.models) > 0, f"Preset {preset.id} has no models"
            assert preset.base_url.startswith("http")
            assert preset.api_key_env

    def test_get_preset_exists(self):
        p = get_preset("openai")
        assert p is not None
        assert p.id == "openai"
        assert any(m.id == "gpt-4o" for m in p.models)

    def test_get_preset_missing(self):
        assert get_preset("nonexistent") is None

    def test_list_presets_structure(self):
        presets = list_presets()
        assert len(presets) == len(ALL_PRESETS)
        for p in presets:
            assert "id" in p
            assert "name" in p
            assert "models" in p
            assert isinstance(p["models"], list)

    def test_build_provider_config(self):
        preset = get_preset("deepseek")
        assert preset is not None
        cfg = build_provider_config(preset, "sk-test123")
        assert cfg.name == "deepseek"
        assert cfg.base_url == "https://api.deepseek.com/v1"
        assert cfg.api_key == "sk-test123"
        assert len(cfg.models) == len(preset.models)
