"""Preset configurations for popular cloud LLM APIs.

Most modern cloud APIs expose an OpenAI-compatible endpoint,
so we only need the correct base_url + api_key to use them.

For providers with non-standard auth (e.g. Gemini query-param keys),
a thin adapter normalizes the config before it reaches OpenAICompatibleProvider.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from js.config import ModelConfig, ModelProviderConfig


@dataclass(frozen=True)
class CloudProviderPreset:
    """A pre-configured cloud provider template."""

    id: str
    name: str
    base_url: str
    api_key_env: str  # Environment variable name for the API key
    description: str
    models: list[ModelConfig]
    # Some providers need auth adapters (e.g. Gemini puts key in query param)
    auth_adapter: str = "bearer"  # bearer | query_param
    query_param_name: str = "key"


# ---------------------------------------------------------------------------
# Presets
# ---------------------------------------------------------------------------

OPENAI_PRESET = CloudProviderPreset(
    id="openai",
    name="OpenAI",
    base_url="https://api.openai.com/v1",
    api_key_env="OPENAI_API_KEY",
    description="Official OpenAI API (GPT-4o, GPT-4, GPT-3.5)",
    models=[
        ModelConfig(id="gpt-4o", name="GPT-4o", context_window=128000, max_tokens=4096),
        ModelConfig(id="gpt-4o-mini", name="GPT-4o Mini", context_window=128000, max_tokens=4096),
        ModelConfig(id="gpt-4-turbo", name="GPT-4 Turbo", context_window=128000, max_tokens=4096),
        ModelConfig(id="gpt-3.5-turbo", name="GPT-3.5 Turbo", context_window=16385, max_tokens=4096),
    ],
)

ANTHROPIC_PRESET = CloudProviderPreset(
    id="anthropic",
    name="Anthropic",
    base_url="https://api.anthropic.com/v1",
    api_key_env="ANTHROPIC_API_KEY",
    description="Anthropic Claude API (Claude 3.5 Sonnet, Claude 3 Opus)",
    models=[
        ModelConfig(id="claude-3-5-sonnet-20241022", name="Claude 3.5 Sonnet", context_window=200000, max_tokens=8192),
        ModelConfig(id="claude-3-opus-20240229", name="Claude 3 Opus", context_window=200000, max_tokens=4096),
        ModelConfig(id="claude-3-sonnet-20240229", name="Claude 3 Sonnet", context_window=200000, max_tokens=4096),
        ModelConfig(id="claude-3-haiku-20240307", name="Claude 3 Haiku", context_window=200000, max_tokens=4096),
    ],
)

DEEPSEEK_PRESET = CloudProviderPreset(
    id="deepseek",
    name="DeepSeek",
    base_url="https://api.deepseek.com/v1",
    api_key_env="DEEPSEEK_API_KEY",
    description="DeepSeek API (DeepSeek-V3, DeepSeek-R1, DeepSeek-Coder)",
    models=[
        ModelConfig(id="deepseek-chat", name="DeepSeek-V3", context_window=64000, max_tokens=8192),
        ModelConfig(id="deepseek-reasoner", name="DeepSeek-R1", context_window=64000, max_tokens=8192),
        ModelConfig(id="deepseek-coder", name="DeepSeek-Coder", context_window=64000, max_tokens=4096),
    ],
)

DASHSCOPE_PRESET = CloudProviderPreset(
    id="dashscope",
    name="Alibaba DashScope (通义千问)",
    base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",
    api_key_env="DASHSCOPE_API_KEY",
    description="Alibaba Tongyi Qianwen API (Qwen3, Qwen-Max, Qwen-Plus)",
    models=[
        ModelConfig(id="qwen3-235b-a22b", name="Qwen3-235B-A22B", context_window=128000, max_tokens=8192),
        ModelConfig(id="qwen-max", name="Qwen-Max", context_window=32000, max_tokens=8192),
        ModelConfig(id="qwen-plus", name="Qwen-Plus", context_window=32000, max_tokens=8192),
        ModelConfig(id="qwen-turbo", name="Qwen-Turbo", context_window=32000, max_tokens=4096),
        ModelConfig(id="qwen-coder-plus", name="Qwen-Coder-Plus", context_window=32000, max_tokens=8192),
    ],
)

SILICONFLOW_PRESET = CloudProviderPreset(
    id="siliconflow",
    name="SiliconFlow",
    base_url="https://api.siliconflow.cn/v1",
    api_key_env="SILICONFLOW_API_KEY",
    description="SiliconFlow API (聚合多种开源模型)",
    models=[
        ModelConfig(id="deepseek-ai/DeepSeek-V3", name="DeepSeek-V3", context_window=64000, max_tokens=4096),
        ModelConfig(id="deepseek-ai/DeepSeek-R1", name="DeepSeek-R1", context_window=64000, max_tokens=4096),
        ModelConfig(id="Qwen/Qwen3-235B-A22B", name="Qwen3-235B", context_window=128000, max_tokens=4096),
    ],
)

VOLCANO_PRESET = CloudProviderPreset(
    id="volcano",
    name="Volcano Engine (火山引擎)",
    base_url="https://ark.cn-beijing.volces.com/api/v3",
    api_key_env="VOLCANO_API_KEY",
    description="ByteDance Volcano Engine Ark API",
    models=[
        ModelConfig(id="doubao-1.5-pro-32k", name="Doubao-1.5-Pro", context_window=32000, max_tokens=4096),
        ModelConfig(id="doubao-1.5-lite-32k", name="Doubao-1.5-Lite", context_window=32000, max_tokens=4096),
    ],
)

GEMINI_PRESET = CloudProviderPreset(
    id="gemini",
    name="Google Gemini",
    base_url="https://generativelanguage.googleapis.com/v1beta/openai/",
    api_key_env="GOOGLE_API_KEY",
    description="Google Gemini API (Gemini 2.5 Pro, Gemini 2.0 Flash)",
    auth_adapter="query_param",
    query_param_name="key",
    models=[
        ModelConfig(id="gemini-2.5-pro-preview-03-25", name="Gemini 2.5 Pro", context_window=1000000, max_tokens=65536),
        ModelConfig(id="gemini-2.0-flash", name="Gemini 2.0 Flash", context_window=1000000, max_tokens=8192),
        ModelConfig(id="gemini-2.0-flash-lite", name="Gemini 2.0 Flash Lite", context_window=1000000, max_tokens=8192),
    ],
)

# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

ALL_PRESETS: list[CloudProviderPreset] = [
    OPENAI_PRESET,
    ANTHROPIC_PRESET,
    DEEPSEEK_PRESET,
    DASHSCOPE_PRESET,
    SILICONFLOW_PRESET,
    VOLCANO_PRESET,
    GEMINI_PRESET,
]


def get_preset(provider_id: str) -> CloudProviderPreset | None:
    """Get a preset by its ID."""
    for p in ALL_PRESETS:
        if p.id == provider_id:
            return p
    return None


def list_presets() -> list[dict[str, Any]]:
    """List all presets with metadata (no API keys)."""
    return [
        {
            "id": p.id,
            "name": p.name,
            "base_url": p.base_url,
            "api_key_env": p.api_key_env,
            "description": p.description,
            "models": [
                {"id": m.id, "name": m.name, "context_window": m.context_window}
                for m in p.models
            ],
        }
        for p in ALL_PRESETS
    ]


def build_provider_config(preset: CloudProviderPreset, api_key: str) -> ModelProviderConfig:
    """Build a ModelProviderConfig from a preset + API key."""
    return ModelProviderConfig(
        name=preset.id,
        base_url=preset.base_url,
        api_key=api_key,
        timeout=120.0,
        max_retries=3,
        default_model=preset.models[0].id if preset.models else "",
        models=list(preset.models),
    )
