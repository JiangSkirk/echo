"""Preset configurations for popular cloud LLM APIs.

Most modern cloud APIs expose an OpenAI-compatible endpoint,
so we only need the correct base_url + api_key to use them.

For providers with non-standard auth (e.g. Gemini query-param keys),
a thin adapter normalizes the config before it reaches OpenAICompatibleProvider.

Pricing units: cost_input / cost_output are per-token rates in USD.
To convert from "per 1M tokens": divide by 1_000_000.
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
# Helpers
# ---------------------------------------------------------------------------

def _c(price_per_million: float) -> float:
    """Convert price-per-million-tokens to per-token rate."""
    return price_per_million / 1_000_000.0


# ---------------------------------------------------------------------------
# Presets
# ---------------------------------------------------------------------------

OPENAI_PRESET = CloudProviderPreset(
    id="openai",
    name="OpenAI",
    base_url="https://api.openai.com/v1",
    api_key_env="OPENAI_API_KEY",
    description="OpenAI API (GPT-5.5, GPT-5.4, GPT-4.1, o3, o4-mini)",
    models=[
        # GPT-5.5 family (flagship, Apr 2026)
        ModelConfig(
            id="gpt-5.5", name="GPT-5.5", context_window=1_000_000, max_tokens=32_768,
            cost_input=_c(5.00), cost_output=_c(30.00),
        ),
        ModelConfig(
            id="gpt-5.5-pro", name="GPT-5.5 Pro", context_window=1_000_000, max_tokens=32_768,
            cost_input=_c(30.00), cost_output=_c(180.00),
        ),
        # GPT-5.4 family (production workhorse)
        ModelConfig(
            id="gpt-5.4", name="GPT-5.4", context_window=1_000_000, max_tokens=32_768,
            cost_input=_c(2.50), cost_output=_c(15.00),
        ),
        ModelConfig(
            id="gpt-5.4-mini", name="GPT-5.4 Mini", context_window=400_000, max_tokens=16_384,
            cost_input=_c(0.75), cost_output=_c(4.50),
        ),
        ModelConfig(
            id="gpt-5.4-nano", name="GPT-5.4 Nano", context_window=400_000, max_tokens=8_192,
            cost_input=_c(0.20), cost_output=_c(1.25),
        ),
        # GPT-4.1 family (budget long-context)
        ModelConfig(
            id="gpt-4.1", name="GPT-4.1", context_window=1_000_000, max_tokens=32_768,
            cost_input=_c(2.00), cost_output=_c(8.00),
        ),
        ModelConfig(
            id="gpt-4.1-mini", name="GPT-4.1 Mini", context_window=1_000_000, max_tokens=16_384,
            cost_input=_c(0.40), cost_output=_c(1.60),
        ),
        ModelConfig(
            id="gpt-4.1-nano", name="GPT-4.1 Nano", context_window=1_000_000, max_tokens=8_192,
            cost_input=_c(0.10), cost_output=_c(0.40),
        ),
        # o-series reasoning models
        ModelConfig(
            id="o3", name="o3", context_window=200_000, max_tokens=32_768,
            cost_input=_c(2.00), cost_output=_c(8.00),
        ),
        ModelConfig(
            id="o3-pro", name="o3-Pro", context_window=200_000, max_tokens=32_768,
            cost_input=_c(20.00), cost_output=_c(80.00),
        ),
        ModelConfig(
            id="o4-mini", name="o4-mini", context_window=200_000, max_tokens=32_768,
            cost_input=_c(0.55), cost_output=_c(2.20),
        ),
        # Legacy (still active but superseded)
        ModelConfig(
            id="gpt-4o", name="GPT-4o", context_window=128_000, max_tokens=4_096,
            cost_input=_c(2.50), cost_output=_c(10.00), supports_vision=True,
        ),
        ModelConfig(
            id="gpt-4o-mini", name="GPT-4o Mini", context_window=128_000, max_tokens=4_096,
            cost_input=_c(0.15), cost_output=_c(0.60),
        ),
        ModelConfig(
            id="gpt-5", name="GPT-5", context_window=400_000, max_tokens=16_384,
            cost_input=_c(1.25), cost_output=_c(10.00),
        ),
        ModelConfig(
            id="gpt-5-mini", name="GPT-5 Mini", context_window=400_000, max_tokens=8_192,
            cost_input=_c(0.25), cost_output=_c(2.00),
        ),
    ],
)

ANTHROPIC_PRESET = CloudProviderPreset(
    id="anthropic",
    name="Anthropic",
    base_url="https://api.anthropic.com/v1",
    api_key_env="ANTHROPIC_API_KEY",
    description="Anthropic Claude API (Claude 4.7 Opus, Claude 4.6 Sonnet, Claude 4.5 Haiku)",
    models=[
        ModelConfig(
            id="claude-opus-4-7", name="Claude Opus 4.7", context_window=1_000_000, max_tokens=32_768,
            cost_input=_c(5.00), cost_output=_c(25.00), supports_vision=True,
        ),
        ModelConfig(
            id="claude-sonnet-4-6", name="Claude Sonnet 4.6", context_window=1_000_000, max_tokens=32_768,
            cost_input=_c(3.00), cost_output=_c(15.00), supports_vision=True,
        ),
        ModelConfig(
            id="claude-haiku-4-5", name="Claude Haiku 4.5", context_window=200_000, max_tokens=8_192,
            cost_input=_c(1.00), cost_output=_c(5.00), supports_vision=True,
        ),
        # Legacy (still active but superseded by 4.x)
        ModelConfig(
            id="claude-3-5-sonnet-20241022", name="Claude 3.5 Sonnet", context_window=200_000, max_tokens=8_192,
            cost_input=_c(3.00), cost_output=_c(15.00), supports_vision=True,
        ),
        ModelConfig(
            id="claude-3-5-haiku-20241022", name="Claude 3.5 Haiku", context_window=200_000, max_tokens=4_096,
            cost_input=_c(0.80), cost_output=_c(4.00), supports_vision=True,
        ),
        ModelConfig(
            id="claude-3-opus-20240229", name="Claude 3 Opus", context_window=200_000, max_tokens=4_096,
            cost_input=_c(15.00), cost_output=_c(75.00), supports_vision=True,
        ),
    ],
)

DEEPSEEK_PRESET = CloudProviderPreset(
    id="deepseek",
    name="DeepSeek",
    base_url="https://api.deepseek.com/v1",
    api_key_env="DEEPSEEK_API_KEY",
    description="DeepSeek API (V4 Flash, V4 Pro, V3.2). deepseek-chat / deepseek-reasoner are deprecated aliases.",
    models=[
        ModelConfig(
            id="deepseek-v4-flash", name="DeepSeek V4 Flash", context_window=1_000_000, max_tokens=384_000,
            cost_input=_c(0.14), cost_output=_c(0.28), supports_tools=True,
        ),
        ModelConfig(
            id="deepseek-v4-pro", name="DeepSeek V4 Pro", context_window=1_000_000, max_tokens=384_000,
            cost_input=_c(0.435), cost_output=_c(0.87), supports_tools=True,
        ),
        ModelConfig(
            id="deepseek-v3.2", name="DeepSeek V3.2", context_window=128_000, max_tokens=8_192,
            cost_input=_c(0.28), cost_output=_c(0.42), supports_tools=True,
        ),
        # Compatibility aliases (scheduled for deprecation 2026-07-24)
        ModelConfig(
            id="deepseek-chat", name="DeepSeek-V3 (alias)", context_window=64_000, max_tokens=8_192,
            cost_input=_c(0.14), cost_output=_c(0.28), supports_tools=True,
        ),
        ModelConfig(
            id="deepseek-reasoner", name="DeepSeek-R1 (alias)", context_window=64_000, max_tokens=8_192,
            cost_input=_c(0.14), cost_output=_c(0.28), supports_tools=False,
        ),
        ModelConfig(
            id="deepseek-coder", name="DeepSeek-Coder", context_window=64_000, max_tokens=4_096,
            cost_input=_c(0.14), cost_output=_c(0.28), supports_tools=True,
        ),
    ],
)

DASHSCOPE_PRESET = CloudProviderPreset(
    id="dashscope",
    name="Alibaba DashScope (通义千问)",
    base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",
    api_key_env="DASHSCOPE_API_KEY",
    description="Alibaba Tongyi Qianwen API (Qwen3, Qwen-Max, Qwen-Plus, Qwen-Coder)",
    models=[
        ModelConfig(
            id="qwen3-235b-a22b", name="Qwen3-235B-A22B", context_window=128_000, max_tokens=8_192,
            cost_input=_c(0.50), cost_output=_c(1.50), supports_vision=True,
        ),
        ModelConfig(
            id="qwen-max", name="Qwen-Max", context_window=32_000, max_tokens=8_192,
            cost_input=_c(0.50), cost_output=_c(1.50), supports_vision=True,
        ),
        ModelConfig(
            id="qwen-plus", name="Qwen-Plus", context_window=32_000, max_tokens=8_192,
            cost_input=_c(0.20), cost_output=_c(0.60), supports_vision=True,
        ),
        ModelConfig(
            id="qwen-turbo", name="Qwen-Turbo", context_window=32_000, max_tokens=4_096,
            cost_input=_c(0.02), cost_output=_c(0.06), supports_vision=True,
        ),
        ModelConfig(
            id="qwen-coder-plus", name="Qwen-Coder-Plus", context_window=32_000, max_tokens=8_192,
            cost_input=_c(0.20), cost_output=_c(0.60), supports_tools=True,
        ),
    ],
)

SILICONFLOW_PRESET = CloudProviderPreset(
    id="siliconflow",
    name="SiliconFlow",
    base_url="https://api.siliconflow.cn/v1",
    api_key_env="SILICONFLOW_API_KEY",
    description="SiliconFlow API (聚合多种开源模型，含 DeepSeek V4 / Qwen3)",
    models=[
        ModelConfig(
            id="deepseek-ai/DeepSeek-V4-Flash", name="DeepSeek V4 Flash", context_window=1_000_000, max_tokens=32_768,
            cost_input=_c(0.14), cost_output=_c(0.28), supports_tools=True,
        ),
        ModelConfig(
            id="deepseek-ai/DeepSeek-V4-Pro", name="DeepSeek V4 Pro", context_window=1_000_000, max_tokens=32_768,
            cost_input=_c(0.435), cost_output=_c(0.87), supports_tools=True,
        ),
        ModelConfig(
            id="deepseek-ai/DeepSeek-V3.2", name="DeepSeek V3.2", context_window=128_000, max_tokens=8_192,
            cost_input=_c(0.28), cost_output=_c(0.42), supports_tools=True,
        ),
        ModelConfig(
            id="Qwen/Qwen3-235B-A22B", name="Qwen3-235B", context_window=128_000, max_tokens=8_192,
            cost_input=_c(0.50), cost_output=_c(1.50), supports_vision=True,
        ),
    ],
)

VOLCANO_PRESET = CloudProviderPreset(
    id="volcano",
    name="Volcano Engine (火山引擎)",
    base_url="https://ark.cn-beijing.volces.com/api/v3",
    api_key_env="VOLCANO_API_KEY",
    description="ByteDance Volcano Engine Ark API (Doubao / Seed)",
    models=[
        ModelConfig(
            id="doubao-1.5-pro-32k", name="Doubao-1.5-Pro", context_window=32_000, max_tokens=4_096,
            cost_input=_c(0.50), cost_output=_c(1.50), supports_vision=True,
        ),
        ModelConfig(
            id="doubao-1.5-lite-32k", name="Doubao-1.5-Lite", context_window=32_000, max_tokens=4_096,
            cost_input=_c(0.10), cost_output=_c(0.30),
        ),
    ],
)

GEMINI_PRESET = CloudProviderPreset(
    id="gemini",
    name="Google Gemini",
    base_url="https://generativelanguage.googleapis.com/v1beta/openai/",
    api_key_env="GOOGLE_API_KEY",
    description="Google Gemini API (Gemini 3.5 Flash, Gemini 3.1 Pro, Gemini 2.5 family)",
    auth_adapter="query_param",
    query_param_name="key",
    models=[
        # Gemini 3.x series (latest)
        ModelConfig(
            id="gemini-3.5-flash", name="Gemini 3.5 Flash", context_window=1_000_000, max_tokens=8_192,
            cost_input=_c(1.50), cost_output=_c(9.00), supports_vision=True,
        ),
        ModelConfig(
            id="gemini-3.1-pro", name="Gemini 3.1 Pro", context_window=1_000_000, max_tokens=65_536,
            cost_input=_c(2.00), cost_output=_c(12.00), supports_vision=True,
        ),
        ModelConfig(
            id="gemini-3-flash", name="Gemini 3 Flash", context_window=1_000_000, max_tokens=8_192,
            cost_input=_c(0.50), cost_output=_c(3.00), supports_vision=True,
        ),
        ModelConfig(
            id="gemini-3.1-flash-lite", name="Gemini 3.1 Flash Lite", context_window=1_000_000, max_tokens=8_192,
            cost_input=_c(0.25), cost_output=_c(1.50), supports_vision=True,
        ),
        # Gemini 2.5 series (previous generation, still supported)
        ModelConfig(
            id="gemini-2.5-pro", name="Gemini 2.5 Pro", context_window=1_000_000, max_tokens=65_536,
            cost_input=_c(1.25), cost_output=_c(10.00), supports_vision=True,
        ),
        ModelConfig(
            id="gemini-2.5-flash", name="Gemini 2.5 Flash", context_window=1_000_000, max_tokens=8_192,
            cost_input=_c(0.30), cost_output=_c(2.50), supports_vision=True,
        ),
        ModelConfig(
            id="gemini-2.5-flash-lite", name="Gemini 2.5 Flash Lite", context_window=1_000_000, max_tokens=8_192,
            cost_input=_c(0.10), cost_output=_c(0.40), supports_vision=True,
        ),
        # Legacy (deprecated June 2026)
        ModelConfig(
            id="gemini-2.0-flash", name="Gemini 2.0 Flash (deprecated)", context_window=1_000_000, max_tokens=8_192,
            cost_input=_c(0.10), cost_output=_c(0.40), supports_vision=True,
        ),
        ModelConfig(
            id="gemini-2.0-flash-lite", name="Gemini 2.0 Flash Lite (deprecated)", context_window=1_000_000, max_tokens=8_192,
            cost_input=_c(0.10), cost_output=_c(0.40), supports_vision=True,
        ),
    ],
)

KIMI_CN_PRESET = CloudProviderPreset(
    id="kimi-cn",
    name="Kimi 国内版 (platform.kimi.com)",
    base_url="https://api.moonshot.cn/v1",
    api_key_env="MOONSHOT_API_KEY",
    description="月之暗面 Moonshot 国内开放平台。账号和 key 与国际版完全独立。",
    models=[
        ModelConfig(
            id="kimi-k2.6", name="Kimi K2.6", context_window=262_144, max_tokens=32_768,
            cost_input=_c(0.95), cost_output=_c(4.00), supports_vision=True,
        ),
        ModelConfig(
            id="kimi-k2.5", name="Kimi K2.5", context_window=262_144, max_tokens=32_768,
            cost_input=_c(0.60), cost_output=_c(3.00), supports_vision=True,
        ),
        ModelConfig(
            id="kimi-k2-thinking", name="Kimi K2 Thinking", context_window=262_144, max_tokens=32_768,
            cost_input=_c(0.60), cost_output=_c(2.50), supports_tools=True,
        ),
        # Legacy (being deprecated)
        ModelConfig(
            id="moonshot-v1-128k", name="Kimi V1 (128K)", context_window=128_000, max_tokens=8_192,
            cost_input=_c(0.60), cost_output=_c(2.50),
        ),
        ModelConfig(
            id="moonshot-v1-32k", name="Kimi V1 (32K)", context_window=32_000, max_tokens=8_192,
            cost_input=_c(0.60), cost_output=_c(2.50),
        ),
        ModelConfig(
            id="moonshot-v1-8k", name="Kimi V1 (8K)", context_window=8_000, max_tokens=4_096,
            cost_input=_c(0.60), cost_output=_c(2.50),
        ),
    ],
)

KIMI_INTL_PRESET = CloudProviderPreset(
    id="kimi-intl",
    name="Kimi 国际版 (platform.kimi.ai)",
    base_url="https://api.moonshot.ai/v1",
    api_key_env="MOONSHOT_API_KEY",
    description="Moonshot AI International Platform。账号和 key 与国内版完全独立。",
    models=[
        ModelConfig(
            id="kimi-k2.6", name="Kimi K2.6", context_window=262_144, max_tokens=32_768,
            cost_input=_c(0.95), cost_output=_c(4.00), supports_vision=True,
        ),
        ModelConfig(
            id="kimi-k2.5", name="Kimi K2.5", context_window=262_144, max_tokens=32_768,
            cost_input=_c(0.60), cost_output=_c(3.00), supports_vision=True,
        ),
        ModelConfig(
            id="kimi-k2-thinking", name="Kimi K2 Thinking", context_window=262_144, max_tokens=32_768,
            cost_input=_c(0.60), cost_output=_c(2.50), supports_tools=True,
        ),
        # Legacy
        ModelConfig(
            id="moonshot-v1-128k", name="Kimi V1 (128K)", context_window=128_000, max_tokens=8_192,
            cost_input=_c(0.60), cost_output=_c(2.50),
        ),
        ModelConfig(
            id="moonshot-v1-32k", name="Kimi V1 (32K)", context_window=32_000, max_tokens=8_192,
            cost_input=_c(0.60), cost_output=_c(2.50),
        ),
        ModelConfig(
            id="moonshot-v1-8k", name="Kimi V1 (8K)", context_window=8_000, max_tokens=4_096,
            cost_input=_c(0.60), cost_output=_c(2.50),
        ),
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
    KIMI_CN_PRESET,
    KIMI_INTL_PRESET,
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
    """Build a ModelProviderConfig from a preset + API key.

    Handles auth adapters (e.g. Gemini query-param) by baking the key into
    the base_url so the OpenAI client passes it on every request.
    """
    base_url = preset.base_url
    if preset.auth_adapter == "query_param" and api_key:
        sep = "&" if "?" in base_url else "?"
        base_url = f"{base_url}{sep}{preset.query_param_name}={api_key}"
        # Clear api_key so the OpenAI client doesn't also send a Bearer token
        api_key = ""
    return ModelProviderConfig(
        name=preset.id,
        base_url=base_url,
        api_key=api_key,
        timeout=120.0,
        max_retries=3,
        default_model=preset.models[0].id if preset.models else "",
        models=[
            model.model_copy(update={"provider": preset.id})
            for model in preset.models
        ],
    )
