"""Auto-detect and configure local model providers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from js.config import JSSettings, ModelConfig


@dataclass
class DiscoveredProvider:
    name: str
    provider_type: str  # lmstudio, ollama, mlx, openai-compatible
    base_url: str
    models: list[ModelConfig]
    healthy: bool
    latency_ms: float


class LocalModelDiscovery:
    """Pure compatibility parser; all network discovery belongs to Echo tools."""

    def __init__(self, timeout: float = 3.0) -> None:
        self.timeout = timeout

    async def discover_all(self) -> list[DiscoveredProvider]:
        raise RuntimeError(
            "Raw local model discovery is disabled; use the Echo "
            "control_provider_discover effect"
        )

    def _parse_models(
        self,
        data: dict[str, Any],
        provider_type: str,
        context_overrides: dict[str, int] | None = None,
    ) -> list[ModelConfig]:
        models: list[ModelConfig] = []
        raw_models = data.get("data", data.get("models", []))
        overrides = context_overrides or {}

        for m in raw_models:
            if isinstance(m, str):
                model_id = m
                name = m
            else:
                model_id = m.get("id", m.get("model", "unknown"))
                name = m.get("name", model_id)

            supports_vision = any(kw in model_id.lower() for kw in ["vision", "vl", "multimodal", "llava"])

            # Priority 1: API-provided context length (from v0 API, etc.)
            context = overrides.get(model_id)
            # Priority 2: OpenAI-compatible /v1/models may expose context_length
            if context is None:
                context = m.get("context_length") or m.get("max_context_length")
            # Priority 3: fallback to name-based inference
            if context is None:
                context = self._infer_context_window(model_id)

            context = int(context)

            models.append(ModelConfig(
                id=model_id,
                name=name,
                provider=provider_type.replace("-alt", ""),
                context_window=context,
                max_tokens=min(context // 4, 8192),
                supports_vision=supports_vision,
                supports_tools=True,
                cost_input=0.0,
                cost_output=0.0,
            ))

        return models

    @staticmethod
    def _infer_context_window(model_id: str) -> int:
        mid = model_id.lower()
        # Explicit context size markers first
        if "256k" in mid or "262k" in mid:
            return 262144
        if "128k" in mid or "131k" in mid:
            return 131072
        if "200k" in mid:
            return 200000
        if "100k" in mid:
            return 100000
        if "96k" in mid:
            return 96000
        if "64k" in mid:
            return 65536
        if "32k" in mid:
            return 32768
        if "16k" in mid:
            return 16384
        if "8k" in mid:
            return 8192
        if "4k" in mid:
            return 4096
        if "2k" in mid:
            return 2048
        # Model family defaults — updated with more accurate defaults
        if "qwen3" in mid:
            return 131072  # Qwen3 series: 128k typical
        if "qwen2.5" in mid or "qwen2-" in mid:
            return 131072
        if "llama3" in mid or "llama-3" in mid:
            return 131072  # Llama 3: 128k context
        if "llama2" in mid or "llama-2" in mid:
            return 4096  # Llama 2: 4k context
        if "mistral" in mid:
            return 32768  # Mistral: 32k context
        if "mixtral" in mid:
            return 32768
        if "gemma-4" in mid or "gemma4" in mid:
            return 262144  # Gemma 4: 256k context
        if "gemma2" in mid or "gemma-2" in mid:
            return 8192  # Gemma 2: 8k context
        if "gemma" in mid:
            return 8192
        if "phi4" in mid or "phi-4" in mid:
            return 131072
        if "phi3" in mid or "phi-3" in mid:
            return 131072
        if "command-r" in mid:
            return 131072  # Cohere Command-R: 128k
        if "deepseek" in mid:
            # DeepSeek model family has varied context windows
            if "v4" in mid:
                return 1_000_000  # DeepSeek V4 Flash/Pro: 1M context
            if "v3.2" in mid:
                return 131_072  # DeepSeek V3.2: 128k context
            if "v3" in mid:
                return 65_536  # DeepSeek-V3 (including deepseek-chat alias): 64k
            if "coder" in mid:
                return 65_536  # DeepSeek-Coder: 64k
            if "reasoner" in mid or "r1" in mid:
                return 65_536  # DeepSeek-R1: 64k
            if "chat" in mid:
                return 65_536  # deepseek-chat is the V3 alias: 64k
            return 131_072  # Default for future DeepSeek models
        if "yi-" in mid:
            return 32768  # Yi: 32k
        if "falcon" in mid:
            return 8192
        if "stablelm" in mid:
            return 4096
        if "gpt-4" in mid or "gpt4" in mid:
            return 128000
        if "gpt-3.5" in mid or "gpt3.5" in mid:
            return 16384
        if "claude-3" in mid or "claude3" in mid:
            return 200000
        if "claude" in mid:
            return 100000
        return 32768

    async def apply_to_settings(self, settings: JSSettings) -> JSSettings:
        del settings
        raise RuntimeError(
            "Raw settings discovery is disabled; use the Echo "
            "control_provider_discover effect"
        )

    async def close(self) -> None:
        return None
