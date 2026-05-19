"""Auto-detect and configure local model providers."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

import httpx

from js.config import JSSettings, ModelConfig, ModelProviderConfig
from js.utils.log import get_logger

logger = get_logger("js.discovery")


@dataclass
class DiscoveredProvider:
    name: str
    provider_type: str  # lmstudio, ollama, mlx, openai-compatible
    base_url: str
    models: list[ModelConfig]
    healthy: bool
    latency_ms: float


class LocalModelDiscovery:
    """Probes common local model endpoints and auto-configures them."""

    PROBES = [
        {"name": "lmstudio", "url": "http://127.0.0.1:1234/v1", "api_key": "lm-studio"},
        {"name": "ollama", "url": "http://127.0.0.1:11434/v1", "api_key": "ollama"},
        {"name": "lmstudio-alt", "url": "http://localhost:1234/v1", "api_key": "lm-studio"},
        {"name": "ollama-alt", "url": "http://localhost:11434/v1", "api_key": "ollama"},
    ]

    def __init__(self, timeout: float = 3.0) -> None:
        self.timeout = timeout
        self._client = httpx.AsyncClient(timeout=httpx.Timeout(timeout))

    async def discover_all(self) -> list[DiscoveredProvider]:
        """Probe all known local endpoints concurrently."""
        tasks = [self._probe(p) for p in self.PROBES]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        discovered: list[DiscoveredProvider] = []
        seen_urls: set[str] = set()

        for r in results:
            if isinstance(r, Exception) or r is None:
                continue
            from typing import cast
            provider = cast("DiscoveredProvider", r)
            if provider.healthy and provider.base_url not in seen_urls:
                seen_urls.add(provider.base_url)
                discovered.append(provider)

        return discovered

    async def _probe(self, probe: dict[str, str]) -> DiscoveredProvider | None:
        import time
        start = time.time()
        try:
            headers = {"Authorization": f"Bearer {probe['api_key']}"} if probe.get("api_key") else {}
            resp = await self._client.get(f"{probe['url']}/models", headers=headers)
            latency = (time.time() - start) * 1000

            if resp.status_code != 200:
                return None

            data = resp.json()
            models = self._parse_models(data, probe["name"])

            return DiscoveredProvider(
                name=probe["name"],
                provider_type=probe["name"].replace("-alt", ""),
                base_url=probe["url"],
                models=models,
                healthy=True,
                latency_ms=latency,
            )
        except Exception as e:
            logger.debug(f"Probe failed for {probe['url']}: {e}")
            return None

    def _parse_models(self, data: dict[str, Any], provider_type: str) -> list[ModelConfig]:
        models: list[ModelConfig] = []
        raw_models = data.get("data", data.get("models", []))

        for m in raw_models:
            if isinstance(m, str):
                model_id = m
                name = m
            else:
                model_id = m.get("id", m.get("model", "unknown"))
                name = m.get("object", model_id)

            supports_vision = any(kw in model_id.lower() for kw in ["vision", "vl", "multimodal", "llava"])
            context = self._infer_context_window(model_id)

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

    def _infer_context_window(self, model_id: str) -> int:
        mid = model_id.lower()
        # Explicit context size markers first
        if "32k" in mid:
            return 32768
        if "128k" in mid:
            return 131072
        if "256k" in mid:
            return 262144
        if "8k" in mid:
            return 8192
        if "4k" in mid:
            return 4096
        # Model family defaults
        if any(x in mid for x in ["qwen3", "llama3", "mistral", "gemma"]):
            return 128000
        return 32768

    def to_provider_config(self, discovered: DiscoveredProvider) -> ModelProviderConfig:
        return ModelProviderConfig(
            name=discovered.provider_type,
            base_url=discovered.base_url,
            api_key="lm-studio" if discovered.provider_type == "lmstudio" else "ollama",
            timeout=120.0,
            max_retries=3,
            default_model=discovered.models[0].id if discovered.models else "",
            models=discovered.models,
        )

    async def apply_to_settings(self, settings: JSSettings) -> JSSettings:
        """Auto-discover and inject local providers into settings."""
        discovered = await self.discover_all()
        existing_names = {p.name for p in settings.providers}

        for d in discovered:
            if d.provider_type not in existing_names:
                config = self.to_provider_config(d)
                settings.providers.append(config)
                settings.models.extend(d.models)
                logger.info(
                    f"Auto-configured {d.provider_type} at {d.base_url} with {len(d.models)} models"
                )

        return settings

    async def close(self) -> None:
        await self._client.aclose()
