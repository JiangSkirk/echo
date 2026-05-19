"""Intelligent model routing with fallback and cost optimization."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from js.config import JSSettings, ModelConfig
from js.models.providers import (
    ChatMessage,
    ChatResponse,
    ModelProvider,
    OpenAICompatibleProvider,
)


@dataclass
class RoutingDecision:
    provider: ModelProvider
    model: str
    provider_name: str
    reason: str


class ModelRouter:
    """Routes requests to appropriate models with health checks and fallback."""

    def __init__(self, settings: JSSettings) -> None:
        self.settings = settings
        self._providers: dict[str, ModelProvider] = {}
        self._model_map: dict[str, tuple[str, ModelConfig]] = {}  # model_id -> (provider_name, config)
        self._init_providers()

    def _init_providers(self) -> None:
        for p_config in self.settings.providers:
            provider = OpenAICompatibleProvider(p_config)
            self._providers[p_config.name] = provider
            for m in p_config.models:
                full_id = f"{p_config.name}/{m.id}"
                self._model_map[full_id] = (p_config.name, m)
                self._model_map[m.id] = (p_config.name, m)

    def add_provider(self, name: str, provider: ModelProvider, models: list[ModelConfig]) -> None:
        self._providers[name] = provider
        for m in models:
            self._model_map[m.id] = (name, m)
            self._model_map[f"{name}/{m.id}"] = (name, m)

    def remove_provider(self, name: str) -> bool:
        """Remove a provider and all its model mappings."""
        if name not in self._providers:
            return False
        del self._providers[name]
        self._model_map = {
            k: v for k, v in self._model_map.items() if v[0] != name
        }
        return True

    def get_model_config(self, model_id: str) -> ModelConfig | None:
        """Get model config by ID."""
        entry = self._model_map.get(model_id)
        if entry:
            return entry[1]
        return None

    def select_model(self, task_complexity: str = "medium", preferred: str | None = None) -> RoutingDecision:
        """Select best model for task."""
        if preferred and preferred in self._model_map:
            provider_name, config = self._model_map[preferred]
            return RoutingDecision(
                provider=self._providers[provider_name],
                model=config.id,
                provider_name=provider_name,
                reason=f"User preferred: {preferred}",
            )

        # Simple heuristic: pick first available
        for full_id, (provider_name, config) in self._model_map.items():
            if "/" not in full_id:  # Avoid duplicates
                return RoutingDecision(
                    provider=self._providers[provider_name],
                    model=config.id,
                    provider_name=provider_name,
                    reason=f"Default model: {config.id}",
                )

        raise RuntimeError("No models configured")

    async def chat(
        self,
        messages: list[ChatMessage],
        model: str | None = None,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
    ) -> ChatResponse:
        """Send chat request with automatic fallback."""
        decision = self.select_model(preferred=model)
        errors: list[str] = []

        try:
            return await decision.provider.chat(
                messages=messages,
                model=decision.model,
                tools=tools,
                temperature=temperature,
            )
        except Exception as e:
            errors.append(f"{decision.provider_name}/{decision.model}: {e}")

        # Try fallback providers
        for name, provider in self._providers.items():
            if name == decision.provider_name:
                continue
            try:
                # Use provider's default model
                fallback_model = next(
                    (m.id for mid, (p, m) in self._model_map.items() if p == name and "/" not in mid),
                    "",
                )
                if not fallback_model:
                    continue
                return await provider.chat(
                    messages=messages,
                    model=fallback_model,
                    tools=tools,
                    temperature=temperature,
                )
            except Exception as e:
                errors.append(f"{name}: {e}")

        raise RuntimeError(f"All providers failed: {'; '.join(errors)}")

    async def health_check(self) -> dict[str, bool]:
        """Check health of all providers."""
        results: dict[str, bool] = {}
        for name, provider in self._providers.items():
            results[name] = await provider.health_check()
        return results

    async def close(self) -> None:
        """Close all provider connections."""
        for provider in self._providers.values():
            try:
                await provider.close()
            except Exception:
                pass
