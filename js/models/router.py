"""Intelligent model routing with fallback and cost optimization."""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any

from cachetools import TTLCache

from js.config import JSSettings, ModelConfig
from js.models.providers import (
    ChatMessage,
    ChatResponse,
    ModelProvider,
    OpenAICompatibleProvider,
)
from js.utils.log import get_logger

logger = get_logger("js.models.router")


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
        self._routing_cache: TTLCache[str, RoutingDecision] = TTLCache(maxsize=50, ttl=10)
        self._init_providers()

    def _init_providers(self) -> None:
        for p_config in self.settings.providers:
            provider = OpenAICompatibleProvider(p_config)
            self._providers[p_config.name] = provider
            # Register explicitly-configured models
            for m in p_config.models:
                full_id = f"{p_config.name}/{m.id}"
                self._model_map[full_id] = (p_config.name, m)
                self._model_map[m.id] = (p_config.name, m)
            # Ensure default_model is always reachable even if not in models list
            if p_config.default_model and p_config.default_model not in self._model_map:
                default_cfg = ModelConfig(
                    id=p_config.default_model,
                    name=p_config.default_model,
                    provider=p_config.name,
                )
                self._model_map[p_config.default_model] = (p_config.name, default_cfg)

    def add_provider(self, name: str, provider: ModelProvider, models: list[ModelConfig]) -> None:
        self._providers[name] = provider
        for m in models:
            self._model_map[m.id] = (name, m)
            self._model_map[f"{name}/{m.id}"] = (name, m)
        self._routing_cache.clear()

    def remove_provider(self, name: str) -> bool:
        """Remove a provider and all its model mappings."""
        if name not in self._providers:
            return False
        del self._providers[name]
        self._model_map = {
            k: v for k, v in self._model_map.items() if v[0] != name
        }
        self._routing_cache.clear()
        return True

    def get_model_config(self, model_id: str) -> ModelConfig | None:
        """Get model config by ID."""
        entry = self._model_map.get(model_id)
        if entry:
            return entry[1]
        return None

    async def _provider_healthy(self, provider: ModelProvider) -> bool:
        """Check if provider is healthy and circuit is not OPEN."""
        try:
            # Fast path: check circuit state without network call
            if hasattr(provider, 'circuit'):
                circuit_state = await provider.circuit.state()
                if circuit_state.value == "open":
                    return False
            # Network health check
            return await provider.health_check()
        except Exception:
            return False

    async def select_model(
        self,
        _task_complexity: str = "medium",  # Reserved for future complexity-based routing
        preferred: str | None = None,
    ) -> RoutingDecision:
        """Select best model for task, skipping unhealthy providers."""
        cache_key = preferred or "__default__"
        cached: RoutingDecision | None = self._routing_cache.get(cache_key)
        if cached is not None:
            return cached

        if preferred and preferred in self._model_map:
            provider_name, config = self._model_map[preferred]
            provider = self._providers[provider_name]
            if await self._provider_healthy(provider):
                decision = RoutingDecision(
                    provider=provider,
                    model=config.id,
                    provider_name=provider_name,
                    reason=f"User preferred: {preferred}",
                )
                self._routing_cache[cache_key] = decision
                return decision

        # Build a unified view of provider → default_model from both
        # settings.providers (static config) and _model_map (runtime adds).
        provider_defaults: dict[str, str] = {}
        for p_config in self.settings.providers:
            if p_config.default_model:
                provider_defaults[p_config.name] = p_config.default_model
            elif p_config.models:
                chat_models = [m for m in p_config.models if "embed" not in m.id.lower()]
                candidates = chat_models if chat_models else p_config.models
                if candidates:
                    provider_defaults[p_config.name] = candidates[0].id

        # Fallback: infer from _model_map for providers added at runtime
        for full_id, (provider_name, config) in self._model_map.items():
            if provider_name not in provider_defaults and "/" not in full_id:
                provider_defaults[provider_name] = config.id

        # Select first healthy provider
        for provider_name, default_model in provider_defaults.items():
            maybe_provider = self._providers.get(provider_name)
            if maybe_provider is None:
                continue
            if await self._provider_healthy(maybe_provider):
                decision = RoutingDecision(
                    provider=maybe_provider,
                    model=default_model,
                    provider_name=provider_name,
                    reason=f"Default model: {default_model}",
                )
                self._routing_cache[cache_key] = decision
                return decision

        # Last resort: first configured provider even if unhealthy
        for provider_name, default_model in provider_defaults.items():
            maybe_provider = self._providers.get(provider_name)
            if maybe_provider is not None:
                decision = RoutingDecision(
                    provider=maybe_provider,
                    model=default_model,
                    provider_name=provider_name,
                    reason=f"Fallback (unhealthy): {default_model}",
                )
                self._routing_cache[cache_key] = decision
                return decision

        raise RuntimeError("No models configured")

    async def chat(
        self,
        messages: list[ChatMessage],
        model: str | None = None,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
    ) -> ChatResponse:
        """Send chat request with automatic fallback."""
        decision = await self.select_model(preferred=model)
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

        # Try fallback providers (skip unhealthy ones)
        for name, provider in self._providers.items():
            if name == decision.provider_name:
                continue
            try:
                if not await self._provider_healthy(provider):
                    continue
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

        # Last resort: try the original selected provider even if unhealthy
        try:
            return await decision.provider.chat(
                messages=messages,
                model=decision.model,
                tools=tools,
                temperature=temperature,
            )
        except Exception as e:
            errors.append(f"{decision.provider_name}/{decision.model} (last resort): {e}")

        raise RuntimeError(f"All providers failed: {'; '.join(errors)}")

    async def chat_stream(
        self,
        messages: list[ChatMessage],
        model: str | None = None,
        temperature: float = 0.7,
    ) -> AsyncIterator[str]:
        """Stream tokens from the selected model with fallback."""
        decision = await self.select_model(preferred=model)
        errors: list[str] = []

        try:
            async for token in decision.provider.chat_stream(
                messages=messages,
                model=decision.model,
                temperature=temperature,
            ):
                yield token
            return
        except Exception as e:
            errors.append(f"{decision.provider_name}/{decision.model}: {e}")

        # Fallback providers (skip unhealthy)
        for name, provider in self._providers.items():
            if name == decision.provider_name:
                continue
            try:
                if not await self._provider_healthy(provider):
                    continue
                fallback_model = next(
                    (m.id for mid, (p, m) in self._model_map.items() if p == name and "/" not in mid),
                    "",
                )
                if not fallback_model:
                    continue
                async for token in provider.chat_stream(
                    messages=messages,
                    model=fallback_model,
                    temperature=temperature,
                ):
                    yield token
                return
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
                logger.warning('Operation failed', exc_info=True)
