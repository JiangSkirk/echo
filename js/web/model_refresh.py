"""Background model-list refresh for local and cloud providers.

Extracted from ``server.py``.  Both refreshes are throttled (process-wide) so
the dashboard's frequent ``/api/models`` polls don't hammer local model servers
or cloud ``/v1/models`` endpoints.  All calls are best-effort and never raise
into the caller.
"""

from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

from js.config import ModelConfig
from js.models.provider_manager import ProviderManager
from js.models.providers import OpenAICompatibleProvider
from js.utils.log import get_logger

if TYPE_CHECKING:
    from js.agent import JSAgent

logger = get_logger("js.web.model_refresh")

# Throttle windows (seconds).
_CLOUD_REFRESH_INTERVAL = 60.0
_LOCAL_REFRESH_INTERVAL = 15.0

# Process-wide throttle state (one web server process per run).
_last_cloud_refresh: float = 0.0
_last_local_refresh: float = 0.0

_LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "0.0.0.0", "::1")


def reset_throttle() -> None:
    """Reset the refresh throttle timers.

    Called once per ``create_app`` so behaviour matches the original
    per-app closure state (and keeps tests that build a fresh app isolated).
    """
    global _last_cloud_refresh, _last_local_refresh
    _last_cloud_refresh = 0.0
    _last_local_refresh = 0.0


def maybe_refresh_models_async(agent: JSAgent) -> None:
    """Trigger model refreshes in the background; do not block the caller."""
    try:
        asyncio.create_task(refresh_local_provider_models(agent))
        asyncio.create_task(refresh_cloud_provider_models(agent))
    except Exception:
        pass


async def refresh_cloud_provider_models(agent: JSAgent) -> None:
    """Refresh model lists for cloud providers via their /v1/models API.

    Throttled to at most once every 60 seconds.
    """
    global _last_cloud_refresh
    now = time.time()
    if now - _last_cloud_refresh < _CLOUD_REFRESH_INTERVAL:
        return
    _last_cloud_refresh = now

    import httpx

    for provider_cfg in agent.settings.providers:
        base_url = getattr(provider_cfg, "base_url", "")
        api_key = getattr(provider_cfg, "api_key", "")
        if not isinstance(base_url, str) or not api_key:
            continue
        parsed = urlparse(base_url)
        hostname = parsed.hostname or ""
        if hostname in _LOOPBACK_HOSTS:
            continue

        try:
            async with httpx.AsyncClient(timeout=15.0, trust_env=False) as client:
                resp = await client.get(
                    f"{base_url.rstrip('/')}/models",
                    headers={"Authorization": f"Bearer {api_key}"},
                )
                if resp.status_code != 200:
                    continue
                data = resp.json()
                raw_models = data.get("data", [])
                if not raw_models:
                    continue

                refreshed: list[dict[str, Any]] = []
                for m in raw_models:
                    model_id = m.get("id", "")
                    if not model_id:
                        continue
                    # Try to get context from API response or infer from name
                    api_ctx = m.get("context_length") or m.get("max_context_length")
                    if api_ctx is None:
                        from js.models.discovery import LocalModelDiscovery
                        context_window = LocalModelDiscovery._infer_context_window(model_id)
                    else:
                        context_window = int(api_ctx)
                    refreshed.append({
                        "model": ModelConfig(
                            id=model_id,
                            name=m.get("name", model_id.split("/")[-1]),
                            provider=provider_cfg.name,
                            context_window=context_window,
                            max_tokens=min(context_window // 4, 8192),
                        ),
                        "api_ctx": api_ctx,
                    })

                if refreshed:
                    # Merge with existing models: preserve cost/pricing from hardcoded presets
                    existing = {m.id: m for m in provider_cfg.models}
                    merged = []
                    for item in refreshed:
                        m = item["model"]
                        api_ctx = item["api_ctx"]
                        old = existing.get(m.id)
                        if old:
                            # If the API explicitly returned a context window, trust it;
                            # otherwise keep the preset value (more accurate for providers
                            # like DeepSeek that don't expose context lengths in their API).
                            final_ctx = int(api_ctx) if api_ctx is not None else old.context_window
                            merged.append(ModelConfig(
                                id=m.id,
                                name=old.name or m.name,
                                provider=m.provider,
                                context_window=final_ctx,
                                max_tokens=m.max_tokens or old.max_tokens,
                                supports_vision=old.supports_vision,
                                supports_tools=old.supports_tools,
                                cost_input=old.cost_input,
                                cost_output=old.cost_output,
                            ))
                        else:
                            merged.append(m)
                    provider_cfg.models = merged
        except Exception as e:
            logger.debug(f"Cloud model refresh failed for {provider_cfg.name}: {e}")


async def refresh_local_provider_models(agent: JSAgent) -> None:
    """Refresh models for local providers so LM Studio model changes show up.

    Throttled to at most one discovery call every 15 seconds to avoid
    hammering the local server on every dashboard poll.
    """
    global _last_local_refresh
    now = time.time()
    if now - _last_local_refresh < _LOCAL_REFRESH_INTERVAL:
        return
    _last_local_refresh = now

    for provider_cfg in agent.settings.providers:
        name = getattr(provider_cfg, "name", "")
        base_url = getattr(provider_cfg, "base_url", "")
        if not isinstance(base_url, str):
            continue
        parsed = urlparse(base_url)
        hostname = parsed.hostname or ""
        if hostname not in _LOOPBACK_HOSTS:
            continue
        result = await ProviderManager.discover_models(
            base_url,
            getattr(provider_cfg, "api_key", None),
        )
        discovered = result.get("models", [])
        if not discovered:
            continue
        refreshed_models = [
            ModelConfig(
                id=str(m["id"]),
                name=str(m.get("name") or m["id"]),
                provider=name,
                context_window=int(m.get("context_window", 32768)),
                max_tokens=min(int(m.get("context_window", 32768)) // 4, 8192),
            )
            for m in discovered
            if isinstance(m, dict) and m.get("id")
        ]
        if not refreshed_models:
            continue
        old_ids = [m.id for m in provider_cfg.models]
        new_ids = [m.id for m in refreshed_models]
        # Also refresh when context windows change
        old_ctx = {m.id: m.context_window for m in provider_cfg.models}
        new_ctx = {m.id: m.context_window for m in refreshed_models}
        if old_ids == new_ids and old_ctx == new_ctx:
            continue
        provider_cfg.models = refreshed_models
        provider_cfg.default_model = refreshed_models[0].id
        agent.router.add_provider(
            provider_cfg.name,
            OpenAICompatibleProvider(provider_cfg),
            refreshed_models,
        )
