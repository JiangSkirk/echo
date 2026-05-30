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
    ]

    # Common ports used by local LLM servers
    COMMON_PORTS = [1234, 11434, 8080, 5000, 8000, 3000, 5001]

    def __init__(self, timeout: float = 3.0) -> None:
        self.timeout = timeout
        # Disable system proxies for local server discovery to avoid
        # 502 errors when a system proxy forwards loopback traffic.
        # httpx 0.28 reads HTTP_PROXY/HTTPS_PROXY env vars by default;
        # trust_env=False disables this behaviour.
        self._client = httpx.AsyncClient(
            trust_env=False,
            timeout=httpx.Timeout(timeout),
        )

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

    async def scan_lan(self, subnet_prefix: str = "192.168") -> list[DiscoveredProvider]:
        """Scan the local network for model servers on common ports.

        Args:
            subnet_prefix: e.g. '192.168' or '10.0'
        """
        # Detect our own subnet
        own_ip = self._get_own_ip(subnet_prefix)
        if not own_ip:
            logger.warning(f"Could not detect own IP in subnet {subnet_prefix}")
            return []

        # Build IP range (e.g. 192.168.31.x)
        parts = own_ip.split(".")
        if len(parts) != 4:
            return []
        base = ".".join(parts[:3])

        # Probe .1 to .254 on common ports
        probes: list[dict[str, str]] = []
        for port in self.COMMON_PORTS:
            for host in range(1, 255):
                ip = f"{base}.{host}"
                probes.append({
                    "name": f"lan-{ip}-{port}",
                    "url": f"http://{ip}:{port}/v1",
                    "api_key": "",
                })

        # Limit concurrent probes to avoid flooding the network
        semaphore = asyncio.Semaphore(50)
        discovered: list[DiscoveredProvider] = []
        seen_urls: set[str] = set()

        async def _probe_lan(p: dict[str, str]) -> DiscoveredProvider | None:
            async with semaphore:
                return await self._probe(p)

        # Probe in batches to avoid overwhelming the event loop
        batch_size = 200
        for i in range(0, len(probes), batch_size):
            batch = probes[i:i + batch_size]
            results = await asyncio.gather(*[_probe_lan(p) for p in batch], return_exceptions=True)
            for r in results:
                if not isinstance(r, DiscoveredProvider) or r is None:
                    continue
                if r.healthy and r.base_url not in seen_urls:
                    seen_urls.add(r.base_url)
                    discovered.append(r)

        logger.info(f"LAN scan found {len(discovered)} providers in subnet {base}.x")
        return discovered

    def _get_own_ip(self, subnet_prefix: str) -> str | None:
        """Get the local IP address that belongs to the given subnet prefix."""
        import socket
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(1)
            try:
                # Connect to a dummy address to trigger interface selection
                s.connect(("8.8.8.8", 80))
                ip_str: str = s.getsockname()[0]
                if ip_str.startswith(subnet_prefix):
                    return ip_str
                # If primary IP doesn't match prefix, try to find one that does
                return self._find_ip_in_subnet(subnet_prefix)
            finally:
                s.close()
        except Exception:
            return self._find_ip_in_subnet(subnet_prefix)

    def _find_ip_in_subnet(self, subnet_prefix: str) -> str | None:
        import socket
        from typing import cast
        try:
            hostname = socket.gethostname()
            addrs = socket.getaddrinfo(hostname, None, socket.AF_INET)
            for addr in addrs:
                ip_str = cast("str", addr[4][0])
                if ip_str.startswith(subnet_prefix):
                    return ip_str
            # Fallback: return any non-loopback IP
            for addr in addrs:
                ip_str = cast("str", addr[4][0])
                if not ip_str.startswith("127."):
                    return ip_str
        except Exception:
            logger.warning('Operation failed', exc_info=True)
        return None

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

            # Build a map of model_id -> context_window from provider-specific APIs
            context_overrides: dict[str, int] = {}

            # For LM Studio: query v0 API for actual context lengths
            if probe["name"] == "lmstudio":
                context_overrides = await self._lmstudio_context_lengths(probe["url"])

            # For Ollama: try to get context lengths from tags API
            if probe["name"] == "ollama":
                context_overrides = await self._ollama_context_lengths(probe["url"])

            models = self._parse_models(data, probe["name"], context_overrides)

            # For LM Studio: filter to only currently-loaded models via v0 API
            if probe["name"] == "lmstudio":
                loaded_ids = set(context_overrides.keys())
                models = [m for m in models if m.id in loaded_ids]

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

    async def _lmstudio_context_lengths(self, base_url: str) -> dict[str, int]:
        """Query LM Studio's v0 API for loaded models and their actual context lengths.

        Returns {model_id: max_context_length} for loaded models.
        """
        contexts: dict[str, int] = {}
        try:
            # base_url is like http://127.0.0.1:1234/v1 → strip /v1
            root = base_url.rsplit("/v1", 1)[0]
            resp = await self._client.get(f"{root}/api/v0/models", timeout=httpx.Timeout(5.0))
            if resp.status_code == 200:
                data = resp.json()
                for m in data.get("data", []):
                    if m.get("state") == "loaded":
                        model_id = m.get("id", "")
                        ctx = m.get("max_context_length") or m.get("loaded_context_length")
                        if model_id and ctx:
                            contexts[model_id] = int(ctx)
        except Exception as e:
            logger.debug(f"LM Studio v0 API context probe failed: {e}")
        return contexts

    async def _ollama_context_lengths(self, base_url: str) -> dict[str, int]:
        """Query Ollama's tags API for model context lengths.

        Returns {model_id: context_length}.
        """
        contexts: dict[str, int] = {}
        try:
            root = base_url.rsplit("/v1", 1)[0]
            resp = await self._client.get(f"{root}/api/tags", timeout=httpx.Timeout(5.0))
            if resp.status_code == 200:
                data = resp.json()
                for m in data.get("models", []):
                    model_id = m.get("name", "")
                    # Ollama doesn't expose context length in tags API,
                    # but model names may contain context markers
                    if model_id:
                        contexts[model_id] = self._infer_context_window(model_id)
        except Exception as e:
            logger.debug(f"Ollama tags API context probe failed: {e}")
        return contexts

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

    def _infer_context_window(self, model_id: str) -> int:
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

    def to_provider_config(self, discovered: DiscoveredProvider) -> ModelProviderConfig:
        return ModelProviderConfig(
            name=discovered.provider_type,
            base_url=discovered.base_url,
            api_key="lm-studio" if discovered.provider_type == "lmstudio" else "ollama",
            timeout=300.0,
            max_retries=3,
            default_model=discovered.models[0].id if discovered.models else "",
            models=discovered.models,
        )

    async def apply_to_settings(self, settings: JSSettings) -> JSSettings:
        """Auto-discover and inject local providers into settings."""
        discovered = await self.discover_all()
        existing_names = {p.name for p in settings.providers}
        existing_urls = {p.base_url for p in settings.providers}
        existing_model_ids = {m.id for m in settings.models}

        for d in discovered:
            # Deduplicate by base_url (127.0.0.1 and localhost are the same host)
            if d.base_url in existing_urls:
                logger.debug(f"Skipping duplicate provider at {d.base_url}")
                continue
            if d.provider_type in existing_names:
                logger.debug(f"Skipping duplicate provider type {d.provider_type}")
                continue
            config = self.to_provider_config(d)
            settings.providers.append(config)
            for m in d.models:
                if m.id not in existing_model_ids:
                    settings.models.append(m)
                    existing_model_ids.add(m.id)
            logger.info(
                f"Auto-configured {d.provider_type} at {d.base_url} with {len(d.models)} models"
            )

        return settings

    async def close(self) -> None:
        await self._client.aclose()
