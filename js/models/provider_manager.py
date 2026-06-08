"""Dynamic provider management with persistent storage."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from js.config import ModelProviderConfig
from js.security.secrets import SecretManager
from js.utils.log import get_logger

logger = get_logger("js.models.provider_manager")


def _secret_key_name(provider_name: str) -> str:
    """Generate a SecretManager key name for a provider's API key."""
    return f"provider_apikey_{provider_name}"


class ProviderManagerError(Exception):
    """Raised when provider management operations fail."""


class ProviderManager:
    """Manages dynamically-added model providers persisted to disk."""

    def __init__(self, state_dir: Path) -> None:
        self.state_dir = Path(state_dir)
        self._providers: list[ModelProviderConfig] = []
        self._path = self.state_dir / "providers.json"
        self._load()

    def _load(self) -> None:
        if not self._path.exists():
            return
        secrets = SecretManager(self.state_dir)
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
            loaded: list[ModelProviderConfig] = []
            for p_data in data.get("providers", []):
                name = p_data.get("name", "")
                # Restore API key from SecretManager if missing in JSON
                if not p_data.get("api_key") and name:
                    p_data["api_key"] = secrets.retrieve(_secret_key_name(name)) or ""
                loaded.append(ModelProviderConfig(**p_data))
            self._providers = loaded
        except json.JSONDecodeError as e:
            # Backup corrupt file instead of silently discarding
            backup = self._path.with_suffix(".json.bak")
            try:
                self._path.rename(backup)
                logger.warning(f"providers.json corrupt, backed up to {backup}: {e}")
            except OSError:
                logger.error(f"providers.json corrupt and backup failed: {e}")
            self._providers = []
        except Exception as e:
            logger.error(f"Failed to load providers: {e}")
            self._providers = []

    def _save(self) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        secrets = SecretManager(self.state_dir)
        try:
            # Store API keys in SecretManager, exclude from JSON
            for p in self._providers:
                if p.api_key:
                    secrets.store(_secret_key_name(p.name), p.api_key, category="provider")
            data = {
                "providers": [
                    p.model_dump(mode="json", exclude={"api_key"}) for p in self._providers
                ]
            }
            self._path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except OSError as e:
            logger.error(f"Failed to save providers: {e}")
            raise ProviderManagerError(f"Failed to save providers: {e}") from e

    def get_all(self) -> list[ModelProviderConfig]:
        return list(self._providers)

    def get(self, name: str) -> ModelProviderConfig | None:
        for p in self._providers:
            if p.name == name:
                return p
        return None

    def add(self, config: ModelProviderConfig) -> None:
        # Remove existing with same name
        self._providers = [p for p in self._providers if p.name != config.name]
        self._providers.append(config)
        self._save()

    def remove(self, name: str) -> bool:
        before = len(self._providers)
        self._providers = [p for p in self._providers if p.name != name]
        if len(self._providers) < before:
            self._save()
            return True
        return False

    def update_api_key(self, name: str, api_key: str) -> bool:
        """Update the API key for an existing dynamic provider."""
        for p in self._providers:
            if p.name == name:
                p.api_key = api_key
                self._save()
                return True
        return False

    @staticmethod
    async def discover_models(
        base_url: str, api_key: str | None = None, *, allow_private: bool = False
    ) -> dict[str, Any]:
        """Query an OpenAI-compatible endpoint for available models.

        Returns {"models": [...]} on success or {"error": "..."} on failure.
        Each model dict includes id, name, and context_window when available.

        SSRF policy: loopback is allowed ONLY when the literal hostname is
        ``localhost`` / ``127.0.0.1`` / ``::1`` — a domain that merely *resolves*
        to loopback (e.g. ``127.0.0.1.nip.io``, ``127.1``, ``2130706433``) is
        treated as remote and rejected by default, defeating DNS rebinding.
        Private-network (RFC1918) hosts require ``allow_private=True`` (driven by
        ``security.allow_private_model_providers``).  Link-local / metadata /
        reserved / multicast destinations are ALWAYS rejected.
        """
        import httpx

        from js.security.net_guard import OutboundURLError, PinnedTransport, resolve_and_validate

        # Only explicit local literals get the loopback exemption; everything
        # else (including loopback-resolving domains) must clear the remote
        # policy, where loopback is forbidden.
        hostname = (urlparse(base_url).hostname or "").lower()
        is_local_literal = hostname in ("localhost", "127.0.0.1", "::1")
        try:
            validated_ips = resolve_and_validate(
                base_url,
                allow_loopback=is_local_literal,
                allow_private=allow_private,
            )
        except OutboundURLError as exc:
            return {"error": f"目标地址被安全策略拒绝: {exc}"}

        headers: dict[str, str] = {}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        # Try to get enhanced context info for known local providers
        context_overrides: dict[str, int] = {}
        if "127.0.0.1:1234" in base_url or "localhost:1234" in base_url:
            try:
                async with httpx.AsyncClient(timeout=5.0, trust_env=False) as client:
                    root = base_url.rstrip("/").rsplit("/v1", 1)[0]
                    resp = await client.get(f"{root}/api/v0/models")
                    if resp.status_code == 200:
                        for m in resp.json().get("data", []):
                            ctx = m.get("max_context_length") or m.get("loaded_context_length")
                            if m.get("id") and ctx:
                                context_overrides[m["id"]] = int(ctx)
            except Exception:
                pass

        try:
            from js.security.net_guard import PinnedTransport

            async with httpx.AsyncClient(
                transport=PinnedTransport(
                    validated_ips[0],
                    verify=True,
                ),
                timeout=30.0,
                trust_env=False,
            ) as client:
                resp = await client.get(
                    f"{base_url.rstrip('/')}/models", headers=headers
                )
                resp.raise_for_status()
                data = resp.json()
                models = data.get("data", [])
                result_models = []
                for m in models:
                    model_id = m.get("id", "")
                    if not model_id:
                        continue
                    # Priority: v0 API context > v1 API context_length > name inference
                    ctx = context_overrides.get(model_id)
                    if ctx is None:
                        ctx = m.get("context_length") or m.get("max_context_length")
                    if ctx is None:
                        from js.models.discovery import LocalModelDiscovery
                        ctx = LocalModelDiscovery._infer_context_window(model_id)
                    result_models.append({
                        "id": model_id,
                        "name": m.get("name", model_id.split("/")[-1]),
                        "context_window": int(ctx),
                    })
                return {"models": result_models}
        except httpx.ConnectTimeout:
            return {"error": "连接超时，请检查网络或 IP 地址是否正确"}
        except httpx.ConnectError as e:
            return {"error": f"无法连接到该地址: {e}"}
        except httpx.HTTPStatusError as e:
            return {"error": f"服务端返回错误: HTTP {e.response.status_code}"}
        except Exception as e:
            return {"error": f"发现失败: {e}"}
