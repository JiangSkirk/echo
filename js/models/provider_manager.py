"""Dynamic provider management with persistent storage."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

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

    @staticmethod
    async def discover_models(
        base_url: str, api_key: str | None = None
    ) -> dict[str, Any]:
        """Query an OpenAI-compatible endpoint for available models.

        Returns {"models": [...]} on success or {"error": "..."} on failure.
        Each model dict includes id, name, and context_window when available.
        """
        import httpx

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
            async with httpx.AsyncClient(timeout=30.0, trust_env=False) as client:
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
                        ctx = LocalModelDiscovery._infer_context_window(None, model_id)
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
