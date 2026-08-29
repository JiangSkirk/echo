"""Dynamic provider management with persistent storage."""

from __future__ import annotations

import importlib
import json
import os
import stat
import tempfile
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
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


def static_provider_secret_key_name(provider_name: str) -> str:
    """Return the separate secret name used by file-configured providers."""
    return f"static_provider_apikey_{provider_name}"


def hydrate_static_provider_api_keys(
    providers: list[ModelProviderConfig],
    secret_manager: SecretManager,
) -> None:
    """Restore locally encrypted UI credentials before router construction."""
    from js.orin.stage_c import in_process_provider_tokens_blocked

    if in_process_provider_tokens_blocked():
        raise RuntimeError("Echo must not hold provider tokens under orin.enforce")
    for provider in providers:
        if provider.api_key:
            continue
        stored = secret_manager.retrieve(static_provider_secret_key_name(provider.name))
        if stored:
            provider.api_key = stored


class ProviderManagerError(Exception):
    """Raised when provider management operations fail."""


class ProviderManager:
    """Manages dynamically-added model providers persisted to disk."""

    _MAX_PROVIDER_FILE_BYTES = 10 * 1024 * 1024
    _MAX_PROVIDERS = 1000

    def __init__(self, state_dir: Path) -> None:
        unresolved_state = Path(state_dir).expanduser()
        unresolved_state.mkdir(parents=True, exist_ok=True)
        self.state_dir = unresolved_state.resolve(strict=True)
        self._providers: list[ModelProviderConfig] = []
        self._path = self.state_dir / "providers.json"
        self._lock_path = self.state_dir / "providers.lock"
        self._thread_lock = threading.RLock()
        self._load()

    def _load(self) -> None:
        try:
            with self._locked():
                self._providers = self._read_unlocked()
        except ProviderManagerError:
            logger.error("Failed to load providers safely", exc_info=True)
            self._providers = []

    def _save(self) -> None:
        snapshot = self.get_all()

        def replace_all(
            _current: list[ModelProviderConfig],
        ) -> tuple[list[ModelProviderConfig], bool]:
            return ([provider.model_copy(deep=True) for provider in snapshot], True)

        self._transaction(replace_all)

    @contextmanager
    def _locked(self) -> Iterator[None]:
        flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_CLOEXEC", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            lock_fd = os.open(self._lock_path, flags, 0o600)
        except OSError as exc:
            raise ProviderManagerError("Provider store lock is unavailable") from exc
        try:
            metadata = os.fstat(lock_fd)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise ProviderManagerError("Provider store lock is unsafe")
            os.fchmod(lock_fd, 0o600)
            with self._thread_lock:
                self._acquire_file_lock(lock_fd)
                try:
                    yield
                finally:
                    self._release_file_lock(lock_fd)
        finally:
            os.close(lock_fd)

    @staticmethod
    def _acquire_file_lock(lock_fd: int) -> None:
        if os.name == "nt":
            msvcrt: Any = importlib.import_module("msvcrt")
            if os.fstat(lock_fd).st_size == 0:
                os.write(lock_fd, b"\0")
            os.lseek(lock_fd, 0, os.SEEK_SET)
            msvcrt.locking(lock_fd, msvcrt.LK_LOCK, 1)
            return
        fcntl: Any = importlib.import_module("fcntl")
        fcntl.flock(lock_fd, fcntl.LOCK_EX)

    @staticmethod
    def _release_file_lock(lock_fd: int) -> None:
        if os.name == "nt":
            msvcrt: Any = importlib.import_module("msvcrt")
            os.lseek(lock_fd, 0, os.SEEK_SET)
            msvcrt.locking(lock_fd, msvcrt.LK_UNLCK, 1)
            return
        fcntl: Any = importlib.import_module("fcntl")
        fcntl.flock(lock_fd, fcntl.LOCK_UN)

    def _read_unlocked(self) -> list[ModelProviderConfig]:
        raw = self._read_provider_bytes_unlocked()
        if raw is None:
            return []
        try:
            data = json.loads(raw.decode("utf-8"))
            if not isinstance(data, dict):
                raise ValueError("provider store schema is invalid")
            provider_data = data.get("providers")
            if not isinstance(provider_data, list):
                raise ValueError("provider store schema is invalid")
            if len(provider_data) > self._MAX_PROVIDERS:
                raise ValueError("provider store exceeds the provider limit")
            secret_manager = SecretManager(self.state_dir)
            loaded: list[ModelProviderConfig] = []
            seen: set[str] = set()
            for item in provider_data:
                if not isinstance(item, dict):
                    raise ValueError("provider entry is invalid")
                payload = dict(item)
                name = payload.get("name", "")
                if not isinstance(name, str) or not name or name in seen:
                    raise ValueError("provider name is invalid or duplicated")
                seen.add(name)
                payload.pop("api_key", None)
                payload["api_key"] = secret_manager.retrieve(_secret_key_name(name)) or ""
                loaded.append(ModelProviderConfig(**payload))
            return loaded
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
            self._quarantine_corrupt_unlocked()
            logger.error("Corrupt provider store quarantined", exc_info=True)
            return []

    def _read_provider_bytes_unlocked(self) -> bytes | None:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            file_fd = os.open(self._path, flags)
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise ProviderManagerError("Provider store is unavailable") from exc
        try:
            before = os.fstat(file_fd)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise ProviderManagerError("Provider store is unsafe")
            if before.st_size > self._MAX_PROVIDER_FILE_BYTES:
                raise ProviderManagerError("Provider store exceeds the size limit")
            chunks: list[bytes] = []
            bytes_read = 0
            while True:
                chunk = os.read(
                    file_fd,
                    min(
                        1024 * 1024,
                        self._MAX_PROVIDER_FILE_BYTES + 1 - bytes_read,
                    ),
                )
                if not chunk:
                    break
                chunks.append(chunk)
                bytes_read += len(chunk)
                if bytes_read > self._MAX_PROVIDER_FILE_BYTES:
                    raise ProviderManagerError("Provider store exceeds the size limit")
            after = os.fstat(file_fd)
        finally:
            os.close(file_fd)
        before_fingerprint = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        after_fingerprint = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if before_fingerprint != after_fingerprint or bytes_read != before.st_size:
            raise ProviderManagerError("Provider store changed while being read")
        return b"".join(chunks)

    def _quarantine_corrupt_unlocked(self) -> None:
        if not self._path.exists():
            return
        backup = self.state_dir / f"providers.corrupt-{time.time_ns()}.json"
        try:
            os.replace(self._path, backup)
            self._fsync_directory()
        except OSError:
            logger.error("Could not quarantine corrupt provider store", exc_info=True)

    def _sync_secrets_unlocked(
        self,
        providers: list[ModelProviderConfig],
        names: set[str],
    ) -> None:
        desired = {provider.name: provider.api_key for provider in providers}
        secret_manager = SecretManager(self.state_dir)
        for name in names:
            value = desired.get(name)
            if value:
                secret_manager.store(
                    _secret_key_name(name),
                    value,
                    category="provider",
                )
            else:
                secret_manager.delete(_secret_key_name(name))

    def _atomic_write_unlocked(self, providers: list[ModelProviderConfig]) -> None:
        data = {
            "providers": [
                provider.model_dump(mode="json", exclude={"api_key"}) for provider in providers
            ]
        }
        payload = (json.dumps(data, indent=2, sort_keys=True) + "\n").encode("utf-8")
        temp_path: Path | None = None
        try:
            temp_fd, raw_temp_path = tempfile.mkstemp(
                prefix=".providers-",
                suffix=".tmp",
                dir=self.state_dir,
            )
            temp_path = Path(raw_temp_path)
            os.fchmod(temp_fd, 0o600)
            with os.fdopen(temp_fd, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_path, self._path)
            temp_path = None
            self._fsync_directory()
        except OSError as exc:
            raise ProviderManagerError("Failed to publish provider store atomically") from exc
        finally:
            if temp_path is not None:
                try:
                    temp_path.unlink()
                except FileNotFoundError:
                    pass
                except OSError:
                    logger.warning("Could not remove provider store staging file")

    def _fsync_directory(self) -> None:
        directory_fd = os.open(self.state_dir, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)

    def _transaction(
        self,
        mutation: Callable[
            [list[ModelProviderConfig]],
            tuple[list[ModelProviderConfig], bool],
        ],
    ) -> bool:
        with self._locked():
            current = self._read_unlocked()
            working = [provider.model_copy(deep=True) for provider in current]
            updated, result = mutation(working)
            if len(updated) > self._MAX_PROVIDERS:
                raise ProviderManagerError("Provider limit exceeded")
            touched_names = {provider.name for provider in current} | {
                provider.name for provider in updated
            }
            try:
                self._sync_secrets_unlocked(updated, touched_names)
                self._atomic_write_unlocked(updated)
            except Exception as exc:
                try:
                    self._sync_secrets_unlocked(current, touched_names)
                except Exception:
                    logger.critical("Provider secret rollback failed", exc_info=True)
                if isinstance(exc, ProviderManagerError):
                    raise
                raise ProviderManagerError("Provider transaction failed") from exc
            self._providers = [provider.model_copy(deep=True) for provider in updated]
            return result

    def get_all(self) -> list[ModelProviderConfig]:
        with self._thread_lock:
            return [provider.model_copy(deep=True) for provider in self._providers]

    def get(self, name: str) -> ModelProviderConfig | None:
        with self._thread_lock:
            for provider in self._providers:
                if provider.name == name:
                    return provider.model_copy(deep=True)
        return None

    def add(self, config: ModelProviderConfig) -> None:
        if not isinstance(config, ModelProviderConfig):
            raise TypeError("config must be a ModelProviderConfig")
        candidate = config.model_copy(deep=True)

        def add_provider(
            current: list[ModelProviderConfig],
        ) -> tuple[list[ModelProviderConfig], bool]:
            current = [provider for provider in current if provider.name != candidate.name]
            current.append(candidate.model_copy(deep=True))
            return current, True

        self._transaction(add_provider)

    def remove(self, name: str) -> bool:
        def remove_provider(
            current: list[ModelProviderConfig],
        ) -> tuple[list[ModelProviderConfig], bool]:
            updated = [provider for provider in current if provider.name != name]
            return updated, len(updated) < len(current)

        return self._transaction(remove_provider)

    def update_api_key(self, name: str, api_key: str) -> bool:
        """Update the API key for an existing dynamic provider."""

        def update_provider(
            current: list[ModelProviderConfig],
        ) -> tuple[list[ModelProviderConfig], bool]:
            for provider in current:
                if provider.name == name:
                    provider.api_key = api_key
                    return current, True
            return current, False

        return self._transaction(update_provider)

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

        try:
            async with httpx.AsyncClient(
                transport=PinnedTransport(
                    validated_ips[0],
                    verify=True,
                ),
                timeout=30.0,
                trust_env=False,
            ) as client:
                # Enhanced LM Studio metadata must use the same DNS-validated,
                # IP-pinned transport as the authoritative /v1/models call.
                context_overrides: dict[str, int] = {}
                if "127.0.0.1:1234" in base_url or "localhost:1234" in base_url:
                    try:
                        root = base_url.rstrip("/").rsplit("/v1", 1)[0]
                        metadata = await client.get(
                            f"{root}/api/v0/models",
                            timeout=httpx.Timeout(5.0),
                        )
                        if metadata.status_code == 200:
                            for item in metadata.json().get("data", []):
                                context = item.get("max_context_length") or item.get(
                                    "loaded_context_length"
                                )
                                if item.get("id") and context:
                                    context_overrides[item["id"]] = int(context)
                    except Exception:
                        pass

                resp = await client.get(f"{base_url.rstrip('/')}/models", headers=headers)
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
                    result_models.append(
                        {
                            "id": model_id,
                            "name": m.get("name", model_id.split("/")[-1]),
                            "context_window": int(ctx),
                        }
                    )
                return {"models": result_models}
        except httpx.ConnectTimeout:
            return {"error": "连接超时，请检查网络或 IP 地址是否正确"}
        except httpx.ConnectError as e:
            from js.models.capability import sanitize_provider_error

            return {
                "error": sanitize_provider_error(
                    f"无法连接到该地址: {e}",
                    api_key=api_key,
                )
            }
        except httpx.HTTPStatusError as e:
            return {"error": f"服务端返回错误: HTTP {e.response.status_code}"}
        except Exception as e:
            from js.models.capability import sanitize_provider_error

            return {
                "error": sanitize_provider_error(
                    f"发现失败: {e}",
                    api_key=api_key,
                )
            }
