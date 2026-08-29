"""Control-plane tool registration for ToolExecutorMixin."""

# mypy: disable-error-code="attr-defined"

from __future__ import annotations

import asyncio
import hashlib
import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from js.agent.base import AgentBase
from js.agent.tool_executor_constants import (
    CONTROL_CLAWHUB_DISCOVER_TOOL,
    CONTROL_CLAWHUB_INSTALL_TOOL,
    CONTROL_CRON_MUTATE_TOOL,
    CONTROL_DESKTOP_STATE_TOOL,
    CONTROL_EVOLUTION_ACTION_TOOL,
    CONTROL_FLEET_CONFIGURE_TOOL,
    CONTROL_FLEET_CONTINUE_TOOL,
    CONTROL_FLEET_SESSION_DELETE_TOOL,
    CONTROL_GATEWAY_PUSH_TOOL,
    CONTROL_MEMORY_MUTATE_TOOL,
    CONTROL_MODEL_SWITCH_TOOL,
    CONTROL_PROVIDER_DISCOVER_TOOL,
    CONTROL_PROVIDER_MUTATE_TOOL,
    CONTROL_SESSION_MUTATE_TOOL,
    CONTROL_SETUP_STATE_TOOL,
    CONTROL_SKILL_INSTALL_TOOL,
    CONTROL_SKILL_MUTATE_TOOL,
    CONTROL_TASK_MUTATE_TOOL,
    CONTROL_UPLOAD_MUTATE_TOOL,
)
from js.echo.turn_context import current_runtime_context
from js.tools.registry import ToolResult


class ControlPlaneMixin(AgentBase):
    """Register Web-only control effects behind Echo leases."""

    def _register_control_plane_tools(self) -> None:
        """Register Web-only skill control effects behind Echo leases."""
        from js.tools.registry import ToolParam, ToolSpec

        provider_mutation_lock = asyncio.Lock()
        setup_mutation_lock = asyncio.Lock()
        desktop_mutation_lock = asyncio.Lock()
        session_mutation_lock = asyncio.Lock()
        task_mutation_lock = asyncio.Lock()
        memory_mutation_lock = asyncio.Lock()
        skill_mutation_lock = asyncio.Lock()
        evolution_action_lock = asyncio.Lock()
        upload_mutation_lock = asyncio.Lock()
        cron_mutation_lock = asyncio.Lock()
        gateway_push_lock = asyncio.Lock()

        def skill_manager() -> Any | None:
            return getattr(self, "skills", None)

        def clawhub_client() -> Any:
            client = getattr(self, "_clawhub", None)
            if client is None:
                from js.skills.clawhub import ClawHubClient

                client = ClawHubClient(self.settings.state_dir)
                self._clawhub = client
            return client

        def failure(error: str, status_code: int) -> ToolResult:
            return ToolResult(
                success=False,
                error=error,
                metadata={"status_code": status_code},
            )

        def persist_static_provider_settings() -> None:
            """Persist only file-configured providers, never runtime dynamics."""
            dynamic_names = {item.name for item in self.provider_manager.get_all()}
            snapshot = self.settings.model_copy(deep=True)
            snapshot.providers = [
                item.model_copy(deep=True)
                for item in self.settings.providers
                if item.name not in dynamic_names
            ]
            config_path = getattr(self.settings, "_config_path", None)
            snapshot.save(
                path=config_path,
                fields=["providers"],
            )

        async def install_handler(source: str, skill_id: str | None = None) -> ToolResult:
            manager = skill_manager()
            if manager is None:
                return failure("Skill system is disabled", 503)
            if not isinstance(source, str) or not source.strip():
                return failure("source is required", 400)
            if skill_id is not None and not isinstance(skill_id, str):
                return failure("skill_id must be a string", 400)
            try:
                spec = await manager.install(source, skill_id)
            except ValueError:
                return failure("Skill source was rejected", 400)
            except Exception:  # noqa: BLE001 - tool boundary returns structured failure
                self.logger.error("Skill install failed", exc_info=True)
                return failure("Skill installation failed safely", 500)
            payload = {
                "skill_id": spec.id,
                "trust_level": spec.trust_level.value,
                "risk_flags": list(spec.risk_flags),
            }
            return ToolResult(
                success=True,
                output=json.dumps(payload, ensure_ascii=True),
                metadata=payload,
            )

        async def discover_handler(query: str = "") -> ToolResult:
            if skill_manager() is None:
                return failure("Skill system is disabled", 503)
            if not isinstance(query, str):
                return failure("query must be a string", 400)
            client = clawhub_client()
            try:
                index = await client.fetch_index()
                results = client.search_index(query) if query else index
            except Exception:  # noqa: BLE001 - tool boundary returns structured failure
                self.logger.error("ClawHub fetch failed", exc_info=True)
                return failure("ClawHub discovery failed safely", 502)
            payload = {
                "total": len(index),
                "results": list(results[:50]),
            }
            return ToolResult(
                success=True,
                output=json.dumps(payload, ensure_ascii=True),
                metadata=payload,
            )

        async def clawhub_install_handler(skill_id: str) -> ToolResult:
            manager = skill_manager()
            if manager is None:
                return failure("Skill system is disabled", 503)
            if not isinstance(skill_id, str) or not skill_id:
                return failure("skill_id is required", 400)
            client = clawhub_client()
            source = client.get_skill_source(skill_id)
            if not source:
                return failure(f"Skill '{skill_id}' not found in ClawHub index", 404)
            try:
                spec = await manager.install(source, skill_id)
            except ValueError:
                return failure("ClawHub skill source was rejected", 400)
            except Exception:  # noqa: BLE001 - tool boundary returns structured failure
                self.logger.error("ClawHub install failed", exc_info=True)
                return failure("ClawHub skill installation failed safely", 500)
            payload = {
                "skill_id": spec.id,
                "trust_level": spec.trust_level.value,
            }
            return ToolResult(
                success=True,
                output=json.dumps(payload, ensure_ascii=True),
                metadata=payload,
            )

        async def provider_discover_handler(
            base_url: str,
            api_key_ref: str = "",
            allow_private: bool = False,
        ) -> ToolResult:
            if not isinstance(base_url, str) or not base_url.strip():
                return failure("base_url is required", 400)
            if not isinstance(api_key_ref, str):
                return failure("api_key_ref must be a string", 400)
            if not isinstance(allow_private, bool):
                return failure("allow_private must be a boolean", 400)
            api_key = None
            if api_key_ref:
                api_key = self.take_provider_discovery_key(api_key_ref)
                if api_key is None:
                    return failure("Provider credential reference is invalid or expired", 401)
            result = await self.provider_manager.discover_models(
                base_url.strip(),
                api_key,
                allow_private=allow_private,
            )
            if "error" in result:
                return failure(str(result["error"]), 502)
            models = result.get("models", [])
            if not isinstance(models, list):
                return failure("Provider returned an invalid model list", 502)
            payload = {"models": models}
            return ToolResult(
                success=True,
                output=json.dumps(payload, ensure_ascii=True),
                metadata=payload,
            )

        async def provider_mutate_handler(
            action: str,
            provider: dict[str, Any] | None = None,
            name: str = "",
            api_key_ref: str = "",
        ) -> ToolResult:
            """Apply one admin-authorized provider mutation inside Echo."""
            if action not in {"upsert", "update_key", "delete"}:
                return failure("Unsupported provider mutation", 400)
            if not isinstance(name, str) or not isinstance(api_key_ref, str):
                return failure("Invalid provider mutation arguments", 400)
            if provider is not None and not isinstance(provider, dict):
                return failure("provider must be an object", 400)
            if provider and {
                "api_key",
                "apiKey",
                "api_key_env",
                "credential",
            }.intersection(provider):
                return failure("Provider credentials must use an opaque reference", 400)

            api_key: str | None = None
            if api_key_ref:
                api_key = self.take_provider_discovery_key(api_key_ref)
                if api_key is None:
                    return failure("Provider credential reference is invalid or expired", 401)

            from js.config import ModelProviderConfig
            from js.models.providers import OpenAICompatibleProvider

            async with provider_mutation_lock:
                if action == "upsert":
                    if not provider:
                        return failure("provider is required", 400)
                    try:
                        cfg = ModelProviderConfig(**provider, api_key=api_key)
                    except Exception:
                        return failure("Provider configuration is invalid", 400)
                    parsed = urlsplit(cfg.base_url)
                    if (
                        not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", cfg.name)
                        or parsed.scheme not in {"http", "https"}
                        or not parsed.hostname
                        or parsed.username is not None
                        or parsed.password is not None
                        or bool(parsed.query)
                        or bool(parsed.fragment)
                        or not cfg.models
                        or len(cfg.models) > 1000
                        or any(model.provider != cfg.name for model in cfg.models)
                    ):
                        return failure("Provider configuration is invalid", 400)

                    static_names = {item.name for item in self.settings.providers}
                    dynamic_names = {item.name for item in self.provider_manager.get_all()}
                    if cfg.name in static_names - dynamic_names:
                        return failure("Provider name conflicts with static config", 409)

                    previous_settings = list(self.settings.providers)
                    previous_dynamic = self.provider_manager.get(cfg.name)
                    try:
                        self.provider_manager.add(cfg)
                        self.settings.providers = [
                            item for item in self.settings.providers if item.name != cfg.name
                        ]
                        self.settings.providers.append(cfg)
                        self.router.add_provider(
                            cfg.name,
                            OpenAICompatibleProvider(cfg),
                            list(cfg.models),
                        )
                    except Exception:  # noqa: BLE001 - rollback at the effect boundary
                        self.logger.error("Provider upsert failed", exc_info=True)
                        self.settings.providers = previous_settings
                        try:
                            self.router.remove_provider(cfg.name)
                            if previous_dynamic is None:
                                self.provider_manager.remove(cfg.name)
                            else:
                                self.provider_manager.add(previous_dynamic)
                                self.router.add_provider(
                                    previous_dynamic.name,
                                    OpenAICompatibleProvider(previous_dynamic),
                                    list(previous_dynamic.models),
                                )
                        except Exception:
                            self.logger.error("Provider upsert rollback failed", exc_info=True)
                        return failure("Provider could not be saved safely", 500)

                    payload = {
                        "provider": cfg.name,
                        "models_added": len(cfg.models),
                    }
                    return ToolResult(
                        success=True,
                        output=json.dumps(payload, ensure_ascii=True),
                        metadata=payload,
                    )

                normalized_name = name.strip()
                if not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", normalized_name):
                    return failure("Invalid provider name", 400)
                target = next(
                    (item for item in self.settings.providers if item.name == normalized_name),
                    None,
                )
                if target is None:
                    return failure("Provider not found", 404)

                if action == "update_key":
                    previous_key = target.api_key
                    previous_dynamic = self.provider_manager.get(normalized_name)
                    from js.models.provider_manager import (
                        static_provider_secret_key_name,
                    )

                    static_secret_name = static_provider_secret_key_name(normalized_name)
                    try:
                        target.api_key = api_key
                        if previous_dynamic is None:
                            if api_key:
                                self.secrets.store(
                                    static_secret_name,
                                    api_key,
                                    category="provider",
                                )
                            else:
                                self.secrets.delete(static_secret_name)
                        else:
                            self.provider_manager.update_api_key(
                                normalized_name,
                                api_key or "",
                            )
                        self.router.remove_provider(normalized_name)
                        self.router.add_provider(
                            normalized_name,
                            OpenAICompatibleProvider(target),
                            list(target.models),
                        )
                    except Exception:  # noqa: BLE001 - rollback at the effect boundary
                        self.logger.error("Provider key update failed", exc_info=True)
                        target.api_key = previous_key
                        try:
                            if previous_dynamic is None:
                                if previous_key:
                                    self.secrets.store(
                                        static_secret_name,
                                        previous_key,
                                        category="provider",
                                    )
                                else:
                                    self.secrets.delete(static_secret_name)
                            else:
                                self.provider_manager.update_api_key(
                                    normalized_name,
                                    previous_key or "",
                                )
                            self.router.remove_provider(normalized_name)
                            self.router.add_provider(
                                normalized_name,
                                OpenAICompatibleProvider(target),
                                list(target.models),
                            )
                        except Exception:
                            self.logger.critical(
                                "Provider key rollback failed",
                                exc_info=True,
                            )
                        return failure("Provider credential could not be updated safely", 500)
                    payload = {"provider": normalized_name}
                    return ToolResult(
                        success=True,
                        output=json.dumps(payload, ensure_ascii=True),
                        metadata=payload,
                    )

                previous_settings = list(self.settings.providers)
                previous_dynamic = self.provider_manager.get(normalized_name)
                from js.models.provider_manager import static_provider_secret_key_name

                static_secret_name = static_provider_secret_key_name(normalized_name)
                try:
                    if previous_dynamic is None:
                        self.secrets.delete(static_secret_name)
                    else:
                        self.provider_manager.remove(normalized_name)
                    self.settings.providers = [
                        item for item in self.settings.providers if item.name != normalized_name
                    ]
                    if previous_dynamic is None:
                        persist_static_provider_settings()
                    self.router.remove_provider(normalized_name)
                except Exception:  # noqa: BLE001 - rollback at the effect boundary
                    self.logger.error("Provider delete failed", exc_info=True)
                    self.settings.providers = previous_settings
                    try:
                        if previous_dynamic is None:
                            if target.api_key:
                                self.secrets.store(
                                    static_secret_name,
                                    target.api_key,
                                    category="provider",
                                )
                            persist_static_provider_settings()
                        else:
                            self.provider_manager.add(previous_dynamic)
                        self.router.add_provider(
                            normalized_name,
                            OpenAICompatibleProvider(target),
                            list(target.models),
                        )
                    except Exception:
                        self.logger.critical(
                            "Provider delete rollback failed",
                            exc_info=True,
                        )
                    return failure("Provider could not be removed safely", 500)
                payload = {"provider": normalized_name}
                return ToolResult(
                    success=True,
                    output=json.dumps(payload, ensure_ascii=True),
                    metadata=payload,
                )

        async def fleet_configure_handler(config: dict[str, str]) -> ToolResult:
            if not isinstance(config, dict) or len(config) > 32:
                return failure("Invalid Fleet configuration", 400)
            normalized: dict[str, str] = {}
            for role, model in config.items():
                if (
                    not isinstance(role, str)
                    or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,31}", role)
                    or not isinstance(model, str)
                    or len(model) > 512
                    or any(not character.isprintable() for character in model)
                ):
                    return failure("Invalid Fleet configuration", 400)
                normalized[role] = model
            fleet_getter = getattr(self, "_fleet_getter", None)
            if not callable(fleet_getter):
                return failure("Fleet is unavailable", 503)
            try:
                fleet_instance = fleet_getter()
                if fleet_instance is None:
                    return failure("Fleet is unavailable", 503)
                fleet_instance.update_agent_config(dict(normalized))
            except Exception:
                self.logger.error("Fleet configuration failed", exc_info=True)
                return failure("Fleet configuration failed", 500)
            payload = {"config": normalized}
            return ToolResult(
                success=True,
                output=json.dumps(payload, ensure_ascii=True),
                metadata=payload,
            )

        async def fleet_continue_handler(session_id: str, follow_up: str) -> ToolResult:
            if (
                not isinstance(session_id, str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", session_id)
                or not isinstance(follow_up, str)
            ):
                return failure("Invalid Fleet continuation request", 400)
            normalized_follow_up = follow_up.strip()
            if not normalized_follow_up or len(normalized_follow_up) > 20_000:
                return failure("Invalid Fleet continuation request", 400)
            fleet_getter = getattr(self, "_fleet_getter", None)
            if not callable(fleet_getter):
                return failure("Fleet is unavailable", 503)
            try:
                fleet_instance = fleet_getter()
                if fleet_instance is None:
                    return failure("Fleet is unavailable", 503)
                result = await fleet_instance.continue_session(
                    session_id,
                    normalized_follow_up,
                )
            except ValueError:
                return failure("Fleet session was not found", 404)
            except Exception:
                self.logger.error("Fleet continuation failed", exc_info=True)
                return failure("Fleet continuation failed", 500)
            raw_subtasks = result.get("subtasks", {}) if isinstance(result, dict) else {}
            bounded_subtasks = (
                {
                    str(key)[:500]: str(value)[:1000]
                    for key, value in list(raw_subtasks.items())[:20]
                }
                if isinstance(raw_subtasks, dict)
                else {}
            )
            final = str(result.get("final", "")) if isinstance(result, dict) else ""
            payload = {
                "session_id": session_id,
                "subtasks": bounded_subtasks,
            }
            return ToolResult(success=True, output=final, metadata=payload)

        async def fleet_session_delete_handler(session_id: str) -> ToolResult:
            if not isinstance(session_id, str) or not re.fullmatch(
                r"[A-Za-z0-9_-]{1,128}", session_id
            ):
                return failure("Invalid Fleet session", 400)
            fleet_getter = getattr(self, "_fleet_getter", None)
            if not callable(fleet_getter):
                return failure("Fleet is unavailable", 503)
            try:
                fleet_instance = fleet_getter()
                if fleet_instance is None:
                    return failure("Fleet is unavailable", 503)
                deleted = fleet_instance.delete_session(session_id)
            except Exception:
                self.logger.error("Fleet session deletion failed", exc_info=True)
                return failure("Fleet session deletion failed", 500)
            if not deleted:
                return failure("Fleet session was not found", 404)
            payload = {"session_id": session_id}
            return ToolResult(
                success=True,
                output=json.dumps(payload, ensure_ascii=True),
                metadata=payload,
            )

        async def model_switch_handler(model_id: str) -> ToolResult:
            if (
                not isinstance(model_id, str)
                or not model_id
                or len(model_id) > 512
                or any(not character.isprintable() for character in model_id)
            ):
                return failure("Invalid model selection", 400)
            configured_providers = {provider.name for provider in self.settings.providers}
            # A model may only become active when its provider is actually
            # configured AND the model is explicitly declared.  Router
            # mappings alone are insufficient: a stale or dynamic mapping
            # does not prove configuration.  This logic is shared with the
            # HTTP endpoint via validate_model_for_activation() to prevent
            # drift between the two layers.
            from js.models.router import (
                ModelSwitchValidationError,
                validate_model_for_activation,
            )

            def _get_preset(name: str) -> Any:
                from js.models.cloud_providers import get_preset

                return get_preset(name)

            try:
                validate_model_for_activation(
                    model_id,
                    configured_providers,
                    get_model_binding=getattr(self.router, "get_model_binding", None),
                    get_preset=_get_preset,
                    provider_models={
                        p.name: {m.id for m in p.models} for p in self.settings.providers
                    },
                )
            except ModelSwitchValidationError as exc:
                if exc.needs_config:
                    return ToolResult(
                        success=False,
                        error=exc.detail,
                        metadata={
                            "status_code": exc.status_code,
                            "needs_config": True,
                        },
                    )
                return failure(exc.detail, exc.status_code)

            from js.utils.atomic_state import read_text_state, write_text_state

            state_path = Path(self.settings.state_dir) / "active_model.txt"
            try:
                previous_persisted = read_text_state(
                    state_path,
                    max_bytes=512,
                ).strip()
            except Exception:
                self.logger.error("Active model state read failed", exc_info=True)
                return failure("Model selection state is unavailable", 500)
            previous_preferred = str(getattr(self.router, "preferred_model", "") or "")
            routing_cache = getattr(self.router, "_routing_cache", None)
            previous_cache = dict(routing_cache) if isinstance(routing_cache, dict) else None
            publisher = getattr(self, "_active_model_publisher", None)
            try:
                write_text_state(state_path, model_id, max_bytes=512)
                self.router.preferred_model = model_id
                if isinstance(routing_cache, dict):
                    routing_cache.clear()
                if callable(publisher):
                    publisher(model_id)
            except Exception:
                self.logger.error("Model switch failed", exc_info=True)
                try:
                    write_text_state(state_path, previous_persisted, max_bytes=512)
                    self.router.preferred_model = previous_preferred
                    if isinstance(routing_cache, dict) and previous_cache is not None:
                        routing_cache.clear()
                        routing_cache.update(previous_cache)
                    if callable(publisher):
                        publisher(previous_persisted)
                except Exception:
                    self.logger.critical("Model switch rollback failed", exc_info=True)
                return failure("Model selection could not be updated safely", 500)
            payload = {"model_id": model_id}
            return ToolResult(
                success=True,
                output=json.dumps(payload, ensure_ascii=True),
                metadata=payload,
            )

        async def setup_state_handler(action: str) -> ToolResult:
            # complete/skip dismiss the wizard; start tracks mid-wizard progress;
            # reopen re-shows the wizard after skip/complete without reopening auth
            # bootstrap; reset returns to pending (admin constraints still apply).
            if action not in {"complete", "reset", "skip", "start", "reopen"}:
                return failure("Invalid setup state action", 400)

            from js.web.auth import AuthManager

            previous_first_run = bool(getattr(self.settings, "first_run_completed", False))
            previous_status = str(getattr(self.settings, "onboarding_status", None) or "pending")

            if action == "complete":
                next_status = "completed"
                next_first_run = True
            elif action == "skip":
                next_status = "skipped"
                next_first_run = True
            elif action == "start":
                next_status = "in_progress"
                # Never reopen the auth bootstrap window via start once dismissed.
                next_first_run = bool(
                    previous_first_run or previous_status in {"completed", "skipped"}
                )
            elif action == "reopen":
                # Settings "重新运行向导": show wizard again; bootstrap stays closed.
                if previous_status not in {"completed", "skipped"} and not previous_first_run:
                    return failure(
                        "Onboarding reopen requires a prior completed or skipped state",
                        409,
                    )
                next_status = "in_progress"
                next_first_run = True
            else:  # reset
                next_status = "pending"
                next_first_run = False

            # Skip/complete may mint a bootstrap *admin* auth key when required.
            # Never invent provider/model API keys.
            mint_admin = action in {"complete", "skip"}

            def _persist_onboarding(target_settings: Any) -> None:
                target_settings.onboarding_status = next_status
                target_settings.first_run_completed = next_first_run
                try:
                    target_settings.save(fields=["first_run_completed", "onboarding_status"])
                except PermissionError:
                    fallback = Path(target_settings.state_dir) / "config.yaml"
                    target_settings.save(fallback, ["first_run_completed", "onboarding_status"])

            def _restore_onboarding(target_settings: Any, *, status: str, first_run: bool) -> None:
                target_settings.onboarding_status = status
                target_settings.first_run_completed = first_run

            async with setup_mutation_lock:
                auth_manager = AuthManager(Path(self.settings.state_dir))
                if action == "reset" and auth_manager.has_admin():
                    return failure("Setup reset is unavailable while an admin key exists", 409)

                peer = getattr(self.settings, "_appshell_peer_settings", None)
                peer_previous_first_run = (
                    bool(getattr(peer, "first_run_completed", False)) if peer is not None else None
                )
                peer_previous_status = (
                    str(getattr(peer, "onboarding_status", None) or "pending")
                    if peer is not None
                    else None
                )
                plaintext_admin_key: str | None = None
                try:
                    if mint_admin and bool(
                        getattr(getattr(self.settings, "security", None), "api_key_required", False)
                    ):
                        plaintext_admin_key = auth_manager.ensure_bootstrap_admin_key()

                    _persist_onboarding(self.settings)
                    # AppShell: one product skip/complete entry mirrors to peer mode.
                    # Workspace paths, leases, and approvals are never mirrored.
                    if peer is not None and bool(
                        getattr(self.settings, "_appshell_managed", False)
                    ):
                        _persist_onboarding(peer)
                except Exception:
                    self.logger.error("Setup state mutation failed", exc_info=True)
                    _restore_onboarding(
                        self.settings, status=previous_status, first_run=previous_first_run
                    )
                    if peer is not None and peer_previous_status is not None:
                        _restore_onboarding(
                            peer,
                            status=peer_previous_status,
                            first_run=bool(peer_previous_first_run),
                        )
                    if plaintext_admin_key:
                        try:
                            auth_manager.revoke_key(
                                hashlib.sha256(plaintext_admin_key.encode("utf-8")).hexdigest()
                            )
                        except Exception:
                            self.logger.critical(
                                "Setup bootstrap-key rollback failed",
                                exc_info=True,
                            )
                    return failure("Setup state could not be saved safely", 500)

                payload: dict[str, Any] = {
                    "first_run_completed": next_first_run,
                    "onboarding_status": next_status,
                    "appshell_mirrored": bool(
                        peer is not None and getattr(self.settings, "_appshell_managed", False)
                    ),
                }
                if plaintext_admin_key:
                    key_reference = self.stage_setup_admin_key(plaintext_admin_key)
                    if not key_reference:
                        _restore_onboarding(
                            self.settings,
                            status=previous_status,
                            first_run=previous_first_run,
                        )
                        if peer is not None and peer_previous_status is not None:
                            _restore_onboarding(
                                peer,
                                status=peer_previous_status,
                                first_run=bool(peer_previous_first_run),
                            )
                        try:
                            auth_manager.revoke_key(
                                hashlib.sha256(plaintext_admin_key.encode("utf-8")).hexdigest()
                            )
                            self.settings.save(fields=["first_run_completed", "onboarding_status"])
                            if peer is not None:
                                peer.save(fields=["first_run_completed", "onboarding_status"])
                        except Exception:
                            self.logger.critical(
                                "Setup key staging rollback failed",
                                exc_info=True,
                            )
                        return failure("Setup credential handoff failed safely", 500)
                    payload["admin_key_ref"] = key_reference
                return ToolResult(
                    success=True,
                    output=json.dumps(payload, ensure_ascii=True),
                    metadata=payload,
                )

        async def session_mutate_handler(action: str, session_id: str) -> ToolResult:
            """Apply cancellation/deletion under the immutable Echo owner."""
            if action not in {"cancel", "delete"}:
                return failure("Invalid session mutation action", 400)
            if not isinstance(session_id, str):
                return failure("session_id must be a string", 400)
            normalized_session = session_id.strip()
            if (
                not normalized_session
                or len(normalized_session) > 256
                or any(
                    ord(character) < 32 or ord(character) == 127 for character in normalized_session
                )
            ):
                return failure("Invalid session_id", 400)

            context = current_runtime_context()
            if context is None or not context.owner_key_hash:
                return failure("Session mutation requires an Echo runtime owner", 500)
            owner = context.owner_key_hash

            async with session_mutation_lock:
                if action == "cancel":
                    request_cancel = getattr(self, "request_cancel", None)
                    if not callable(request_cancel):
                        return failure("Session cancellation is unavailable", 503)
                    try:
                        cancelled = request_cancel(
                            normalized_session,
                            owner_key_hash=owner,
                        )
                    except PermissionError:
                        return failure("Session cancellation is not permitted", 403)
                    except Exception:
                        self.logger.error("Session cancellation failed", exc_info=True)
                        return failure("Session cancellation failed safely", 500)
                    if not cancelled:
                        return failure("No active run for session", 404)
                    payload = {
                        "session_id": normalized_session,
                        "cancelled": True,
                    }
                    return ToolResult(
                        success=True,
                        output=json.dumps(payload, ensure_ascii=True),
                        metadata=payload,
                    )

                from js.echo.turn_context import runtime_partition_key

                partition_key = runtime_partition_key(
                    context.product_id,
                    owner,
                    normalized_session,
                )
                active = getattr(self, "_cancel_tokens", {})
                if isinstance(active, dict) and partition_key in active:
                    return failure("Active sessions must be cancelled before deletion", 409)
                memory = getattr(self, "memory", None)
                delete_session = getattr(memory, "delete_session", None)
                if not callable(delete_session):
                    return failure("Session storage is unavailable", 503)
                memory_partition_owner: str | None = owner
                if context.product_id == "js-agent" and owner == "local-user":
                    memory_partition_owner = None
                try:
                    deleted = delete_session(
                        normalized_session,
                        owner_key_hash=memory_partition_owner,
                    )
                except PermissionError:
                    return failure("Session deletion is not permitted", 403)
                except Exception:
                    self.logger.error("Session deletion failed", exc_info=True)
                    return failure("Session deletion failed safely", 500)
                if not deleted:
                    return failure("Session not found", 404)
                payload = {"session_id": normalized_session, "deleted": True}
                return ToolResult(
                    success=True,
                    output=json.dumps(payload, ensure_ascii=True),
                    metadata=payload,
                )

        async def desktop_state_handler(action: str) -> ToolResult:
            """Mutate desktop registration and persisted opt-in as one Echo effect."""
            if action not in {"toggle", "enable_read_only", "enable_writes", "disable"}:
                return failure("Invalid desktop state action", 400)
            context = current_runtime_context()
            if context is None:
                return failure("Desktop mutation requires an Echo runtime context", 500)
            if context.product_id == "js-work":
                return failure("Desktop control is unavailable in JS Agent Work", 403)

            async with desktop_mutation_lock:
                desktop = getattr(self, "_desktop_tools", None)
                enabled = bool(getattr(self.settings, "desktop_control_enabled", False))
                resolved_action = action
                if action == "toggle":
                    resolved_action = (
                        "disable" if enabled or desktop is not None else "enable_read_only"
                    )

                if resolved_action == "disable":
                    if desktop is not None:
                        try:
                            for spec in desktop.get_specs():
                                self.registry.unregister(spec.name)
                        except Exception:
                            self.logger.error("Desktop tool unregistration failed", exc_info=True)
                            return failure("Desktop tools could not be disabled safely", 500)
                    self._desktop_tools = None
                    self.settings.desktop_control_enabled = False
                    try:
                        self.settings.save(fields=["desktop_control_enabled"])
                    except Exception:
                        # Keep the live registry disabled even if persistence is
                        # unavailable; this is the fail-closed state.
                        self.logger.error("Desktop disable persistence failed", exc_info=True)
                        return failure("Desktop state could not be saved safely", 500)
                    payload = {"enabled": False, "stage": "disabled"}
                    return ToolResult(
                        success=True,
                        output=json.dumps(payload, ensure_ascii=True),
                        metadata=payload,
                    )

                if resolved_action == "enable_writes":
                    if desktop is None or not enabled:
                        return failure("Enable read-only desktop control first", 409)
                    try:
                        count = desktop.register_write_tools(self.registry)
                    except Exception:
                        self.logger.error("Desktop write-tool registration failed", exc_info=True)
                        return failure("Desktop write tools could not be enabled safely", 500)
                    if not isinstance(count, int) or count <= 0:
                        return failure(
                            "Desktop write tools are already enabled or unavailable", 409
                        )
                    payload = {
                        "enabled": True,
                        "stage": "write_enabled",
                        "write_tools": count,
                        "total_tools": len(desktop.get_specs()),
                    }
                    return ToolResult(
                        success=True,
                        output=json.dumps(payload, ensure_ascii=True),
                        metadata=payload,
                    )

                if desktop is not None and enabled:
                    payload = {
                        "enabled": True,
                        "stage": "read_only",
                        "tools_count": len(desktop.get_read_only_specs()),
                    }
                    return ToolResult(
                        success=True,
                        output=json.dumps(payload, ensure_ascii=True),
                        metadata=payload,
                    )

                from js.tools.desktop.wizard import run_wizard

                try:
                    wizard_state = await asyncio.to_thread(run_wizard)
                except Exception:
                    self.logger.error("Desktop readiness check failed", exc_info=True)
                    return failure("Desktop readiness could not be verified", 503)
                if not bool(getattr(wizard_state, "ready", False)):
                    return failure("Desktop control is not ready", 409)

                from js.orin.stage_c import product_desktop_cell_required
                from js.tools.desktop_tools import DesktopTools

                cell_backend = self._desktop_cell_backend()
                if product_desktop_cell_required(getattr(self.settings, "orin", None)):
                    if cell_backend is None:
                        return failure("Desktop Cell safety boundary unavailable", 503)
                    candidate = DesktopTools(
                        approval_queue=self.approvals,
                        cell_backend=cell_backend,
                    )
                else:
                    candidate = DesktopTools(approval_queue=self.approvals)
                if not bool(getattr(candidate, "available", False)):
                    return failure("Desktop control dependencies are unavailable", 409)
                try:
                    count = candidate.register_read_only(self.registry)
                    if not isinstance(count, int) or count <= 0:
                        raise RuntimeError("no read-only desktop tools were registered")
                    self._desktop_tools = candidate
                    self.settings.desktop_control_enabled = True
                    self.settings.save(fields=["desktop_control_enabled"])
                except Exception:
                    self.logger.error("Desktop read-only enable failed", exc_info=True)
                    try:
                        for spec in candidate.get_read_only_specs():
                            self.registry.unregister(spec.name)
                    except Exception:
                        self.logger.critical("Desktop enable rollback failed", exc_info=True)
                    self._desktop_tools = None
                    self.settings.desktop_control_enabled = False
                    return failure("Desktop control could not be enabled safely", 500)

                payload = {
                    "enabled": True,
                    "stage": "read_only",
                    "tools_count": count,
                }
                warning = str(getattr(candidate, "init_error", "") or "")
                if warning:
                    payload["warning"] = warning
                return ToolResult(
                    success=True,
                    output=json.dumps(payload, ensure_ascii=True),
                    metadata=payload,
                )

        async def task_mutate_handler(action: str, task_id: str) -> ToolResult:
            """Apply an administrator task transition under the Echo owner."""
            if action not in {"pause", "resume", "delete"}:
                return failure("Invalid task mutation action", 400)
            if not isinstance(task_id, str):
                return failure("task_id must be a string", 400)
            normalized_task = task_id.strip()
            if (
                not normalized_task
                or len(normalized_task) > 256
                or any(
                    ord(character) < 32 or ord(character) == 127 for character in normalized_task
                )
            ):
                return failure("Invalid task_id", 400)
            context = current_runtime_context()
            if context is None or not context.owner_key_hash:
                return failure("Task mutation requires an Echo runtime owner", 500)
            manager = getattr(self, "task_manager", None)
            operation = getattr(manager, action, None)
            if not callable(operation):
                return failure("Task manager is unavailable", 503)

            async with task_mutation_lock:
                try:
                    changed = operation(
                        normalized_task,
                        owner_key_hash=context.owner_key_hash,
                    )
                except PermissionError:
                    return failure("Task mutation is not permitted", 403)
                except Exception:
                    self.logger.error("Task mutation failed", exc_info=True)
                    return failure("Task mutation failed safely", 500)
            if not changed:
                return failure("Task not found", 404)
            status = {"pause": "paused", "resume": "running", "delete": "deleted"}[action]
            payload = {"task_id": normalized_task, "status": status}
            return ToolResult(
                success=True,
                output=json.dumps(payload, ensure_ascii=True),
                metadata=payload,
            )

        async def memory_mutate_handler(action: str, payload_ref: str) -> ToolResult:
            """Apply private memory writes without journaling memory contents."""
            allowed_actions = {
                "file_put",
                "semantic_create",
                "semantic_delete",
                "semantic_update",
                "semantic_verify",
                "proposal_approve",
                "proposal_reject",
                "organize",
                "block_move",
                "block_merge",
                "embedder_recover",
                "capsule_store",
                "capsule_delete",
                "compression_create",
                "compression_approve",
                "compression_reject",
            }
            if action not in allowed_actions:
                return failure("Invalid memory mutation action", 400)
            if not isinstance(payload_ref, str) or not payload_ref:
                return failure("Memory payload reference is required", 400)
            context = current_runtime_context()
            if context is None or not context.owner_key_hash:
                return failure("Memory mutation requires an Echo runtime owner", 500)
            owner = context.owner_key_hash
            payload = self.take_memory_mutation_payload(payload_ref, owner)
            if payload is None:
                return failure("Memory payload reference is invalid or expired", 401)
            memory = getattr(self, "memory", None)
            if memory is None:
                return failure("Memory storage is unavailable", 503)
            store_owner: str | None = owner
            if context.product_id == "js-agent" and owner == "local-user":
                store_owner = None

            result_ref = self._reserve_memory_control_result(
                "_memory_mutation_results",
                owner,
            )
            if not result_ref:
                return failure("Memory result handoff is unavailable", 503)

            def memory_failure(message: str, status_code: int) -> ToolResult:
                self._discard_memory_control_value(
                    "_memory_mutation_results",
                    result_ref,
                    owner,
                )
                return failure(message, status_code)

            try:
                async with memory_mutation_lock:
                    if action == "file_put":
                        name = payload.get("name")
                        content = payload.get("content")
                        if not isinstance(name, str) or not isinstance(content, str):
                            return memory_failure("Invalid memory file payload", 400)
                        from js.memory.store import MemoryStore

                        if name not in MemoryStore._VALID_MEMORY_FILES:
                            return memory_failure("Invalid memory file payload", 400)
                        await asyncio.to_thread(
                            memory.write_memory_file,
                            name,
                            content,
                            store_owner,
                        )
                        response: dict[str, Any] = {"name": name, "saved": True}
                    elif action == "semantic_create":
                        key = payload.get("key")
                        value = payload.get("value")
                        category = payload.get("category")
                        source = payload.get("source")
                        if not all(
                            isinstance(item, str) and item
                            for item in (key, value, category, source)
                        ):
                            return memory_failure("Invalid semantic memory payload", 400)
                        created = await asyncio.to_thread(
                            memory.store_semantic,
                            key=key,
                            value=value,
                            category=category,
                            source=source,
                            memory_path=payload.get("memory_path"),
                            entity_type=payload.get("entity_type"),
                            entity_name=payload.get("entity_name"),
                            parent_id=payload.get("parent_id"),
                            relation_type=payload.get("relation_type"),
                            owner_key_hash=store_owner,
                            evidence=payload.get("evidence") or "",
                        )
                        if not isinstance(created, dict):
                            return memory_failure(
                                "Memory storage returned an invalid result",
                                500,
                            )
                        response = {"success": True, "key": key, **created}
                    elif action == "semantic_delete":
                        memory_id = payload.get("memory_id")
                        if not isinstance(memory_id, int) or isinstance(memory_id, bool):
                            return memory_failure("Invalid memory_id", 400)
                        deleted = await asyncio.to_thread(
                            memory.delete_semantic,
                            memory_id,
                            source="user",
                            owner_key_hash=store_owner,
                        )
                        if not deleted:
                            return memory_failure("Memory not found", 404)
                        response = {"success": True}
                    elif action == "semantic_update":
                        memory_id = payload.get("memory_id")
                        value = payload.get("value")
                        if (
                            not isinstance(memory_id, int)
                            or isinstance(memory_id, bool)
                            or not isinstance(value, str)
                            or not value
                        ):
                            return memory_failure("Invalid semantic memory update", 400)
                        updated = await asyncio.to_thread(
                            memory.update_semantic,
                            memory_id,
                            value,
                            category=payload.get("category"),
                            source="user",
                            memory_path=payload.get("memory_path"),
                            entity_type=payload.get("entity_type"),
                            entity_name=payload.get("entity_name"),
                            parent_id=payload.get("parent_id"),
                            relation_type=payload.get("relation_type"),
                            owner_key_hash=store_owner,
                        )
                        if not updated:
                            return memory_failure("Memory not found", 404)
                        response = {"success": True}
                    elif action == "semantic_verify":
                        memory_id = payload.get("memory_id")
                        if not isinstance(memory_id, int) or isinstance(memory_id, bool):
                            return memory_failure("Invalid memory_id", 400)
                        verified = await asyncio.to_thread(
                            memory.verify_semantic,
                            memory_id,
                            "user",
                            owner_key_hash=store_owner,
                        )
                        if not verified:
                            return memory_failure("Memory not found", 404)
                        response = {"success": True, "verified": True}
                    elif action == "proposal_approve":
                        proposal_id = payload.get("proposal_id")
                        overrides = payload.get("overrides")
                        if (
                            not isinstance(proposal_id, int)
                            or isinstance(proposal_id, bool)
                            or (overrides is not None and not isinstance(overrides, dict))
                        ):
                            return memory_failure(
                                "Invalid memory proposal payload",
                                400,
                            )
                        proposal_result = await asyncio.to_thread(
                            memory.approve_proposal,
                            proposal_id,
                            owner_key_hash=store_owner,
                            overrides=overrides,
                        )
                        if not isinstance(proposal_result, dict) or not proposal_result.get(
                            "success"
                        ):
                            return memory_failure("Memory proposal not found", 404)
                        response = proposal_result
                    elif action == "proposal_reject":
                        proposal_id = payload.get("proposal_id")
                        if not isinstance(proposal_id, int) or isinstance(proposal_id, bool):
                            return memory_failure("Invalid proposal_id", 400)
                        proposal_result = await asyncio.to_thread(
                            memory.reject_proposal,
                            proposal_id,
                            owner_key_hash=store_owner,
                        )
                        if not isinstance(proposal_result, dict) or not proposal_result.get(
                            "success"
                        ):
                            return memory_failure("Memory proposal not found", 404)
                        response = proposal_result
                    elif action == "organize":
                        scheduler = getattr(self, "_dream_scheduler", None)
                        buffer = (
                            scheduler.snapshot_buffer()
                            if scheduler is not None and hasattr(scheduler, "snapshot_buffer")
                            else []
                        )
                        if not buffer:
                            response = {
                                "success": True,
                                "turns": 0,
                                "proposed": 0,
                                "auto_applied": 0,
                                "pending": 0,
                                "skipped": "no recent conversation",
                            }
                        else:
                            extract = getattr(self, "_extract_memories", None)
                            if not callable(extract):
                                return memory_failure(
                                    "Memory extraction is unavailable",
                                    501,
                                )
                            report = await extract(buffer)
                            if not isinstance(report, dict):
                                return memory_failure(
                                    "Memory extraction returned an invalid result",
                                    500,
                                )
                            response = {"success": True, "turns": len(buffer), **report}
                    elif action in {"block_move", "block_merge"}:
                        src = payload.get("src")
                        dst = payload.get("dst")
                        if (
                            not isinstance(src, str)
                            or not src
                            or not isinstance(dst, str)
                            or not dst
                        ):
                            return memory_failure("Invalid memory block payload", 400)
                        method = (
                            memory.move_block if action == "block_move" else memory.merge_blocks
                        )
                        moved = await asyncio.to_thread(
                            method,
                            src,
                            dst,
                            owner_key_hash=store_owner,
                        )
                        response = {
                            "success": True,
                            "moved" if action == "block_move" else "merged": moved,
                            "src": src,
                            "dst": dst,
                        }
                    elif action == "embedder_recover":
                        setup_embedder = getattr(self, "_setup_embedder", None)
                        if not callable(setup_embedder):
                            return memory_failure(
                                "Embedder recovery is unavailable",
                                503,
                            )
                        from js.memory.embeddings import KeywordEmbedder

                        try:
                            new_embedder = await asyncio.to_thread(setup_embedder)
                        except Exception:
                            self.logger.warning(
                                "Embedder rebuild failed; probing existing embedder",
                                exc_info=True,
                            )
                            new_embedder = None

                        if new_embedder is not None and not isinstance(
                            new_embedder,
                            KeywordEmbedder,
                        ):
                            memory.replace_embedder(new_embedder)
                            health = new_embedder.health()
                            response = {
                                "success": True,
                                "provider": health.provider,
                                "active": health.active,
                                "fallback_provider": health.fallback_provider,
                                "failure_count": health.failure_count,
                                "recovered": True,
                                "method": "rebuild",
                            }
                        else:
                            embedder = memory.embedder
                            if hasattr(embedder, "force_recover"):
                                recovered = embedder.force_recover()
                                health = embedder.health()
                                response = {
                                    "success": bool(recovered),
                                    "provider": health.provider,
                                    "active": health.active,
                                    "fallback_provider": health.fallback_provider,
                                    "failure_count": health.failure_count,
                                    "recovered": bool(recovered),
                                    "method": "force_recover",
                                }
                            else:
                                health = embedder.health()
                                response = {
                                    "success": False,
                                    "provider": health.provider,
                                    "active": health.active,
                                    "fallback_provider": health.fallback_provider,
                                    "failure_count": health.failure_count,
                                    "recovered": False,
                                    "method": "none",
                                }
                    elif action == "capsule_store":
                        session_id = payload.get("session_id")
                        capsule_text = payload.get("capsule_text")
                        if (
                            not isinstance(session_id, str)
                            or not session_id
                            or not isinstance(capsule_text, str)
                            or not capsule_text
                        ):
                            return memory_failure("Invalid capsule payload", 400)
                        capsule_meta = await asyncio.to_thread(
                            memory.store_capsule,
                            session_id=session_id,
                            capsule_text=capsule_text,
                            owner_key_hash=store_owner,
                            refresh_reason=payload.get("refresh_reason") or "manual_refresh",
                        )
                        if not isinstance(capsule_meta, dict):
                            return memory_failure(
                                "Capsule storage returned an invalid result",
                                500,
                            )
                        response = {
                            "metadata": {
                                key: value
                                for key, value in capsule_meta.items()
                                if key != "capsule_text"
                            }
                        }
                    elif action == "compression_create":
                        from js.memory.layers import (
                            MemoryCompressionAuthorityV1,
                            MemoryRecordKind,
                            MemorySourceRefV1,
                        )

                        source_refs_raw = payload.get("source_refs")
                        proposed_summary = payload.get("proposed_summary")
                        if not isinstance(source_refs_raw, list) or not source_refs_raw:
                            return memory_failure("source_refs must be a non-empty list", 400)
                        if not isinstance(proposed_summary, str) or not proposed_summary.strip():
                            return memory_failure("proposed_summary must be non-empty string", 400)
                        if context.task_ref is None:
                            return memory_failure("Compression requires signed TaskRef", 403)
                        role_val = getattr(context, "role", "user") or "user"
                        comp_auth = MemoryCompressionAuthorityV1(
                            task_ref_hash=context.task_ref.canonical_hash(),
                            owner=context.task_ref.owner,
                            mode=context.task_ref.mode.value,
                            workspace=context.task_ref.workspace,
                            role=role_val,
                            session=context.task_ref.session,
                            run=context.task_ref.run,
                        )
                        comp_refs: list[MemorySourceRefV1] = []
                        for sr in source_refs_raw:
                            if (
                                not isinstance(sr, dict)
                                or "kind" not in sr
                                or "record_id" not in sr
                            ):
                                return memory_failure("Invalid source_ref entry", 400)
                            comp_refs.append(
                                MemorySourceRefV1(
                                    kind=MemoryRecordKind(str(sr["kind"])),
                                    record_id=str(sr["record_id"]),
                                )
                            )
                        comp_proposal = await asyncio.to_thread(
                            memory.create_compression_proposal,
                            authority=comp_auth,
                            source_refs=tuple(comp_refs),
                            proposed_summary=proposed_summary,
                        )
                        response = {"success": True, "proposal": comp_proposal.as_dict()}
                    elif action == "compression_approve":
                        from js.memory.layers import MemoryCompressionAuthorityV1

                        comp_pid = payload.get("proposal_id")
                        if not isinstance(comp_pid, str) or not comp_pid:
                            return memory_failure("proposal_id must be non-empty string", 400)
                        if context.task_ref is None:
                            return memory_failure("Compression requires signed TaskRef", 403)
                        role_val = getattr(context, "role", "user") or "user"
                        comp_auth = MemoryCompressionAuthorityV1(
                            task_ref_hash=context.task_ref.canonical_hash(),
                            owner=context.task_ref.owner,
                            mode=context.task_ref.mode.value,
                            workspace=context.task_ref.workspace,
                            role=role_val,
                            session=context.task_ref.session,
                            run=context.task_ref.run,
                        )
                        comp_result = await asyncio.to_thread(
                            memory.approve_compression_proposal,
                            comp_pid,
                            authority=comp_auth,
                        )
                        response = {
                            "success": comp_result.success,
                            "error_code": comp_result.error_code,
                            "proposal": comp_result.proposal.as_dict()
                            if comp_result.proposal
                            else None,
                            "capsule": comp_result.capsule.as_dict()
                            if comp_result.capsule
                            else None,
                        }
                    elif action == "compression_reject":
                        from js.memory.layers import MemoryCompressionAuthorityV1

                        comp_pid = payload.get("proposal_id")
                        if not isinstance(comp_pid, str) or not comp_pid:
                            return memory_failure("proposal_id must be non-empty string", 400)
                        if context.task_ref is None:
                            return memory_failure("Compression requires signed TaskRef", 403)
                        role_val = getattr(context, "role", "user") or "user"
                        comp_auth = MemoryCompressionAuthorityV1(
                            task_ref_hash=context.task_ref.canonical_hash(),
                            owner=context.task_ref.owner,
                            mode=context.task_ref.mode.value,
                            workspace=context.task_ref.workspace,
                            role=role_val,
                            session=context.task_ref.session,
                            run=context.task_ref.run,
                        )
                        comp_rejected = await asyncio.to_thread(
                            memory.reject_compression_proposal,
                            comp_pid,
                            authority=comp_auth,
                        )
                        response = {
                            "success": comp_rejected is not None,
                            "proposal": comp_rejected.as_dict() if comp_rejected else None,
                        }
                    else:
                        session_id = payload.get("session_id")
                        if not isinstance(session_id, str) or not session_id:
                            return memory_failure("Invalid session_id", 400)
                        deleted = await asyncio.to_thread(
                            memory.delete_capsule,
                            session_id=session_id,
                            owner_key_hash=store_owner,
                        )
                        response = {"session_id": session_id, "deleted": bool(deleted)}
            except asyncio.CancelledError:
                self._discard_memory_control_value(
                    "_memory_mutation_results",
                    result_ref,
                    owner,
                )
                raise
            except ValueError:
                return memory_failure("Memory mutation payload was rejected", 400)
            except PermissionError:
                return memory_failure("Memory mutation is not permitted", 403)
            except Exception:
                self.logger.error("Memory mutation failed", exc_info=True)
                return memory_failure("Memory mutation failed safely", 500)

            if not self._commit_memory_control_result(
                "_memory_mutation_results",
                result_ref,
                owner,
                response,
            ):
                return memory_failure("Memory result handoff is unavailable", 503)
            return ToolResult(
                success=True,
                output="Memory mutation completed",
                metadata={"result_ref": result_ref},
            )

        async def skill_mutate_handler(action: str, payload_ref: str) -> ToolResult:
            """Apply privileged skill writes with private input/output handoff."""
            allowed_actions = {
                "refresh_hermes",
                "promotion_approve",
                "promotion_reject",
                "promotion_revert",
                "uninstall",
                "trust",
            }
            if action not in allowed_actions:
                return failure("Invalid skill mutation action", 400)
            if not isinstance(payload_ref, str) or not payload_ref:
                return failure("Skill payload reference is required", 400)
            context = current_runtime_context()
            if context is None or not context.owner_key_hash:
                return failure("Skill mutation requires an Echo runtime owner", 500)
            if context.product_id == "js-work":
                return failure("Runtime skill mutation is disabled in JS Agent Work", 403)
            owner = context.owner_key_hash
            payload = self.take_skill_mutation_payload(payload_ref, owner)
            if payload is None:
                return failure("Skill payload reference is invalid or expired", 401)
            manager = skill_manager()
            if manager is None:
                return failure("Skill system is disabled", 503)

            result_ref = self._reserve_memory_control_result(
                "_skill_mutation_results",
                owner,
            )
            if not result_ref:
                return failure("Skill result handoff is unavailable", 503)

            def skill_failure(message: str, status_code: int) -> ToolResult:
                self._discard_memory_control_value(
                    "_skill_mutation_results",
                    result_ref,
                    owner,
                )
                return failure(message, status_code)

            def required_identifier(field: str) -> str | None:
                value = payload.get(field)
                if (
                    not isinstance(value, str)
                    or not value.strip()
                    or len(value.strip()) > 256
                    or any(ord(character) < 32 or ord(character) == 127 for character in value)
                ):
                    return None
                return value.strip()

            try:
                async with skill_mutation_lock:
                    if action == "refresh_hermes":
                        response = await asyncio.to_thread(manager.refresh_hermes_skills)
                        if not isinstance(response, dict) or not response.get("success"):
                            return skill_failure("Hermes skill refresh failed", 409)
                    elif action == "promotion_approve":
                        event_id = required_identifier("event_id")
                        if event_id is None:
                            return skill_failure("Invalid promotion event ID", 400)
                        response = await manager.apply_proposal(
                            event_id,
                            decided_by="web",
                            owner_key_hash=owner,
                        )
                        if not isinstance(response, dict) or not response.get("success"):
                            return skill_failure(
                                "Skill promotion could not be applied",
                                409,
                            )
                    elif action == "promotion_reject":
                        event_id = required_identifier("event_id")
                        reason = payload.get("reason", "")
                        if event_id is None or not isinstance(reason, str) or len(reason) > 1_000:
                            return skill_failure("Invalid skill rejection payload", 400)
                        promotion_store = getattr(self, "promotion_store", None)
                        if promotion_store is None:
                            promotion_store = getattr(manager, "promotion_store", None)
                        reject = getattr(promotion_store, "mark_rejected", None)
                        if not callable(reject):
                            return skill_failure(
                                "Skill promotion store is unavailable",
                                503,
                            )
                        rejected = await asyncio.to_thread(
                            reject,
                            event_id,
                            owner_key_hash=owner,
                            decided_by="web",
                            reason=reason,
                        )
                        if not rejected:
                            return skill_failure(
                                "Skill promotion cannot be rejected",
                                404,
                            )
                        response = {
                            "success": True,
                            "event_id": event_id,
                            "status": "rejected",
                        }
                    elif action == "promotion_revert":
                        event_id = required_identifier("event_id")
                        if event_id is None:
                            return skill_failure("Invalid promotion event ID", 400)
                        response = await asyncio.to_thread(
                            manager.revert_promotion,
                            event_id,
                            decided_by="web",
                            owner_key_hash=owner,
                        )
                        if not isinstance(response, dict) or not response.get("success"):
                            return skill_failure(
                                "Skill promotion could not be reverted",
                                409,
                            )
                    elif action == "uninstall":
                        skill_id = required_identifier("skill_id")
                        if skill_id is None:
                            return skill_failure("Invalid skill ID", 400)
                        removed = await manager.uninstall(skill_id)
                        if not removed:
                            return skill_failure("Skill not found or immutable", 404)
                        response = {"success": True}
                    else:
                        skill_id = required_identifier("skill_id")
                        level = payload.get("level")
                        if skill_id is None or not isinstance(level, str):
                            return skill_failure("Invalid skill trust payload", 400)
                        from js.skills.spec import TrustLevel

                        try:
                            trust_level = TrustLevel(level)
                        except ValueError:
                            return skill_failure("Invalid skill trust level", 400)
                        trusted = await asyncio.to_thread(
                            manager.trust_skill,
                            skill_id,
                            trust_level,
                            decided_by="web",
                            owner_key_hash=owner,
                        )
                        if not trusted:
                            return skill_failure("Skill not found", 404)
                        response = {
                            "success": True,
                            "skill_id": skill_id,
                            "trust_level": level,
                        }
            except asyncio.CancelledError:
                self._discard_memory_control_value(
                    "_skill_mutation_results",
                    result_ref,
                    owner,
                )
                raise
            except PermissionError:
                return skill_failure("Skill mutation is not permitted", 403)
            except Exception:
                self.logger.error("Skill mutation failed", exc_info=True)
                return skill_failure("Skill mutation failed safely", 500)

            if not self._commit_memory_control_result(
                "_skill_mutation_results",
                result_ref,
                owner,
                response,
            ):
                return skill_failure("Skill result handoff is unavailable", 503)
            return ToolResult(
                success=True,
                output="Skill mutation completed",
                metadata={"result_ref": result_ref},
            )

        async def evolution_action_handler(
            action: str,
            proposal_id: str = "",
        ) -> ToolResult:
            """Run privileged evolution actions and stage their private reports."""
            if action not in {"run", "reflect", "approve", "reject"}:
                return failure("Invalid evolution action", 400)
            context = current_runtime_context()
            if context is None or not context.owner_key_hash:
                return failure("Evolution requires an Echo runtime owner", 500)
            if context.product_id == "js-work":
                return failure("Evolution is disabled in JS Agent Work", 403)

            owner = context.owner_key_hash
            result_ref = self._reserve_memory_control_result(
                "_evolution_action_results",
                owner,
            )
            if not result_ref:
                return failure("Evolution result handoff is unavailable", 503)

            def evolution_failure(message: str, status_code: int) -> ToolResult:
                self._discard_memory_control_value(
                    "_evolution_action_results",
                    result_ref,
                    owner,
                )
                return failure(message, status_code)

            try:
                async with evolution_action_lock:
                    if action == "run":
                        run_cycle = getattr(self, "_run_evolution_cycle", None)
                        if not callable(run_cycle):
                            return evolution_failure(
                                "Evolution cycle is unavailable",
                                501,
                            )
                        missing = [
                            name
                            for name in (
                                "metacognition",
                                "learner",
                                "optimizer",
                                "evolver",
                            )
                            if getattr(self, name, None) is None
                        ]
                        if missing:
                            return evolution_failure(
                                "Evolution subsystems are not ready",
                                503,
                            )
                        scheduler = getattr(self, "_dream_scheduler", None)
                        buffer = (
                            scheduler.snapshot_buffer()
                            if scheduler is not None and hasattr(scheduler, "snapshot_buffer")
                            else []
                        )
                        report = await run_cycle(buffer)
                        if not isinstance(report, dict):
                            return evolution_failure(
                                "Evolution returned an invalid report",
                                500,
                            )
                        response: dict[str, Any] = {
                            "success": True,
                            "message": "Evolution cycle completed",
                            "report": report,
                        }
                    elif action == "reflect":
                        metacognition = getattr(self, "metacognition", None)
                        reflect = getattr(metacognition, "reflect", None)
                        if not callable(reflect):
                            return evolution_failure(
                                "Metacognition subsystem is not ready",
                                503,
                            )
                        report = await asyncio.to_thread(reflect)
                        response = {
                            "health_score": report.overall_health_score,
                            "proposals": len(report.proposals),
                            "actions_taken": len(report.actions_taken),
                            "timestamp": report.timestamp,
                        }
                    else:
                        if not proposal_id.strip():
                            return evolution_failure("proposal_id is required", 400)
                        from js.evolution.cycle import (
                            EvolutionCycle,
                            load_baseline_score,
                            run_mock_benchmark,
                        )

                        cycle = EvolutionCycle(self.settings.state_dir)

                        def _decide() -> dict[str, Any]:
                            if action == "reject":
                                item = cycle.reject(
                                    proposal_id,
                                    owner,
                                    decided_by=owner,
                                )
                            else:
                                item = cycle.approve_and_apply(
                                    proposal_id,
                                    owner,
                                    decided_by=owner,
                                    benchmark=run_mock_benchmark,
                                    baseline_score=load_baseline_score(),
                                )
                            return {
                                "proposal_id": item.proposal_id,
                                "status": item.status,
                                "owner": item.owner,
                            }

                        response = await asyncio.to_thread(_decide)
            except asyncio.CancelledError:
                self._discard_memory_control_value(
                    "_evolution_action_results",
                    result_ref,
                    owner,
                )
                raise
            except Exception as exc:
                self.logger.error(
                    "Evolution action failed: %s",
                    type(exc).__name__,
                )
                message = str(exc)
                if "404" in message and "model" in message.lower():
                    return evolution_failure(
                        "Configured evolution model was not found",
                        502,
                    )
                return evolution_failure("Evolution action failed safely", 500)

            if not self._commit_memory_control_result(
                "_evolution_action_results",
                result_ref,
                owner,
                response,
            ):
                return evolution_failure("Evolution result handoff is unavailable", 503)
            return ToolResult(
                success=True,
                output="Evolution action completed",
                metadata={"result_ref": result_ref},
            )

        async def upload_mutate_handler(
            action: str,
            payload_ref: str,
        ) -> ToolResult:
            """Commit or delete owner/session uploads inside one Echo effect."""
            if action not in {"commit", "delete"}:
                return failure("Invalid upload mutation action", 400)
            if not isinstance(payload_ref, str) or not payload_ref:
                return failure("Upload payload reference is required", 400)
            context = current_runtime_context()
            if context is None or not context.owner_key_hash:
                return failure("Upload mutation requires an Echo runtime owner", 500)
            owner = context.owner_key_hash

            from js.echo.attachment_gate import (
                AttachmentGateError,
                delete_owned_upload_by_name,
            )

            if action == "delete":
                payload = self.take_upload_mutation_payload(payload_ref, owner)
                if payload is None:
                    return failure("Upload payload reference is invalid or expired", 401)
                filename = payload.get("filename")
                session_id = payload.get("session_id")
                if (
                    not isinstance(filename, str)
                    or not filename
                    or not isinstance(session_id, str)
                    or not session_id.strip()
                    or len(session_id) > 256
                ):
                    return failure("Invalid upload deletion payload", 400)
                try:
                    async with upload_mutation_lock:
                        deleted = await asyncio.to_thread(
                            delete_owned_upload_by_name,
                            Path(self.settings.workspace),
                            owner,
                            filename,
                            session_id,
                        )
                except AttachmentGateError as exc:
                    return failure(exc.detail, exc.status_code)
                except Exception:
                    self.logger.error("Upload deletion failed", exc_info=True)
                    return failure("Upload deletion failed safely", 500)
                if not deleted:
                    return failure("File not found", 404)
                return ToolResult(
                    success=True,
                    output="Upload deletion completed",
                )

            result_ref = self._reserve_memory_control_result(
                "_upload_mutation_results",
                owner,
            )
            if not result_ref:
                return failure("Upload result handoff is unavailable", 503)

            def upload_failure(message: str, status_code: int) -> ToolResult:
                self._discard_memory_control_value(
                    "_upload_mutation_results",
                    result_ref,
                    owner,
                )
                return failure(message, status_code)

            staged = self.take_upload_commit(payload_ref, owner)
            if staged is None:
                return upload_failure(
                    "Upload payload reference is invalid or expired",
                    401,
                )
            session_id, writer = staged
            target_path: Path
            try:
                async with upload_mutation_lock:
                    target_path = await asyncio.to_thread(writer.commit)
                relative_path = target_path.relative_to(Path(self.settings.workspace))
                response = {
                    "saved_as": target_path.name,
                    "path": relative_path.as_posix(),
                    "size": writer.bytes_written,
                }
            except asyncio.CancelledError:
                self._discard_memory_control_value(
                    "_upload_mutation_results",
                    result_ref,
                    owner,
                )
                raise
            except AttachmentGateError as exc:
                return upload_failure(exc.detail, exc.status_code)
            except Exception:
                self.logger.error("Upload commit failed", exc_info=True)
                return upload_failure("Upload commit failed safely", 500)
            if not self._commit_memory_control_result(
                "_upload_mutation_results",
                result_ref,
                owner,
                response,
            ):
                try:
                    await asyncio.to_thread(
                        delete_owned_upload_by_name,
                        Path(self.settings.workspace),
                        owner,
                        target_path.name,
                        session_id,
                    )
                except Exception:
                    self.logger.critical(
                        "Upload result handoff rollback failed",
                        exc_info=True,
                    )
                return upload_failure("Upload result handoff is unavailable", 503)
            return ToolResult(
                success=True,
                output="Upload commit completed",
                metadata={"result_ref": result_ref},
            )

        async def cron_mutate_handler(
            action: str,
            payload_ref: str,
        ) -> ToolResult:
            """Apply owner-bound scheduled-job mutations inside Echo."""
            if action not in {"create", "update", "delete", "run"}:
                return failure("Invalid cron mutation action", 400)
            if not isinstance(payload_ref, str) or not payload_ref:
                return failure("Cron payload reference is required", 400)
            context = current_runtime_context()
            if context is None or not context.owner_key_hash:
                return failure("Cron mutation requires an Echo runtime owner", 500)
            owner = context.owner_key_hash
            payload = self.take_cron_mutation_payload(payload_ref, owner)
            if payload is None:
                return failure("Cron payload reference is invalid or expired", 401)
            daemon = getattr(self, "_daemon", None)
            if daemon is None:
                return failure("Daemon is not running", 503)

            result_ref = self._reserve_memory_control_result(
                "_cron_mutation_results",
                owner,
            )
            if not result_ref:
                return failure("Cron result handoff is unavailable", 503)

            def cron_failure(message: str, status_code: int) -> ToolResult:
                self._discard_memory_control_value(
                    "_cron_mutation_results",
                    result_ref,
                    owner,
                )
                return failure(message, status_code)

            from js.cron.engine import (
                CronExpression,
                CronJobAlreadyRunningError,
                ScheduledJob,
            )

            def bounded_text(
                value: Any,
                *,
                default: str = "",
                maximum: int = 20_000,
            ) -> str | None:
                if value is None:
                    return default
                if not isinstance(value, str) or len(value) > maximum:
                    return None
                return value

            def strict_bool(value: Any, default: bool) -> bool | None:
                if value is None:
                    return default
                return value if isinstance(value, bool) else None

            try:
                async with cron_mutation_lock:
                    if action == "create":
                        template_id = payload.get("template_id")
                        if template_id is not None and (
                            not isinstance(template_id, str)
                            or not template_id
                            or len(template_id) > 256
                        ):
                            return cron_failure("Invalid cron template ID", 400)
                        supplied_payload = payload.get("payload", {})
                        if not isinstance(supplied_payload, dict):
                            return cron_failure(
                                "Cron job payload must be an object",
                                400,
                            )
                        if template_id:
                            from js.cron.templates import get_template

                            template = get_template(template_id)
                            if template is None:
                                return cron_failure("Unknown cron template", 400)
                            name = bounded_text(
                                payload.get("name"),
                                default=template.name,
                                maximum=512,
                            )
                            description = bounded_text(
                                payload.get("description"),
                                default=template.description,
                            )
                            cron_expr = bounded_text(
                                payload.get("cron_expr"),
                                default=template.default_cron,
                                maximum=256,
                            )
                            if name is None or description is None or cron_expr is None:
                                return cron_failure(
                                    "Invalid cron job text field",
                                    400,
                                )
                            try:
                                CronExpression(cron_expr)
                            except (TypeError, ValueError):
                                return cron_failure("Invalid cron expression", 400)
                            job = ScheduledJob(
                                name=name,
                                description=description,
                                cron_expr=cron_expr,
                                task_type=template.task_type,
                                payload={**template.default_payload, **supplied_payload},
                            )
                        else:
                            cron_expr = bounded_text(
                                payload.get("cron_expr"),
                                maximum=256,
                            )
                            if cron_expr is None:
                                return cron_failure("Invalid cron expression", 400)
                            if not cron_expr:
                                natural_language = bounded_text(
                                    payload.get("natural_language"),
                                    maximum=2_000,
                                )
                                if natural_language is None:
                                    return cron_failure(
                                        "Invalid natural-language schedule",
                                        400,
                                    )
                                from js.cron.nlp import parse_natural_language

                                parsed = (
                                    parse_natural_language(natural_language)
                                    if natural_language
                                    else None
                                )
                                if not parsed:
                                    return cron_failure(
                                        "A cron schedule is required",
                                        400,
                                    )
                                cron_expr = parsed["cron_expr"]
                            try:
                                CronExpression(cron_expr)
                            except (TypeError, ValueError):
                                return cron_failure("Invalid cron expression", 400)
                            name = bounded_text(
                                payload.get("name"),
                                default="Untitled Job",
                                maximum=512,
                            )
                            description = bounded_text(payload.get("description"))
                            task_type = bounded_text(
                                payload.get("task_type"),
                                default="custom",
                                maximum=128,
                            )
                            schedule_summary = bounded_text(
                                payload.get("schedule_summary"),
                                maximum=2_000,
                            )
                            notify_success = strict_bool(
                                payload.get("notify_on_success"),
                                False,
                            )
                            notify_failure = strict_bool(
                                payload.get("notify_on_failure"),
                                True,
                            )
                            if (
                                name is None
                                or description is None
                                or task_type is None
                                or schedule_summary is None
                                or notify_success is None
                                or notify_failure is None
                            ):
                                return cron_failure("Invalid cron job payload", 400)
                            job = ScheduledJob(
                                name=name,
                                description=description,
                                cron_expr=cron_expr,
                                task_type=task_type,
                                payload=supplied_payload,
                                schedule_summary=schedule_summary,
                                notify_on_success=notify_success,
                                notify_on_failure=notify_failure,
                            )
                        job.owner_key_hash = owner
                        job.product_id = context.product_id
                        job.session_id = f"cron:{job.id}"
                        await asyncio.to_thread(daemon.add_job, job)
                        response: dict[str, Any] = {
                            "success": True,
                            "job": job.to_dict(),
                        }
                    else:
                        job_id = bounded_text(
                            payload.get("job_id"),
                            maximum=256,
                        )
                        if not job_id:
                            return cron_failure("Invalid cron job ID", 400)
                        if action == "delete":
                            removed = await asyncio.to_thread(
                                daemon.remove_job,
                                job_id,
                                owner_key_hash=owner,
                            )
                            if not removed:
                                return cron_failure("Cron job not found", 404)
                            response = {"success": True}
                        else:
                            job = await asyncio.to_thread(
                                daemon.get_job,
                                job_id,
                                owner_key_hash=owner,
                            )
                            if job is None:
                                return cron_failure("Cron job not found", 404)
                            if action == "run":
                                run_result = await daemon.cron.run_job_now(job_id)
                                run_output, output_truncated = self._bounded_control_text(
                                    run_result.output
                                )
                                run_error, error_truncated = self._bounded_control_text(
                                    run_result.error
                                )
                                response = {
                                    "success": bool(run_result.success),
                                    "status": str(run_result.status),
                                    "duration_ms": run_result.duration_ms,
                                    "output": run_output,
                                    "error": run_error,
                                    "output_truncated": bool(
                                        getattr(run_result, "output_truncated", False)
                                    )
                                    or output_truncated,
                                    "error_truncated": bool(
                                        getattr(run_result, "error_truncated", False)
                                    )
                                    or error_truncated,
                                }
                            else:
                                changes = payload.get("changes")
                                if not isinstance(changes, dict):
                                    return cron_failure(
                                        "Cron changes must be an object",
                                        400,
                                    )
                                allowed_changes = {
                                    "name",
                                    "description",
                                    "cron_expr",
                                    "enabled",
                                    "task_type",
                                    "payload",
                                    "notify_on_success",
                                    "notify_on_failure",
                                }
                                if set(changes) - allowed_changes:
                                    return cron_failure(
                                        "Unsupported cron update field",
                                        400,
                                    )
                                validated_changes: dict[str, Any] = {}
                                for field in ("name", "description", "task_type"):
                                    if field in changes:
                                        maximum = 512 if field == "name" else 20_000
                                        value = bounded_text(
                                            changes[field],
                                            maximum=maximum,
                                        )
                                        if value is None:
                                            return cron_failure(
                                                "Invalid cron text update",
                                                400,
                                            )
                                        validated_changes[field] = value
                                next_run_at: float | None = None
                                if "cron_expr" in changes:
                                    cron_expr = bounded_text(
                                        changes["cron_expr"],
                                        maximum=256,
                                    )
                                    if not cron_expr:
                                        return cron_failure(
                                            "Invalid cron expression",
                                            400,
                                        )
                                    try:
                                        parsed_cron = CronExpression(cron_expr)
                                    except (TypeError, ValueError):
                                        return cron_failure(
                                            "Invalid cron expression",
                                            400,
                                        )
                                    validated_changes["cron_expr"] = cron_expr
                                    next_run_at = parsed_cron.next_run()
                                for field in (
                                    "enabled",
                                    "notify_on_success",
                                    "notify_on_failure",
                                ):
                                    if field in changes:
                                        value = changes[field]
                                        if not isinstance(value, bool):
                                            return cron_failure(
                                                "Invalid cron boolean update",
                                                400,
                                            )
                                        validated_changes[field] = value
                                if "payload" in changes:
                                    if not isinstance(changes["payload"], dict):
                                        return cron_failure(
                                            "Cron job payload must be an object",
                                            400,
                                        )
                                    validated_changes["payload"] = changes["payload"]
                                # Persist first via the daemon store-first
                                # update; memory is only mutated after the
                                # store commits.
                                await asyncio.to_thread(
                                    daemon.update_job,
                                    job.id,
                                    validated_changes,
                                    owner_key_hash=owner,
                                    next_run_at=next_run_at
                                    if "cron_expr" in validated_changes
                                    else None,
                                )
                                response = {"success": True, "job": job.to_dict()}
            except asyncio.CancelledError:
                self._discard_memory_control_value(
                    "_cron_mutation_results",
                    result_ref,
                    owner,
                )
                raise
            except CronJobAlreadyRunningError:
                return cron_failure("Cron job is already running", 409)
            except PermissionError:
                return cron_failure("Cron mutation is not permitted", 403)
            except Exception:
                self.logger.error("Cron mutation failed", exc_info=True)
                return cron_failure("Cron mutation failed safely", 500)

            if not self._commit_memory_control_result(
                "_cron_mutation_results",
                result_ref,
                owner,
                response,
            ):
                return cron_failure("Cron result handoff is unavailable", 503)
            return ToolResult(
                success=True,
                output="Cron mutation completed",
                metadata={"result_ref": result_ref},
            )

        async def gateway_push_handler(
            template_id: str,
            channel: str,
            peer_id: str,
        ) -> ToolResult:
            """Send one allowlisted template to a paired gateway peer."""
            async with gateway_push_lock:
                from js.echo.turn_context import current_runtime_context
                from js.gateway.adapter import ChannelPeer
                from js.gateway.attach import attach_gateway_service
                from js.gateway.push import (
                    PushTemplateError,
                    authorize_push,
                    render_push_template,
                )

                try:
                    text = render_push_template(template_id)
                except PushTemplateError as exc:
                    return failure(str(exc), 400)
                context = current_runtime_context()
                if context is None or not context.owner_key_hash:
                    return failure("Gateway push requires an Echo runtime owner", 500)
                service = attach_gateway_service(self)
                peer = ChannelPeer(channel=channel, peer_id=peer_id)
                denied = authorize_push(service, owner=context.owner_key_hash, peer=peer)
                if denied is not None:
                    return failure(denied, 403)
                try:
                    await service.send(peer, text)
                except Exception as exc:
                    return failure(f"{type(exc).__name__}: {exc}", 500)
                return ToolResult(success=True, output="gateway push sent")

        specs = (
            (
                ToolSpec(
                    name=CONTROL_SKILL_INSTALL_TOOL,
                    description="Internal administrator-approved skill installation.",
                    parameters=[
                        ToolParam("source", "string", "Local path or approved remote source"),
                        ToolParam(
                            "skill_id",
                            "string",
                            "Optional installed skill identifier",
                            required=False,
                        ),
                    ],
                    model_visible=False,
                ),
                install_handler,
            ),
            (
                ToolSpec(
                    name=CONTROL_CLAWHUB_DISCOVER_TOOL,
                    description="Internal ClawHub marketplace discovery.",
                    parameters=[
                        ToolParam(
                            "query",
                            "string",
                            "Optional marketplace query",
                            required=False,
                        )
                    ],
                    read_only=True,
                    model_visible=False,
                ),
                discover_handler,
            ),
            (
                ToolSpec(
                    name=CONTROL_CLAWHUB_INSTALL_TOOL,
                    description="Internal administrator-approved ClawHub installation.",
                    parameters=[ToolParam("skill_id", "string", "ClawHub skill identifier")],
                    model_visible=False,
                ),
                clawhub_install_handler,
            ),
            (
                ToolSpec(
                    name=CONTROL_PROVIDER_DISCOVER_TOOL,
                    description="Internal exact-endpoint provider model discovery.",
                    parameters=[
                        ToolParam("base_url", "string", "Exact provider base URL"),
                        ToolParam(
                            "api_key_ref",
                            "string",
                            "Opaque one-time in-memory credential reference",
                            required=False,
                        ),
                        ToolParam(
                            "allow_private",
                            "boolean",
                            "Allow an explicitly configured RFC1918 provider",
                            required=False,
                        ),
                    ],
                    read_only=True,
                    model_visible=False,
                ),
                provider_discover_handler,
            ),
            (
                ToolSpec(
                    name=CONTROL_PROVIDER_MUTATE_TOOL,
                    description="Internal administrator-approved provider mutation.",
                    parameters=[
                        ToolParam(
                            "action",
                            "string",
                            "Provider mutation action",
                            enum=["upsert", "update_key", "delete"],
                        ),
                        ToolParam(
                            "provider",
                            "object",
                            "Provider configuration without credentials",
                            required=False,
                        ),
                        ToolParam(
                            "name",
                            "string",
                            "Provider name for update or delete",
                            required=False,
                        ),
                        ToolParam(
                            "api_key_ref",
                            "string",
                            "Opaque one-time in-memory credential reference",
                            required=False,
                        ),
                    ],
                    model_visible=False,
                ),
                provider_mutate_handler,
            ),
            (
                ToolSpec(
                    name=CONTROL_FLEET_CONFIGURE_TOOL,
                    description="Internal administrator-approved Fleet model configuration.",
                    parameters=[
                        ToolParam(
                            "config",
                            "object",
                            "Validated role-to-model configuration",
                        )
                    ],
                    model_visible=False,
                ),
                fleet_configure_handler,
            ),
            (
                ToolSpec(
                    name=CONTROL_FLEET_CONTINUE_TOOL,
                    description="Internal administrator-approved Fleet continuation.",
                    parameters=[
                        ToolParam("session_id", "string", "Fleet session identifier"),
                        ToolParam("follow_up", "string", "Fleet follow-up task"),
                    ],
                    model_visible=False,
                ),
                fleet_continue_handler,
            ),
            (
                ToolSpec(
                    name=CONTROL_FLEET_SESSION_DELETE_TOOL,
                    description="Internal administrator-approved Fleet session deletion.",
                    parameters=[ToolParam("session_id", "string", "Fleet session identifier")],
                    model_visible=False,
                ),
                fleet_session_delete_handler,
            ),
            (
                ToolSpec(
                    name=CONTROL_MODEL_SWITCH_TOOL,
                    description="Internal administrator-approved active-model switch.",
                    parameters=[ToolParam("model_id", "string", "Configured model ID")],
                    model_visible=False,
                ),
                model_switch_handler,
            ),
            (
                ToolSpec(
                    name=CONTROL_SETUP_STATE_TOOL,
                    description="Internal setup completion or reset state mutation.",
                    parameters=[
                        ToolParam(
                            "action",
                            "string",
                            "Setup state action",
                            enum=["complete", "reset", "skip", "start", "reopen"],
                        )
                    ],
                    model_visible=False,
                ),
                setup_state_handler,
            ),
            (
                ToolSpec(
                    name=CONTROL_SESSION_MUTATE_TOOL,
                    description="Internal owner-bound session cancellation or deletion.",
                    parameters=[
                        ToolParam(
                            "action",
                            "string",
                            "Session mutation action",
                            enum=["cancel", "delete"],
                        ),
                        ToolParam("session_id", "string", "Owner-bound session ID"),
                    ],
                    model_visible=False,
                ),
                session_mutate_handler,
            ),
            (
                ToolSpec(
                    name=CONTROL_DESKTOP_STATE_TOOL,
                    description="Internal staged desktop-control state mutation.",
                    parameters=[
                        ToolParam(
                            "action",
                            "string",
                            "Desktop state action",
                            enum=[
                                "toggle",
                                "enable_read_only",
                                "enable_writes",
                                "disable",
                            ],
                        )
                    ],
                    model_visible=False,
                ),
                desktop_state_handler,
            ),
            (
                ToolSpec(
                    name=CONTROL_TASK_MUTATE_TOOL,
                    description="Internal owner-bound task state mutation.",
                    parameters=[
                        ToolParam(
                            "action",
                            "string",
                            "Task mutation action",
                            enum=["pause", "resume", "delete"],
                        ),
                        ToolParam("task_id", "string", "Owner-bound task ID"),
                    ],
                    model_visible=False,
                ),
                task_mutate_handler,
            ),
            (
                ToolSpec(
                    name=CONTROL_MEMORY_MUTATE_TOOL,
                    description="Internal owner-bound private memory mutation.",
                    parameters=[
                        ToolParam(
                            "action",
                            "string",
                            "Memory mutation action",
                            enum=[
                                "file_put",
                                "semantic_create",
                                "semantic_delete",
                                "semantic_update",
                                "semantic_verify",
                                "proposal_approve",
                                "proposal_reject",
                                "organize",
                                "block_move",
                                "block_merge",
                                "embedder_recover",
                                "capsule_store",
                                "capsule_delete",
                                "compression_create",
                                "compression_approve",
                                "compression_reject",
                            ],
                        ),
                        ToolParam("payload_ref", "string", "Opaque one-time memory payload"),
                    ],
                    model_visible=False,
                ),
                memory_mutate_handler,
            ),
            (
                ToolSpec(
                    name=CONTROL_SKILL_MUTATE_TOOL,
                    description="Internal owner-bound privileged skill mutation.",
                    parameters=[
                        ToolParam(
                            "action",
                            "string",
                            "Skill mutation action",
                            enum=[
                                "refresh_hermes",
                                "promotion_approve",
                                "promotion_reject",
                                "promotion_revert",
                                "uninstall",
                                "trust",
                            ],
                        ),
                        ToolParam("payload_ref", "string", "Opaque one-time skill payload"),
                    ],
                    model_visible=False,
                ),
                skill_mutate_handler,
            ),
            (
                ToolSpec(
                    name=CONTROL_EVOLUTION_ACTION_TOOL,
                    description="Internal administrator-approved evolution action.",
                    parameters=[
                        ToolParam(
                            "action",
                            "string",
                            "Evolution action",
                            enum=["run", "reflect", "approve", "reject"],
                        ),
                        ToolParam("proposal_id", "string", "Evolution proposal id"),
                    ],
                    model_visible=False,
                ),
                evolution_action_handler,
            ),
            (
                ToolSpec(
                    name=CONTROL_UPLOAD_MUTATE_TOOL,
                    description="Internal owner-bound upload commit or deletion.",
                    parameters=[
                        ToolParam(
                            "action",
                            "string",
                            "Upload mutation action",
                            enum=["commit", "delete"],
                        ),
                        ToolParam(
                            "payload_ref",
                            "string",
                            "Opaque one-time upload payload",
                        ),
                    ],
                    model_visible=False,
                ),
                upload_mutate_handler,
            ),
            (
                ToolSpec(
                    name=CONTROL_GATEWAY_PUSH_TOOL,
                    description="Internal lease-gated gateway template push.",
                    parameters=[
                        ToolParam("template_id", "string", "Allowlisted push template"),
                        ToolParam("channel", "string", "Gateway channel name"),
                        ToolParam("peer_id", "string", "Paired peer id"),
                    ],
                    model_visible=False,
                ),
                gateway_push_handler,
            ),
            (
                ToolSpec(
                    name=CONTROL_CRON_MUTATE_TOOL,
                    description="Internal owner-bound scheduled-job mutation.",
                    parameters=[
                        ToolParam(
                            "action",
                            "string",
                            "Cron mutation action",
                            enum=["create", "update", "delete", "run"],
                        ),
                        ToolParam(
                            "payload_ref",
                            "string",
                            "Opaque one-time cron payload",
                        ),
                    ],
                    model_visible=False,
                ),
                cron_mutate_handler,
            ),
        )
        for spec, handler in specs:
            self.registry.register(spec, handler)
