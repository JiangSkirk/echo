"""Intelligent model routing with fallback and cost optimization."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator, AsyncIterator, Awaitable, Callable
from contextlib import aclosing
from dataclasses import dataclass
from typing import Any

from cachetools import TTLCache

from js.config import JSSettings, ModelConfig
from js.models.capability import (
    SafeProviderError,
    reraise_safe_provider_error,
    safe_provider_error,
)
from js.models.permit import ModelPermitError
from js.models.providers import (
    ChatMessage,
    ChatResponse,
    ModelProvider,
    OpenAICompatibleProvider,
    is_retryable_provider_error,
)
from js.models.stream_events import StreamEvent
from js.utils.log import get_logger

logger = get_logger("js.models.router")
_NO_ROUTER_FALLBACK_ATTR = "_js_router_no_fallback"
_MAX_ROUTER_PROVIDER_ATTEMPTS = 5

_ALLOWED_ERROR_META: dict[str, type] = {
    "retryable": bool,
    "completion_tokens": int,
    "prompt_tokens": int,
    "token_source": str,
    "echo_error_code": str,
    "provider_reported_prompt_tokens": int,
    "provider_reported_completion_tokens": int,
    "provider_reported_total_tokens": int,
}

# Per-kind meta allowlists. Non-error stream frames intentionally keep meta empty
# so custom providers cannot smuggle credentials or forge diagnostic bags.
_ALLOWED_STREAM_META: dict[str, dict[str, type]] = {
    "text_delta": {},
    "thinking_delta": {},
    "tool_call_delta": {},
    "usage": {},
    "done": {},
    "error": _ALLOWED_ERROR_META,
}


def _filter_stream_meta(kind: str, meta: dict[str, Any] | None) -> dict[str, Any]:
    """Keep only allowlisted meta keys for the given stream event kind."""
    if not meta:
        return {}
    allowed = _ALLOWED_STREAM_META.get(kind, {})
    if not allowed:
        return {}
    filtered: dict[str, Any] = {}
    for key, expected_type in allowed.items():
        if key not in meta:
            continue
        value = meta[key]
        if isinstance(value, expected_type):
            filtered[key] = value
    return filtered


def _filter_error_meta(meta: dict[str, Any] | None) -> dict[str, Any]:
    """Keep only allowlisted error meta keys with strict runtime types."""
    return _filter_stream_meta("error", meta)


def _trusted_stream_event(ev: StreamEvent, decision: RoutingDecision) -> StreamEvent:
    """Rebuild a stream event with trusted routing identity and meta allowlist."""
    return StreamEvent(
        kind=ev.kind,
        text=ev.text if ev.kind in {"text_delta", "thinking_delta"} else "",
        tool_call=ev.tool_call if ev.kind == "tool_call_delta" else None,
        usage=ev.usage if ev.kind == "usage" else None,
        finish_reason=ev.finish_reason if ev.kind == "done" else None,
        error="",
        provider=decision.provider_name,
        model=decision.model,
        meta=_filter_stream_meta(ev.kind, ev.meta),
    )


def _rebuild_error_event(
    ev: StreamEvent | None,
    decision: RoutingDecision,
    safe_error: BaseException | str,
    *,
    failure_meta: dict[str, Any] | None = None,
) -> StreamEvent:
    """Rebuild a terminal error event from trusted routing + scrubbed text only."""
    meta = _filter_error_meta(failure_meta)
    if isinstance(safe_error, SafeProviderError) and "retryable" not in meta:
        meta["retryable"] = safe_error.retryable
    return StreamEvent(
        kind="error",
        error=str(safe_error),
        provider=decision.provider_name,
        model=decision.model,
        meta=meta,
    )


def _sanitize_with_provider(exc: BaseException, provider: ModelProvider) -> str:
    return str(_as_safe_provider_error(exc, provider))


def _as_safe_provider_error(exc: BaseException, provider: ModelProvider) -> SafeProviderError:
    """Ensure provider failures observed by the router are :class:`SafeProviderError`.

    Real ``OpenAICompatibleProvider`` exits already raise SafeProviderError.
    This helper covers mock/legacy providers and aggregation so logs and
    fallback messages never embed raw credential-bearing exception text.

    Always re-scrubs provider-aware — do not trust custom/legacy SafeProviderError
    messages that may have skipped sanitization.
    """
    from js.models.capability import sanitize_provider_error

    api_key = getattr(getattr(provider, "config", None), "api_key", None)
    query_param = getattr(getattr(provider, "config", None), "query_param_name", None)
    if isinstance(exc, SafeProviderError):
        message = sanitize_provider_error(
            str(exc),
            api_key=api_key,
            query_param_name=query_param,
        )
        return SafeProviderError(message, retryable=exc.retryable)
    return safe_provider_error(
        exc,
        api_key=api_key,
        query_param_name=query_param,
        retryable=is_retryable_provider_error(exc),
    )


class _StreamCompletionBudgetExceededError(RuntimeError):
    is_stream_completion_budget_exceeded = True

    def __init__(self, completion_tokens: int) -> None:
        super().__init__("Echo budget exceeded: completion_tokens_exceeded")
        self.completion_tokens = completion_tokens


@dataclass
class RoutingDecision:
    provider: ModelProvider
    model: str
    provider_name: str
    reason: str


def _mark_no_router_fallback(exc: BaseException) -> None:
    try:
        setattr(exc, _NO_ROUTER_FALLBACK_ATTR, True)
    except Exception:
        pass


def _is_no_router_fallback(exc: BaseException) -> bool:
    return bool(getattr(exc, _NO_ROUTER_FALLBACK_ATTR, False))


def _provider_is_local(provider: Any) -> bool:
    return bool(getattr(provider, "_is_local", False))


def _forbid_local_on_this_call() -> bool:
    from js.models.cascade import current_cascade_intent

    intent = current_cascade_intent()
    return bool(intent is not None and intent.forbid_local)


def _provider_attempt_limit(provider: ModelProvider) -> int:
    configured = getattr(getattr(provider, "config", None), "max_retries", 1)
    try:
        attempts = int(configured)
    except (TypeError, ValueError):
        attempts = 1
    return max(1, min(attempts, _MAX_ROUTER_PROVIDER_ATTEMPTS))


def _stream_chat_response(
    *,
    model: str,
    text: str,
    usage: dict[str, int],
    finish_reason: str,
    estimated_completion_tokens: int,
) -> ChatResponse:
    response_usage = (
        dict(usage)
        if usage
        else {
            "prompt_tokens": 0,
            "completion_tokens": estimated_completion_tokens,
            "total_tokens": estimated_completion_tokens,
            "cached_tokens": 0,
        }
    )
    prompt_tokens = int(response_usage.get("prompt_tokens", 0) or 0)
    provider_completion_tokens = int(response_usage.get("completion_tokens", 0) or 0)
    completion_tokens = max(provider_completion_tokens, estimated_completion_tokens)
    provider_total_tokens = int(
        response_usage.get("total_tokens", prompt_tokens + provider_completion_tokens) or 0
    )
    total_tokens = max(provider_total_tokens, prompt_tokens + completion_tokens)
    cached_tokens = int(response_usage.get("cached_tokens", 0) or 0)
    conservative_override = bool(usage) and completion_tokens > provider_completion_tokens
    normalized_usage = {
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "total_tokens": total_tokens,
        "cached_tokens": cached_tokens,
    }
    if conservative_override:
        normalized_usage["provider_reported_completion_tokens"] = provider_completion_tokens
        normalized_usage["provider_reported_total_tokens"] = provider_total_tokens
    return ChatResponse(
        content=text,
        tool_calls=[],
        model=model,
        usage=normalized_usage,
        finish_reason=finish_reason,
        usage_source="provider_actual" if usage and not conservative_override else "estimated",
    )


def _annotate_stream_failure(
    error: BaseException,
    *,
    text: str,
    usage: dict[str, int],
    estimated_completion_tokens: int,
) -> dict[str, int | str]:
    provider_completion_tokens = int(usage.get("completion_tokens", 0) or 0)
    completion_tokens = max(provider_completion_tokens, estimated_completion_tokens)
    token_source = (
        "provider_actual"
        if usage and provider_completion_tokens >= estimated_completion_tokens
        else "estimated"
    )
    details: dict[str, int | str] = {
        "completion_tokens": completion_tokens,
        "token_source": token_source,
    }
    if getattr(error, "is_stream_completion_budget_exceeded", False):
        details["echo_error_code"] = "completion_tokens_exceeded"
    if usage:
        provider_prompt_tokens = int(usage.get("prompt_tokens", 0) or 0)
        provider_total_tokens = int(
            usage.get(
                "total_tokens",
                provider_prompt_tokens + provider_completion_tokens,
            )
            or 0
        )
        details.update(
            prompt_tokens=provider_prompt_tokens,
            provider_reported_prompt_tokens=provider_prompt_tokens,
            provider_reported_completion_tokens=provider_completion_tokens,
            provider_reported_total_tokens=provider_total_tokens,
        )
    try:
        error.__dict__.update(
            assistant_text=text,
            **details,
        )
    except Exception:
        pass
    return details


def _stream_failure_completion(event: StreamEvent | None, error: BaseException | None) -> int:
    value: Any = None
    if event is not None:
        value = event.meta.get("completion_tokens")
    if value is None and error is not None:
        value = getattr(error, "completion_tokens", None)
    return max(0, int(value)) if isinstance(value, int) else 0


class ModelSwitchValidationError(Exception):
    """Raised when a model switch is rejected with a status code and detail."""

    def __init__(self, status_code: int, detail: str, *, needs_config: bool = False) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail
        self.needs_config = needs_config


def validate_model_for_activation(
    model_id: str,
    configured_providers: set[str],
    *,
    get_model_binding: Callable[[str], tuple[str, ModelConfig] | None] | None = None,
    get_preset: Callable[[str], Any] | None = None,
    provider_models: dict[str, set[str]] | None = None,
) -> None:
    """Validate that a model_id may become the active model.

    This is a shared pure function used by both the HTTP endpoint
    (``server.py``) and the control-plane tool (``tool_executor.py``)
    so the two layers can never drift.

    Rules (fail-closed):
    1. Extract ``provider_name`` from ``model_id`` (``"provider/model"``).
    2. If ``provider_name`` is **not** in ``configured_providers``:
       - If ``get_preset`` says it is a known preset -> raise 409
         ``needs_config``.
       - Otherwise -> raise 400 invalid.
       Router mappings (stale or dynamic) are **irrelevant** here:
       a mapping alone does not prove the provider is configured.
    3. If ``provider_name`` **is** configured, the model must still be
       explicitly declared.  Accept if any of:
       - ``provider_models`` maps ``provider_name`` to a set containing
         ``model_suffix`` (declared in ``settings.models``); **or**
       - ``get_model_binding(model_id)`` returns a tuple whose
         ``[0]`` equals ``provider_name`` and whose ``[1].id`` equals
         ``model_suffix``; **or**
       - ``get_model_binding(model_suffix)`` returns a tuple whose
         ``[0]`` equals ``provider_name`` and whose ``[1].id`` equals
         ``model_suffix``.
    4. Otherwise -> raise 400 invalid.
    """
    provider_name = model_id.split("/", 1)[0] if "/" in model_id else ""

    if provider_name not in configured_providers:
        if get_preset is not None:
            try:
                if get_preset(provider_name) is not None:
                    raise ModelSwitchValidationError(
                        409,
                        (f"Provider '{provider_name}' 尚未配置，请先添加该云模型并填写 API Key。"),
                        needs_config=True,
                    )
            except ModelSwitchValidationError:
                raise
            except Exception:
                pass
        raise ModelSwitchValidationError(400, f"Invalid model '{model_id}'")

    model_suffix = model_id.split("/", 1)[1] if "/" in model_id else model_id

    if provider_models is not None:
        declared = provider_models.get(provider_name)
        if declared and model_suffix in declared:
            return

    if get_model_binding is not None:
        try:
            binding = get_model_binding(model_id)
        except Exception:
            binding = None
        if binding is not None and isinstance(binding, tuple) and len(binding) == 2:
            bp_name, bp_config = binding
            if (
                isinstance(bp_name, str)
                and isinstance(bp_config, ModelConfig)
                and bp_name == provider_name
                and bp_config.id == model_suffix
            ):
                return
        try:
            binding_short = get_model_binding(model_suffix)
        except Exception:
            binding_short = None
        if (
            binding_short is not None
            and isinstance(binding_short, tuple)
            and len(binding_short) == 2
        ):
            bp_name, bp_config = binding_short
            if (
                isinstance(bp_name, str)
                and isinstance(bp_config, ModelConfig)
                and bp_name == provider_name
                and bp_config.id == model_suffix
            ):
                return

    raise ModelSwitchValidationError(400, f"Invalid model '{model_id}'")


class ModelRouter:
    """Routes requests to appropriate models with health checks and fallback."""

    # Class-level default so subclasses that bypass ``__init__`` still fail
    # closed at the permit gate instead of raising AttributeError.
    _permit_verifier: Any | None = None

    def __init__(self, settings: JSSettings, *, permit_verifier: Any | None = None) -> None:
        self.settings = settings
        self._providers: dict[str, ModelProvider] = {}
        self._model_map: dict[
            str, tuple[str, ModelConfig]
        ] = {}  # model_id -> (provider_name, config)
        self._routing_cache: TTLCache[str, RoutingDecision] = TTLCache(maxsize=50, ttl=10)
        self.preferred_model: str | None = None
        # Unforgeable single-use permit verifier owned by the Echo turn runtime.
        # There is deliberately no public setter: authorization identity comes
        # from this cryptographic capability, not from rebindable callbacks.
        self._permit_verifier = permit_verifier
        self._init_providers()

    def _consume_model_permit(
        self,
        permit_grant: Callable[
            [RoutingDecision, list[ChatMessage], list[dict[str, Any]] | None], Any
        ],
        decision: RoutingDecision,
        messages: list[ChatMessage],
        tools: list[dict[str, Any]] | None,
    ) -> None:
        """Issue-and-verify a fresh single-use permit for one provider attempt.

        Called before every real provider attempt (initial try, transport
        retry, cross-provider fallback and stream reconnect).  Fails closed:
        a missing/invalid verifier or a forged, expired, mismatched, or
        replayed permit aborts the call before any provider code runs.
        """
        if self._permit_verifier is None:
            raise ModelPermitError(
                "ModelRouter has no Echo permit verifier; direct provider calls "
                "are only available through the Echo turn runtime."
            )
        try:
            permit = permit_grant(decision, messages, tools)
            self._permit_verifier.verify_and_consume(
                permit,
                provider_name=decision.provider_name,
                model=decision.model,
                messages=messages,
                tools=tools,
            )
        except ModelPermitError as exc:
            _mark_no_router_fallback(exc)
            raise
        except Exception as exc:  # defensive: a broken grant must fail closed
            _mark_no_router_fallback(exc)
            raise ModelPermitError(f"model permit grant failed: {exc}") from exc

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
        # Clear stale mappings for this provider first so that old model ids
        # (e.g. from a previous discover_models refresh) don't linger.
        old_provider = self._providers.pop(name, None)
        self._model_map = {k: v for k, v in self._model_map.items() if v[0] != name}
        self._providers[name] = provider
        for m in models:
            self._model_map[m.id] = (name, m)
            self._model_map[f"{name}/{m.id}"] = (name, m)
        self._routing_cache.clear()
        # Close the old provider asynchronously without blocking the caller.
        if old_provider is not None:
            try:
                asyncio.get_running_loop()
                from js.utils.async_tasks import spawn_background_task

                spawn_background_task(old_provider.close(), name=f"close-provider-{name}")
            except RuntimeError:
                pass

    def remove_provider(self, name: str) -> bool:
        """Remove a provider and all its model mappings."""
        if name not in self._providers:
            return False
        old_provider = self._providers.pop(name)
        self._model_map = {k: v for k, v in self._model_map.items() if v[0] != name}
        self._routing_cache.clear()
        # Close the old provider asynchronously without blocking the caller.
        try:
            asyncio.get_running_loop()
            from js.utils.async_tasks import spawn_background_task

            spawn_background_task(old_provider.close(), name=f"close-provider-{name}")
        except RuntimeError:
            pass
        return True

    def get_model_config(self, model_id: str) -> ModelConfig | None:
        """Get model config by ID."""
        entry = self._model_map.get(model_id)
        if entry:
            return entry[1]
        return None

    def _clamp_stream_max_tokens(
        self,
        decision: RoutingDecision,
        requested_max_tokens: int | None,
    ) -> int | None:
        model_cfg = self.get_model_config(decision.model)
        model_cap = getattr(model_cfg, "max_tokens", None) if model_cfg is not None else None
        if isinstance(model_cap, bool) or not isinstance(model_cap, int) or model_cap <= 0:
            return requested_max_tokens
        if requested_max_tokens is None:
            return model_cap
        return min(max(0, requested_max_tokens), model_cap)

    def get_model_binding(self, model_id: str) -> tuple[str, ModelConfig] | None:
        """Return the configured provider/model pair without probing provider health."""
        entry = self._model_map.get(model_id)
        if entry and isinstance(entry, tuple) and len(entry) == 2:
            provider_name, config = entry
            if isinstance(provider_name, str) and isinstance(config, ModelConfig):
                return provider_name, config
        return None

    def get_model_bindings(self) -> tuple[tuple[str, ModelConfig], ...]:
        """Return deduplicated bindings backed by exact full model IDs."""
        bindings: list[tuple[str, ModelConfig]] = []
        seen: set[str] = set()
        for model_id, entry in self._model_map.items():
            if not isinstance(entry, tuple) or len(entry) != 2:
                continue
            provider_name, config = entry
            if not isinstance(provider_name, str) or not isinstance(config, ModelConfig):
                continue
            full_id = f"{provider_name}/{config.id}"
            if model_id != full_id or full_id in seen:
                continue
            seen.add(full_id)
            bindings.append((provider_name, config))
        return tuple(bindings)

    def is_local_model(self, model_id: str) -> bool:
        """Return True if the model is served by a local provider (e.g. LMStudio, Ollama)."""
        entry = self._model_map.get(model_id)
        if not entry:
            return False
        provider = self._providers.get(entry[0])
        return _provider_is_local(provider)

    def has_non_local_backend(self) -> bool:
        """True when at least one configured provider is not a local server."""

        return any(not _provider_is_local(provider) for provider in self._providers.values())

    def local_only_backends(self) -> bool:
        """True when every configured provider is local (and at least one exists)."""

        return bool(self._providers) and not self.has_non_local_backend()

    async def _provider_healthy(self, provider: ModelProvider) -> bool:
        """Read local health state without starting an unpermitted network probe.

        Routing is allowed to consult circuit-breaker and previously recorded
        provider state only.  An unknown provider remains eligible so its real
        model request can run through the Echo permit boundary and report the
        authoritative outcome there.
        """
        try:
            if hasattr(provider, "circuit"):
                circuit_state = await provider.circuit.state()
                if circuit_state.value == "open":
                    return False

            last_check = getattr(provider, "_last_health_check", 0.0)
            if isinstance(last_check, (int, float)) and last_check > 0:
                return bool(getattr(provider, "_health_status", False))

            # Lightweight/mock providers may expose explicit in-memory state.
            healthy = getattr(provider, "healthy", None)
            if isinstance(healthy, bool):
                return healthy

            return True
        except Exception:
            return False

    def _provider_defaults(self) -> dict[str, str]:
        """Provider name → default model id from settings and runtime adds."""

        provider_defaults: dict[str, str] = {}
        for p_config in self.settings.providers:
            if p_config.default_model:
                provider_defaults[p_config.name] = p_config.default_model
            elif p_config.models:
                chat_models = [m for m in p_config.models if "embed" not in m.id.lower()]
                model_candidates = chat_models if chat_models else p_config.models
                if model_candidates:
                    provider_defaults[p_config.name] = model_candidates[0].id
        for full_id, (provider_name, config) in self._model_map.items():
            if provider_name not in provider_defaults and "/" not in full_id:
                provider_defaults[provider_name] = config.id
        return provider_defaults

    def _order_candidates(
        self,
        candidates: list[tuple[str, str, ModelProvider]],
        *,
        complexity: str,
        forbid_local: bool,
    ) -> list[tuple[str, str, ModelProvider]]:
        if forbid_local:
            remote = [item for item in candidates if not _provider_is_local(item[2])]
            return remote
        from js.models.cascade import cascade_routing_enabled

        if complexity == "light" and cascade_routing_enabled(self.settings):
            local = [item for item in candidates if _provider_is_local(item[2])]
            remote = [item for item in candidates if not _provider_is_local(item[2])]
            return local + remote
        return candidates

    async def select_model(
        self,
        _task_complexity: str = "medium",
        preferred: str | None = None,
    ) -> RoutingDecision:
        """Select best model for task, skipping unhealthy providers.

        ``_task_complexity`` is the T11 cascade input (light / medium / heavy).
        Echo may override it via cascade intent. Heavy + a non-local backend
        never returns a local model; that rule is not a routing-table flag.
        """
        from js.models.cascade import current_cascade_intent

        intent = current_cascade_intent()
        complexity = intent.complexity if intent is not None else _task_complexity
        if complexity not in {"light", "medium", "heavy"}:
            complexity = "medium"
        forbid_local = bool(intent is not None and intent.forbid_local)
        if (
            preferred is None
            and self.preferred_model
            and not (complexity == "light" and not forbid_local)
        ):
            preferred = self.preferred_model
        if preferred and forbid_local and self.is_local_model(preferred):
            preferred = None
        cache_key = f"{preferred or '__default__'}|{complexity}|{int(forbid_local)}"
        cached: RoutingDecision | None = self._routing_cache.get(cache_key)
        if cached is not None:
            if forbid_local and _provider_is_local(cached.provider):
                self._routing_cache.pop(cache_key, None)
            else:
                return cached

        if preferred and preferred in self._model_map:
            provider_name, config = self._model_map[preferred]
            provider = self._providers[provider_name]
            if not (forbid_local and _provider_is_local(provider)):
                if await self._provider_healthy(provider):
                    decision = RoutingDecision(
                        provider=provider,
                        model=config.id,
                        provider_name=provider_name,
                        reason=f"User preferred: {preferred}",
                    )
                else:
                    # Respect user's explicit choice even if the provider appears
                    # unhealthy.  Let the actual API call fail and surface the
                    # error rather than silently falling back to a different model.
                    decision = RoutingDecision(
                        provider=provider,
                        model=config.id,
                        provider_name=provider_name,
                        reason=f"User preferred (unhealthy): {preferred}",
                    )
                self._routing_cache[cache_key] = decision
                return decision

        provider_defaults = self._provider_defaults()
        candidates = [
            (name, model, self._providers[name])
            for name, model in provider_defaults.items()
            if name in self._providers
        ]
        ordered = self._order_candidates(
            candidates,
            complexity=complexity,
            forbid_local=forbid_local,
        )
        if forbid_local and not ordered:
            raise RuntimeError("plan-commit and mid-turn dirty calls require a non-local model")
        if ordered:
            health_results = await asyncio.gather(
                *[self._provider_healthy(p) for _, _, p in ordered],
                return_exceptions=True,
            )
            for (name, model, _provider), healthy in zip(ordered, health_results, strict=False):
                if isinstance(healthy, bool) and healthy:
                    decision = RoutingDecision(
                        provider=self._providers[name],
                        model=model,
                        provider_name=name,
                        reason=f"Default model: {model} ({complexity})",
                    )
                    self._routing_cache[cache_key] = decision
                    return decision

        last_resort = (
            [(item[0], item[1]) for item in ordered] if ordered else list(provider_defaults.items())
        )
        for provider_name, default_model in last_resort:
            maybe_provider = self._providers.get(provider_name)
            if maybe_provider is None:
                continue
            if forbid_local and _provider_is_local(maybe_provider):
                continue
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
        max_tokens: int | None = None,
        before_model_call: Callable[
            [RoutingDecision, list[ChatMessage], list[dict[str, Any]] | None], Awaitable[Any]
        ]
        | None = None,
        after_model_call: Callable[
            [Any, ChatResponse | None, BaseException | None], Awaitable[None]
        ]
        | None = None,
        permit_grant: Callable[
            [RoutingDecision, list[ChatMessage], list[dict[str, Any]] | None], Any
        ]
        | None = None,
    ) -> ChatResponse:
        """Send chat request with automatic fallback.

        When ``model`` is explicitly specified by the user we respect that
        choice and do **not** silently fall back to another provider – the
        user should see an error if their chosen model fails.  Fallback is
        only allowed when ``model`` is ``None`` (auto-select).

        Every provider attempt (initial try, transport retry, cross-provider
        fallback) consumes a fresh single-use permit obtained from
        ``permit_grant`` and verified against the runtime-owned verifier;
        without it the call fails closed before any provider code runs.
        """
        if before_model_call is None or after_model_call is None or permit_grant is None:
            raise RuntimeError(
                "Echo requires before_model_call/after_model_call callbacks and "
                "a runtime-issued permit_grant for ModelRouter.chat(); direct "
                "provider chat is only available through the Echo turn runtime."
            )
        if self._permit_verifier is None:
            raise ModelPermitError(
                "ModelRouter has no Echo permit verifier; direct provider calls "
                "are only available through the Echo turn runtime."
            )
        decision = await self.select_model(preferred=model)
        errors: list[str] = []

        async def _before(call_decision: RoutingDecision) -> Any:
            if before_model_call is None:
                return None
            try:
                return await before_model_call(call_decision, messages, tools)
            except Exception as exc:
                _mark_no_router_fallback(exc)
                raise

        async def _after(
            context: Any,
            response: ChatResponse | None,
            error: BaseException | None,
        ) -> None:
            if after_model_call is not None:
                try:
                    await after_model_call(context, response, error)
                except Exception as exc:
                    _mark_no_router_fallback(exc)
                    raise

        async def _call_provider_once(call_decision: RoutingDecision) -> ChatResponse:
            context: Any = None
            try:
                self._consume_model_permit(permit_grant, call_decision, messages, tools)
                context = await _before(call_decision)
                response = await call_decision.provider.chat(
                    messages=messages,
                    model=call_decision.model,
                    tools=tools,
                    temperature=temperature,
                    max_tokens=max_tokens,
                )
            except BaseException as exc:
                # Convert provider failures before after-hooks / re-raise so Echo
                # finalizers and logs never observe raw credential-bearing errors.
                observed: BaseException = exc
                if not isinstance(
                    exc, (asyncio.CancelledError, SafeProviderError)
                ) and not _is_no_router_fallback(exc):
                    observed = _as_safe_provider_error(exc, call_decision.provider)
                if context is not None:
                    if isinstance(exc, asyncio.CancelledError):
                        try:
                            await _after(context, None, exc)
                        except BaseException as cleanup_error:
                            logger.warning(
                                "Model-call cancellation cleanup failed",
                                exc_info=True,
                            )
                            raise cleanup_error from None
                    else:
                        await _after(context, None, observed)
                if isinstance(observed, SafeProviderError):
                    reraise_safe_provider_error(observed)
                raise observed from None
            await _after(context, response, None)
            return response

        async def _call_provider(call_decision: RoutingDecision) -> ChatResponse:
            attempt_limit = _provider_attempt_limit(call_decision.provider)
            for attempt in range(attempt_limit):
                try:
                    return await _call_provider_once(call_decision)
                except Exception as exc:
                    if (
                        _is_no_router_fallback(exc)
                        or not is_retryable_provider_error(exc)
                        or attempt + 1 >= attempt_limit
                    ):
                        raise
                    delay = min(2**attempt, 30)
                    logger.warning(
                        "Provider transport retry %s/%s for %s after %ss",
                        attempt + 2,
                        attempt_limit,
                        call_decision.provider_name,
                        delay,
                    )
                    await asyncio.sleep(delay)
            reraise_safe_provider_error(
                SafeProviderError("provider retry loop ended without a result")
            )

        try:
            return await _call_provider(decision)
        except Exception as e:
            if _is_no_router_fallback(e):
                raise
            safe = _as_safe_provider_error(e, decision.provider)
            errors.append(f"{decision.provider_name}/{decision.model}: {safe}")
            if model is not None:
                # User explicitly requested this model – do not silently fallback.
                reraise_safe_provider_error(
                    SafeProviderError(f"Requested model '{model}' failed: {safe}")
                )

        # Fallback is only reached when ``model`` is None (auto-select).
        # Try fallback providers (skip unhealthy ones)
        for name, provider in self._providers.items():
            if name == decision.provider_name:
                continue
            if _forbid_local_on_this_call() and _provider_is_local(provider):
                continue
            try:
                if not await self._provider_healthy(provider):
                    continue
                # Use provider's default model
                fallback_model = next(
                    (
                        m.id
                        for mid, (p, m) in self._model_map.items()
                        if p == name and "/" not in mid
                    ),
                    "",
                )
                if not fallback_model:
                    continue
                fallback_decision = RoutingDecision(
                    provider=provider,
                    model=fallback_model,
                    provider_name=name,
                    reason=f"Fallback: {fallback_model}",
                )
                return await _call_provider(fallback_decision)
            except Exception as e:
                if _is_no_router_fallback(e):
                    raise
                safe = _as_safe_provider_error(e, provider)
                errors.append(f"{name}: {safe}")
                logger.warning("Provider fallback %s failed: %s", name, safe)

        # Last resort: try the original selected provider even if unhealthy
        try:
            return await _call_provider(decision)
        except Exception as e:
            if _is_no_router_fallback(e):
                raise
            safe = _as_safe_provider_error(e, decision.provider)
            errors.append(f"{decision.provider_name}/{decision.model} (last resort): {safe}")

        reraise_safe_provider_error(SafeProviderError(f"All providers failed: {'; '.join(errors)}"))

    async def chat_stream(
        self,
        messages: list[ChatMessage],
        model: str | None = None,
        temperature: float = 0.7,
    ) -> AsyncIterator[str]:
        """Stream tokens from the selected model with fallback.

        When ``model`` is explicitly specified by the user we respect that
        choice and do **not** silently fall back to another provider.
        """
        del messages, model, temperature
        raise RuntimeError(
            "Echo requires Echo-gated chat_stream_events() with "
            "before_model_call/after_model_call hooks; direct ModelRouter.chat_stream() "
            "is not a supported JS Agent runtime path."
        )
        yield ""  # pragma: no cover - keeps this API an async iterator

    async def chat_stream_events(
        self,
        messages: list[ChatMessage],
        model: str | None = None,
        temperature: float = 0.7,
        tools: list[dict[str, Any]] | None = None,
        max_tokens: int | None = None,
        before_model_call: Callable[
            [RoutingDecision, list[ChatMessage], list[dict[str, Any]] | None], Awaitable[Any]
        ]
        | None = None,
        after_model_call: Callable[
            [Any, ChatResponse | None, BaseException | None], Awaitable[None]
        ]
        | None = None,
        permit_grant: Callable[
            [RoutingDecision, list[ChatMessage], list[dict[str, Any]] | None], Any
        ]
        | None = None,
    ) -> AsyncGenerator[StreamEvent, None]:
        """Structured-event variant of ``chat_stream``.

        Returns one stream of ``StreamEvent`` (text_delta / thinking_delta /
        tool_call_delta / usage / done / error). When the chosen provider
        fails before emitting text AND ``model`` was auto-selected, we may
        fail over to the next healthy provider. Once text has been emitted,
        every error or incomplete close is terminal so fallback cannot
        duplicate output or bypass the completion budget.

        Every provider attempt (initial try, reconnect, fallback) consumes a
        fresh single-use permit from ``permit_grant``; without a valid permit
        the stream fails closed before any provider code runs.
        """

        if before_model_call is None or after_model_call is None or permit_grant is None:
            raise RuntimeError(
                "Echo requires before_model_call/after_model_call callbacks and "
                "a runtime-issued permit_grant for "
                "ModelRouter.chat_stream_events(); direct provider stream "
                "is only available through the Echo turn runtime."
            )
        if self._permit_verifier is None:
            raise ModelPermitError(
                "ModelRouter has no Echo permit verifier; direct provider calls "
                "are only available through the Echo turn runtime."
            )
        decision = await self.select_model(preferred=model)
        first_error: StreamEvent | None = None
        fallback_error: StreamEvent | None = None
        fallback_error_decision: RoutingDecision | None = None
        consumed_completion_tokens = 0

        attempt_limit = _provider_attempt_limit(decision.provider)
        for attempt in range(attempt_limit):
            attempt_max_tokens = (
                None if max_tokens is None else max(0, max_tokens - consumed_completion_tokens)
            )
            if attempt_max_tokens == 0:
                break
            primary_stream = self._chat_stream_events_for_decision(
                decision,
                messages=messages,
                tools=tools,
                temperature=temperature,
                max_tokens=attempt_max_tokens,
                before_model_call=before_model_call,
                after_model_call=after_model_call,
                permit_grant=permit_grant,
            )
            primary_emitted_output = False
            retry_requested = False
            try:
                async with aclosing(primary_stream):
                    async for ev in primary_stream:
                        if ev.kind in {"text_delta", "thinking_delta", "tool_call_delta"}:
                            primary_emitted_output = True
                        if ev.kind == "error":
                            first_error = ev
                            consumed_completion_tokens += _stream_failure_completion(ev, None)
                            retry_requested = (
                                bool(ev.meta.get("retryable"))
                                and not primary_emitted_output
                                and attempt + 1 < attempt_limit
                            )
                            if retry_requested:
                                break
                            if model is not None or primary_emitted_output:
                                yield ev
                                return
                            break
                        yield ev
                        if ev.kind == "done":
                            return
                if retry_requested:
                    delay = min(2**attempt, 30)
                    logger.warning(
                        "Provider stream reconnect %s/%s for %s after %ss",
                        attempt + 2,
                        attempt_limit,
                        decision.provider_name,
                        delay,
                    )
                    await asyncio.sleep(delay)
                    continue
                break
            except Exception as exc:
                if _is_no_router_fallback(exc) or primary_emitted_output:
                    raise
                safe = _as_safe_provider_error(exc, decision.provider)
                consumed_completion_tokens += _stream_failure_completion(None, safe)
                first_error = _rebuild_error_event(None, decision, safe)
                if is_retryable_provider_error(safe) and attempt + 1 < attempt_limit:
                    delay = min(2**attempt, 30)
                    logger.warning(
                        "Provider stream reconnect %s/%s for %s after %ss",
                        attempt + 2,
                        attempt_limit,
                        decision.provider_name,
                        delay,
                    )
                    await asyncio.sleep(delay)
                    continue
                if model is not None:
                    reraise_safe_provider_error(safe)
                break

        # Fallback path is only reached when ``model`` is None.
        for name, provider in self._providers.items():
            if name == decision.provider_name:
                continue
            if _forbid_local_on_this_call() and _provider_is_local(provider):
                continue
            fallback_emitted_text = False
            attempt_max_tokens = (
                None if max_tokens is None else max(0, max_tokens - consumed_completion_tokens)
            )
            if attempt_max_tokens == 0:
                break
            try:
                if not await self._provider_healthy(provider):
                    continue
                fallback_model = next(
                    (
                        m.id
                        for mid, (p, m) in self._model_map.items()
                        if p == name and "/" not in mid
                    ),
                    "",
                )
                if not fallback_model:
                    continue
                fallback_decision = RoutingDecision(
                    provider=provider,
                    model=fallback_model,
                    provider_name=name,
                    reason=f"Fallback: {fallback_model}",
                )
                fallback_failed = False
                fallback_stream = self._chat_stream_events_for_decision(
                    fallback_decision,
                    messages=messages,
                    tools=tools,
                    temperature=temperature,
                    max_tokens=attempt_max_tokens,
                    before_model_call=before_model_call,
                    after_model_call=after_model_call,
                    permit_grant=permit_grant,
                )
                async with aclosing(fallback_stream):
                    async for ev in fallback_stream:
                        if ev.kind == "text_delta" and ev.text:
                            fallback_emitted_text = True
                        if ev.kind == "error":
                            fallback_error = ev
                            fallback_error_decision = fallback_decision
                            fallback_failed = True
                            consumed_completion_tokens += _stream_failure_completion(ev, None)
                            if fallback_emitted_text:
                                yield ev
                                return
                            break
                        yield ev
                        if ev.kind == "done":
                            return
                if fallback_failed:
                    continue
                return
            except Exception as e:
                if _is_no_router_fallback(e) or fallback_emitted_text:
                    raise
                safe = _as_safe_provider_error(e, provider)
                consumed_completion_tokens += _stream_failure_completion(None, safe)
                logger.warning("Stream-event fallback %s failed: %s", name, safe)

        # All providers failed: emit the original error (or a synthesised one)
        # so the consumer always sees a terminal event.
        if fallback_error is not None:
            yield _rebuild_error_event(
                fallback_error,
                fallback_error_decision or decision,
                SafeProviderError(fallback_error.error or "stream error"),
                failure_meta=fallback_error.meta,
            )
        elif first_error is not None:
            yield _rebuild_error_event(
                first_error,
                decision,
                SafeProviderError(first_error.error or "stream error"),
                failure_meta=first_error.meta,
            )
        else:
            yield _rebuild_error_event(
                None,
                decision,
                SafeProviderError("all providers failed to produce a stream"),
            )

    async def _chat_stream_events_for_decision(
        self,
        decision: RoutingDecision,
        *,
        messages: list[ChatMessage],
        tools: list[dict[str, Any]] | None,
        temperature: float,
        max_tokens: int | None,
        before_model_call: Callable[
            [RoutingDecision, list[ChatMessage], list[dict[str, Any]] | None], Awaitable[Any]
        ]
        | None,
        after_model_call: Callable[
            [Any, ChatResponse | None, BaseException | None], Awaitable[None]
        ]
        | None,
        permit_grant: Callable[
            [RoutingDecision, list[ChatMessage], list[dict[str, Any]] | None], Any
        ]
        | None = None,
    ) -> AsyncGenerator[StreamEvent, None]:
        """Stream one provider decision through the same model-gate hooks as chat()."""
        provider_max_tokens = self._clamp_stream_max_tokens(decision, max_tokens)
        context: Any = None
        finalized = False
        text_parts: list[str] = []
        usage: dict[str, int] = {}
        estimated_completion_tokens = 0
        estimated_completion_bytes = 0

        async def _before() -> Any:
            if before_model_call is None:
                return None
            try:
                return await before_model_call(decision, messages, tools)
            except Exception as exc:
                _mark_no_router_fallback(exc)
                raise

        async def _after(
            response: ChatResponse | None,
            error: BaseException | None,
        ) -> None:
            if after_model_call is None:
                return
            try:
                await after_model_call(context, response, error)
            except Exception as exc:
                _mark_no_router_fallback(exc)
                raise

        async def _finalize(
            response: ChatResponse | None,
            error: BaseException | None,
        ) -> None:
            nonlocal finalized
            if finalized:
                return
            finalized = True
            await _after(response, error)

        try:
            if permit_grant is None:
                raise ModelPermitError(
                    "Echo model stream attempt is missing its runtime permit grant"
                )
            self._consume_model_permit(permit_grant, decision, messages, tools)
            context = await _before()
            async for raw_ev in decision.provider.chat_stream_events(
                messages=messages,
                model=decision.model,
                tools=tools,
                temperature=temperature,
                max_tokens=provider_max_tokens,
            ):
                if raw_ev.kind == "error":
                    # Re-scrub provider-aware: custom/legacy streams may emit raw secrets.
                    error = _as_safe_provider_error(
                        SafeProviderError(
                            raw_ev.error or "stream error",
                            retryable=bool(raw_ev.meta.get("retryable")),
                        ),
                        decision.provider,
                    )
                    failure_meta = _annotate_stream_failure(
                        error,
                        text="".join(text_parts),
                        usage=usage,
                        estimated_completion_tokens=estimated_completion_tokens,
                    )
                    await _finalize(None, error)
                    yield _rebuild_error_event(
                        raw_ev,
                        decision,
                        error,
                        failure_meta=failure_meta,
                    )
                    return

                ev = _trusted_stream_event(raw_ev, decision)
                if ev.kind == "text_delta" and ev.text:
                    estimated_completion_bytes += len(ev.text.encode("utf-8"))
                    estimated_completion_tokens = max(
                        1,
                        (estimated_completion_bytes + 3) // 4,
                    )
                    if max_tokens is not None and estimated_completion_tokens > max_tokens:
                        budget_error = _StreamCompletionBudgetExceededError(
                            estimated_completion_tokens
                        )
                        failure_meta = _annotate_stream_failure(
                            budget_error,
                            text="".join(text_parts),
                            usage=usage,
                            estimated_completion_tokens=estimated_completion_tokens,
                        )
                        await _finalize(None, budget_error)
                        yield _rebuild_error_event(
                            None,
                            decision,
                            budget_error,
                            failure_meta=failure_meta,
                        )
                        return
                    text_parts.append(ev.text)
                elif ev.kind == "usage" and ev.usage:
                    usage = dict(ev.usage)
                elif ev.kind == "done":
                    await _finalize(
                        _stream_chat_response(
                            model=decision.model,
                            text="".join(text_parts),
                            usage=usage,
                            finish_reason=ev.finish_reason or "stop",
                            estimated_completion_tokens=estimated_completion_tokens,
                        ),
                        None,
                    )
                    yield ev
                    return
                yield ev
            error = SafeProviderError("model stream ended without done event")
            failure_meta = _annotate_stream_failure(
                error,
                text="".join(text_parts),
                usage=usage,
                estimated_completion_tokens=estimated_completion_tokens,
            )
            await _finalize(None, error)
            yield _rebuild_error_event(
                None,
                decision,
                error,
                failure_meta=failure_meta,
            )
        except BaseException as exc:
            # Preserve Echo/permit fail-closed control errors. Only scrub unknown
            # provider/stream failures into SafeProviderError.
            preserve_control = isinstance(
                exc,
                (asyncio.CancelledError, PermissionError),
            ) or _is_no_router_fallback(exc)
            if context is not None and not finalized:
                if isinstance(exc, asyncio.CancelledError) or preserve_control:
                    cleanup_error: BaseException = exc
                elif isinstance(exc, Exception):
                    # Convert unknown stream-generator failures before after-hook /
                    # logs / Echo finalizer can observe credential-bearing text.
                    cleanup_error = _as_safe_provider_error(exc, decision.provider)
                else:
                    cleanup_error = RuntimeError("model stream closed early")
                _annotate_stream_failure(
                    cleanup_error,
                    text="".join(text_parts),
                    usage=usage,
                    estimated_completion_tokens=estimated_completion_tokens,
                )
                if text_parts:
                    _mark_no_router_fallback(cleanup_error)
                try:
                    await _finalize(None, cleanup_error)
                except Exception as finalize_error:
                    if isinstance(exc, (Exception, asyncio.CancelledError, GeneratorExit)):
                        raise finalize_error from None
                    logger.warning(
                        "Model stream cleanup finalization failed",
                        exc_info=True,
                    )
            if preserve_control:
                raise
            if isinstance(exc, Exception):
                raise _as_safe_provider_error(exc, decision.provider) from None
            raise

    async def health_check(self) -> dict[str, bool]:
        """Return cached provider health without performing network I/O."""
        results: dict[str, bool] = {}
        for name, provider in self._providers.items():
            results[name] = await self._provider_healthy(provider)
        return results

    async def close(self) -> None:
        """Close all provider connections."""
        for provider in self._providers.values():
            try:
                await provider.close()
            except Exception:
                logger.warning("Operation failed", exc_info=True)
