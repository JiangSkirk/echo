"""Rule-based cascade routing (T11). Not an LLM classifier.

Light path prefers a local model, then upgrades to cloud. Plan-commit and
mid-turn dirty calls are marked ``heavy`` by Echo; the router must not send
those to ``is_local_model`` when a non-local backend exists. That ban is not a
routing-table flag.
"""

from __future__ import annotations

from collections.abc import Sequence
from contextvars import ContextVar, Token
from dataclasses import dataclass
from typing import Any, Final, Literal

TaskComplexity = Literal["light", "medium", "heavy"]

# Predefined light-path set for the P2-3 ≥40% cloud-share drop check.
LIGHT_PATH_TASKS: Final[tuple[str, ...]] = (
    "hello",
    "hi",
    "thanks",
    "what is 2+2",
    "ping",
    "ok",
    "yes",
    "define latency",
    "translate cat to french",
    "what day is it",
)

_LIGHT_MAX_CHARS: Final[int] = 240
_HEAVY_HINTS: Final[tuple[str, ...]] = (
    " then ",
    " after that",
    "write ",
    "save ",
    "shell",
    "https://",
    "http://",
    "rm -",
    "curl ",
    "fetch ",
    "plan:",
    "step 1",
)

_cascade_intent: ContextVar[CascadeIntent | None] = ContextVar(
    "echo_cascade_intent",
    default=None,
)


@dataclass(frozen=True, slots=True)
class CascadeIntent:
    """Echo-authored routing constraint for one model call."""

    complexity: TaskComplexity
    forbid_local: bool
    local_only_deny_write: bool


def classify_task_complexity(
    *,
    user_text: str = "",
    messages: Sequence[Any] | None = None,
    plan_commit: bool = False,
    midturn_dirty: bool = False,
) -> TaskComplexity:
    """Deterministic difficulty/risk class. Never calls a model."""

    if plan_commit or midturn_dirty:
        return "heavy"
    text = user_text.strip()
    if not text and messages:
        for message in reversed(tuple(messages)):
            if getattr(message, "role", "") != "user":
                continue
            content = getattr(message, "content", "")
            if isinstance(content, str):
                text = content.strip()
                break
    lowered = text.lower()
    if not lowered:
        return "light"
    if len(lowered) > _LIGHT_MAX_CHARS or any(hint in lowered for hint in _HEAVY_HINTS):
        return "medium"
    return "light"


def current_cascade_intent() -> CascadeIntent | None:
    return _cascade_intent.get()


def set_cascade_intent(intent: CascadeIntent | None) -> Token[CascadeIntent | None]:
    return _cascade_intent.set(intent)


def reset_cascade_intent(token: Token[CascadeIntent | None]) -> None:
    _cascade_intent.reset(token)


def cascade_routing_enabled(settings: Any) -> bool:
    """Light-path local-first switch. Does not control the heavy-path ban."""

    cfg = getattr(settings, "model_cascade", None)
    if cfg is None:
        return True
    return bool(getattr(cfg, "enabled", True))


def router_has_non_local_backend(router: Any) -> bool:
    fn = getattr(router, "has_non_local_backend", None)
    if callable(fn):
        return bool(fn())
    providers = getattr(router, "_providers", None)
    if not isinstance(providers, dict) or not providers:
        return False
    return any(not provider_is_local(provider) for provider in providers.values())


def router_is_local_only(router: Any) -> bool:
    fn = getattr(router, "local_only_backends", None)
    if callable(fn):
        return bool(fn())
    providers = getattr(router, "_providers", None)
    if not isinstance(providers, dict) or not providers:
        return False
    return not any(not provider_is_local(provider) for provider in providers.values())


def provider_is_local(provider: Any) -> bool:
    return bool(getattr(provider, "_is_local", False))


def decision_is_local(router: Any, *, provider_id: str, model_id: str) -> bool:
    is_local = getattr(router, "is_local_model", None)
    if callable(is_local):
        if model_id and is_local(model_id):
            return True
        full_id = f"{provider_id}/{model_id}" if provider_id and model_id else ""
        if full_id and is_local(full_id):
            return True
    providers = getattr(router, "_providers", None)
    if isinstance(providers, dict) and provider_id in providers:
        return provider_is_local(providers[provider_id])
    return False
