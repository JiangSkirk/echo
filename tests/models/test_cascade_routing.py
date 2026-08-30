"""P2-3 cascade routing: light-path local-first, heavy-path no local degrade."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

import pytest

from js.config import JSSettings, ModelCascadeConfig, ModelConfig
from js.models.cascade import (
    LIGHT_PATH_TASKS,
    CascadeIntent,
    classify_task_complexity,
    reset_cascade_intent,
    set_cascade_intent,
)
from js.models.permit import ModelPermitIssuer
from js.models.providers import ChatMessage, ChatResponse, ModelProvider
from js.models.router import ModelRouter


class _TaggedProvider(ModelProvider):
    def __init__(self, name: str, *, local: bool) -> None:
        self.name = name
        self.healthy = True
        self._is_local = local

    async def chat(
        self,
        messages: list[ChatMessage],
        model: str,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> ChatResponse:
        return ChatResponse(
            content=f"{self.name}:{model}",
            tool_calls=[],
            model=model,
            usage={"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
            finish_reason="stop",
        )

    def chat_stream(
        self,
        messages: list[ChatMessage],
        model: str,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> AsyncIterator[str]:
        async def _gen() -> AsyncIterator[str]:
            yield self.name

        return _gen()

    async def health_check(self) -> bool:
        return True

    async def close(self) -> None:
        return None


def _dual_router(*, cascade: bool = True) -> ModelRouter:
    settings = JSSettings(model_cascade=ModelCascadeConfig(enabled=cascade))
    router = ModelRouter(settings, permit_verifier=ModelPermitIssuer())
    cloud = _TaggedProvider("cloud", local=False)
    local = _TaggedProvider("ollama", local=True)
    router.add_provider("cloud", cloud, [ModelConfig(id="gpt-test", name="Cloud")])
    router.add_provider("ollama", local, [ModelConfig(id="llama", name="Local")])
    return router


def test_classifier_marks_predefined_light_path_tasks() -> None:
    for prompt in LIGHT_PATH_TASKS:
        assert classify_task_complexity(user_text=prompt) == "light"


def test_classifier_marks_write_then_fetch_medium() -> None:
    assert (
        classify_task_complexity(user_text="write notes.txt then fetch https://example.com")
        == "medium"
    )


def test_classifier_plan_commit_is_heavy() -> None:
    assert classify_task_complexity(user_text="hello", plan_commit=True) == "heavy"
    assert classify_task_complexity(user_text="hello", midturn_dirty=True) == "heavy"


@pytest.mark.asyncio
async def test_light_path_prefers_local_when_both_exist() -> None:
    router = _dual_router()
    medium = await router.select_model(_task_complexity="medium")
    light = await router.select_model(_task_complexity="light")
    assert not router.is_local_model(medium.model)
    assert router.is_local_model(light.model)


@pytest.mark.asyncio
async def test_light_path_cloud_share_drops_at_least_40_percent() -> None:
    router = _dual_router()
    baseline_cloud = 0
    cascade_cloud = 0
    baseline_ok = 0
    cascade_ok = 0
    for prompt in LIGHT_PATH_TASKS:
        assert classify_task_complexity(user_text=prompt) == "light"
        baseline = await router.select_model(_task_complexity="medium")
        baseline_ok += 1
        if not router.is_local_model(baseline.model):
            baseline_cloud += 1
        chosen = await router.select_model(_task_complexity="light")
        cascade_ok += 1
        if not router.is_local_model(chosen.model):
            cascade_cloud += 1
    assert baseline_ok == cascade_ok == len(LIGHT_PATH_TASKS)
    assert baseline_cloud == len(LIGHT_PATH_TASKS)
    drop = (baseline_cloud - cascade_cloud) / baseline_cloud
    assert drop >= 0.40


@pytest.mark.asyncio
async def test_cascade_off_restores_first_provider_order() -> None:
    router = _dual_router(cascade=False)
    light = await router.select_model(_task_complexity="light")
    assert not router.is_local_model(light.model)


@pytest.mark.asyncio
async def test_heavy_intent_never_selects_local_when_cloud_exists() -> None:
    router = _dual_router(cascade=False)
    token = set_cascade_intent(
        CascadeIntent(complexity="heavy", forbid_local=True, local_only_deny_write=False)
    )
    try:
        decision = await router.select_model(
            _task_complexity="light",
            preferred="ollama/llama",
        )
        assert not router.is_local_model(decision.model)
        assert not getattr(decision.provider, "_is_local", False)
    finally:
        reset_cascade_intent(token)


@pytest.mark.asyncio
async def test_heavy_intent_fails_when_only_local_would_match_forbid() -> None:
    settings = JSSettings()
    router = ModelRouter(settings, permit_verifier=ModelPermitIssuer())
    local = _TaggedProvider("ollama", local=True)
    router.add_provider("ollama", local, [ModelConfig(id="llama", name="Local")])
    token = set_cascade_intent(
        CascadeIntent(complexity="heavy", forbid_local=True, local_only_deny_write=True)
    )
    try:
        with pytest.raises(RuntimeError, match="non-local model"):
            await router.select_model()
    finally:
        reset_cascade_intent(token)
