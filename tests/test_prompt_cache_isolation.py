from __future__ import annotations

import asyncio
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest
from cachetools import TTLCache

from js.agent.prompt_builder import (
    PromptBuilderMixin,
    consume_selected_prompt_variant_id,
)
from js.echo.turn_context import (
    RuntimeContext,
    reset_current_owner_key_hash,
    reset_runtime_context,
    set_current_owner_key_hash,
    set_runtime_context,
)


class _OwnerMemory:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def get_context_string(self, **kwargs: Any) -> str:
        self.calls.append(kwargs)
        return f"private-memory:{kwargs['owner_key_hash']}:call-{len(self.calls)}"


class _AllowGuard:
    def check_tool_result(self, value: str) -> SimpleNamespace:
        return SimpleNamespace(decision=SimpleNamespace(value="allow"), reason="")


@contextmanager
def _turn_context(
    tmp_path: Path,
    owner: str,
    *,
    product_id: str = "js-agent",
    profile: str = "default",
    capabilities: tuple[str, ...] = ("file_read",),
) -> Iterator[None]:
    context = RuntimeContext(
        product_id=product_id,
        channel="test",
        owner_key_hash=owner,
        session_id="shared-session",
        run_id=f"run-{owner}",
        role="user",
        profile=profile,
        capabilities=capabilities,
        workspace=tmp_path,
        state_dir=tmp_path,
    )
    owner_token = set_current_owner_key_hash(owner)
    runtime_token = set_runtime_context(context)
    try:
        yield
    finally:
        reset_runtime_context(runtime_token)
        reset_current_owner_key_hash(owner_token)


def _prompt_builder() -> PromptBuilderMixin:
    builder = PromptBuilderMixin()
    builder.SYSTEM_PROMPT = "base-system-prompt"
    builder.settings = SimpleNamespace(memory=SimpleNamespace(enabled=True, max_memory_chars=2000))
    builder.router = SimpleNamespace(is_local_model=lambda model: False)
    builder.memory = _OwnerMemory()
    builder.secrets = SimpleNamespace(detect_and_redact=lambda value, source: value)
    builder.guard = _AllowGuard()
    builder.audit = MagicMock()
    builder.logger = MagicMock()
    builder.learner = None
    builder.optimizer = None
    builder._system_message_cache = TTLCache(maxsize=100, ttl=60)
    return builder


def test_system_prompt_cache_does_not_leak_memory_across_owners(tmp_path: Path) -> None:
    builder = _prompt_builder()

    with _turn_context(tmp_path, "owner-a"):
        prompt_a = builder._build_system_message(
            query="same query",
            session_id="shared-session",
            model="shared-model",
        )

    with _turn_context(tmp_path, "owner-b"):
        prompt_b = builder._build_system_message(
            query="same query",
            session_id="shared-session",
            model="shared-model",
        )

    assert "private-memory:owner-a" in prompt_a
    assert "private-memory:owner-b" in prompt_b
    assert "private-memory:owner-a" not in prompt_b


def test_system_prompt_cache_key_contains_full_runtime_scope(tmp_path: Path) -> None:
    builder = _prompt_builder()

    with _turn_context(
        tmp_path,
        "owner-a",
        product_id="js-work",
        profile="office",
        capabilities=("file_read", "spreadsheet_run"),
    ):
        key = builder._system_prompt_cache_key(
            query="",
            session_id="shared-session",
            model="shared-model",
        )

    assert key is not None
    assert key.product_id == "js-work"
    assert key.owner_key_hash == "owner-a"
    assert key.session_id == "shared-session"
    assert key.model == "shared-model"
    assert key.profile == "office"
    assert key.capabilities == ("file_read", "spreadsheet_run")
    assert key.prompt_version.startswith("system-message-v2:")
    assert key.query == ""


def test_system_prompt_cache_skips_query_dependent_prompts(tmp_path: Path) -> None:
    builder = _prompt_builder()

    with _turn_context(tmp_path, "owner-a"):
        builder._build_system_message(
            query="first unique query",
            session_id="shared-session",
            model="shared-model",
        )
        builder._build_system_message(
            query="second unique query",
            session_id="shared-session",
            model="shared-model",
        )

    assert len(builder._system_message_cache) == 0


def test_system_prompt_cache_is_disabled_for_missing_identity_placeholder(
    tmp_path: Path,
) -> None:
    builder = _prompt_builder()

    with _turn_context(tmp_path, "local-user"):
        first = builder._build_system_message(
            query="same query",
            session_id="shared-session",
            model="shared-model",
        )
        second = builder._build_system_message(
            query="same query",
            session_id="shared-session",
            model="shared-model",
        )

    assert isinstance(builder.memory, _OwnerMemory)
    assert first != second
    assert len(builder.memory.calls) == 2
    assert len(builder._system_message_cache) == 0


@pytest.mark.asyncio
async def test_prompt_variant_selection_is_isolated_per_concurrent_turn(
    tmp_path: Path,
) -> None:
    builder = _prompt_builder()

    class _Optimizer:
        def select_variant(self, _context: str) -> tuple[str, str]:
            from js.echo.turn_context import current_owner_key_hash

            owner = current_owner_key_hash() or "missing"
            return f"variant-{owner}", f"prompt-{owner}"

    builder.optimizer = _Optimizer()
    ready = 0
    release = asyncio.Event()

    async def select(owner: str) -> str | None:
        nonlocal ready
        with _turn_context(tmp_path, owner):
            builder._build_system_message(
                query="same query",
                session_id="shared-session",
                model="shared-model",
            )
            ready += 1
            if ready == 2:
                release.set()
            await release.wait()
            return consume_selected_prompt_variant_id()

    selected = await asyncio.gather(select("owner-a"), select("owner-b"))

    assert selected == ["variant-owner-a", "variant-owner-b"]
