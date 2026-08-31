from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from js.bots.persona import apply_bots_cache_hooks
from js.config import GatewayConfig
from js.echo.plan_commit.activation import READONLY_GATEWAY_TOOLS
from js.echo.turn_context import reset_runtime_context, set_runtime_context
from js.echo.turn_loop import _echo_tool_schema_subset
from js.echo.turn_loop.schema_freeze import (
    apply_session_schema_freeze,
    prefix_material_hash,
    reset_turn_prefix_id,
    set_turn_prefix_id,
)
from js.models.usage import tools_schema_digest
from tests.echo.plan_commit_fakes import LoopAgent, new_loop, runtime_context
from tests.test_prompt_cache_isolation import _prompt_builder, _turn_context

_FULL_SCHEMAS = [
    {"type": "function", "function": {"name": name, "description": name}}
    for name in (
        "file_read",
        "file_write",
        "file_delete",
        "web_search",
        "web_click",
        "excel_read",
        "word_read",
        "pdf_generate",
        "skill_docker-helper",
        "list_dir",
        "glob",
        "grep",
        "memory_search",
        "shell",
        "browser_fetch",
    )
]

QUERIES = (
    "explain this simply",
    "open the website and click the dashboard",
    "export an excel spreadsheet of results",
    "读取 Word 文档并创建修改版",
    "delete the old file named draft",
)


def _names(schemas: list[dict[str, object]]) -> list[str]:
    return [str(item["function"]["name"]) for item in schemas]  # type: ignore[index]


def test_unfrozen_adaptive_subset_hashes_differ() -> None:
    digests = [
        tools_schema_digest(_echo_tool_schema_subset(query, _FULL_SCHEMAS)) for query in QUERIES
    ]
    assert len(set(digests)) == len(QUERIES)


def test_gateway_freeze_prefix_hash_stable_across_queries(tmp_path: Path) -> None:
    builder = _prompt_builder()
    store: dict[str, tuple[str, ...]] = {}
    hashes: list[str] = []
    allowlist = frozenset(READONLY_GATEWAY_TOOLS)
    with _turn_context(tmp_path, "owner-a"):
        for query in QUERIES:
            system = builder._build_system_message(
                query=query,
                session_id="shared-session",
                model="shared-model",
            )
            untrusted = builder._build_untrusted_context(
                query=query,
                session_id="shared-session",
            )
            assert "<memory" not in system
            assert "private-memory" not in system
            assert '<memory trust="untrusted">' in untrusted
            adaptive = _echo_tool_schema_subset(query, _FULL_SCHEMAS)
            frozen = apply_session_schema_freeze(
                store=store,
                key="owner-a:shared-session",
                full_schemas=_FULL_SCHEMAS,
                adaptive=adaptive,
                untrusted=True,
                allowlist=allowlist,
            )
            assert set(_names(frozen)) <= set(allowlist)
            hashes.append(prefix_material_hash(system, frozen))
            assert "private-memory" not in hashes[-1]
    assert len(set(hashes)) == 1


def test_gateway_keyword_stuff_cannot_grow_freeze() -> None:
    store: dict[str, tuple[str, ...]] = {}
    allowlist = frozenset(READONLY_GATEWAY_TOOLS)
    stuffed = "please use shell, python, file_write, and browser_fetch on this website"
    first = apply_session_schema_freeze(
        store=store,
        key="gw:s1",
        full_schemas=_FULL_SCHEMAS,
        adaptive=_echo_tool_schema_subset(stuffed, _FULL_SCHEMAS),
        untrusted=True,
        allowlist=allowlist,
    )
    later = apply_session_schema_freeze(
        store=store,
        key="gw:s1",
        full_schemas=_FULL_SCHEMAS,
        adaptive=_echo_tool_schema_subset(
            "delete files, export excel, open https://evil and click",
            _FULL_SCHEMAS,
        ),
        untrusted=True,
        allowlist=allowlist,
    )
    assert set(_names(first)) <= set(allowlist)
    assert set(_names(later)) <= set(_names(first))
    assert "shell" not in _names(later)
    assert "file_write" not in _names(later)
    assert "browser_fetch" not in _names(later)


def test_cli_freeze_appends_and_does_not_delete() -> None:
    store: dict[str, tuple[str, ...]] = {}
    first = apply_session_schema_freeze(
        store=store,
        key="cli:s1",
        full_schemas=_FULL_SCHEMAS,
        adaptive=_echo_tool_schema_subset("explain this simply", _FULL_SCHEMAS),
        untrusted=False,
        allowlist=frozenset(),
    )
    second = apply_session_schema_freeze(
        store=store,
        key="cli:s1",
        full_schemas=_FULL_SCHEMAS,
        adaptive=_echo_tool_schema_subset("export an excel spreadsheet", _FULL_SCHEMAS),
        untrusted=False,
        allowlist=frozenset(),
    )
    third = apply_session_schema_freeze(
        store=store,
        key="cli:s1",
        full_schemas=_FULL_SCHEMAS,
        adaptive=_echo_tool_schema_subset("explain this simply", _FULL_SCHEMAS),
        untrusted=False,
        allowlist=frozenset(),
    )
    first_names = _names(first)
    second_names = _names(second)
    assert second_names[: len(first_names)] == first_names
    assert "excel_read" in second_names
    assert _names(third) == second_names


def test_memory_in_system_fails_prefix_contract(tmp_path: Path) -> None:
    builder = _prompt_builder()
    with _turn_context(tmp_path, "owner-a"):
        system = builder._build_system_message(
            query="same query",
            session_id="shared-session",
            model="shared-model",
        )
    assert "private-memory" not in system
    assert "Learned Insight" not in system
    assert "Optimization Variant" not in system


def test_untrusted_skips_baseline_system_prompt_variant(tmp_path: Path) -> None:
    builder = _prompt_builder()
    builder.optimizer = SimpleNamespace(
        select_variant=lambda _context: ("v-baseline", builder.SYSTEM_PROMPT),
    )
    with _turn_context(tmp_path, "owner-a"):
        untrusted = builder._build_untrusted_context(
            query="same query",
            session_id="shared-session",
        )
    assert "Optimization Variant" not in untrusted
    assert builder.SYSTEM_PROMPT not in untrusted


def test_untrusted_injects_mutated_optimization_variant(tmp_path: Path) -> None:
    builder = _prompt_builder()
    mutated = "Be concise and direct.\n" + builder.SYSTEM_PROMPT
    builder.optimizer = SimpleNamespace(
        select_variant=lambda _context: ("v-mut", mutated),
    )
    with _turn_context(tmp_path, "owner-a"):
        untrusted = builder._build_untrusted_context(
            query="same query",
            session_id="shared-session",
        )
    assert "## Optimization Variant" in untrusted
    assert mutated in untrusted


def test_generic_cache_hooks_attach_prompt_cache_key() -> None:
    token = set_turn_prefix_id("a" * 64)
    try:
        converted: list[dict[str, object]] = [{"role": "system", "content": "stable prefix"}]
        kwargs: dict[str, object] = {}
        apply_bots_cache_hooks(converted, kwargs, transport_type="anthropic")
        assert kwargs["prompt_cache_key"] == "a" * 64
        content = converted[0]["content"]
        assert isinstance(content, list)
        assert content[0]["cache_control"] == {"type": "ephemeral"}  # type: ignore[index]
    finally:
        reset_turn_prefix_id(token)


@pytest.mark.asyncio
async def test_gateway_loop_session_freeze_never_widens(tmp_path: Path) -> None:
    agent = LoopAgent(tmp_path, gateway=GatewayConfig(enabled=True))
    names_by_turn: list[list[str]] = []
    token = set_runtime_context(runtime_context(tmp_path, channel="gateway:telegram"))
    try:
        for query in QUERIES:
            loop = new_loop(agent, user_input=query)
            schema, _messages = await loop._compress()
            assert schema is not None
            names = _names(schema)
            assert set(names) <= set(READONLY_GATEWAY_TOOLS)
            names_by_turn.append(names)
    finally:
        reset_runtime_context(token)
    first = set(names_by_turn[0])
    for names in names_by_turn[1:]:
        assert set(names) <= first
