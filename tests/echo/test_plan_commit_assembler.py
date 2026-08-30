from __future__ import annotations

import pytest

from js.config import GatewayConfig
from js.echo.effect_interpreter import ToolEffect
from js.echo.plan_commit.assembler import (
    AssemblyError,
    apply_assembled_arguments,
    assemble_step,
    assembled_args_schema,
    plan_commit_argument_error,
    project_value,
    reset_assembled_call,
    set_assembled_call,
)
from js.echo.plan_commit.extract import EXTRACT_INSTRUCTIONS, parse_extracted_value
from js.echo.plan_commit.plan import PlanStep, SlotBinding
from js.echo.turn_context import reset_runtime_context, set_runtime_context
from js.models.providers import ChatMessage, ChatResponse
from js.orin.taint import reset_entry_source, set_entry_source
from js.tools.registry import ToolResult
from tests.echo.plan_commit_fakes import (
    LoopAgent,
    RecordingRuntime,
    new_loop,
    runtime_context,
    text_response,
)


def test_allowlist_alone_does_not_bind_model_arguments() -> None:
    """Negative: lease_tool_allowlist without assembler still accepts model args."""

    assert plan_commit_argument_error("file_write", {"path": "/etc/passwd"}) is None


def test_apply_assembled_arguments_uses_bind_dict() -> None:
    tokens = set_assembled_call(tool="file_write", arguments={"path": "a.txt", "content": "x"})
    try:
        error, bound = apply_assembled_arguments("file_write", {"path": "a.txt"})
        assert error is None
        assert bound == {"path": "a.txt", "content": "x"}
        assert assembled_args_schema(bound) == assembled_args_schema(
            {"path": "a.txt", "content": "x"}
        )
        mismatch, _ = apply_assembled_arguments(
            "file_write",
            {"path": "a.txt", "content": "x", "mode": "append"},
        )
        assert mismatch is not None
    finally:
        reset_assembled_call(tokens)


def test_assembled_arguments_reject_extra_keys_and_slot_edits() -> None:
    tokens = set_assembled_call(tool="file_write", arguments={"path": "a.txt", "content": "x"})
    try:
        assert plan_commit_argument_error("file_write", {"path": "a.txt", "content": "x"}) is None
        assert plan_commit_argument_error("shell", {"path": "a.txt", "content": "x"}) is not None
        assert (
            plan_commit_argument_error(
                "file_write",
                {"path": "a.txt", "content": "x", "mode": "append"},
            )
            is not None
        )
        assert (
            plan_commit_argument_error("file_write", {"path": "/etc/passwd", "content": "x"})
            is not None
        )
    finally:
        reset_assembled_call(tokens)


def test_project_value_reads_path_id_url_status() -> None:
    blob = '{"path": "/tmp/out.txt", "id": "abc", "url": "https://ex.com", "status": 200}'
    assert project_value(blob, "path") == "/tmp/out.txt"
    assert project_value(blob, "id") == "abc"
    assert project_value(blob, "url") == "https://ex.com"
    assert project_value(blob, "status") == 200
    assert project_value("see https://ex.com/a", "url") == "https://ex.com/a"


@pytest.mark.asyncio
async def test_assemble_step_prefers_projection_over_extract() -> None:
    called = {"extract": 0}

    async def _extract(slot: SlotBinding, source: str) -> str:
        called["extract"] += 1
        return "from-extract"

    step = PlanStep(
        tool="file_write",
        arguments={},
        slots=(SlotBinding(name="path", taint_policy="untrusted", fill_source="extract"),),
    )
    assembled = await assemble_step(
        step,
        prior_outputs=('{"path": "notes.txt"}',),
        extract=_extract,
    )
    assert assembled.arguments["path"] == "notes.txt"
    assert called["extract"] == 0
    assert assembled.slot_labels[0].source_label == "prior_tool"


@pytest.mark.asyncio
async def test_assemble_step_projects_from_latest_output() -> None:
    async def _extract(slot: SlotBinding, source: str) -> str:
        raise AssertionError("latest projection must not extract")

    step = PlanStep(
        tool="file_write",
        arguments={"content": "ok"},
        slots=(SlotBinding(name="path", taint_policy="untrusted", fill_source="projection"),),
    )
    assembled = await assemble_step(
        step,
        prior_outputs=('{"path": "old.txt"}', '{"path": "new.txt"}'),
        extract=_extract,
    )
    assert assembled.arguments["path"] == "new.txt"


@pytest.mark.asyncio
async def test_assemble_step_extract_when_projection_missing() -> None:
    async def _extract(slot: SlotBinding, source: str) -> str:
        assert slot.name == "content"
        assert "hello" in source
        return "extracted-body"

    step = PlanStep(
        tool="file_write",
        arguments={"path": "out.txt"},
        slots=(SlotBinding(name="content", taint_policy="untrusted", fill_source="extract"),),
    )
    assembled = await assemble_step(
        step,
        prior_outputs=("hello from the page",),
        extract=_extract,
    )
    assert assembled.arguments == {"path": "out.txt", "content": "extracted-body"}
    assert assembled.slot_labels[0].source_label == "extract"


@pytest.mark.asyncio
async def test_assemble_step_fails_closed_when_unbound() -> None:
    async def _extract(slot: SlotBinding, source: str) -> None:
        return None

    step = PlanStep(
        tool="file_write",
        arguments={},
        slots=(SlotBinding(name="path", taint_policy="untrusted", fill_source="extract"),),
    )
    with pytest.raises(AssemblyError):
        await assemble_step(step, prior_outputs=(), extract=_extract)


@pytest.mark.asyncio
async def test_undeclared_placeholder_is_not_executed() -> None:
    async def _extract(slot: SlotBinding, source: str) -> str:
        return "should-not-run"

    step = PlanStep(
        tool="file_write",
        arguments={"path": "out.txt", "content": "{slot:content}"},
        slots=(SlotBinding(name="path", taint_policy="trusted", fill_source="literal"),),
    )
    with pytest.raises(AssemblyError, match="unbound slots"):
        await assemble_step(step, prior_outputs=(), extract=_extract)


@pytest.mark.asyncio
async def test_json_literal_argument_is_not_projected() -> None:
    async def _extract(slot: SlotBinding, source: str) -> str:
        raise AssertionError("json literals must not extract")

    step = PlanStep(
        tool="file_write",
        arguments={"path": "out.txt", "content": '{"note":"hello"}'},
        slots=(),
    )
    assembled = await assemble_step(
        step,
        prior_outputs=('{"path": "/etc/passwd", "content": "tainted"}',),
        extract=_extract,
    )
    assert assembled.arguments == {"path": "out.txt", "content": '{"note":"hello"}'}


def test_parse_extracted_value() -> None:
    assert parse_extracted_value('{"value": "notes.txt"}', "path") == "notes.txt"
    with pytest.raises(AssemblyError):
        parse_extracted_value("not json", "path")


class _JsonRuntime(RecordingRuntime):
    async def execute_tool_effect(
        self,
        effect: ToolEffect,
        *_args: object,
        **_kwargs: object,
    ) -> tuple[ChatMessage, ToolResult]:
        self.executed.append(effect.tool_name)
        output = '{"path": "notes.txt", "status": "ok"}'
        return (
            ChatMessage(
                role="tool",
                content=output,
                tool_call_id=effect.tool_call_id,
                name=effect.tool_name,
            ),
            ToolResult(success=True, output=output),
        )


@pytest.mark.asyncio
async def test_execute_projects_path_into_next_step(tmp_path) -> None:
    agent = LoopAgent(tmp_path, gateway=GatewayConfig(enabled=True))
    agent.echo_runtime = _JsonRuntime()
    loop = new_loop(agent, user_input="read then write the same path")
    calls = 0

    async def _fake_get(
        _messages: list[ChatMessage],
        _tools_schema: list[dict[str, object]] | None,
    ) -> ChatResponse:
        nonlocal calls
        calls += 1
        if calls == 1:
            return text_response(
                '{"steps":['
                '{"tool":"file_read","arguments":{"path":"notes.txt"}},'
                '{"tool":"file_write","arguments":{"content":"ok"},'
                '"slots":[{"name":"path","taint_policy":"untrusted",'
                '"fill_source":"projection"}]}'
                "]}"
            )
        return text_response("done")

    loop._get_response = _fake_get  # type: ignore[method-assign]
    entry = set_entry_source("gateway:telegram")
    token = set_runtime_context(runtime_context(tmp_path, channel="gateway:telegram"))
    try:
        await loop._run_loop()
    finally:
        reset_runtime_context(token)
        reset_entry_source(entry)

    assert agent.echo_runtime.executed == ["file_read", "file_write"]
    assert calls == 2
    receipts = loop.state.compression_stats["plan_commit"]["receipts"]
    bind = next(item for item in receipts if item.get("phase") == "bind")
    assert any(slot.get("name") == "path" for slot in bind["slots"])
    execute_ok = [
        item for item in receipts if item.get("phase") == "execute" and item.get("status") == "ok"
    ]
    assert len(execute_ok) == 2
    assert all(item.get("args_schema") for item in execute_ok)


@pytest.mark.asyncio
async def test_isolated_extract_does_not_advertise_tools(tmp_path) -> None:
    agent = LoopAgent(tmp_path, gateway=GatewayConfig(enabled=True))
    loop = new_loop(agent, user_input="summarize the page into out.txt")
    schemas: list[list[str] | None] = []
    calls = 0

    async def _fake_get(
        _messages: list[ChatMessage],
        tools_schema: list[dict[str, object]] | None,
    ) -> ChatResponse:
        nonlocal calls
        calls += 1
        names = None
        if tools_schema is not None:
            names = [str(item["function"]["name"]) for item in tools_schema]  # type: ignore[index]
        schemas.append(names)
        if calls == 1:
            return text_response(
                '{"steps":[{"tool":"file_write","arguments":{"path":"out.txt"},'
                '"slots":[{"name":"content","taint_policy":"untrusted",'
                '"fill_source":"extract"}]}]}'
            )
        if calls == 2:
            from js.echo.turn_loop.schema_freeze import current_turn_prefix_id

            assert tools_schema is None
            assert current_turn_prefix_id() == ""
            return text_response('{"value": "hello"}')
        return text_response("wrote")

    loop._get_response = _fake_get  # type: ignore[method-assign]
    entry = set_entry_source("gateway:telegram")
    token = set_runtime_context(runtime_context(tmp_path, channel="gateway:telegram"))
    try:
        await loop._run_loop()
    finally:
        reset_runtime_context(token)
        reset_entry_source(entry)

    assert agent.echo_runtime.executed == ["file_write"]
    assert all(item is None for item in schemas)
    assert calls == 3
    assert not any(
        isinstance(message.content, str) and EXTRACT_INSTRUCTIONS in message.content
        for message in loop.state.messages
    )


@pytest.mark.asyncio
async def test_isolated_extract_respects_max_turns(tmp_path) -> None:
    agent = LoopAgent(tmp_path, gateway=GatewayConfig(enabled=True), max_turns=2)
    loop = new_loop(agent, user_input="write a summary")
    calls = 0

    async def _fake_get(
        _messages: list[ChatMessage],
        tools_schema: list[dict[str, object]] | None,
    ) -> ChatResponse:
        nonlocal calls
        calls += 1
        assert tools_schema is None
        if calls == 1:
            return text_response(
                '{"steps":[{"tool":"file_write","arguments":{"path":"out.txt"},'
                '"slots":[{"name":"content","taint_policy":"untrusted",'
                '"fill_source":"extract"}]}]}'
            )
        raise AssertionError("extract must not call the model when at max_turns")

    loop._get_response = _fake_get  # type: ignore[method-assign]
    entry = set_entry_source("gateway:telegram")
    token = set_runtime_context(runtime_context(tmp_path, channel="gateway:telegram"))
    try:
        await loop._run_loop()
    finally:
        reset_runtime_context(token)
        reset_entry_source(entry)

    assert calls == 1
    assert agent.echo_runtime.executed == []
    skipped = [
        item
        for item in loop._plan_commit_receipts
        if item.get("status") == "skipped" and item.get("tool") == "file_write"
    ]
    assert skipped
