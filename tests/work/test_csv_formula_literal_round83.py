"""Round 8.3 D: Work csv_write must escape formula-triggering literals."""

from __future__ import annotations

import asyncio
import csv
import io
import json
from pathlib import Path
from typing import Any

import pytest

from js.echo.attachment_gate import owner_slug, session_slug
from js.echo.turn_context import RuntimeContext, reset_runtime_context, set_runtime_context
from js_work.agent_factory import create_work_agent
from js_work.config import load_work_settings
from js_work.tools import WorkToolProfile


def _context(workspace: Path, state_dir: Path, owner: str) -> RuntimeContext:
    return RuntimeContext(
        product_id="js-work",
        channel="test",
        owner_key_hash=owner,
        session_id="session-a",
        run_id="run-a",
        role="user",
        profile="office",
        capabilities=(
            "csv_write",
            "excel_merge",
            "excel_read",
            "excel_write",
            "file_list",
            "file_write",
        ),
        workspace=workspace,
        state_dir=state_dir,
    )


def _execute(
    agent: Any,
    echo_tool_context: Any,
    *,
    tool_name: str,
    arguments: dict[str, Any],
    owner_root: Path,
) -> Any:
    return asyncio.run(
        agent.registry.execute(
            "run-a",
            tool_name,
            arguments,
            echo_mode="on",
            execution_context=echo_tool_context(
                run_id="run-a",
                tool_name=tool_name,
                arguments=arguments,
                owner_key_hash="owner-a",
                fs_roots=(str(owner_root),),
                registry=agent.registry,
            ),
        )
    )


def _write_csv(
    tmp_path: Path,
    echo_tool_context: Any,
    *,
    rows: list[list[Any]],
    output_name: str = "reports/literals.csv",
) -> Path:
    settings = load_work_settings(home=tmp_path)
    agent = create_work_agent(settings=settings, profile=WorkToolProfile.OFFICE)
    owner_root = settings.workspace / "owners" / owner_slug("owner-a") / session_slug("session-a")
    arguments = {"path": output_name, "data": json.dumps(rows)}
    token = set_runtime_context(_context(settings.workspace, settings.state_dir, "owner-a"))
    try:
        result = _execute(
            agent,
            echo_tool_context,
            tool_name="csv_write",
            arguments=arguments,
            owner_root=owner_root,
        )
    finally:
        reset_runtime_context(token)
        asyncio.run(agent.close())
    assert result.success is True, result.error
    return owner_root / output_name


@pytest.mark.parametrize(
    ("value", "escaped_prefix"),
    [
        ("=2+2", "'=2+2"),
        ("+123", "'+123"),
        ("-9", "'-9"),
        ("@name", "'@name"),
    ],
)
def test_csv_write_escapes_formula_trigger_literals(
    tmp_path: Path,
    echo_tool_context: Any,
    value: str,
    escaped_prefix: str,
) -> None:
    output = _write_csv(
        tmp_path,
        echo_tool_context,
        rows=[["label", "payload"], ["row", value]],
        output_name=f"reports/{value.lstrip('@=+-').replace('+', 'plus')}.csv",
    )
    text = output.read_text(encoding="utf-8")
    assert escaped_prefix in text
    assert f",{value}\n" not in text
    assert f",{value}\r\n" not in text


@pytest.mark.parametrize(
    "expression",
    [
        '=IMAGE("http://example.test/x.png")',
        '=WEBSERVICE("http://example.test")',
        '=HYPERLINK("http://example.test","x")',
        "=UNKNOWNFUNC(1)",
    ],
)
def test_csv_write_unsafe_formula_text_is_escaped_not_executable(
    tmp_path: Path,
    echo_tool_context: Any,
    expression: str,
) -> None:
    output = _write_csv(
        tmp_path,
        echo_tool_context,
        rows=[["payload"], [expression]],
        output_name=f"reports/unsafe_{abs(hash(expression))}.csv",
    )
    text = output.read_text(encoding="utf-8")
    rows = list(csv.reader(io.StringIO(text)))
    assert rows[-1][0] == f"'{expression}"
    assert not rows[-1][0].startswith("=")


def test_csv_write_typed_formula_is_escaped_not_executable(
    tmp_path: Path,
    echo_tool_context: Any,
) -> None:
    output = _write_csv(
        tmp_path,
        echo_tool_context,
        rows=[["total"], [{"__work_formula__": "=SUM(A1:A3)"}]],
        output_name="reports/sum_literal.csv",
    )
    text = output.read_text(encoding="utf-8")
    assert "'=SUM(A1:A3)" in text
    assert text.strip().endswith("'=SUM(A1:A3)")


@pytest.mark.parametrize(
    "expression",
    [
        '=IMAGE("http://example.test/x.png")',
        '=WEBSERVICE("http://example.test")',
        '=HYPERLINK("http://example.test","x")',
        "=UNKNOWNFUNC(1)",
    ],
)
def test_csv_write_rejects_typed_unsafe_formula(
    tmp_path: Path,
    echo_tool_context: Any,
    expression: str,
) -> None:
    settings = load_work_settings(home=tmp_path)
    agent = create_work_agent(settings=settings, profile=WorkToolProfile.OFFICE)
    owner_root = settings.workspace / "owners" / owner_slug("owner-a") / session_slug("session-a")
    arguments = {
        "path": "unsafe.csv",
        "data": json.dumps([[{"__work_formula__": expression}]]),
    }
    token = set_runtime_context(_context(settings.workspace, settings.state_dir, "owner-a"))
    try:
        result = _execute(
            agent,
            echo_tool_context,
            tool_name="csv_write",
            arguments=arguments,
            owner_root=owner_root,
        )
    finally:
        reset_runtime_context(token)
        asyncio.run(agent.close())
    assert result.success is False


def test_csv_write_plain_values_unmodified(tmp_path: Path, echo_tool_context: Any) -> None:
    output = _write_csv(
        tmp_path,
        echo_tool_context,
        rows=[["name", "qty"], ["widget", 42]],
    )
    text = output.read_text(encoding="utf-8")
    assert "widget,42" in text.replace("\r\n", "\n")
    assert "'" not in text
