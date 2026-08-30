from __future__ import annotations

import pytest

from js.echo.plan_commit.plan import PlanError, parse_plan


def test_parse_plan_empty_steps_is_legal() -> None:
    plan = parse_plan('{"steps":[]}')
    assert plan.steps == ()
    assert plan.tool_names() == ()


def test_parse_plan_rejects_empty_text() -> None:
    with pytest.raises(PlanError, match="empty"):
        parse_plan("   ")


def test_parse_plan_rejects_non_object() -> None:
    with pytest.raises(PlanError, match="JSON object"):
        parse_plan("[1]")


def test_parse_plan_rejects_non_list_steps() -> None:
    with pytest.raises(PlanError, match="must be a list"):
        parse_plan('{"steps":{}}')


def test_parse_plan_rejects_too_many_steps() -> None:
    steps = ",".join('{"tool":"file_read","arguments":{}}' for _ in range(33))
    with pytest.raises(PlanError, match="step limit"):
        parse_plan('{"steps":[' + steps + "]}")


def test_parse_plan_rejects_invalid_tool_name() -> None:
    with pytest.raises(PlanError, match="invalid tool name"):
        parse_plan('{"steps":[{"tool":"","arguments":{}}]}')
    with pytest.raises(PlanError, match="invalid tool name"):
        parse_plan('{"steps":[{"tool":"file read","arguments":{}}]}')


def test_parse_plan_rejects_non_object_step() -> None:
    with pytest.raises(PlanError, match="must be an object"):
        parse_plan('{"steps":["file_read"]}')


def test_parse_plan_rejects_step_unknown_keys() -> None:
    with pytest.raises(PlanError, match="unknown keys"):
        parse_plan('{"steps":[{"tool":"file_read","arguments":{},"extra":1}]}')


def test_parse_plan_rejects_bad_arguments() -> None:
    with pytest.raises(PlanError, match="arguments must be an object"):
        parse_plan('{"steps":[{"tool":"file_read","arguments":[]}]}')


def test_parse_plan_rejects_invalid_json() -> None:
    with pytest.raises(PlanError, match="not valid JSON"):
        parse_plan("not-json")


def test_parse_plan_extracts_embedded_object() -> None:
    plan = parse_plan(
        'Here is the plan:\n{"steps":[{"tool":"list_dir","arguments":{"path":"."}}]}\n'
    )
    assert plan.tool_names() == ("list_dir",)


def test_parse_plan_null_arguments_become_empty() -> None:
    plan = parse_plan('{"steps":[{"tool":"list_dir","arguments":null}]}')
    assert plan.steps[0].arguments == {}


def test_parse_plan_rejects_duplicate_slots() -> None:
    with pytest.raises(PlanError, match="duplicate slot"):
        parse_plan(
            '{"steps":[{"tool":"file_write","arguments":{},"slots":['
            '{"name":"path","taint_policy":"trusted","fill_source":"literal"},'
            '{"name":"path","taint_policy":"trusted","fill_source":"literal"}'
            "]}]}"
        )


def test_parse_plan_rejects_bad_taint_policy() -> None:
    with pytest.raises(PlanError, match="taint_policy"):
        parse_plan(
            '{"steps":[{"tool":"file_read","arguments":{},"slots":['
            '{"name":"path","taint_policy":"owner","fill_source":"literal"}]}]}'
        )


def test_parse_plan_rejects_bad_fill_source() -> None:
    with pytest.raises(PlanError, match="fill_source"):
        parse_plan(
            '{"steps":[{"tool":"file_read","arguments":{},"slots":['
            '{"name":"path","taint_policy":"trusted","fill_source":"model"}]}]}'
        )


def test_parse_plan_rejects_non_list_slots() -> None:
    with pytest.raises(PlanError, match="slots must be a list"):
        parse_plan('{"steps":[{"tool":"file_read","arguments":{},"slots":{}}]}')


def test_literal_fill_source_is_not_untrusted() -> None:
    plan = parse_plan(
        '{"steps":[{"tool":"file_read","arguments":{"path":"a"},"slots":['
        '{"name":"path","taint_policy":"trusted","fill_source":"literal"}]}]}'
    )
    assert not plan.steps[0].needs_untrusted_fill()


def test_nested_slot_dict_argument_is_untrusted() -> None:
    plan = parse_plan(
        '{"steps":[{"tool":"file_write","arguments":{"content":{"fill":"extract"}}}]}'
    )
    assert plan.steps[0].needs_untrusted_fill()
