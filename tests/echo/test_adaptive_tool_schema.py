from __future__ import annotations

from js.echo.turn_loop import _echo_tool_schema_subset


def _schema(name: str) -> dict[str, object]:
    return {"type": "function", "function": {"name": name, "description": name}}


def _names(schemas: list[dict[str, object]]) -> list[str]:
    return [str(item["function"]["name"]) for item in schemas]  # type: ignore[index]


def test_echo_adaptive_tool_schema_keeps_core_tools_for_plain_chat() -> None:
    schemas = [
        _schema("file_read"),
        _schema("file_delete"),
        _schema("web_search"),
        _schema("web_click"),
        _schema("excel_read"),
        _schema("pdf_generate"),
        _schema("skill_docker-helper"),
    ]

    names = _names(_echo_tool_schema_subset("explain this simply", schemas))

    assert names == ["file_read", "web_search"]


def test_echo_adaptive_tool_schema_expands_when_query_needs_specific_tools() -> None:
    schemas = [
        _schema("file_read"),
        _schema("file_delete"),
        _schema("web_search"),
        _schema("web_click"),
        _schema("excel_read"),
        _schema("pdf_generate"),
        _schema("skill_docker-helper"),
    ]

    names = _names(
        _echo_tool_schema_subset(
            "open the website, click the dashboard, export excel, then use docker helper",
            schemas,
        )
    )

    assert names == [
        "file_read",
        "web_search",
        "web_click",
        "excel_read",
        "skill_docker-helper",
    ]


def test_echo_adaptive_tool_schema_exposes_word_tools_for_document_work() -> None:
    schemas = [
        _schema("file_read"),
        _schema("word_read"),
        _schema("word_create"),
        _schema("pdf_extract"),
    ]

    names = _names(_echo_tool_schema_subset("读取 Word 文档并创建修改版", schemas))

    assert names == ["file_read", "word_read", "word_create"]


def test_echo_adaptive_tool_schema_exposes_work_domain_routines() -> None:
    schemas = [
        _schema("file_read"),
        _schema("accessory_order_run"),
        _schema("packing_details_run"),
        _schema("work_routine_preview"),
    ]

    accessory_names = _names(
        _echo_tool_schema_subset("根据数量表和 BOM 生成辅料供应商下单表", schemas)
    )
    packing_names = _names(
        _echo_tool_schema_subset("把第五次发货做成 PACKING DETAILS", schemas)
    )

    assert accessory_names == ["file_read", "accessory_order_run"]
    assert packing_names == ["file_read", "packing_details_run"]
