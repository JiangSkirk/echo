"""Work-runtime Office safety helpers."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from js.echo.turn_context import current_runtime_context


def _is_work_runtime() -> bool:
    context = current_runtime_context()
    return context is not None and context.product_id == "js-work"


# Spreadsheet formula-injection triggers, aligned with
# js_work.routines.office_safety._CSV_FORMULA_TRIGGERS.
_FORMULA_TRIGGERS = frozenset({"=", "+", "-", "@"})


def _escape_formula_text(value: Any) -> Any:
    """Prefix formula-like text with ``'`` so spreadsheet apps keep it literal.

    Aligned with js_work.routines.office_safety._csv_literal_prefix: text that
    already starts with a quote is returned unchanged (no double escaping), and
    non-string values pass through untouched.
    """
    if not isinstance(value, str):
        return value
    if value.startswith("'"):
        return value
    if value.lstrip()[:1] in _FORMULA_TRIGGERS:
        return f"'{value}"
    return value


def _escape_formula_rows(rows: list[list[Any]]) -> list[list[Any]]:
    return [[_escape_formula_text(cell) for cell in row] for row in rows]


def _normalize_work_cell_values(value: Any) -> Any:
    """Accept literals and typed Formula payloads; never auto-promote strings."""
    from js_work.routines.office_safety import coerce_work_cell_value

    if isinstance(value, list):
        return [_normalize_work_cell_values(item) for item in value]
    return coerce_work_cell_value(value)


def _write_work_excel_cell(cell: Any, value: Any) -> None:
    from js_work.routines.office_safety import apply_work_cell_value

    apply_work_cell_value(cell, value)


def _validate_work_xlsx(path: Path) -> None:
    from js_work.routines.office_safety import validate_safe_xlsx

    validate_safe_xlsx(path)


def _publish_work_artifact(
    target: Path,
    writer: Callable[[Path], None],
    *,
    validate_xlsx: bool,
) -> None:
    from js_work.safe_output import ensure_absent, publish_no_clobber, staged_path

    message = "Work Office output already exists"
    ensure_absent(target, message)
    with staged_path(target) as staged:
        writer(staged)
        if validate_xlsx:
            _validate_work_xlsx(staged)
        publish_no_clobber(staged, target, message)
