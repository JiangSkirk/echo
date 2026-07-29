"""Shared fail-closed Office input checks for JS Agent Work routines."""

from __future__ import annotations

import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_ALLOWED_FORMULA_FUNCS = frozenset({"SUM"})
_FUNC_RE = re.compile(r"\b([A-Za-z][A-Za-z0-9.]*)\s*\(")
_UNSAFE_FORMULA_RE = re.compile(
    r"\b(?:CALL|DDE|EXEC|FILTERXML|HYPERLINK|IMAGE|REGISTER(?:\.ID)?|RTD|SHELL|"
    r"URLDOWNLOADTOFILE|WEBSERVICE)\s*\(",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class Formula:
    """Explicit, immutable Work formula value.

    Plain strings are always treated as literals. Only this typed object may
    become an executable spreadsheet formula, and only after restricted
    validation.
    """

    expression: str

    def __post_init__(self) -> None:
        expr = self.expression
        if not isinstance(expr, str) or not expr.startswith("=") or len(expr) < 2:
            raise ValueError("Formula expression must be a non-empty '=...' string")
        if len(expr) > 32_767:
            raise ValueError("Formula expression exceeds Excel length limit")
        validate_restricted_formula(expr)


def validate_restricted_formula(formula: str) -> None:
    """Reject external links, DDE/macros, and unknown/disallowed functions."""
    if not isinstance(formula, str) or not formula.startswith("="):
        raise ValueError("formula must start with '='")
    if "[" in formula or "]" in formula or "|" in formula:
        raise ValueError("external or executable formula is not allowed")
    if _UNSAFE_FORMULA_RE.search(formula):
        raise ValueError("external or executable formula is not allowed")
    if "://" in formula or "\\\\" in formula:
        raise ValueError("external or executable formula is not allowed")
    for match in _FUNC_RE.finditer(formula):
        name = match.group(1).upper()
        if name not in _ALLOWED_FORMULA_FUNCS:
            raise ValueError(f"unsupported or unknown formula function: {name}")


def reject_formula_like_text(value: Any, *, label: str = "Office value") -> None:
    """Historical helper.

    Round 8.1 product semantics: ordinary strings are always literals, even when
    they look like formulas. This function therefore no longer rejects text; it
    remains only so call sites keep a stable import while typed :class:`Formula`
    is the sole executable path.
    """
    del value, label


def coerce_work_cell_value(value: Any) -> Any:
    """Normalize Work cell inputs: Formula stays typed; strings stay literals."""
    if isinstance(value, Formula):
        return value
    if isinstance(value, dict) and set(value.keys()) == {"__work_formula__"}:
        expression = value.get("__work_formula__")
        if not isinstance(expression, str):
            raise ValueError("Work formula payload must be a string")
        return Formula(expression)
    return value


def apply_work_cell_value(cell: Any, value: Any) -> None:
    """Write a Work cell value without auto-promoting formula-like strings."""
    normalized = coerce_work_cell_value(value)
    if isinstance(normalized, Formula):
        cell.value = normalized.expression
        return
    if isinstance(normalized, str):
        # Force literal text so leading '=', '+', '-', '@' never become formulas.
        cell.value = normalized
        if normalized.lstrip()[:1] in {"=", "+", "-", "@"}:
            cell.data_type = "s"
        return
    cell.value = normalized


_CSV_FORMULA_TRIGGERS = frozenset({"=", "+", "-", "@"})


def escape_work_csv_cell(value: Any) -> Any:
    """Escape CSV fields that Excel would interpret as formulas.

    Uses a leading single quote so the original text is preserved when the
    file is opened in Excel without becoming an executable formula.
    """
    normalized = coerce_work_cell_value(value)
    if isinstance(normalized, Formula):
        return _csv_literal_prefix(normalized.expression)
    if isinstance(normalized, str):
        return _csv_literal_prefix(normalized)
    return normalized


def escape_work_csv_rows(rows: list[list[Any]]) -> list[list[Any]]:
    return [[escape_work_csv_cell(cell) for cell in row] for row in rows]


def _csv_literal_prefix(text: str) -> str:
    if text.startswith("'"):
        return text
    if text.lstrip()[:1] in _CSV_FORMULA_TRIGGERS:
        return f"'{text}"
    return text


def validate_safe_xlsx(path: Path) -> None:
    """Validate one macro-free XLSX before higher-level libraries open it."""
    from openpyxl import load_workbook

    from js_work.routines.precise_edit import PreciseExcelEditEngine

    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ValueError("Office workbook is unavailable") from exc
    if path.suffix.lower() != ".xlsx" or not stat.S_ISREG(metadata.st_mode):
        raise ValueError("Office workbook must be a regular .xlsx file")
    before = _file_fingerprint(metadata)
    PreciseExcelEditEngine._validate_archive(path)
    workbook = load_workbook(path, data_only=False, read_only=False, keep_links=False)
    try:
        PreciseExcelEditEngine._validate_workbook_shape(workbook)
        PreciseExcelEditEngine._validate_existing_formulas(workbook)
    finally:
        workbook.close()
    try:
        after_metadata = path.lstat()
    except OSError as exc:
        raise ValueError("Office workbook changed while it was validated") from exc
    if not stat.S_ISREG(after_metadata.st_mode) or _file_fingerprint(after_metadata) != before:
        raise ValueError("Office workbook changed while it was validated")


def _file_fingerprint(metadata: Any) -> tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )
