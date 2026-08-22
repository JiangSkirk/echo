"""Tests for attachment extraction limits and file-like handling."""

from __future__ import annotations

from io import BytesIO
from pathlib import Path
from unittest.mock import patch

import pytest

from js.utils.attachments import (
    MAX_EXCEL_ROWS,
    MAX_EXCEL_TEXT_BYTES,
    MAX_PDF_PAGES,
    AttachmentLimitError,
    extract_excel_text,
    extract_pdf_text,
)


def _make_xlsx_bytes(rows: list[list[object]]) -> bytes:
    from openpyxl import Workbook

    wb = Workbook()
    ws = wb.active
    assert ws is not None
    for row in rows:
        ws.append(row)
    buffer = BytesIO()
    wb.save(buffer)
    return buffer.getvalue()


def test_extract_excel_text_file_like_falls_back_to_openpyxl() -> None:
    """The openpyxl fallback must accept file-like input, not str() it."""
    data = _make_xlsx_bytes([["alpha", "beta"], [1, 2]])
    with patch("pandas.read_excel", side_effect=ValueError("boom")):
        text = extract_excel_text(BytesIO(data))
    assert "alpha" in text
    assert "beta" in text


def test_extract_excel_text_row_limit() -> None:
    rows = [["a"], ["b"]]  # header-ish rows so pandas parses normally
    data = _make_xlsx_bytes(rows + [[i] for i in range(MAX_EXCEL_ROWS + 1)])
    with pytest.raises(AttachmentLimitError, match="row limit"):
        extract_excel_text(BytesIO(data))


def test_extract_excel_text_byte_limit() -> None:
    # Excel caps a cell at 32767 chars, so stack many max-size cells.
    rows = [["x" * 32767] for _ in range(MAX_EXCEL_TEXT_BYTES // 32767 + 2)]
    data = _make_xlsx_bytes(rows)
    with (
        patch("pandas.read_excel", side_effect=ValueError("boom")),
        pytest.raises(AttachmentLimitError, match="byte limit"),
    ):
        extract_excel_text(BytesIO(data))


def test_extract_excel_text_small_file_ok() -> None:
    data = _make_xlsx_bytes([["Name", "Qty"], ["apple", 3]])
    text = extract_excel_text(BytesIO(data))
    assert "apple" in text


def test_extract_pdf_text_page_limit(tmp_path: Path) -> None:
    from reportlab.pdfgen import canvas

    pdf_path = tmp_path / "big.pdf"
    doc = canvas.Canvas(str(pdf_path))
    for i in range(MAX_PDF_PAGES + 1):
        doc.drawString(72, 72, f"page {i}")
        doc.showPage()
    doc.save()

    with pytest.raises(AttachmentLimitError, match="page limit"):
        extract_pdf_text(pdf_path)


def test_extract_pdf_text_small_pdf_ok(tmp_path: Path) -> None:
    from reportlab.pdfgen import canvas

    pdf_path = tmp_path / "small.pdf"
    doc = canvas.Canvas(str(pdf_path))
    doc.drawString(72, 72, "hello pdf")
    doc.save()

    text = extract_pdf_text(pdf_path)
    assert "hello pdf" in text
