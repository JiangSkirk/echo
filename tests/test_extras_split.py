"""Tests for optional dependency extras split ([office] + [pdf])."""

from __future__ import annotations

import builtins
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from js.config import ToolLimits
from js.security.guard import SecurityDecisionType
from js.tools.office import OfficeTools
from js.utils.attachments import extract_excel_text, extract_pdf_text


class _AllowGuard:
    """Minimal guard that allows all path operations."""

    def check_path_operation(self, path: str, op: str) -> Any:
        return type("Decision", (), {"decision": SecurityDecisionType.ALLOW, "reason": ""})()


def _block_import(names: set[str]) -> Any:
    """Return a patched ``__import__`` that blocks the given top-level modules."""
    real_import = builtins.__import__

    def fake(name: str, *args: Any, **kwargs: Any) -> Any:
        top = name.split(".")[0]
        if top in names:
            raise ModuleNotFoundError(f"No module named '{name}'")
        return real_import(name, *args, **kwargs)

    return fake


def test_extract_pdf_text_without_pdf_extras_raises(tmp_path: Path) -> None:
    with (
        patch.object(builtins, "__import__", _block_import({"pypdf", "pdfplumber"})),
        pytest.raises(ImportError, match="js-agent\\[pdf\\]"),
    ):
        extract_pdf_text(tmp_path / "dummy.pdf")


def test_extract_excel_text_without_office_extras_raises(tmp_path: Path) -> None:
    with (
        patch.object(builtins, "__import__", _block_import({"pandas", "openpyxl"})),
        pytest.raises(ImportError, match="js-agent\\[office\\]"),
    ):
        extract_excel_text(tmp_path / "dummy.xlsx")


async def test_office_excel_read_without_openpyxl_returns_error(tmp_path: Path) -> None:
    tools = OfficeTools(tmp_path, ToolLimits(), _AllowGuard())
    with patch.object(builtins, "__import__", _block_import({"openpyxl"})):
        result = await tools.excel_read("test.xlsx")
    assert result.success is False
    assert "js-agent[office]" in result.error


async def test_office_pdf_generate_without_reportlab_returns_error(tmp_path: Path) -> None:
    tools = OfficeTools(tmp_path, ToolLimits(), _AllowGuard())
    with patch.object(builtins, "__import__", _block_import({"reportlab"})):
        result = await tools.pdf_generate("test.pdf", data='[["A"]]')
    assert result.success is False
    assert "js-agent[pdf]" in result.error


def test_attachments_pdf_with_extras_installed(tmp_path: Path) -> None:
    """Sanity check that real extras are available in the dev environment."""
    pdf_path = tmp_path / "empty.pdf"
    pdf_path.write_bytes(b"%PDF-1.4\n%%EOF\n")
    # pypdf can parse the header but returns no text; should not raise.
    extract_pdf_text(pdf_path)
