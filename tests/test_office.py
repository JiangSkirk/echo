"""Tests for office document tools (Excel + PDF)."""

from pathlib import Path

import pytest

from js.config import SecurityConfig, ToolLimits
from js.security.guard import BehaviorGuard
from js.tools.office import OfficeTools


class TestOfficeTools:
    @pytest.fixture
    def office(self, tmp_path: Path) -> OfficeTools:
        limits = ToolLimits()
        guard = BehaviorGuard(SecurityConfig(allow_workspace_delete=True), tmp_path)
        return OfficeTools(tmp_path, limits, guard)

    @pytest.mark.asyncio
    async def test_excel_create_and_read(self, office: OfficeTools, tmp_path: Path) -> None:
        result = await office.excel_create("test.xlsx", sheet_name="Data", headers='["Name","Age","City"]')
        assert result.success

        result = await office.excel_read("test.xlsx", sheet="Data")
        assert result.success
        assert "Name" in result.output
        assert "Age" in result.output

    @pytest.mark.asyncio
    async def test_excel_write_and_read(self, office: OfficeTools, tmp_path: Path) -> None:
        await office.excel_create("write_test.xlsx")
        data = '[["Alice", 30, "NYC"], ["Bob", 25, "LA"]]'
        result = await office.excel_write("write_test.xlsx", data=data, start_cell="A1")
        assert result.success

        result = await office.excel_read("write_test.xlsx")
        assert result.success
        assert "Alice" in result.output
        assert "Bob" in result.output

    @pytest.mark.asyncio
    async def test_excel_merge(self, office: OfficeTools, tmp_path: Path) -> None:
        # Create source file with data
        await office.excel_create("source.xlsx", headers='["ID","Value"]')
        await office.excel_write("source.xlsx", data='[[1, "A"], [2, "B"], [3, "C"]]', start_cell="A2")

        # Create target file with existing structure
        await office.excel_create("target.xlsx", headers='["X","Y","Z","A","B","C","D"]')
        await office.excel_write("target.xlsx", data='[[10, 20, 30, 40, 50, 60, 70]]', start_cell="A2")

        # Merge source data into target at column E (E2)
        result = await office.excel_merge(
            source_path="source.xlsx",
            target_path="target.xlsx",
            source_range="A2:B4",
            target_start_cell="E2",
            include_header=False,
        )
        assert result.success
        assert result.metadata is not None
        assert result.metadata.get("rows_copied") == 3

        # Verify target contents
        result = await office.excel_read("target.xlsx")
        assert result.success
        # Row 2 should have: 10, 20, 30, 40, 1, "A", 70
        rows = result.output
        assert "1" in rows
        assert "A" in rows

    @pytest.mark.asyncio
    async def test_pdf_generate(self, office: OfficeTools, tmp_path: Path) -> None:
        data = '[["Product", "Price", "Qty"], ["Apple", 1.5, 10], ["Banana", 0.8, 20]]'
        result = await office.pdf_generate("report.pdf", title="Sales Report", data=data)
        assert result.success
        assert (tmp_path / "report.pdf").exists()

    @pytest.mark.asyncio
    async def test_excel_path_escape_blocked(self, office: OfficeTools) -> None:
        result = await office.excel_read("../../../etc/passwd")
        assert not result.success
        assert "escapes workspace" in result.error or "blocked" in result.error.lower()
