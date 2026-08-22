from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import xlrd
from openpyxl import load_workbook

from js_work.routines import legacy_xls
from js_work.routines.legacy_xls import LegacyXlsError, convert_legacy_xls_to_xlsx

_OLE_MAGIC = bytes.fromhex("d0cf11e0a1b11ae1")


class _FakeSheet:
    name = "Legacy/Data"
    nrows = 2
    ncols = 4
    _rows = (
        (
            SimpleNamespace(ctype=xlrd.XL_CELL_TEXT, value="STYLE"),
            SimpleNamespace(ctype=xlrd.XL_CELL_TEXT, value="QTY"),
            SimpleNamespace(ctype=xlrd.XL_CELL_TEXT, value="ACTIVE"),
            SimpleNamespace(ctype=xlrd.XL_CELL_TEXT, value="NOTE"),
        ),
        (
            SimpleNamespace(ctype=xlrd.XL_CELL_TEXT, value="S1"),
            SimpleNamespace(ctype=xlrd.XL_CELL_NUMBER, value=12.0),
            SimpleNamespace(ctype=xlrd.XL_CELL_BOOLEAN, value=1),
            SimpleNamespace(ctype=xlrd.XL_CELL_TEXT, value="=WEBSERVICE(\"https://x\")"),
        ),
    )

    def row_len(self, row: int) -> int:
        return len(self._rows[row])

    def cell(self, row: int, column: int) -> Any:
        return self._rows[row][column]


class _FakeBook:
    nsheets = 1
    datemode = 0

    def __init__(self) -> None:
        self.released = False

    def sheet_by_index(self, index: int) -> _FakeSheet:
        assert index == 0
        return _FakeSheet()

    def release_resources(self) -> None:
        self.released = True


def _stub_xls(path: Path) -> None:
    path.write_bytes(_OLE_MAGIC + b"bounded generated fixture")


def test_pure_python_legacy_reader_copies_values_and_neutralizes_formula_text(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source.xls"
    output = tmp_path / "sanitized.xlsx"
    _stub_xls(source)
    fake_book = _FakeBook()
    observed: dict[str, Any] = {}

    def fake_open_workbook(**kwargs: Any) -> _FakeBook:
        observed.update(kwargs)
        return fake_book

    monkeypatch.setattr(xlrd, "open_workbook", fake_open_workbook)

    assert convert_legacy_xls_to_xlsx(source, output) == output

    assert observed["file_contents"] == _OLE_MAGIC + b"bounded generated fixture"
    assert "filename" not in observed
    assert observed["on_demand"] is True
    assert observed["formatting_info"] is False
    assert observed["ignore_workbook_corruption"] is False
    assert fake_book.released is True
    workbook = load_workbook(output, data_only=False)
    try:
        worksheet = workbook["Legacy_Data"]
        assert worksheet["A2"].value == "S1"
        assert worksheet["B2"].value == 12
        assert worksheet["C2"].value is True
        assert worksheet["D2"].value == '=WEBSERVICE("https://x")'
        assert worksheet["D2"].data_type == "s"
    finally:
        workbook.close()


def test_legacy_reader_never_overwrites_existing_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source.xls"
    output = tmp_path / "sanitized.xlsx"
    _stub_xls(source)
    output.write_bytes(b"keep-output")
    monkeypatch.setattr(xlrd, "open_workbook", lambda **_kwargs: _FakeBook())

    with pytest.raises(LegacyXlsError, match="already exists"):
        convert_legacy_xls_to_xlsx(source, output)

    assert output.read_bytes() == b"keep-output"


def test_legacy_reader_rejects_non_ole_input_before_parser(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "fake.xls"
    source.write_bytes(b"not an xls workbook")

    def forbidden_open(**_kwargs: Any) -> Any:
        raise AssertionError("parser received a non-OLE file")

    monkeypatch.setattr(xlrd, "open_workbook", forbidden_open)

    with pytest.raises(LegacyXlsError, match="not an OLE BIFF"):
        convert_legacy_xls_to_xlsx(source, tmp_path / "out.xlsx")


def test_legacy_reader_rejects_symlink_source_before_parser(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "target.xls"
    source = tmp_path / "alias.xls"
    _stub_xls(target)
    source.symlink_to(target)

    def forbidden_open(**_kwargs: Any) -> Any:
        raise AssertionError("parser received a symlinked file")

    monkeypatch.setattr(xlrd, "open_workbook", forbidden_open)

    with pytest.raises(LegacyXlsError, match="regular file"):
        convert_legacy_xls_to_xlsx(source, tmp_path / "out.xlsx")


def test_legacy_reader_enforces_cell_limit_before_iteration(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source.xls"
    _stub_xls(source)
    fake_book = _FakeBook()
    monkeypatch.setattr(xlrd, "open_workbook", lambda **_kwargs: fake_book)
    monkeypatch.setattr(legacy_xls, "MAX_LEGACY_XLS_CELLS", 7)

    with pytest.raises(LegacyXlsError, match="cell limit"):
        convert_legacy_xls_to_xlsx(source, tmp_path / "out.xlsx")

    assert fake_book.released is True
    assert not (tmp_path / "out.xlsx").exists()
