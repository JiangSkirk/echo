"""F-07: csv_read must enforce streaming size/row/column/field/cell limits."""

from __future__ import annotations

import asyncio
import csv
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from js.config import SecurityConfig, ToolLimits
from js.security.guard import BehaviorGuard, SecurityDecisionType
from js.tools.office import OfficeTools


@pytest.fixture
def office(tmp_path: Path) -> OfficeTools:
    limits = ToolLimits(
        csv_read_max_bytes=2_048,
        csv_read_max_rows=5,
        csv_read_max_columns=3,
        csv_read_max_field_chars=20,
        csv_read_max_cells=12,
        tool_output_budget_chars=50_000,
    )
    guard = BehaviorGuard(SecurityConfig(allow_workspace_delete=True), tmp_path)
    return OfficeTools(tmp_path, limits, guard)


@pytest.mark.asyncio
async def test_csv_read_empty_file(office: OfficeTools, tmp_path: Path) -> None:
    path = tmp_path / "empty.csv"
    path.write_text("", encoding="utf-8")
    result = await office.csv_read("empty.csv")
    assert result.success
    assert result.metadata["rows"] == 0
    assert result.metadata["columns"] == 0
    assert result.metadata["complete"] is True
    assert result.metadata["bytes_read"] == 0
    assert result.metadata["pending_high_water"] == 0
    assert isinstance(result.metadata["max_pending_chars"], int)
    assert result.metadata["max_pending_chars"] > 0
    assert "error_class" not in result.metadata


@pytest.mark.asyncio
async def test_csv_read_rejects_non_csv_suffix(office: OfficeTools, tmp_path: Path) -> None:
    path = tmp_path / "data.xlsx"
    path.write_text("a,b\n1,2\n", encoding="utf-8")
    result = await office.csv_read("data.xlsx")
    assert not result.success
    assert "csv" in (result.error or "").lower() or "delimited" in (result.error or "").lower()


@pytest.mark.asyncio
async def test_csv_read_rejects_oversize_file_before_parse(
    office: OfficeTools, tmp_path: Path
) -> None:
    path = tmp_path / "big.csv"
    path.write_bytes(b"a," + b"x" * 3000 + b"\n")
    result = await office.csv_read("big.csv")
    assert not result.success
    assert "size" in (result.error or "").lower() or "bytes" in (result.error or "").lower()


@pytest.mark.asyncio
async def test_csv_read_fail_closed_on_too_many_rows(office: OfficeTools, tmp_path: Path) -> None:
    path = tmp_path / "rows.csv"
    path.write_text("a,b\n1,2\n3,4\n5,6\n7,8\n9,0\n1,1\n", encoding="utf-8")
    result = await office.csv_read("rows.csv")
    assert not result.success
    assert "row" in (result.error or "").lower()
    assert result.metadata.get("complete") is False


@pytest.mark.asyncio
async def test_csv_read_fail_closed_on_long_field(office: OfficeTools, tmp_path: Path) -> None:
    path = tmp_path / "field.csv"
    path.write_text("a,b\n1," + ("x" * 40) + "\n", encoding="utf-8")
    result = await office.csv_read("field.csv")
    assert not result.success
    assert "field" in (result.error or "").lower()


@pytest.mark.asyncio
async def test_csv_read_fail_closed_on_too_many_columns(
    office: OfficeTools, tmp_path: Path
) -> None:
    path = tmp_path / "cols.csv"
    path.write_text("a,b,c,d\n1,2,3,4\n", encoding="utf-8")
    result = await office.csv_read("cols.csv")
    assert not result.success
    assert "column" in (result.error or "").lower()


@pytest.mark.asyncio
async def test_csv_read_fail_closed_on_cell_budget(office: OfficeTools, tmp_path: Path) -> None:
    # max_cells=12 with 3 columns => 5 rows would exceed when counting header+data
    path = tmp_path / "cells.csv"
    path.write_text("a,b,c\n1,2,3\n4,5,6\n7,8,9\n0,1,2\n", encoding="utf-8")
    result = await office.csv_read("cells.csv")
    assert not result.success
    assert "cell" in (result.error or "").lower()


@pytest.mark.asyncio
async def test_csv_read_encoding_error(office: OfficeTools, tmp_path: Path) -> None:
    path = tmp_path / "bad.csv"
    path.write_bytes(b"\xff\xfe,a\n")
    result = await office.csv_read("bad.csv", encoding="utf-8")
    assert not result.success
    assert "encoding" in (result.error or "").lower()


@pytest.mark.asyncio
async def test_csv_read_boundary_exact_rows_ok(office: OfficeTools, tmp_path: Path) -> None:
    # limits: max_rows=5, max_columns=3, max_cells=12 -> 4 rows * 2 cols = 8 cells OK
    # (header + 3 data rows = 4 rows total)
    path = tmp_path / "ok.csv"
    path.write_text("a,b\n1,2\n3,4\n5,6\n", encoding="utf-8")
    result = await office.csv_read("ok.csv")
    assert result.success
    assert result.metadata["complete"] is True
    assert result.metadata["rows"] == 4


@pytest.mark.asyncio
async def test_csv_read_true_boundary_equality(office: OfficeTools, tmp_path: Path) -> None:
    """Exact limit values must succeed; one past each limit must fail."""
    # Exactly max_rows=5, max_columns=2 => 10 cells (<=12), field len=20.
    exact = tmp_path / "exact.csv"
    field = "x" * 20
    lines = ["a,b", f"1,{field}", "3,4", "5,6", "7,8"]
    assert len(lines) == 5
    exact.write_text("\n".join(lines) + "\n", encoding="utf-8")
    ok = await office.csv_read("exact.csv")
    assert ok.success
    assert ok.metadata["rows"] == 5
    assert ok.metadata["complete"] is True

    # One past max_rows.
    over_rows = tmp_path / "over_rows.csv"
    over_rows.write_text("\n".join(lines + ["9,0"]) + "\n", encoding="utf-8")
    bad_rows = await office.csv_read("over_rows.csv")
    assert not bad_rows.success
    assert "row" in (bad_rows.error or "").lower()

    # Exactly max_bytes file size is accepted.
    tight = ToolLimits(
        csv_read_max_bytes=1024,
        csv_read_max_rows=80,
        csv_read_max_columns=10,
        csv_read_max_field_chars=100,
        csv_read_max_cells=2_000,
        tool_output_budget_chars=50_000,
    )
    guard = BehaviorGuard(SecurityConfig(allow_workspace_delete=True), tmp_path)
    bounded = OfficeTools(tmp_path, tight, guard)
    # Build valid short-field CSV rows that land on exactly 1024 bytes.
    row = b"1234567890,abcdefghij\n"  # 22 bytes
    header = b"col_a,col_b\n"  # 12 bytes
    body_rows = (1024 - len(header)) // len(row)
    padded = header + (row * body_rows)
    pad = 1024 - len(padded)
    assert pad < len(row)
    padded = padded + (b"z" * pad)
    assert len(padded) == 1024
    (tmp_path / "bytes.csv").write_bytes(padded)
    bytes_ok = await bounded.csv_read("bytes.csv")
    assert bytes_ok.success

    (tmp_path / "bytes_over.csv").write_bytes(padded + b"y")
    bytes_bad = await bounded.csv_read("bytes_over.csv")
    assert not bytes_bad.success


@pytest.mark.asyncio
async def test_csv_read_restores_global_field_size_limit(
    office: OfficeTools, tmp_path: Path
) -> None:
    (tmp_path / "ok.csv").write_text("a,b\n1,2\n", encoding="utf-8")
    previous = csv.field_size_limit(12_345)
    try:
        assert csv.field_size_limit() == 12_345
        result = await office.csv_read("ok.csv")
        assert result.success
        assert csv.field_size_limit() == 12_345
    finally:
        csv.field_size_limit(previous)


@pytest.mark.asyncio
async def test_csv_read_restores_field_size_limit_after_failure(
    office: OfficeTools, tmp_path: Path
) -> None:
    (tmp_path / "bad.csv").write_text("a,b,c,d\n1,2,3,4\n", encoding="utf-8")
    previous = csv.field_size_limit(9_999)
    try:
        result = await office.csv_read("bad.csv")
        assert not result.success
        assert csv.field_size_limit() == 9_999
    finally:
        csv.field_size_limit(previous)


@pytest.mark.asyncio
async def test_csv_read_fails_closed_on_parent_dir_swap(
    office: OfficeTools,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = tmp_path / "parent"
    parent.mkdir()
    (parent / "data.csv").write_text("a,b\n1,2\n", encoding="utf-8")
    outside = tmp_path.parent / f"{tmp_path.name}-outside-csv"
    outside.mkdir()
    (outside / "data.csv").write_text("secret,leak\n9,9\n", encoding="utf-8")
    swapped = False

    def swap_parent(_path: str, _operation: str) -> SimpleNamespace:
        nonlocal swapped
        if not swapped:
            parent.rename(tmp_path / "original-parent")
            parent.symlink_to(outside, target_is_directory=True)
            swapped = True
        return SimpleNamespace(decision=SecurityDecisionType.ALLOW, reason="")

    monkeypatch.setattr(office.guard, "check_path_operation", swap_parent)
    result = await office.csv_read("parent/data.csv")
    assert result.success is False
    # Must not return the outside secret contents.
    assert "secret" not in (result.output or "")
    assert "leak" not in (result.output or "")


@pytest.mark.asyncio
async def test_csv_read_output_budget(tmp_path: Path) -> None:
    limits = ToolLimits(
        csv_read_max_bytes=200_000,
        csv_read_max_rows=500,
        csv_read_max_columns=10,
        csv_read_max_field_chars=200,
        csv_read_max_cells=10_000,
        tool_output_budget_chars=1_000,
    )
    guard = BehaviorGuard(SecurityConfig(allow_workspace_delete=True), tmp_path)
    office = OfficeTools(tmp_path, limits, guard)
    # Parses fine, but indented JSON exceeds the output budget.
    (tmp_path / "wide.csv").write_text(
        "name,value\n" + "\n".join(f"row{i:03d},{'y' * 40}" for i in range(80)) + "\n",
        encoding="utf-8",
    )
    result = await office.csv_read("wide.csv")
    assert not result.success
    assert "budget" in (result.error or "").lower()
    assert result.metadata.get("complete") is False


@pytest.mark.asyncio
async def test_csv_read_cancel_stops_background_work(
    office: OfficeTools,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "slow.csv").write_text("a,b\n1,2\n", encoding="utf-8")
    previous = csv.field_size_limit()
    started = threading.Event()
    rows_seen = {"n": 0}

    real_reader = csv.reader

    def slow_reader(*args: object, **kwargs: object):  # type: ignore[no-untyped-def]
        for row in real_reader(*args, **kwargs):
            started.set()
            rows_seen["n"] += 1
            time.sleep(0.02)
            yield row
        # Keep producing so a cancelled task has time to observe cancellation.
        while rows_seen["n"] < 10_000:
            started.set()
            rows_seen["n"] += 1
            time.sleep(0.02)
            yield ["x", "y"]

    monkeypatch.setattr(csv, "reader", slow_reader)

    task = asyncio.create_task(office.csv_read("slow.csv"))
    assert await asyncio.to_thread(started.wait, 2.0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    # Give the worker a moment to unwind its finally restore.
    await asyncio.sleep(0.05)
    assert csv.field_size_limit() == previous
    # Background parse must not run to the artificial 10k-row ceiling.
    assert rows_seen["n"] < 10_000
