"""Round 8.4: CSV pending/physical-line hard boundary before expansion."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from js.config import SecurityConfig, ToolLimits
from js.security.guard import BehaviorGuard
from js.tools.office import OfficeTools, _BinaryIncrementalCSVReader


def _office(
    tmp_path: Path,
    *,
    max_bytes: int = 2_000_000,
    max_field_chars: int = 20,
    max_columns: int = 2,
    max_rows: int = 1_000_000,
    output_budget: int = 50_000_000,
) -> OfficeTools:
    limits = ToolLimits(
        csv_read_max_bytes=max_bytes,
        csv_read_max_rows=max_rows,
        csv_read_max_columns=max_columns,
        csv_read_max_field_chars=max_field_chars,
        csv_read_max_cells=2_000_000,
        tool_output_budget_chars=output_budget,
    )
    guard = BehaviorGuard(SecurityConfig(allow_workspace_delete=True), tmp_path)
    return OfficeTools(tmp_path, limits, guard)


def _write_csv(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")


@pytest.mark.asyncio
async def test_many_short_rows_succeed_without_pending_overshoot(tmp_path: Path) -> None:
    """max_field_chars=20, max_columns=2 must accept ~80KB of short a,b lines."""
    path = tmp_path / "short.csv"
    line = "a,b\n"
    count = (80 * 1024 // len(line)) + 10
    _write_csv(path, line * count)
    tools = _office(
        tmp_path,
        max_field_chars=20,
        max_columns=2,
        max_rows=max(count + 10, 50_000),
        output_budget=50_000_000,
    )
    result = await tools.csv_read(str(path.name))
    assert result.success is True, result.error
    assert result.metadata.get("complete") is True
    assert isinstance(result.metadata.get("bytes_read"), int)
    assert result.metadata["bytes_read"] > 0
    high = result.metadata.get("pending_high_water")
    max_pending = result.metadata.get("max_pending_chars")
    assert high is not None and max_pending is not None
    assert high <= max_pending
    # Success schema: omit error_class when complete.
    assert "error_class" not in result.metadata


def test_reader_many_short_rows_pending_stays_within_cap(tmp_path: Path) -> None:
    path = tmp_path / "short_reader.csv"
    line = b"a,b\n"
    path.write_bytes(line * ((80 * 1024 // len(line)) + 10))
    fd = os.open(path, os.O_RDONLY)
    try:
        reader = _BinaryIncrementalCSVReader(
            fd,
            "utf-8",
            max_bytes=2_000_000,
            max_field_chars=20,
            max_columns=2,
        )
        lines = 0
        while True:
            got = reader.readline()
            if got == "":
                break
            lines += 1
            assert len(reader._pending) <= reader.max_pending_chars
        assert lines > 10_000
        assert reader.pending_high_water <= reader.max_pending_chars
        assert reader.bytes_read == path.stat().st_size
    finally:
        reader.close()


def test_reader_2mib_unquoted_rejects_before_full_file(tmp_path: Path) -> None:
    path = tmp_path / "huge.csv"
    payload = "x" * (2 * 1024 * 1024)
    path.write_bytes(payload.encode("utf-8"))
    fd = os.open(path, os.O_RDONLY)
    try:
        reader = _BinaryIncrementalCSVReader(
            fd,
            "utf-8",
            max_bytes=2 * 1024 * 1024,
            max_field_chars=100,
            max_columns=2,
        )
        with pytest.raises(ValueError, match="physical line|pending"):
            while True:
                line = reader.readline()
                if line == "":
                    break
        assert reader.pending_high_water <= reader.max_pending_chars
        assert reader.bytes_read == reader.fd_offset
        assert reader.bytes_read < path.stat().st_size
    finally:
        try:
            reader.close()
        except Exception:
            os.close(fd)


def test_reader_2mib_quoted_rejects_before_full_file(tmp_path: Path) -> None:
    path = tmp_path / "quoted.csv"
    inner = "y" * (2 * 1024 * 1024)
    path.write_text(f'"{inner}"\n', encoding="utf-8")
    fd = os.open(path, os.O_RDONLY)
    try:
        reader = _BinaryIncrementalCSVReader(
            fd,
            "utf-8",
            max_bytes=3 * 1024 * 1024,
            max_field_chars=100,
            max_columns=2,
        )
        with pytest.raises(ValueError, match="physical line|pending"):
            while True:
                line = reader.readline()
                if line == "":
                    break
        assert reader.pending_high_water <= reader.max_pending_chars
        assert reader.bytes_read == reader.fd_offset
        assert reader.bytes_read < path.stat().st_size
    finally:
        try:
            reader.close()
        except Exception:
            os.close(fd)


@pytest.mark.asyncio
async def test_csv_error_field_limit_includes_bytes_read_and_error_class(
    tmp_path: Path,
) -> None:
    # Wide column budget so the physical-line gate does not fire before _csv.Error.
    path = tmp_path / "field.csv"
    _write_csv(path, "a," + ("z" * 200) + "\n")
    tools = _office(
        tmp_path,
        max_field_chars=20,
        max_columns=16,
        max_bytes=1_000_000,
    )
    result = await tools.csv_read(str(path.name))
    assert result.success is False
    assert result.metadata.get("complete") is False
    assert isinstance(result.metadata.get("bytes_read"), int)
    assert result.metadata["bytes_read"] > 0
    assert result.metadata.get("error_class") == "csv_field_limit_exceeded"


def test_readline_does_not_expand_pending_past_hard_cap(tmp_path: Path) -> None:
    """Chunk decode must not temporarily push pending above max_pending_chars."""
    path = tmp_path / "cap.csv"
    path.write_bytes(b"a" * (128 * 1024))
    fd = os.open(path, os.O_RDONLY)
    try:
        reader = _BinaryIncrementalCSVReader(
            fd,
            "utf-8",
            max_bytes=256 * 1024,
            max_field_chars=32,
            max_columns=2,
        )
        hard = reader.max_pending_chars
        with pytest.raises(ValueError):
            reader.readline()
        assert reader.pending_high_water <= hard
        assert len(reader._pending) <= hard
    finally:
        try:
            reader.close()
        except Exception:
            os.close(fd)
