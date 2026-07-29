"""Round 8.6 A: decoder getstate() bytes in unified budget + LF/CRLF/EOF boundaries."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from js.config import SecurityConfig, ToolLimits
from js.security.guard import BehaviorGuard
from js.tools.office import OfficeTools, _BinaryIncrementalCSVReader, _csv_reader_pending_limits


def _office(
    tmp_path: Path,
    *,
    max_bytes: int = 2_000_000,
    max_field_chars: int = 20,
    max_columns: int = 1,
    max_rows: int = 1_000_000,
) -> OfficeTools:
    limits = ToolLimits(
        csv_read_max_bytes=max_bytes,
        csv_read_max_rows=max_rows,
        csv_read_max_columns=max_columns,
        csv_read_max_field_chars=max_field_chars,
        csv_read_max_cells=2_000_000,
        tool_output_budget_chars=50_000_000,
    )
    guard = BehaviorGuard(SecurityConfig(allow_workspace_delete=True), tmp_path)
    return OfficeTools(tmp_path, limits, guard)


@pytest.mark.asyncio
async def test_csv_read_exact_crlf_boundary_succeeds(tmp_path: Path) -> None:
    max_phys, max_pending = _csv_reader_pending_limits(
        max_bytes=1_000_000, max_field_chars=20, max_columns=1
    )
    assert max_phys == 22
    text = '"' + ("x" * 20) + '"\r\n'
    assert len(text.replace("\r\n", "\n")) - 1 == max_phys
    (tmp_path / "exact_crlf.csv").write_bytes(text.encode("ascii"))
    tools = _office(tmp_path, max_field_chars=20, max_columns=1)
    result = await tools.csv_read("exact_crlf.csv")
    assert result.success is True, result.error
    assert result.metadata.get("complete") is True
    assert result.metadata.get("pending_high_water", 0) <= max_pending


@pytest.mark.asyncio
async def test_csv_read_exact_lf_boundary_succeeds(tmp_path: Path) -> None:
    max_phys, _ = _csv_reader_pending_limits(max_bytes=1_000_000, max_field_chars=20, max_columns=1)
    text = '"' + ("y" * 20) + '"\n'
    assert len(text) - 1 == max_phys
    (tmp_path / "exact_lf.csv").write_text(text, encoding="utf-8")
    tools = _office(tmp_path, max_field_chars=20, max_columns=1)
    result = await tools.csv_read("exact_lf.csv")
    assert result.success is True, result.error
    assert result.metadata.get("complete") is True


@pytest.mark.asyncio
async def test_csv_read_exact_eof_boundary_succeeds(tmp_path: Path) -> None:
    max_phys, _ = _csv_reader_pending_limits(max_bytes=1_000_000, max_field_chars=20, max_columns=1)
    text = '"' + ("z" * 20) + '"'
    assert len(text) == max_phys
    (tmp_path / "exact_eof.csv").write_text(text, encoding="utf-8")
    tools = _office(tmp_path, max_field_chars=20, max_columns=1)
    result = await tools.csv_read("exact_eof.csv")
    assert result.success is True, result.error
    assert result.metadata.get("complete") is True


@pytest.mark.asyncio
async def test_csv_read_decoder_held_bytes_cannot_bypass_budget(tmp_path: Path) -> None:
    """Incomplete UTF-8 in decoder.getstate() must count toward the hard pending budget."""
    max_bytes = 4096
    max_field_chars = 32
    max_columns = 2
    _max_phys, max_pending = _csv_reader_pending_limits(
        max_bytes=max_bytes, max_field_chars=max_field_chars, max_columns=max_columns
    )
    # Fill to the pending hard cap with ASCII, then append an incomplete UTF-8
    # sequence that remains inside decoder.getstate().
    filler = "a" * max_pending
    payload = filler.encode("ascii") + b"\xe2\x82"
    path = tmp_path / "decoder_bypass.csv"
    path.write_bytes(payload)
    tools = _office(
        tmp_path,
        max_bytes=max_bytes,
        max_field_chars=max_field_chars,
        max_columns=max_columns,
    )
    result = await tools.csv_read("decoder_bypass.csv")
    assert result.success is False
    assert result.metadata.get("complete") is False
    assert result.metadata.get("error_class") in {
        "csv_line_limit_exceeded",
        "csv_byte_budget_exceeded",
        "csv_field_limit_exceeded",
        "csv_encoding_error",
    }

    fd = os.open(path, os.O_RDONLY)
    try:
        reader = _BinaryIncrementalCSVReader(
            fd,
            "utf-8",
            max_bytes=max_bytes,
            max_field_chars=max_field_chars,
            max_columns=max_columns,
        )
        with pytest.raises(ValueError, match="pending|physical|byte"):
            while True:
                if reader.readline() == "":
                    break
        assert reader._unified_buffer_chars() <= reader.max_pending_chars
        assert reader.pending_high_water <= reader.max_pending_chars
    finally:
        reader.close()


def test_decoder_getstate_bytes_counted_in_unified_buffer(tmp_path: Path) -> None:
    path = tmp_path / "partial.csv"
    path.write_bytes(b"abc\xe2\x82")
    fd = os.open(path, os.O_RDONLY)
    try:
        reader = _BinaryIncrementalCSVReader(
            fd, "utf-8", max_bytes=64, max_field_chars=8, max_columns=1
        )
        original = reader._read_binary

        def tiny(size: int | None = None) -> bytes:
            return original(1 if size is None else min(size, 1))

        reader._read_binary = tiny  # type: ignore[method-assign]
        try:
            while not reader._eof:
                budget = reader._char_fill_budget(char_limit=None)
                if budget <= 0:
                    break
                if not reader._fill_pending_bounded(char_limit=None):
                    break
                if reader._decoder_held_bytes() > 0:
                    break
        except ValueError:
            pass
        assert reader._unified_buffer_chars() == (
            len(reader._pending) + len(reader._decoded_pushback) + reader._decoder_held_bytes()
        )
        assert reader._unified_buffer_chars() <= reader.max_pending_chars
    finally:
        reader.close()


def test_reader_exact_crlf_boundary_succeeds(tmp_path: Path) -> None:
    max_phys, max_pending = _csv_reader_pending_limits(
        max_bytes=1_000_000, max_field_chars=20, max_columns=2
    )
    body = "x" * max_phys
    path = tmp_path / "reader_crlf.csv"
    path.write_bytes(body.encode("ascii") + b"\r\n")
    fd = os.open(path, os.O_RDONLY)
    try:
        reader = _BinaryIncrementalCSVReader(
            fd, "utf-8", max_bytes=1_000_000, max_field_chars=20, max_columns=2
        )
        line = reader.readline()
        assert line == body + "\r\n"
        assert reader.pending_high_water <= max_pending
    finally:
        reader.close()
