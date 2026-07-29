"""Round 8.5 A: CSV unified buffer budget + exact physical-line boundary."""

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


def test_exact_physical_line_boundary_then_newline_succeeds(tmp_path: Path) -> None:
    """Content length == max_physical_line_chars with trailing newline must succeed."""
    max_phys, max_pending = _csv_reader_pending_limits(
        max_bytes=1_000_000, max_field_chars=20, max_columns=2
    )
    # Build an unquoted physical line of exactly max_phys chars ending with \n
    # "a," + padding + "b" style: use single field of max_phys-1 then \n...
    # Physical line chars exclude newline in our limit check (len without \n).
    body = "x" * max_phys
    path = tmp_path / "exact.csv"
    path.write_text(body + "\n", encoding="utf-8")
    fd = os.open(path, os.O_RDONLY)
    try:
        reader = _BinaryIncrementalCSVReader(
            fd, "utf-8", max_bytes=1_000_000, max_field_chars=20, max_columns=2
        )
        assert reader.max_physical_line_chars == max_phys
        line = reader.readline()
        assert line == body + "\n"
        assert reader.pending_high_water <= reader.max_pending_chars
        # Unified buffer: pending + pushback must never exceed hard pending cap
        assert len(reader._pending) + len(reader._decoded_pushback) <= reader.max_pending_chars
    finally:
        reader.close()


def test_physical_line_boundary_plus_one_rejects(tmp_path: Path) -> None:
    max_phys, _ = _csv_reader_pending_limits(max_bytes=1_000_000, max_field_chars=20, max_columns=2)
    body = "x" * (max_phys + 1)
    path = tmp_path / "plus1.csv"
    path.write_text(body + "\n", encoding="utf-8")
    fd = os.open(path, os.O_RDONLY)
    try:
        reader = _BinaryIncrementalCSVReader(
            fd, "utf-8", max_bytes=1_000_000, max_field_chars=20, max_columns=2
        )
        with pytest.raises(ValueError, match="physical line|pending"):
            reader.readline()
        assert reader.pending_high_water <= reader.max_pending_chars
        assert len(reader._pending) + len(reader._decoded_pushback) <= reader.max_pending_chars
    finally:
        reader.close()


@pytest.mark.asyncio
async def test_csv_read_exact_quoted_boundary_succeeds(tmp_path: Path) -> None:
    """OfficeTools path: quoted field sized to exact physical-line budget."""
    max_phys, max_pending = _csv_reader_pending_limits(
        max_bytes=1_000_000, max_field_chars=20, max_columns=1
    )
    assert max_phys == 22  # 20 field chars + 2 quote chars
    text = '"' + ("y" * 20) + '"\n'
    assert len(text) - 1 == max_phys
    path = tmp_path / "quoted_exact.csv"
    path.write_text(text, encoding="utf-8")
    tools = _office(tmp_path, max_field_chars=20, max_columns=1, max_rows=10)
    result = await tools.csv_read("quoted_exact.csv")
    assert result.success is True, result.error
    assert result.metadata.get("complete") is True
    assert result.metadata.get("pending_high_water", 0) <= max_pending
    assert "error_class" not in result.metadata


@pytest.mark.asyncio
async def test_csv_read_boundary_plus_one_rejects(tmp_path: Path) -> None:
    max_phys, _max_pending = _csv_reader_pending_limits(
        max_bytes=1_000_000, max_field_chars=20, max_columns=1
    )
    text = '"' + ("z" * 21) + '"\n'
    assert len(text) - 1 == max_phys + 1
    path = tmp_path / "quoted_plus1.csv"
    path.write_text(text, encoding="utf-8")
    tools = _office(tmp_path, max_field_chars=20, max_columns=1)
    result = await tools.csv_read("quoted_plus1.csv")
    assert result.success is False
    assert result.metadata.get("complete") is False
    # May trip field limit or line limit depending on parse order; both are fail-closed.
    assert result.metadata.get("error_class") in {
        "csv_line_limit_exceeded",
        "csv_field_limit_exceeded",
    }
    assert isinstance(result.metadata.get("bytes_read"), int)


def test_2mib_no_newline_unified_buffer_bound(tmp_path: Path) -> None:
    path = tmp_path / "huge.csv"
    path.write_bytes(b"a" * (2 * 1024 * 1024))
    fd = os.open(path, os.O_RDONLY)
    try:
        reader = _BinaryIncrementalCSVReader(
            fd, "utf-8", max_bytes=2 * 1024 * 1024, max_field_chars=100, max_columns=2
        )
        with pytest.raises(ValueError, match="physical line|pending"):
            while True:
                if reader.readline() == "":
                    break
        hard = reader.max_pending_chars
        assert reader.pending_high_water <= hard
        assert len(reader._pending) + len(reader._decoded_pushback) <= hard
        assert reader.bytes_read == reader.fd_offset
        assert reader.bytes_read < path.stat().st_size
    finally:
        reader.close()


def test_utf8_multibyte_straddle_chunk_unified(tmp_path: Path) -> None:
    """€ is 3 bytes; force straddle across small reads into unified buffer."""
    path = tmp_path / "utf8.csv"
    # Many euro signs then newline — must not overshoot pending via pushback
    payload = ("€" * 40) + "\n"
    path.write_text(payload, encoding="utf-8")
    fd = os.open(path, os.O_RDONLY)
    try:
        reader = _BinaryIncrementalCSVReader(
            fd, "utf-8", max_bytes=10_000, max_field_chars=200, max_columns=4
        )
        # Force tiny binary reads
        original = reader._read_binary

        def tiny(size: int | None = None) -> bytes:
            if size is None or size > 2:
                size = 2
            return original(size)

        reader._read_binary = tiny  # type: ignore[method-assign]
        line = reader.readline()
        assert line == payload
        assert reader.pending_high_water <= reader.max_pending_chars
        assert len(reader._pending) + len(reader._decoded_pushback) <= reader.max_pending_chars
    finally:
        reader.close()


@pytest.mark.asyncio
async def test_csv_error_metadata_stable(tmp_path: Path) -> None:
    path = tmp_path / "field.csv"
    path.write_text("a," + ("z" * 200) + "\n", encoding="utf-8")
    tools = _office(tmp_path, max_field_chars=20, max_columns=16)
    result = await tools.csv_read("field.csv")
    assert result.success is False
    assert result.metadata.get("complete") is False
    assert result.metadata.get("error_class") == "csv_field_limit_exceeded"
    assert int(result.metadata.get("bytes_read", 0)) > 0


@pytest.mark.asyncio
async def test_csv_read_append_during_read_fail_closed(tmp_path: Path) -> None:
    path = tmp_path / "mut.csv"
    path.write_text("a,b\n" * 200, encoding="utf-8")
    tools = _office(tmp_path, max_field_chars=50, max_columns=4, max_bytes=500_000)

    # Hook reader to append after first bytes
    from js.tools import office as office_mod

    original = office_mod._BinaryIncrementalCSVReader

    class Mutating(original):  # type: ignore[valid-type,misc]
        def _read_binary(self, size: int | None = None) -> bytes:  # noqa: N802
            chunk = super()._read_binary(size)
            if chunk and not getattr(self, "_mutated", False):
                self._mutated = True
                with open(path, "ab") as handle:
                    handle.write(b"extra,row\n")
            return chunk

    office_mod._BinaryIncrementalCSVReader = Mutating  # type: ignore[misc]
    try:
        result = await tools.csv_read("mut.csv")
        assert result.success is False
        assert result.metadata.get("complete") is False
        assert result.metadata.get("error_class") in {
            "csv_file_changed",
            "csv_byte_budget_exceeded",
            "csv_line_limit_exceeded",
        }
    finally:
        office_mod._BinaryIncrementalCSVReader = original  # type: ignore[misc]


@pytest.mark.asyncio
async def test_csv_read_truncate_during_read_fail_closed(tmp_path: Path) -> None:
    path = tmp_path / "trunc.csv"
    path.write_text("a,b\n" * 500, encoding="utf-8")
    tools = _office(tmp_path, max_field_chars=50, max_columns=4, max_bytes=500_000)
    from js.tools import office as office_mod

    original = office_mod._BinaryIncrementalCSVReader

    class Truncating(original):  # type: ignore[valid-type,misc]
        def _read_binary(self, size: int | None = None) -> bytes:  # noqa: N802
            chunk = super()._read_binary(size)
            if chunk and not getattr(self, "_mutated", False):
                self._mutated = True
                os.truncate(path, 4)
            return chunk

    office_mod._BinaryIncrementalCSVReader = Truncating  # type: ignore[misc]
    try:
        result = await tools.csv_read("trunc.csv")
        assert result.success is False
        assert result.metadata.get("complete") is False
        assert result.metadata.get("error_class") in {
            "csv_file_changed",
            "csv_byte_budget_exceeded",
            "csv_encoding_error",
        }
    finally:
        office_mod._BinaryIncrementalCSVReader = original  # type: ignore[misc]


@pytest.mark.asyncio
async def test_csv_read_same_size_replace_fail_closed(tmp_path: Path) -> None:
    path = tmp_path / "swap.csv"
    original_text = "a,b\n" * 100
    path.write_text(original_text, encoding="utf-8")
    tools = _office(tmp_path, max_field_chars=50, max_columns=4, max_bytes=500_000)
    from js.tools import office as office_mod

    original_cls = office_mod._BinaryIncrementalCSVReader

    class Replacing(original_cls):  # type: ignore[valid-type,misc]
        def _read_binary(self, size: int | None = None) -> bytes:  # noqa: N802
            chunk = super()._read_binary(size)
            if chunk and not getattr(self, "_mutated", False):
                self._mutated = True
                path_size = path.stat().st_size
                replacement = ("c,d\n" * 100).encode("utf-8")
                if len(replacement) < path_size:
                    replacement = replacement + b"x" * (path_size - len(replacement))
                else:
                    replacement = replacement[:path_size]
                path.write_bytes(replacement)
            return chunk

    office_mod._BinaryIncrementalCSVReader = Replacing  # type: ignore[misc]
    try:
        result = await tools.csv_read("swap.csv")
        # Fingerprint should catch content change even at same size when inode/mtime/hash differs
        assert result.success is False or result.metadata.get("changed") is True
        if not result.success:
            assert result.metadata.get("complete") is False
            assert result.metadata.get("error_class") in {
                "csv_file_changed",
                "csv_byte_budget_exceeded",
            }
    finally:
        office_mod._BinaryIncrementalCSVReader = original_cls  # type: ignore[misc]


def test_pushback_cannot_hide_overshoot(tmp_path: Path) -> None:
    """At hard cap, lookahead must not leave excess chars in pushback past hard limit."""
    max_phys, max_pending = _csv_reader_pending_limits(
        max_bytes=256 * 1024, max_field_chars=32, max_columns=2
    )
    path = tmp_path / "cap.csv"
    path.write_bytes(b"a" * (128 * 1024))
    fd = os.open(path, os.O_RDONLY)
    try:
        reader = _BinaryIncrementalCSVReader(
            fd, "utf-8", max_bytes=256 * 1024, max_field_chars=32, max_columns=2
        )
        with pytest.raises(ValueError):
            reader.readline()
        assert reader.pending_high_water <= max_pending
        assert len(reader._pending) + len(reader._decoded_pushback) <= max_pending
        assert max_phys <= max_pending
    finally:
        reader.close()
