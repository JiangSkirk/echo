"""Round 8.2 C: CSV reader actual IO budget and bounded pending buffer."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from js.config import SecurityConfig, ToolLimits
from js.security.guard import BehaviorGuard
from js.tools.office import OfficeTools, _BinaryIncrementalCSVReader


def _office(tmp_path: Path, *, max_bytes: int = 1024) -> OfficeTools:
    limits = ToolLimits(
        csv_read_max_bytes=max_bytes,
        csv_read_max_rows=5_000,
        csv_read_max_columns=20,
        csv_read_max_field_chars=4_000,
        csv_read_max_cells=50_000,
        tool_output_budget_chars=200_000,
    )
    guard = BehaviorGuard(SecurityConfig(allow_workspace_delete=True), tmp_path)
    return OfficeTools(tmp_path, limits, guard)


def test_oversize_fail_fd_offset_tracks_bytes_read_not_buffer_prefetch(tmp_path: Path) -> None:
    path = tmp_path / "prefetch.csv"
    path.write_bytes(b"a,b\n" + (b"x,yyyyyyyy\n" * 1200))
    assert path.stat().st_size > 12_288
    fd = os.open(path, os.O_RDONLY)
    reader = _BinaryIncrementalCSVReader(fd, "utf-8", max_bytes=1024)
    try:
        with pytest.raises(ValueError, match="byte limit"):
            while True:
                chunk = reader._read_binary()
                if not chunk:
                    break
        assert reader.bytes_read == 1025
        assert reader.fd_offset <= 1025
    finally:
        reader.close()


def test_first_line_readline_pending_bounded_on_huge_file(tmp_path: Path) -> None:
    path = tmp_path / "huge_line.csv"
    long_field = b"x" * (2 * 1024 * 1024 - 2)
    path.write_bytes(b"a," + long_field)
    assert path.stat().st_size >= 2 * 1024 * 1024
    fd = os.open(path, os.O_RDONLY)
    reader = _BinaryIncrementalCSVReader(fd, "utf-8", max_bytes=10 * 1024 * 1024)
    chunk_sizes: list[int] = []
    original = reader._read_binary

    def _track(size: int | None = None) -> bytes:
        chunk = original(size)
        chunk_sizes.append(len(chunk))
        return chunk

    reader._read_binary = _track  # type: ignore[method-assign]
    try:
        line = reader.readline()
        assert line.startswith("a,")
        assert len(line) >= 2 * 1024 * 1024 - 10
        assert max(chunk_sizes, default=0) <= 64 * 1024
        assert reader.bytes_read == path.stat().st_size
    finally:
        reader.close()


def test_multibyte_utf8_straddling_64kib_boundary(tmp_path: Path) -> None:
    path = tmp_path / "utf8_boundary.csv"
    prefix = b"h\na,"
    euro = "€".encode()
    body = ("y" * 65530).encode("utf-8") + euro + ("z" * 20).encode("utf-8")
    path.write_bytes(prefix + body + b"\n")
    fd = os.open(path, os.O_RDONLY)
    reader = _BinaryIncrementalCSVReader(fd, "utf-8", max_bytes=path.stat().st_size)
    try:
        lines = list(reader)
        assert any("€" in line for line in lines)
        assert reader.fd_offset == reader.bytes_read
    finally:
        reader.close()


@pytest.mark.asyncio
async def test_csv_read_static_oversize_reports_bytes_read_zero(
    tmp_path: Path,
) -> None:
    office = _office(tmp_path, max_bytes=1024)
    path = tmp_path / "static_big.csv"
    path.write_bytes(b"a,b\n" + b"x," + (b"y" * 2797) + b"\n")
    assert path.stat().st_size == 2804
    result = await office.csv_read("static_big.csv")
    assert result.success is False
    assert result.metadata.get("complete") is False
    assert result.metadata.get("bytes_read") == 0


@pytest.mark.asyncio
async def test_csv_read_dynamic_oversize_reports_actual_bytes_read(tmp_path: Path) -> None:
    office = _office(tmp_path, max_bytes=1024)
    path = tmp_path / "dynamic_big.csv"
    path.write_bytes(b"a,b\n" + b"x," + (b"y" * 2797) + b"\n")
    assert path.stat().st_size == 2804
    result = await office.csv_read("dynamic_big.csv")
    assert result.success is False
    assert result.metadata.get("complete") is False
    if result.metadata.get("error_class") == "csv_byte_budget_exceeded":
        assert int(result.metadata.get("bytes_read", -1)) == 1025
    else:
        assert result.metadata.get("bytes_read") == 0
        assert "size limit" in (result.error or "").lower()


@pytest.mark.asyncio
async def test_csv_read_changed_file_reports_bytes_before_detect(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    office = _office(tmp_path, max_bytes=50_000)
    path = tmp_path / "mut.csv"
    path.write_bytes(b"a,b\n" + (b"1,2\n" * 200))
    original = _BinaryIncrementalCSVReader._read_binary

    def append_once(self: _BinaryIncrementalCSVReader, size: int | None = None) -> bytes:
        chunk = original(self, size)
        if self.bytes_read > 0 and not getattr(self, "_mutated", False):
            self._mutated = True
            with path.open("ab") as handle:
                handle.write(b"9,9\n" * 40)
        return chunk

    monkeypatch.setattr(_BinaryIncrementalCSVReader, "_read_binary", append_once)
    result = await office.csv_read("mut.csv")
    assert result.success is False
    assert result.metadata.get("complete") is False
    assert int(result.metadata.get("bytes_read", 0)) > 0


@pytest.mark.asyncio
async def test_csv_read_never_returns_partial_success_on_budget_fail(tmp_path: Path) -> None:
    office = _office(tmp_path, max_bytes=1024)
    path = tmp_path / "partial.csv"
    path.write_bytes(b"a,b\n" + b"x," + (b"y" * 2797) + b"\n")
    result = await office.csv_read("partial.csv")
    assert result.success is False
    assert result.metadata.get("complete") is False
    assert result.output in (None, "", [])
