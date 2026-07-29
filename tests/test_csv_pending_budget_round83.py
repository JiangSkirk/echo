"""Round 8.3 C: CSV pending buffer budget and uniform bytes_read metadata."""

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
    max_bytes: int = 1024,
    max_field_chars: int = 4_000,
    max_columns: int = 20,
    output_budget: int = 200_000,
) -> OfficeTools:
    limits = ToolLimits(
        csv_read_max_bytes=max_bytes,
        csv_read_max_rows=5_000,
        csv_read_max_columns=max_columns,
        csv_read_max_field_chars=max_field_chars,
        csv_read_max_cells=50_000,
        tool_output_budget_chars=output_budget,
    )
    guard = BehaviorGuard(SecurityConfig(allow_workspace_delete=True), tmp_path)
    return OfficeTools(tmp_path, limits, guard)


def test_no_newline_huge_field_fails_before_whole_line_buffered(tmp_path: Path) -> None:
    path = tmp_path / "no_nl.csv"
    long_field = b"x" * (2 * 1024 * 1024 - 2)
    path.write_bytes(b"a," + long_field)
    assert path.stat().st_size >= 2 * 1024 * 1024
    fd = os.open(path, os.O_RDONLY)
    reader = _BinaryIncrementalCSVReader(
        fd,
        "utf-8",
        max_bytes=10 * 1024 * 1024,
        max_field_chars=4_000,
        max_columns=20,
    )
    chunk_sizes: list[int] = []
    original = reader._read_binary

    def _track(size: int | None = None) -> bytes:
        chunk = original(size)
        chunk_sizes.append(len(chunk))
        return chunk

    reader._read_binary = _track  # type: ignore[method-assign]
    try:
        with pytest.raises(ValueError, match="line exceeds length limit|pending buffer exceeds"):
            reader.readline()
        assert max(chunk_sizes, default=0) <= 64 * 1024
        assert reader.pending_high_water <= reader.max_pending_chars
        assert reader.bytes_read < path.stat().st_size
    finally:
        reader.close()


def test_max_bytes_1024_bytes_read_matches_fd_offset(tmp_path: Path) -> None:
    path = tmp_path / "budget.csv"
    path.write_bytes(b"a,b\n" + (b"x,yyyyyyyy\n" * 1200))
    fd = os.open(path, os.O_RDONLY)
    reader = _BinaryIncrementalCSVReader(fd, "utf-8", max_bytes=1024)
    try:
        with pytest.raises(ValueError, match="byte limit"):
            while True:
                chunk = reader._read_binary()
                if not chunk:
                    break
        assert reader.bytes_read == 1025
        assert reader.fd_offset == 1025
        assert reader.bytes_read == reader.fd_offset
    finally:
        reader.close()


@pytest.mark.asyncio
async def test_csv_read_success_includes_bytes_read(tmp_path: Path) -> None:
    office = _office(tmp_path, max_bytes=50_000)
    payload = "name,value\none,1\ntwo,2\n"
    (tmp_path / "ok.csv").write_text(payload, encoding="utf-8")
    result = await office.csv_read("ok.csv")
    assert result.success is True
    assert result.metadata.get("complete") is True
    assert result.metadata.get("bytes_read") == len(payload.encode("utf-8"))


@pytest.mark.asyncio
async def test_csv_read_field_limit_reports_error_class_and_bytes_read(
    tmp_path: Path,
) -> None:
    office = _office(tmp_path, max_bytes=50_000, max_field_chars=20)
    path = tmp_path / "field.csv"
    path.write_text("a,b\n1," + ("x" * 40) + "\n", encoding="utf-8")
    result = await office.csv_read("field.csv")
    assert result.success is False
    assert result.metadata.get("complete") is False
    assert result.metadata.get("error_class") == "csv_field_limit_exceeded"
    assert isinstance(result.metadata.get("bytes_read"), int)
    assert int(result.metadata["bytes_read"]) > 0
    assert result.output in (None, "", [])


@pytest.mark.asyncio
async def test_csv_read_output_budget_reports_bytes_read(tmp_path: Path) -> None:
    office = _office(tmp_path, max_bytes=200_000, output_budget=1_000)
    (tmp_path / "wide.csv").write_text(
        "name,value\n" + "\n".join(f"row{i:03d},{'y' * 40}" for i in range(80)) + "\n",
        encoding="utf-8",
    )
    result = await office.csv_read("wide.csv")
    assert result.success is False
    assert result.metadata.get("complete") is False
    assert result.metadata.get("error_class") == "csv_output_budget_exceeded"
    assert isinstance(result.metadata.get("bytes_read"), int)
    assert int(result.metadata["bytes_read"]) > 0
    assert result.output in (None, "", [])


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
async def test_csv_read_detects_append_during_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    office = _office(tmp_path, max_bytes=50_000)
    path = tmp_path / "live.csv"
    path.write_bytes(b"a,b\n" + (b"1,2\n" * 200))
    mutated = {"done": False}
    original = _BinaryIncrementalCSVReader._read_binary

    def growing(self: _BinaryIncrementalCSVReader, size: int | None = None) -> bytes:
        chunk = original(self, size)
        if self.bytes_read > 0 and not mutated["done"]:
            mutated["done"] = True
            with path.open("ab") as handle:
                handle.write(b"9,9\n" * 40)
        return chunk

    monkeypatch.setattr(_BinaryIncrementalCSVReader, "_read_binary", growing)
    result = await office.csv_read("live.csv")
    assert result.success is False
    assert result.metadata.get("complete") is False
    assert result.metadata.get("error_class") in {
        "csv_file_changed",
        "csv_byte_budget_exceeded",
    }


@pytest.mark.asyncio
async def test_csv_read_detects_truncate_during_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    office = _office(tmp_path, max_bytes=50_000)
    path = tmp_path / "trunc.csv"
    path.write_bytes(b"a,b\n" + (b"1,2\n" * 400))
    mutated = {"done": False}
    original = _BinaryIncrementalCSVReader._read_binary

    def truncating(self: _BinaryIncrementalCSVReader, size: int | None = None) -> bytes:
        chunk = original(self, size)
        if self.bytes_read > 0 and not mutated["done"]:
            mutated["done"] = True
            os.truncate(path, 8)
        return chunk

    monkeypatch.setattr(_BinaryIncrementalCSVReader, "_read_binary", truncating)
    result = await office.csv_read("trunc.csv")
    assert result.success is False
    assert result.metadata.get("complete") is False
    assert result.metadata.get("error_class") == "csv_file_changed"


@pytest.mark.asyncio
async def test_csv_read_detects_same_size_edit_with_mtime_restored(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    office = _office(tmp_path, max_bytes=50_000)
    path = tmp_path / "same.csv"
    original = b"a,b\n1,hello-world\n2,second-line\n"
    path.write_bytes(original)
    mutated = {"done": False}
    base = _BinaryIncrementalCSVReader._read_binary

    def rewrite(self: _BinaryIncrementalCSVReader, size: int | None = None) -> bytes:
        chunk = base(self, size)
        if self.bytes_read > 0 and not mutated["done"]:
            mutated["done"] = True
            before = path.stat()
            replacement = b"a,b\n1,HELLO-WORLD\n2,second-line\n"
            assert len(replacement) == len(original)
            path.write_bytes(replacement)
            os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
        return chunk

    monkeypatch.setattr(_BinaryIncrementalCSVReader, "_read_binary", rewrite)
    result = await office.csv_read("same.csv")
    assert result.success is False
    assert result.metadata.get("complete") is False
    assert result.metadata.get("error_class") == "csv_file_changed"
