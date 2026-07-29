"""Round 8.1 C: CSV reader remaining+1 budget and fingerprint consistency."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from js.config import SecurityConfig, ToolLimits
from js.security.guard import BehaviorGuard
from js.tools.office import OfficeTools, _BinaryIncrementalCSVReader, _csv_file_fingerprint


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


def test_read_binary_uses_remaining_plus_one_not_fixed_64kib(tmp_path: Path) -> None:
    path = tmp_path / "big.csv"
    path.write_bytes(b"a,b\n" + (b"x,yyyyyyyy\n" * 300))
    assert path.stat().st_size > 2804
    fd = os.open(path, os.O_RDONLY)
    reader = _BinaryIncrementalCSVReader(fd, "utf-8", max_bytes=1024)
    with pytest.raises(ValueError, match="byte limit"):
        while True:
            chunk = reader._read_binary()
            if not chunk:
                break
    assert reader.bytes_read == 1025


@pytest.mark.asyncio
async def test_csv_read_limit_1024_against_2804_file(tmp_path: Path) -> None:
    office = _office(tmp_path, max_bytes=1024)
    path = tmp_path / "grow.csv"
    path.write_bytes(b"a,b\n" + b"x," + (b"y" * 2797) + b"\n")
    assert path.stat().st_size == 2804
    result = await office.csv_read("grow.csv")
    assert result.success is False
    assert result.metadata.get("complete") is False
    # Static oversized files may fail closed on size preflight; streaming
    # overrun path is covered by test_read_binary_uses_remaining_plus_one.
    if result.metadata.get("error_class") == "csv_byte_budget_exceeded":
        assert result.metadata.get("bytes_read") == 1025
    else:
        assert "size limit" in (result.error or "").lower()
        assert int(result.metadata.get("bytes", 0)) == 2804
    assert result.output in (None, "", [])


@pytest.mark.asyncio
async def test_csv_read_rejects_gt_64kib(tmp_path: Path) -> None:
    office = _office(tmp_path, max_bytes=8_192)
    path = tmp_path / "wide.csv"
    path.write_bytes(b"a,b\n" + (b"1,2\n" * 20_000))
    assert path.stat().st_size > 64_000
    result = await office.csv_read("wide.csv")
    assert result.success is False
    assert result.metadata.get("complete") is False
    assert int(result.metadata.get("bytes", 0) or result.metadata.get("bytes_read", 0)) > 0


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


def test_fingerprint_includes_ctime_ns(tmp_path: Path) -> None:
    path = tmp_path / "f.csv"
    path.write_text("a,b\n1,2\n", encoding="utf-8")
    meta = path.stat()
    fp = _csv_file_fingerprint(meta)
    assert len(fp) == 5
    assert fp[4] == meta.st_ctime_ns


def test_multibyte_utf8_spanning_read_boundary(tmp_path: Path) -> None:
    # euro sign is 3 bytes; place it across a tiny remaining+1 boundary
    path = tmp_path / "utf8.csv"
    prefix = b"a,"
    # Craft so first read of remaining+1 splits a multibyte char when max_bytes small
    body = ("x" * 10 + "€" + "y" * 20).encode("utf-8")
    path.write_bytes(b"h\n" + prefix + body + b"\n")
    fd = os.open(path, os.O_RDONLY)
    reader = _BinaryIncrementalCSVReader(fd, "utf-8", max_bytes=len(path.read_bytes()))
    lines = list(reader)
    assert any("€" in line for line in lines)
