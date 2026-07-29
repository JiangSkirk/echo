"""Round 8.7 A: direct getstate()[0] accounting + mutation-resistant budget tests."""

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
) -> OfficeTools:
    limits = ToolLimits(
        csv_read_max_bytes=max_bytes,
        csv_read_max_rows=1_000_000,
        csv_read_max_columns=max_columns,
        csv_read_max_field_chars=max_field_chars,
        csv_read_max_cells=2_000_000,
        tool_output_budget_chars=50_000_000,
    )
    guard = BehaviorGuard(SecurityConfig(allow_workspace_delete=True), tmp_path)
    return OfficeTools(tmp_path, limits, guard)


def _raw_decoder_held(reader: _BinaryIncrementalCSVReader) -> int:
    """Read decoder-held bytes directly from getstate()[0] — never via helpers."""
    state = reader._decoder.getstate()
    assert isinstance(state, tuple)
    buf = state[0]
    assert isinstance(buf, (bytes, bytearray))
    return len(buf)


@pytest.mark.asyncio
async def test_csv_read_exact_lf_crlf_eof_round87(tmp_path: Path) -> None:
    max_phys, _ = _csv_reader_pending_limits(max_bytes=1_000_000, max_field_chars=20, max_columns=1)
    tools = _office(tmp_path, max_field_chars=20, max_columns=1)
    cases = {
        "lf.csv": ('"' + ("a" * 20) + '"\n').encode(),
        "crlf.csv": ('"' + ("b" * 20) + '"\r\n').encode(),
        "eof.csv": ('"' + ("c" * 20) + '"').encode(),
    }
    for name, payload in cases.items():
        (tmp_path / name).write_bytes(payload)
        result = await tools.csv_read(name)
        assert result.success is True, (name, result.error)
        assert result.metadata.get("complete") is True
    assert max_phys == 22


def test_utf8_truncation_getstate_direct(tmp_path: Path) -> None:
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
        while not reader._eof and _raw_decoder_held(reader) == 0:
            if not reader._fill_pending_bounded(char_limit=None):
                break
        held = _raw_decoder_held(reader)
        assert held > 0
        state = reader._decoder.getstate()
        assert isinstance(state[0], (bytes, bytearray))
        assert len(state[0]) == held
        # Unified budget must count raw getstate bytes.
        assert reader._unified_buffer_chars() == (
            len(reader._pending) + len(reader._decoded_pushback) + held
        )
    finally:
        reader.close()


def test_decoder_held_bytes_helper_stub_zero_cannot_bypass(tmp_path: Path) -> None:
    """If ``_decoder_held_bytes`` is stubbed to 0, budget must still see getstate()[0]."""
    max_bytes = 4096
    max_field_chars = 32
    max_columns = 2
    _max_phys, max_pending = _csv_reader_pending_limits(
        max_bytes=max_bytes, max_field_chars=max_field_chars, max_columns=max_columns
    )
    payload = (b"a" * max_pending) + b"\xe2\x82"
    path = tmp_path / "stub.csv"
    path.write_bytes(payload)
    fd = os.open(path, os.O_RDONLY)
    try:
        reader = _BinaryIncrementalCSVReader(
            fd,
            "utf-8",
            max_bytes=max_bytes,
            max_field_chars=max_field_chars,
            max_columns=max_columns,
        )
        reader._decoder_held_bytes = lambda: 0  # type: ignore[method-assign]
        with pytest.raises(ValueError, match="pending|physical|byte"):
            while True:
                if reader.readline() == "":
                    break
        assert reader._unified_buffer_chars() <= reader.max_pending_chars
    finally:
        reader.close()


def test_helper_stub_zero_fails_when_tests_rely_on_helper(tmp_path: Path) -> None:
    """Mutation: ``_decoder_held_bytes`` always 0 must make helper-based asserts fail."""
    path = tmp_path / "partial.csv"
    path.write_bytes(b"ab\xe2\x82")
    fd = os.open(path, os.O_RDONLY)
    try:
        reader = _BinaryIncrementalCSVReader(
            fd, "utf-8", max_bytes=64, max_field_chars=8, max_columns=1
        )
        original = reader._read_binary

        def tiny(size: int | None = None) -> bytes:
            return original(1 if size is None else min(size, 1))

        reader._read_binary = tiny  # type: ignore[method-assign]
        while not reader._eof and _raw_decoder_held(reader) == 0:
            if not reader._fill_pending_bounded(char_limit=None):
                break
        assert _raw_decoder_held(reader) > 0
        reader._decoder_held_bytes = lambda: 0  # type: ignore[method-assign]
        with pytest.raises(AssertionError):
            assert reader._decoder_held_bytes() == _raw_decoder_held(reader)
            assert reader._decoder_held_bytes() > 0
    finally:
        reader.close()


def test_mutation_clearing_getstate_breaks_accounting_invariant(tmp_path: Path) -> None:
    """Clearing getstate()[0] while claiming budget via helper must be detectable."""
    path = tmp_path / "mutate.csv"
    path.write_bytes(b"xy\xe2\x82")
    fd = os.open(path, os.O_RDONLY)
    try:
        reader = _BinaryIncrementalCSVReader(
            fd, "utf-8", max_bytes=64, max_field_chars=8, max_columns=1
        )
        original = reader._read_binary

        def tiny(size: int | None = None) -> bytes:
            return original(1 if size is None else min(size, 1))

        reader._read_binary = tiny  # type: ignore[method-assign]
        while not reader._eof and _raw_decoder_held(reader) == 0:
            if not reader._fill_pending_bounded(char_limit=None):
                break
        assert _raw_decoder_held(reader) > 0
        state = reader._decoder.getstate()
        # Adversarial clear of decoder buffer.
        reader._decoder.setstate((b"", state[1] if isinstance(state, tuple) else 0))
        assert _raw_decoder_held(reader) == 0
        # Production unified count must follow cleared getstate (not a cached helper).
        assert reader._unified_buffer_chars() == (
            len(reader._pending) + len(reader._decoded_pushback)
        )
    finally:
        reader.close()


def test_2mib_no_newline_regression(tmp_path: Path) -> None:
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
        assert reader.pending_high_water <= reader.max_pending_chars
        assert reader.bytes_read < path.stat().st_size
    finally:
        reader.close()
