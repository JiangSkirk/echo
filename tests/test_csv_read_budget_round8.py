"""Round 8: csv_read binary byte budget, encoding allowlist, and stability checks."""

from __future__ import annotations

from pathlib import Path

import pytest

from js.config import SecurityConfig, ToolLimits
from js.security.guard import BehaviorGuard
from js.tools.office import OfficeTools


@pytest.fixture
def office(tmp_path: Path) -> OfficeTools:
    limits = ToolLimits(
        csv_read_max_bytes=2_048,
        csv_read_max_rows=500,
        csv_read_max_columns=10,
        csv_read_max_field_chars=200,
        csv_read_max_cells=10_000,
        tool_output_budget_chars=50_000,
    )
    guard = BehaviorGuard(SecurityConfig(allow_workspace_delete=True), tmp_path)
    return OfficeTools(tmp_path, limits, guard)


@pytest.mark.asyncio
async def test_csv_read_rejects_unicode_escape_encoding(
    office: OfficeTools, tmp_path: Path
) -> None:
    (tmp_path / "data.csv").write_text("a,b\n1,2\n", encoding="utf-8")
    result = await office.csv_read("data.csv", encoding="unicode_escape")
    assert not result.success
    assert result.metadata.get("complete") is False
    assert "encoding" in (result.error or "").lower() or "unsafe" in (result.error or "").lower()


@pytest.mark.asyncio
async def test_csv_read_rejects_bool_encoding(office: OfficeTools, tmp_path: Path) -> None:
    (tmp_path / "data.csv").write_text("a,b\n1,2\n", encoding="utf-8")
    result = await office.csv_read("data.csv", encoding=True)  # type: ignore[arg-type]
    assert not result.success
    assert result.metadata.get("complete") is False
    assert "encoding" in (result.error or "").lower()


@pytest.mark.asyncio
async def test_csv_read_counts_binary_bytes_not_reencoded_text(tmp_path: Path) -> None:
    """Streaming failures must report actual binary bytes read, not re-encoded text."""
    limits = ToolLimits(
        csv_read_max_bytes=10_000,
        csv_read_max_rows=3,
        csv_read_max_columns=10,
        csv_read_max_field_chars=200,
        csv_read_max_cells=10_000,
        tool_output_budget_chars=50_000,
    )
    guard = BehaviorGuard(SecurityConfig(allow_workspace_delete=True), tmp_path)
    bounded = OfficeTools(tmp_path, limits, guard)
    row = "α,β\n"
    (tmp_path / "wide.csv").write_text(row * 20, encoding="utf-8")
    result = await bounded.csv_read("wide.csv", encoding="utf-8")
    assert not result.success
    assert result.metadata.get("complete") is False
    bytes_read = result.metadata.get("bytes_read", 0)
    assert bytes_read > 0
    assert bytes_read <= len((row * 20).encode("utf-8"))


@pytest.mark.asyncio
async def test_csv_read_concurrent_append_exceeds_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    limits = ToolLimits(
        csv_read_max_bytes=1_024,
        csv_read_max_rows=500,
        csv_read_max_columns=10,
        csv_read_max_field_chars=200,
        csv_read_max_cells=10_000,
        tool_output_budget_chars=50_000,
    )
    guard = BehaviorGuard(SecurityConfig(allow_workspace_delete=True), tmp_path)
    office = OfficeTools(tmp_path, limits, guard)
    path = tmp_path / "grow.csv"
    row = b"1,2\n"
    path.write_bytes(b"a,b\n" + (row * 80))
    mutated = {"done": False}
    from js.tools.office import _BinaryIncrementalCSVReader

    original_read = _BinaryIncrementalCSVReader._read_binary

    def growing_read(self: _BinaryIncrementalCSVReader, size: int = 65_536) -> bytes:
        chunk = original_read(self, size)
        if self.bytes_read > 0 and not mutated["done"]:
            mutated["done"] = True
            with path.open("ab") as handle:
                handle.write(row * 120)
        return chunk

    monkeypatch.setattr(_BinaryIncrementalCSVReader, "_read_binary", growing_read)

    result = await office.csv_read("grow.csv")

    assert not result.success
    assert result.metadata.get("complete") is False
    assert isinstance(result.metadata.get("bytes_read"), int)
    assert result.metadata["bytes_read"] > 0
    error = (result.error or "").lower()
    assert "byte" in error or "changed" in error


@pytest.mark.asyncio
async def test_csv_read_stable_file_reports_binary_bytes_read(
    office: OfficeTools, tmp_path: Path
) -> None:
    payload = "name,value\none,1\n"
    (tmp_path / "stable.csv").write_text(payload, encoding="utf-8")
    result = await office.csv_read("stable.csv")
    assert result.success
    assert result.metadata.get("complete") is True
    assert len(payload.encode("utf-8")) == len(payload)
