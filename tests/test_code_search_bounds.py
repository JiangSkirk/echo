"""F-08: code_search literal-by-default with killable regex workers."""

from __future__ import annotations

import asyncio
import multiprocessing as mp
import threading
import time
from pathlib import Path

import pytest

from js.config import SecurityConfig, ToolLimits
from js.security.guard import BehaviorGuard
from js.tools.files import FileTools


@pytest.fixture
def files(tmp_path: Path) -> FileTools:
    limits = ToolLimits(
        code_search_max_pattern_chars=32,
        code_search_max_files=50,
        code_search_max_bytes=100_000,
        code_search_max_line_chars=200,
        code_search_regex_timeout_seconds=0.5,
    )
    guard = BehaviorGuard(SecurityConfig(allow_workspace_delete=True), tmp_path)
    return FileTools(tmp_path, limits, guard)


@pytest.mark.asyncio
async def test_literal_search_finds_substring(files: FileTools, tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("hello world\nfoo bar\n", encoding="utf-8")
    result = await files.code_search("foo")
    assert result.success
    assert "foo bar" in (result.output or "")
    assert result.metadata["mode"] == "literal"


@pytest.mark.asyncio
async def test_literal_does_not_interpret_regex_metacharacters(
    files: FileTools, tmp_path: Path
) -> None:
    (tmp_path / "a.py").write_text("price is $5.00\n", encoding="utf-8")
    result = await files.code_search(r"$5")
    assert result.success
    assert "$5" in (result.output or "")


@pytest.mark.asyncio
async def test_regex_mode_matches_and_rejects_invalid(files: FileTools, tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("abc123xyz\n", encoding="utf-8")
    ok = await files.code_search(r"abc\d+", use_regex=True)
    assert ok.success
    assert "abc123xyz" in (ok.output or "")
    assert ok.metadata["mode"] == "regex"

    bad = await files.code_search(r"[unterminated", use_regex=True)
    assert not bad.success
    assert "regex" in (bad.error or "").lower() or "error" in (bad.error or "").lower()
    assert bad.metadata == {"matches": 0, "truncated": False, "complete": False}


@pytest.mark.asyncio
async def test_overlong_pattern_returns_incomplete_metadata(
    files: FileTools, tmp_path: Path
) -> None:
    (tmp_path / "a.py").write_text("x\n", encoding="utf-8")
    result = await files.code_search("p" * 64)
    assert not result.success
    assert "pattern" in (result.error or "").lower()
    assert result.metadata == {"matches": 0, "truncated": False, "complete": False}


@pytest.mark.asyncio
async def test_catastrophic_regex_times_out_and_cleans_worker(
    files: FileTools, tmp_path: Path
) -> None:
    # Classic pathological pattern against a non-matching long string.
    (tmp_path / "evil.txt").write_text("a" * 40 + "b\n", encoding="utf-8")
    result = await files.code_search(r"(a+)+$", use_regex=True)
    assert not result.success
    assert "timed out" in (result.error or "").lower()


@pytest.mark.asyncio
async def test_overlong_pattern_rejected(files: FileTools, tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("x\n", encoding="utf-8")
    result = await files.code_search("p" * 64)
    assert not result.success
    assert "pattern" in (result.error or "").lower()


@pytest.mark.asyncio
async def test_overlong_line_is_truncated_for_matching(files: FileTools, tmp_path: Path) -> None:
    # Needle only appears after the max_line_chars cut — must not match.
    line = ("x" * 250) + "NEEDLE"
    (tmp_path / "long.txt").write_text(line + "\n", encoding="utf-8")
    result = await files.code_search("NEEDLE")
    assert result.success
    assert "No matches" in (result.output or "") or result.metadata["matches"] == 0


@pytest.mark.asyncio
async def test_strict_type_rejects_bool_float_string(files: FileTools, tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("hello\n", encoding="utf-8")
    # bool is a subclass of int — must still be rejected.
    bad_bool = await files.code_search("hello", max_results=True)  # type: ignore[arg-type]
    assert not bad_bool.success
    assert "integer" in (bad_bool.error or "").lower()

    bad_float = await files.code_search("hello", max_results=3.5)  # type: ignore[arg-type]
    assert not bad_float.success

    bad_str = await files.code_search("hello", max_results="3")  # type: ignore[arg-type]
    assert not bad_str.success

    bad_regex = await files.code_search("hello", use_regex=1)  # type: ignore[arg-type]
    assert not bad_regex.success
    assert "boolean" in (bad_regex.error or "").lower()


@pytest.mark.asyncio
async def test_max_files_and_max_bytes_fail_closed(tmp_path: Path) -> None:
    limits = ToolLimits(
        code_search_max_pattern_chars=32,
        code_search_max_files=2,
        code_search_max_bytes=1024,
        code_search_max_line_chars=200,
        code_search_regex_timeout_seconds=0.5,
    )
    guard = BehaviorGuard(SecurityConfig(allow_workspace_delete=True), tmp_path)
    tools = FileTools(tmp_path, limits, guard)

    (tmp_path / "a.txt").write_text("alpha needle\n", encoding="utf-8")
    (tmp_path / "b.txt").write_text("beta needle\n", encoding="utf-8")
    (tmp_path / "c.txt").write_text("gamma needle\n", encoding="utf-8")
    too_many = await tools.code_search("needle")
    assert not too_many.success
    assert "file" in (too_many.error or "").lower()
    assert too_many.metadata.get("complete") is False

    small = ToolLimits(
        code_search_max_pattern_chars=32,
        code_search_max_files=50,
        code_search_max_bytes=1024,
        code_search_max_line_chars=200,
        code_search_regex_timeout_seconds=0.5,
    )
    tight = FileTools(tmp_path, small, guard)
    (tmp_path / "big1.txt").write_text("x" * 600 + "\n", encoding="utf-8")
    (tmp_path / "big2.txt").write_text("y" * 600 + " needle\n", encoding="utf-8")
    too_big = await tight.code_search("needle")
    assert not too_big.success
    assert "byte" in (too_big.error or "").lower()
    assert too_big.metadata.get("complete") is False


@pytest.mark.asyncio
async def test_large_pipe_payload_does_not_false_timeout(tmp_path: Path) -> None:
    limits = ToolLimits(
        code_search_max_pattern_chars=32,
        code_search_max_files=200,
        code_search_max_bytes=2_000_000,
        code_search_max_line_chars=200,
        code_search_regex_timeout_seconds=5.0,
    )
    guard = BehaviorGuard(SecurityConfig(allow_workspace_delete=True), tmp_path)
    tools = FileTools(tmp_path, limits, guard)
    # Many small matches — large Pipe payload, must still complete.
    for index in range(80):
        (tmp_path / f"f{index}.txt").write_text(
            "\n".join(f"needle line {index}-{j}" for j in range(5)) + "\n",
            encoding="utf-8",
        )
    result = await tools.code_search(r"needle", use_regex=True, max_results=100)
    assert result.success
    assert result.metadata["mode"] == "regex"
    assert result.metadata["matches"] == 100
    assert result.metadata["truncated"] is True
    assert result.metadata["complete"] is False


@pytest.mark.asyncio
async def test_regex_timeout_leaves_no_orphan_processes(files: FileTools, tmp_path: Path) -> None:
    (tmp_path / "evil.txt").write_text("a" * 40 + "b\n", encoding="utf-8")
    before = {proc.pid for proc in mp.active_children()}
    result = await files.code_search(r"(a+)+$", use_regex=True)
    assert not result.success
    assert "timed out" in (result.error or "").lower()
    deadline = time.time() + 2.0
    while time.time() < deadline:
        alive = {proc.pid for proc in mp.active_children()} - before
        if not alive:
            break
        await asyncio.sleep(0.05)
    leftovers = {proc.pid for proc in mp.active_children()} - before
    assert not leftovers


@pytest.mark.asyncio
async def test_code_search_cancel_stops_background_work(
    files: FileTools,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "a.txt").write_text("needle\n", encoding="utf-8")
    started = threading.Event()
    calls = {"n": 0}
    real = files._secure_read_text_detailed

    def slow_read(path: str, *, max_bytes: int):  # type: ignore[no-untyped-def]
        started.set()
        calls["n"] += 1
        time.sleep(0.05)
        return real(path, max_bytes=max_bytes)

    monkeypatch.setattr(files, "_secure_read_text_detailed", slow_read)
    # Many files so cancel can interrupt the collect loop.
    for index in range(40):
        (tmp_path / f"f{index}.txt").write_text(f"needle {index}\n", encoding="utf-8")

    task = asyncio.create_task(files.code_search("needle"))
    assert await asyncio.to_thread(started.wait, 2.0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    # Allow the worker thread to observe cancellation and stop.
    await asyncio.sleep(0.3)
    assert calls["n"] < 40


@pytest.mark.asyncio
async def test_read_error_marks_complete_false(
    files: FileTools,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "ok.txt").write_text("needle here\n", encoding="utf-8")
    (tmp_path / "bad.txt").write_text("needle too\n", encoding="utf-8")

    real = files._secure_read_text_detailed

    def flaky(path: str, *, max_bytes: int):  # type: ignore[no-untyped-def]
        if path.endswith("bad.txt"):
            raise OSError("simulated read failure")
        return real(path, max_bytes=max_bytes)

    monkeypatch.setattr(files, "_secure_read_text_detailed", flaky)
    result = await files.code_search("needle")
    assert result.success
    assert "ok.txt" in (result.output or "")
    assert result.metadata["complete"] is False


@pytest.mark.asyncio
async def test_file_change_marks_complete_false(
    files: FileTools,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "changing.txt").write_text("needle stable\n", encoding="utf-8")

    real = files._secure_read_text_detailed

    def unstable(path: str, *, max_bytes: int):  # type: ignore[no-untyped-def]
        text, logical, nbytes, _stable = real(path, max_bytes=max_bytes)
        return text, logical, nbytes, False

    monkeypatch.setattr(files, "_secure_read_text_detailed", unstable)
    result = await files.code_search("needle")
    assert result.success
    assert result.metadata["matches"] >= 1
    assert result.metadata["complete"] is False


@pytest.mark.asyncio
async def test_byte_budget_uses_actual_bytes_read(tmp_path: Path) -> None:
    """Budget is accounted from actual bytes read across files."""
    limits = ToolLimits(
        code_search_max_pattern_chars=32,
        code_search_max_files=50,
        code_search_max_bytes=1024,
        code_search_max_line_chars=200,
        code_search_regex_timeout_seconds=0.5,
    )
    guard = BehaviorGuard(SecurityConfig(allow_workspace_delete=True), tmp_path)
    tools = FileTools(tmp_path, limits, guard)
    # First file consumes most of the budget; second pushes actual bytes over.
    (tmp_path / "a.txt").write_text("a" * 800 + "\n", encoding="utf-8")
    (tmp_path / "b.txt").write_text("b" * 800 + " needle\n", encoding="utf-8")
    result = await tools.code_search("needle")
    assert not result.success
    assert "byte" in (result.error or "").lower()
    assert result.metadata.get("complete") is False


@pytest.mark.asyncio
async def test_caller_cancel_kills_regex_worker_within_250ms(
    tmp_path: Path,
) -> None:
    """Cancel during regex poll must terminate the worker; no orphan within 250ms."""
    limits = ToolLimits(
        code_search_max_pattern_chars=32,
        code_search_max_files=50,
        code_search_max_bytes=100_000,
        code_search_max_line_chars=200,
        # Long timeout so cancel must interrupt the poll loop (not natural timeout).
        code_search_regex_timeout_seconds=30.0,
    )
    guard = BehaviorGuard(SecurityConfig(allow_workspace_delete=True), tmp_path)
    tools = FileTools(tmp_path, limits, guard)
    (tmp_path / "evil.txt").write_text("a" * 40 + "b\n", encoding="utf-8")

    before = {proc.pid for proc in mp.active_children()}
    task = asyncio.create_task(tools.code_search(r"(a+)+$", use_regex=True))
    child_seen = False
    deadline = time.time() + 2.0
    while time.time() < deadline:
        if {proc.pid for proc in mp.active_children()} - before:
            child_seen = True
            break
        await asyncio.sleep(0.01)
    assert child_seen, "regex worker never started"

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    clear_deadline = time.time() + 0.25
    while time.time() < clear_deadline:
        leftovers = {proc.pid for proc in mp.active_children()} - before
        if not leftovers:
            break
        await asyncio.sleep(0.01)
    leftovers = {proc.pid for proc in mp.active_children()} - before
    assert not leftovers, f"residual regex workers after cancel: {leftovers}"


@pytest.mark.asyncio
async def test_walk_failure_marks_complete_false(
    files: FileTools,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "a.txt").write_text("needle\n", encoding="utf-8")

    def boom(*_args: object, **_kwargs: object) -> list[object]:
        raise OSError("simulated walk failure")

    monkeypatch.setattr(files, "_walk_secure_directory", boom)
    result = await files.code_search("needle")
    assert not result.success
    assert result.metadata.get("complete") is False


@pytest.mark.asyncio
async def test_unknown_failure_marks_complete_false(
    files: FileTools,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "a.txt").write_text("needle\n", encoding="utf-8")

    def boom(*_args: object, **_kwargs: object) -> object:
        raise RuntimeError("simulated unknown failure")

    monkeypatch.setattr(files, "_open_secure_directory", boom)
    result = await files.code_search("needle")
    assert not result.success
    assert result.metadata.get("complete") is False
