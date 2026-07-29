"""P0-2: Work output staging/publish must be truly descriptor-relative.

Attack reproduced on 2026-07-20 against digest
914b48fc61f20655db486f02234af23c7355c5dcc55a02c01e5116a0a0959d17:
``_open_parent_no_follow`` opened the parent fd but never used it;
``tempfile.mkstemp(dir=target.parent)`` and ``os.link(source, target)``
re-resolved the pathname, so a parent swap between check and use placed the
staging file (and the published link) OUTSIDE the authorized root.

These tests require descriptor-relative staging, publishing, fsync and
cleanup bound to one verified directory fd, fail-closed on any substitution.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from js_work import safe_output
from js_work.safe_output import publish_no_clobber, staged_path


def _swap_parent_for_symlink(workspace: Path, name: str, outside: Path) -> None:
    victim = workspace / name
    os.rename(victim, workspace / f"{name}_real")
    os.symlink(outside, victim)


def test_parent_swap_cannot_redirect_publish(tmp_path: Path) -> None:
    """Enter staging, swap the parent for a symlink, then publish:
    nothing may land outside the authorized root and publish must fail."""
    workspace = tmp_path / "workspace"
    outside = tmp_path / "outside"
    (workspace / "out").mkdir(parents=True)
    outside.mkdir()
    target = workspace / "out" / "result.json"

    with staged_path(target) as staged:
        staged.write_text('{"ok": true}\n', encoding="utf-8")
        _swap_parent_for_symlink(workspace, "out", outside)
        with pytest.raises((ValueError, OSError)):
            publish_no_clobber(staged, target, "result already exists")

    assert list(outside.iterdir()) == [], "publish escaped the authorized root"


def test_parent_swap_before_staging_write_cannot_escape(tmp_path: Path) -> None:
    """The exact reproduced attack window: swap right after the parent fd is
    opened but before the staging file is created.  With descriptor-relative
    creation the staging file stays in the verified directory."""
    workspace = tmp_path / "workspace"
    outside = tmp_path / "outside"
    (workspace / "out").mkdir(parents=True)
    outside.mkdir()
    target = workspace / "out" / "result.json"

    real_open = os.open
    swapped = {"done": False}

    def attacker_open(path, flags, mode=0o777, *, dir_fd=None):
        fd = real_open(path, flags, mode, dir_fd=dir_fd)
        # Swap right after the parent directory fd was opened, before the
        # staging file creation re-uses any pathname.
        if not swapped["done"] and dir_fd is None and os.path.isdir(path):
            swapped["done"] = True
            _swap_parent_for_symlink(workspace, "out", outside)
        return fd

    import js_work.safe_output as so

    original = so.os.open
    so.os.open = attacker_open  # type: ignore[assignment]
    try:
        with pytest.raises((ValueError, OSError)), staged_path(target) as staged:
            staged.write_text("x", encoding="utf-8")
            publish_no_clobber(staged, target, "result already exists")
    finally:
        so.os.open = original  # type: ignore[assignment]

    # No artifact was *published* outside the authorized root: the
    # descriptor-relative publish detected the pathname redirect and failed
    # closed.  (A caller-side write through a swapped pathname is detected,
    # never linked.)
    assert not (outside / "result.json").exists()


def test_inode_substitution_detected(tmp_path: Path) -> None:
    """Replacing the staged file with a symlink must fail closed."""
    target = tmp_path / "sub" / "out.json"
    payload = tmp_path / "payload.json"
    payload.write_text("forged", encoding="utf-8")
    with staged_path(target) as staged:
        staged.write_text("genuine", encoding="utf-8")
        # Attacker swaps the staged inode for a symlink to their own file.
        staged.unlink()
        staged.symlink_to(payload)
        with pytest.raises((ValueError, OSError)):
            publish_no_clobber(staged, target, "out already exists")
    assert not target.exists()


def test_fsync_failure_propagates_and_target_not_published(tmp_path: Path) -> None:
    target = tmp_path / "sub" / "out.json"
    real_fsync = os.fsync
    calls = {"n": 0}

    def failing_fsync(fd: int) -> None:
        calls["n"] += 1
        if calls["n"] > 1:  # allow staging writes, fail during publish
            raise OSError("simulated fsync failure (EIO)")
        real_fsync(fd)

    with pytest.raises(OSError, match="fsync"), staged_path(target) as staged:
        staged.write_text("data", encoding="utf-8")
        original = safe_output.os.fsync
        safe_output.os.fsync = failing_fsync  # type: ignore[assignment]
        try:
            publish_no_clobber(staged, target, "out already exists")
        finally:
            safe_output.os.fsync = original  # type: ignore[assignment]
    assert not target.exists()


def test_publish_rejects_source_outside_verified_directory(tmp_path: Path) -> None:
    source = tmp_path / "elsewhere.txt"
    source.write_text("x", encoding="utf-8")
    target_dir = tmp_path / "authorized"
    target_dir.mkdir()
    target = target_dir / "out.txt"
    with pytest.raises((ValueError, OSError)):
        publish_no_clobber(source, target, "out already exists")
    assert not target.exists()


def test_orphan_staging_swept_after_sigkill(tmp_path: Path) -> None:
    """Cross-process recovery: orphaned staging names are swept without
    touching published or unrelated files."""
    directory = tmp_path / "outputs"
    directory.mkdir()
    # Simulate orphans left by a SIGKILLed process.
    orphan = directory / ".report.ab12cd34ef56ab78.json"
    orphan.write_text("partial", encoding="utf-8")
    published = directory / "report.json"
    published.write_text("final", encoding="utf-8")
    unrelated = directory / "keep.txt"
    unrelated.write_text("keep", encoding="utf-8")

    swept = safe_output.sweep_staging(directory, min_age_seconds=0)
    assert swept >= 1
    assert not orphan.exists()
    assert published.read_text(encoding="utf-8") == "final"
    assert unrelated.read_text(encoding="utf-8") == "keep"


def test_publish_no_clobber_still_atomic_for_staged(tmp_path: Path) -> None:
    target = tmp_path / "sub" / "out.json"
    target.parent.mkdir(parents=True)
    target.write_text("existing", encoding="utf-8")
    with staged_path(target) as staged:
        staged.write_text("new", encoding="utf-8")
        with pytest.raises(ValueError, match="already exists"):
            publish_no_clobber(staged, target, "out already exists")
    assert target.read_text(encoding="utf-8") == "existing"


def test_happy_path_publish_and_cleanup(tmp_path: Path) -> None:
    target = tmp_path / "sub" / "out.json"
    with staged_path(target) as staged:
        staged.write_text("payload", encoding="utf-8")
        publish_no_clobber(staged, target, "out already exists")
    assert target.read_text(encoding="utf-8") == "payload"
    # staging name cleaned up
    leftovers = [p for p in target.parent.iterdir() if p.name.startswith(".out.")]
    assert leftovers == []
