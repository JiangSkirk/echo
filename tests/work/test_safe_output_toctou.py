"""Verify: Work output staging rejects symlinked parent (TOCTOU hardening)."""

from __future__ import annotations

from pathlib import Path

import pytest

from js_work.safe_output import staged_path


def test_staged_path_rejects_symlinked_parent(tmp_path: Path) -> None:
    """If the target parent is a symlink, staging must fail closed."""
    real_dir = tmp_path / "real"
    real_dir.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real_dir)

    target = link / "output.xlsx"
    with pytest.raises((ValueError, OSError)), staged_path(target) as _staged:
        pass


def test_staged_path_works_for_regular_parent(tmp_path: Path) -> None:
    """Normal directories still work."""
    target = tmp_path / "sub" / "output.xlsx"
    with staged_path(target) as staged:
        assert staged.parent == target.parent
        assert staged.exists()
    assert not staged.exists()


def test_publish_no_clobber_is_atomic(tmp_path: Path) -> None:
    """publish_no_clobber must not overwrite an existing target."""
    from js_work.safe_output import publish_no_clobber

    source = tmp_path / "source.txt"
    source.write_text("content")
    target = tmp_path / "target.txt"
    target.write_text("existing")

    with pytest.raises(ValueError, match="already exists"):
        publish_no_clobber(source, target, "target already exists")

    assert target.read_text() == "existing"
