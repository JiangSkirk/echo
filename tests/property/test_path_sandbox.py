"""Property tests for lexical path sandbox, NFC, casefold, and symlink escape."""

from __future__ import annotations

import tempfile
import unicodedata
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from js.config import SecurityConfig, ToolLimits
from js.security.guard import BehaviorGuard
from js.tools.files import FileTools

_NAME = st.from_regex(r"[A-Za-z0-9][A-Za-z0-9._-]{0,10}", fullmatch=True)


def _tools(tmp_path: Path) -> FileTools:
    return FileTools(tmp_path, ToolLimits(), BehaviorGuard(SecurityConfig(), tmp_path))


@settings(max_examples=60, deadline=None)
@given(st.lists(_NAME, min_size=1, max_size=4))
def test_relative_safe_names_stay_inside_workspace(parts: list[str]) -> None:
    with tempfile.TemporaryDirectory() as raw:
        tools = _tools(Path(raw))
        relative = tools._relative_path("/".join(parts))
        assert ".." not in relative.parts
        resolved = (tools.workspace / relative).resolve()
        resolved.relative_to(tools.workspace)


@settings(max_examples=40, deadline=None)
@given(_NAME)
def test_parent_segments_are_rejected(name: str) -> None:
    with tempfile.TemporaryDirectory() as raw:
        tools = _tools(Path(raw))
        with pytest.raises(ValueError, match="escapes workspace"):
            tools._relative_path(f"../{name}")
        with pytest.raises(ValueError, match="escapes workspace"):
            tools._relative_path(f"{name}/../../{name}")


def test_absolute_and_home_paths_are_rejected(tmp_path: Path) -> None:
    tools = _tools(tmp_path)
    with pytest.raises(ValueError):
        tools._relative_path("/etc/passwd")
    with pytest.raises(ValueError, match="Home-relative"):
        tools._relative_path("~/secret")
    with pytest.raises(ValueError, match="Invalid workspace path"):
        tools._relative_path("bad\x00name")


def test_nfc_equivalence_does_not_open_parent(tmp_path: Path) -> None:
    tools = _tools(tmp_path)
    composed = unicodedata.normalize("NFC", "café")
    decomposed = unicodedata.normalize("NFD", "café")
    assert tools._relative_path(composed).name in {composed, decomposed, "café"}
    with pytest.raises(ValueError):
        tools._relative_path(unicodedata.normalize("NFC", "../café"))
    with pytest.raises(ValueError):
        tools._relative_path(unicodedata.normalize("NFD", "../café"))


def test_git_metadata_write_is_casefold_rejected(tmp_path: Path) -> None:
    tools = _tools(tmp_path)
    for path in (".git/config", ".GIT/hooks/pre-commit", "src/.Git/HEAD"):
        with pytest.raises(ValueError, match="git metadata"):
            tools._reject_git_metadata_write(path)


def test_symlink_escape_is_rejected(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    workspace.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("secret", encoding="utf-8")
    escape = workspace / "escape"
    escape.symlink_to(outside)
    inside = workspace / "real.txt"
    inside.write_text("ok", encoding="utf-8")
    inner = workspace / "inner"
    inner.symlink_to(inside)
    tools = _tools(workspace)
    with pytest.raises(ValueError, match="escapes workspace"):
        tools._resolve("escape", follow_symlinks=True)
    with pytest.raises(ValueError, match="escapes workspace"):
        tools._resolve("escape", follow_symlinks=False)
    assert tools._resolve("inner", follow_symlinks=True) == inside.resolve()
    with pytest.raises(ValueError, match="Symlinks are not allowed"):
        tools._resolve("inner", follow_symlinks=False)
