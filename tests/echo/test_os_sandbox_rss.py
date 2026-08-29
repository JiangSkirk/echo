"""Process-group RSS accounting helpers."""

from __future__ import annotations

import os

from js.echo.os_sandbox import SandboxExecutor


def test_process_group_rss_covers_current_process() -> None:
    rss = SandboxExecutor._process_group_rss(os.getpid())
    assert rss > 0
    tree = SandboxExecutor._process_tree_rss(os.getpid())
    assert rss >= tree


def test_accounted_rss_prefers_larger_of_group_and_cgroup(monkeypatch) -> None:
    executor = SandboxExecutor.__new__(SandboxExecutor)
    monkeypatch.setattr(SandboxExecutor, "_process_group_rss", staticmethod(lambda _pid: 100))
    monkeypatch.setattr(SandboxExecutor, "_cgroup_rss", staticmethod(lambda _pid: 250))
    assert executor._accounted_rss(1) == 250
    monkeypatch.setattr(SandboxExecutor, "_cgroup_rss", staticmethod(lambda _pid: None))
    assert executor._accounted_rss(1) == 100
    monkeypatch.setattr(SandboxExecutor, "_cgroup_rss", staticmethod(lambda _pid: 50))
    assert executor._accounted_rss(1) == 100


def test_cgroup_rss_is_none_or_non_negative() -> None:
    value = SandboxExecutor._cgroup_rss(os.getpid())
    if value is not None:
        assert value >= 0


def test_bwrap_placeholder_for_missing_git(tmp_path, monkeypatch) -> None:
    workspace = tmp_path / "ws"
    workspace.mkdir()
    executor = SandboxExecutor(workspace, strict_isolation=False)
    monkeypatch.setattr(executor, "_has_bwrap", True)
    monkeypatch.setattr("js.echo.os_sandbox.platform.system", lambda: "Linux")
    wrapped = executor._wrap_filesystem_isolation(
        ["echo", "ok"],
        fs_restricted=True,
        network_allowed=False,
    )
    assert "--dir" in wrapped
    assert str(workspace / ".git") in wrapped
    assert any(str(part).endswith("git-deny-placeholder") for part in wrapped)
