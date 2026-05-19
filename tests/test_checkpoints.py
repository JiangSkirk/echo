"""Tests for checkpoint system.

CheckpointManager was removed in Phase 1 cleanup.
These tests are skipped to preserve test count history.
Restore from git history if checkpoint functionality is reintroduced.
"""

from pathlib import Path

import pytest

pytestmark = pytest.mark.skip(reason="CheckpointManager removed in Phase 1 cleanup")


class TestCheckpointManager:
    @pytest.fixture
    def manager(self, tmp_path: Path):
        pytest.skip("CheckpointManager removed")

    @pytest.fixture
    def work_dir(self, tmp_path: Path) -> Path:
        wd = tmp_path / "project"
        wd.mkdir()
        (wd / "main.py").write_text("print('hello')")
        (wd / "README.md").write_text("# Project")
        return wd

    def test_snapshot_and_restore(self, manager, work_dir: Path) -> None:
        pass

    def test_list_snapshots(self, manager, work_dir: Path) -> None:
        pass

    def test_deduplication(self, manager, work_dir: Path) -> None:
        pass

    def test_reset_turn(self, manager, work_dir: Path) -> None:
        pass

    def test_cleanup_old(self, manager, work_dir: Path) -> None:
        pass
