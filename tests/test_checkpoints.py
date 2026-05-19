"""Tests for checkpoint system."""

from pathlib import Path

import pytest

from js.checkpoints.manager import CheckpointManager


class TestCheckpointManager:
    @pytest.fixture
    def manager(self, tmp_path: Path) -> CheckpointManager:
        return CheckpointManager(tmp_path)

    @pytest.fixture
    def work_dir(self, tmp_path: Path) -> Path:
        wd = tmp_path / "project"
        wd.mkdir()
        (wd / "main.py").write_text("print('hello')")
        (wd / "README.md").write_text("# Project")
        return wd

    def test_snapshot_and_restore(self, manager: CheckpointManager, work_dir: Path) -> None:
        commit = manager.snapshot(work_dir, "initial")
        assert commit is not None
        assert len(commit) == 40  # SHA-1 hash

        # Modify files
        (work_dir / "main.py").write_text("print('modified')")

        # Restore
        success = manager.restore(work_dir, commit)
        assert success
        assert (work_dir / "main.py").read_text() == "print('hello')"

    def test_list_snapshots(self, manager: CheckpointManager, work_dir: Path) -> None:
        manager.snapshot(work_dir, "first")
        manager.snapshot(work_dir, "second")
        snapshots = manager.list_snapshots(work_dir)
        assert len(snapshots) >= 1

    def test_deduplication(self, manager: CheckpointManager, work_dir: Path) -> None:
        commit1 = manager.snapshot(work_dir, "test")
        commit2 = manager.snapshot(work_dir, "test")  # Same turn
        assert commit1 is not None
        assert commit2 is None  # Deduplicated

    def test_reset_turn(self, manager: CheckpointManager, work_dir: Path) -> None:
        manager.snapshot(work_dir, "first")
        manager.reset_turn()
        commit2 = manager.snapshot(work_dir, "second")
        assert commit2 is not None

    def test_cleanup_old(self, manager: CheckpointManager, work_dir: Path) -> None:
        manager.snapshot(work_dir, "test")
        removed = manager.cleanup_old(retention_days=0)
        assert removed >= 0
