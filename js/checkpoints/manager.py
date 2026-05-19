"""Hermes-style checkpoint system with transparent git shadow repos.

Key design:
- Shadow repos live outside the user's project (no .git pollution)
- Uses GIT_DIR + GIT_WORK_TREE to isolate from user's global git config
- Signing disabled to avoid interactive prompts
- Deduplication: at most one snapshot per dir per turn
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from js.utils.log import get_logger

logger = get_logger("js.checkpoints")

_COMMIT_HASH_RE = re.compile(r"^[0-9a-fA-F]{4,64}$")


class CheckpointManager:
    """Manages transparent filesystem snapshots."""

    def __init__(self, state_dir: Path) -> None:
        self.state_dir = state_dir
        self.checkpoints_dir = state_dir / "checkpoints"
        self.checkpoints_dir.mkdir(parents=True, exist_ok=True)
        self._checkpointed_dirs: set[str] = set()

    def _shadow_repo_path(self, work_dir: Path) -> Path:
        """Get the shadow repo path for a work directory."""
        dir_hash = hashlib.sha256(str(work_dir.resolve()).encode()).hexdigest()[:16]
        return self.checkpoints_dir / dir_hash

    def _init_shadow_repo(self, shadow_path: Path, work_dir: Path) -> None:
        """Initialize a shadow git repo."""
        if (shadow_path / "HEAD").exists():
            return

        shadow_path.mkdir(parents=True, exist_ok=True)

        # Write workdir marker
        (shadow_path / "HERMES_WORKDIR").write_text(str(work_dir.resolve()))

        # Init repo (not bare, so GIT_WORK_TREE works)
        env = self._git_env(shadow_path, work_dir)
        subprocess.run(
            ["git", "init"],
            cwd=str(work_dir),
            env=env,
            capture_output=True,
            check=True,
        )

        # Configure isolation
        self._git_config(shadow_path, work_dir, "commit.gpgsign", "false")
        self._git_config(shadow_path, work_dir, "tag.gpgSign", "false")
        self._git_config(shadow_path, work_dir, "user.email", "js@localhost")
        self._git_config(shadow_path, work_dir, "user.name", "JS Agent")

    def _git_env(self, shadow_path: Path, work_dir: Path) -> dict[str, str]:
        """Build isolated git environment."""
        env = os.environ.copy()
        env["GIT_DIR"] = str(shadow_path / ".git")
        env["GIT_WORK_TREE"] = str(work_dir)
        env["GIT_CONFIG_GLOBAL"] = "/dev/null"
        env["GIT_CONFIG_SYSTEM"] = "/dev/null"
        return env

    def _git_config(self, shadow_path: Path, work_dir: Path, key: str, value: str) -> None:
        """Set a git config value in the shadow repo."""
        env = self._git_env(shadow_path, work_dir)
        subprocess.run(
            ["git", "config", key, value],
            env=env,
            capture_output=True,
            check=True,
        )

    def _git(self, shadow_path: Path, work_dir: Path, *args: str) -> subprocess.CompletedProcess[str]:
        """Run a git command in the shadow repo."""
        env = self._git_env(shadow_path, work_dir)
        return subprocess.run(
            ["git", *args],
            env=env,
            capture_output=True,
            text=True,
            check=True,
        )

    def snapshot(self, work_dir: Path | str, label: str = "auto") -> str | None:
        """Create a snapshot of the working directory. Returns commit hash."""
        work_path = Path(work_dir).resolve()
        if not work_path.exists():
            logger.warning(f"Work directory does not exist: {work_path}")
            return None

        # Deduplication: one snapshot per dir per turn
        dir_key = str(work_path)
        if dir_key in self._checkpointed_dirs:
            logger.debug(f"Directory already checkpointed this turn: {work_path}")
            return None

        shadow_path = self._shadow_repo_path(work_path)

        try:
            self._init_shadow_repo(shadow_path, work_path)

            # Add all files
            self._git(shadow_path, work_path, "add", "-A")

            # Commit
            self._git(
                shadow_path, work_path,
                "commit", "-m", f"js-snapshot: {label}",
                "--no-verify", "--allow-empty",
            )

            # Get commit hash
            hash_result = self._git(shadow_path, work_path, "rev-parse", "HEAD")
            commit_hash = hash_result.stdout.strip()

            self._checkpointed_dirs.add(dir_key)
            logger.info(f"Snapshot created: {commit_hash[:8]} for {work_path}")
            return commit_hash

        except subprocess.CalledProcessError as e:
            logger.warning(f"Snapshot failed: {e.stderr}")
            return None

    def restore(self, work_dir: Path | str, commit_hash: str) -> bool:
        """Restore working directory to a snapshot."""
        if not _COMMIT_HASH_RE.match(commit_hash):
            logger.error(f"Invalid commit hash: {commit_hash}")
            return False

        work_path = Path(work_dir).resolve()
        shadow_path = self._shadow_repo_path(work_path)

        if not shadow_path.exists():
            logger.error(f"No shadow repo found for {work_path}")
            return False

        try:
            # First, stash any current changes
            self._git(shadow_path, work_path, "stash", "push", "-m", "pre-restore-stash")
        except subprocess.CalledProcessError as e:
            # "No local changes to save" is OK; anything else is a real error
            if e.stderr and "No local changes to save" not in e.stderr:
                logger.error(f"Stash failed before restore: {e.stderr}")
                raise

        try:
            # Reset to the snapshot
            self._git(shadow_path, work_path, "reset", "--hard", commit_hash)

            logger.info(f"Restored {work_path} to {commit_hash[:8]}")
            return True

        except subprocess.CalledProcessError as e:
            logger.error(f"Restore failed: {e.stderr}")
            # Attempt to recover stash so user data isn't lost
            try:
                self._git(shadow_path, work_path, "stash", "pop")
            except subprocess.CalledProcessError:
                pass
            return False

    def list_snapshots(self, work_dir: Path | str) -> list[dict[str, Any]]:
        """List all snapshots for a working directory."""
        work_path = Path(work_dir).resolve()
        shadow_path = self._shadow_repo_path(work_path)

        if not shadow_path.exists():
            return []

        try:
            result = self._git(
                shadow_path, work_path,
                "log", "--pretty=format:%H|%ci|%s", "--all",
            )
            snapshots: list[dict[str, Any]] = []
            for line in result.stdout.strip().splitlines():
                parts = line.split("|", 2)
                if len(parts) == 3:
                    snapshots.append({
                        "hash": parts[0],
                        "date": parts[1],
                        "message": parts[2],
                    })
            return snapshots
        except subprocess.CalledProcessError:
            return []

    def reset_turn(self) -> None:
        """Reset deduplication tracker for a new turn."""
        self._checkpointed_dirs.clear()

    def cleanup_old(self, retention_days: int = 7) -> int:
        """Remove shadow repos older than retention_days."""
        import time
        cutoff = time.time() - (retention_days * 86400)
        removed = 0

        for shadow_path in self.checkpoints_dir.iterdir():
            if not shadow_path.is_dir():
                continue
            try:
                mtime = shadow_path.stat().st_mtime
                if mtime < cutoff:
                    shutil.rmtree(shadow_path)
                    removed += 1
                    logger.info(f"Cleaned old shadow repo: {shadow_path.name}")
            except Exception as e:
                logger.warning(f"Failed to clean {shadow_path}: {e}")

        return removed
