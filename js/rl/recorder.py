"""Trajectory recorder for RL training data collection."""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from js.rl.env import EnvironmentStep
from js.utils.log import get_logger

logger = get_logger("js.rl.recorder")


@dataclass
class TrajectoryStep:
    """One step in a trajectory."""

    step_idx: int
    observation: dict[str, Any] = field(default_factory=dict)
    action: dict[str, Any] = field(default_factory=dict)
    reward: float = 0.0
    terminated: bool = False
    truncated: bool = False
    info: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


@dataclass
class Trajectory:
    """A complete episode trajectory."""

    trajectory_id: str
    env_name: str
    task_id: str = ""
    steps: list[TrajectoryStep] = field(default_factory=list)
    total_reward: float = 0.0
    success: bool = False
    start_time: float = field(default_factory=time.time)
    end_time: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "trajectory_id": self.trajectory_id,
            "env_name": self.env_name,
            "task_id": self.task_id,
            "steps": [asdict(s) for s in self.steps],
            "total_reward": self.total_reward,
            "success": self.success,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_seconds": self.end_time - self.start_time if self.end_time else 0,
            "metadata": self.metadata,
        }


class TrajectoryRecorder:
    """Records and persists trajectories for RL training."""

    def __init__(self, output_dir: Path | None = None) -> None:
        self.output_dir = output_dir or (Path.home() / ".js" / "rl" / "trajectories")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._current: Trajectory | None = None

    def start(self, env_name: str, task_id: str = "", metadata: dict[str, Any] | None = None) -> Trajectory:
        import uuid
        traj = Trajectory(
            trajectory_id=f"traj_{uuid.uuid4().hex[:12]}",
            env_name=env_name,
            task_id=task_id,
            metadata=metadata or {},
        )
        self._current = traj
        logger.info(f"Started trajectory {traj.trajectory_id} on {env_name}")
        return traj

    def record_step(self, observation: dict[str, Any], action: dict[str, Any], step: EnvironmentStep) -> None:
        if self._current is None:
            raise RuntimeError("No active trajectory. Call start() first.")
        traj_step = TrajectoryStep(
            step_idx=len(self._current.steps),
            observation=observation,
            action=action,
            reward=step.reward,
            terminated=step.terminated,
            truncated=step.truncated,
            info=step.info,
        )
        self._current.steps.append(traj_step)
        self._current.total_reward += step.reward

    def finish(self, success: bool = False) -> Trajectory:
        if self._current is None:
            raise RuntimeError("No active trajectory.")
        self._current.end_time = time.time()
        self._current.success = success
        self._save(self._current)
        traj = self._current
        self._current = None
        logger.info(
            f"Finished trajectory {traj.trajectory_id}: "
            f"reward={traj.total_reward:.2f}, steps={len(traj.steps)}, success={success}"
        )
        return traj

    def _save(self, trajectory: Trajectory) -> None:
        path = self.output_dir / f"{trajectory.trajectory_id}.json"
        path.write_text(json.dumps(trajectory.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")

    def list_trajectories(self) -> list[Path]:
        return sorted(self.output_dir.glob("traj_*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
