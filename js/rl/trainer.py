"""RL trainer: orchestrate episodes, collect trajectories, compute metrics."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from js.rl.env import BaseAgentEnv
from js.rl.recorder import TrajectoryRecorder
from js.utils.log import get_logger

logger = get_logger("js.rl.trainer")


@dataclass
class EpisodeResult:
    """Result of a single training episode."""

    episode_num: int
    total_reward: float
    steps: int
    success: bool
    duration_seconds: float
    trajectory_id: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class TrainingReport:
    """Aggregate report after a training run."""

    env_name: str
    num_episodes: int
    total_steps: int
    success_count: int
    avg_reward: float
    avg_steps: float
    episodes: list[EpisodeResult] = field(default_factory=list)
    start_time: float = field(default_factory=time.time)
    end_time: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "env_name": self.env_name,
            "num_episodes": self.num_episodes,
            "total_steps": self.total_steps,
            "success_count": self.success_count,
            "success_rate": self.success_count / self.num_episodes if self.num_episodes > 0 else 0,
            "avg_reward": self.avg_reward,
            "avg_steps": self.avg_steps,
            "duration_seconds": self.end_time - self.start_time if self.end_time else 0,
            "episodes": [vars(e) for e in self.episodes],
        }


class RLTrainer:
    """Orchestrates RL training loops.

    This is a skeleton trainer — it runs episodes and collects trajectories.
    A full implementation would include a policy network and update loop.
    """

    def __init__(self, env: BaseAgentEnv, output_dir: Path | None = None) -> None:
        self.env = env
        self.recorder = TrajectoryRecorder(output_dir=output_dir)
        self.episode_results: list[EpisodeResult] = []

    async def run_episodes(
        self,
        num_episodes: int = 10,
        max_steps_per_episode: int = 20,
        agent_callback: Any | None = None,
    ) -> TrainingReport:
        """Run multiple episodes and collect training data.

        Args:
            num_episodes: Number of episodes to run.
            max_steps_per_episode: Step limit per episode.
            agent_callback: Optional async callable(obs) -> action dict.
                          If None, uses random actions (for testing).
        """
        report = TrainingReport(
            env_name=self.env.name, num_episodes=num_episodes,
            total_steps=0, success_count=0, avg_reward=0.0, avg_steps=0.0,
        )

        for ep in range(num_episodes):
            logger.info(f"Starting episode {ep + 1}/{num_episodes}")
            ep_start = time.perf_counter()
            obs = self.env.reset(seed=ep)
            self.recorder.start(self.env.name, task_id=f"ep_{ep}")

            total_reward = 0.0
            step_count = 0
            success = False

            for _step in range(max_steps_per_episode):
                # Get action from agent callback or random
                if agent_callback is not None:
                    action = await agent_callback(obs)
                else:
                    action = self._random_action(obs)

                # Environment steps may run untrusted tests.  Keep their
                # synchronous sandbox bridge off the event-loop thread.
                step_result = await asyncio.to_thread(self.env.step, action)
                self.recorder.record_step(obs, action, step_result)

                total_reward += step_result.reward
                step_count += 1
                obs = step_result.observation

                if step_result.terminated:
                    success = step_result.reward > 0
                    break
                if step_result.truncated:
                    break

            traj = self.recorder.finish(success=success)
            ep_duration = time.perf_counter() - ep_start

            result = EpisodeResult(
                episode_num=ep + 1,
                total_reward=total_reward,
                steps=step_count,
                success=success,
                duration_seconds=ep_duration,
                trajectory_id=traj.trajectory_id,
            )
            report.episodes.append(result)
            logger.info(
                f"Episode {ep + 1} done: reward={total_reward:.2f}, "
                f"steps={step_count}, success={success}"
            )

        report.end_time = time.time()
        report.total_steps = sum(e.steps for e in report.episodes)
        report.success_count = sum(1 for e in report.episodes if e.success)
        report.avg_reward = sum(e.total_reward for e in report.episodes) / num_episodes
        report.avg_steps = report.total_steps / num_episodes

        logger.info(
            f"Training complete: {num_episodes} episodes, "
            f"success_rate={report.success_count / num_episodes:.1%}, "
            f"avg_reward={report.avg_reward:.2f}"
        )
        return report

    def _random_action(self, obs: dict[str, Any]) -> dict[str, Any]:
        """Generate a random action for baseline/testing."""
        import random
        action_types = ["test", "noop"]
        # If source code is available, sometimes try an edit
        if obs.get("source_code"):
            action_types.append("edit")
        action_type = random.choice(action_types)
        if action_type == "edit":
            code = obs.get("source_code", "")
            # Naive "fix": replace common bug patterns
            new_code = code
            if "return 0  # BUG" in code:
                new_code = code.replace("return 0  # BUG: should return 1", "return 1")
            elif "return 0" in code and "factorial" in code:
                new_code = code.replace("return 0", "return 1", 1)
            return {"type": "edit", "file": "math_utils.py", "content": new_code}
        return {"type": action_type}
