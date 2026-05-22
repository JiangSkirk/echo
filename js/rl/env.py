"""Base RL environment interface for training agent policies."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any


@dataclass
class EnvironmentStep:
    """Result of one environment step."""

    observation: dict[str, Any]
    reward: float
    terminated: bool
    truncated: bool
    info: dict[str, Any]


class BaseAgentEnv(ABC):
    """Abstract base for RL environments that train agent tool-use policies.

    Follows the Gymnasium API pattern:
      reset() -> observation
      step(action) -> EnvironmentStep
      close()
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Environment identifier."""

    @abstractmethod
    def reset(self, *, seed: int | None = None, options: dict[str, Any] | None = None) -> dict[str, Any]:
        """Reset environment to initial state. Returns initial observation."""

    @abstractmethod
    def step(self, action: dict[str, Any]) -> EnvironmentStep:
        """Execute one action in the environment."""

    @abstractmethod
    def close(self) -> None:
        """Clean up resources."""

    def render(self) -> str:
        """Human-readable state representation for debugging."""
        return f"<{self.name} environment>"
