"""Deterministic ID generation for prompt-cache consistency.

When context is reconstructed (compression, checkpoint resume, fleet respawn),
identical seeds produce identical IDs. This lets providers reuse cached prefixes
and avoids UUID regeneration on every restart.
"""

from __future__ import annotations

import hashlib


def deterministic_id(seed: str, prefix: str = "", length: int = 24) -> str:
    """Generate a deterministic ID from a seed string.

    Uses SHA-256 to ensure identical seeds always produce identical IDs.
    """
    h = hashlib.sha256(seed.encode("utf-8")).hexdigest()
    return f"{prefix}{h[:length]}"


def tool_call_id(tool_name: str, arguments: str, turn_idx: int, session_id: str = "") -> str:
    """Deterministic fallback tool_call_id when the model does not supply one."""
    seed = f"{session_id}:{turn_idx}:{tool_name}:{arguments}"
    return deterministic_id(seed, prefix="call_", length=22)


def agent_id(name: str, role: str, model: str | None = None) -> str:
    """Deterministic fleet agent ID.

    Same (name, role, model) always yields the same ID, so fleet
    restoration after restart is idempotent.
    """
    seed = f"{role}:{name}:{model or 'default'}"
    return deterministic_id(seed, prefix="agent_", length=22)


def task_id(description: str, role: str, group_id: str = "") -> str:
    """Deterministic task ID for fleet strategies."""
    seed = f"{group_id}:{role}:{description[:100]}"
    return deterministic_id(seed, prefix="task_", length=22)


def session_id_from_input(user_input: str, timestamp: str = "") -> str:
    """Deterministic session identifier from user input."""
    seed = f"{timestamp}:{user_input[:200]}"
    return deterministic_id(seed, prefix="sess_", length=16)
