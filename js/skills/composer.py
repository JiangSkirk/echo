"""Skill composition DAG: meta-skills that chain existing skills.

Auto-discovers useful skill chains from execution logs.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from js.utils.db import db_connection
from js.utils.log import get_logger

logger = get_logger("js.skills.composer")


@dataclass
class CompositionNode:
    """A node in a skill composition graph."""

    skill_id: str
    args_mapping: dict[str, str] = field(default_factory=dict)
    condition: dict[str, Any] | None = None


@dataclass
class SkillChain:
    """A discovered or defined chain of skills."""

    id: str
    name: str
    description: str
    steps: list[CompositionNode]
    created_at: float
    usage_count: int = 0
    success_rate: float = 1.0


class SkillComposer:
    """Manages skill composition DAGs and auto-discovers useful chains."""

    def __init__(self, state_dir: Path) -> None:
        self.state_dir = state_dir
        self.db_path = state_dir / "skill_composition.db"
        self._init_db()
        self._chains: dict[str, SkillChain] = {}

    def _init_db(self) -> None:
        with db_connection(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS skill_chains (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    steps_json TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    usage_count INTEGER DEFAULT 0,
                    success_rate REAL DEFAULT 1.0
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS chain_executions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    chain_id TEXT NOT NULL,
                    success INTEGER NOT NULL,
                    executed_at REAL NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS transition_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    from_skill TEXT NOT NULL,
                    to_skill TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    timestamp REAL NOT NULL
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_transitions ON transition_log(from_skill, to_skill)
            """)
            conn.commit()

    def create_chain(
        self,
        name: str,
        description: str,
        steps: list[CompositionNode],
    ) -> SkillChain:
        """Create a new skill composition chain."""
        import uuid
        chain_id = f"chain_{uuid.uuid4().hex[:8]}"
        chain = SkillChain(
            id=chain_id,
            name=name,
            description=description,
            steps=steps,
            created_at=time.time(),
        )
        self._chains[chain_id] = chain
        with db_connection(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO skill_chains (id, name, description, steps_json, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (chain_id, name, description, json.dumps([
                    {"skill_id": s.skill_id, "args_mapping": s.args_mapping, "condition": s.condition}
                    for s in steps
                ]), chain.created_at),
            )
            conn.commit()
        logger.info(f"Created skill chain: {chain_id} with {len(steps)} steps")
        return chain

    def record_transition(self, from_skill: str, to_skill: str, session_id: str) -> None:
        """Record that one skill was followed by another in a session."""
        with db_connection(self.db_path) as conn:
            conn.execute(
                "INSERT INTO transition_log (from_skill, to_skill, session_id, timestamp) VALUES (?, ?, ?, ?)",
                (from_skill, to_skill, session_id, time.time()),
            )
            conn.commit()

    def discover_chains(self, min_frequency: int = 3) -> list[SkillChain]:
        """Auto-discover commonly used skill chains from transition logs."""
        with db_connection(self.db_path) as conn:
            # Find frequent transitions
            rows = conn.execute(
                """
                SELECT from_skill, to_skill, COUNT(*) as freq
                FROM transition_log
                GROUP BY from_skill, to_skill
                HAVING freq >= ?
                ORDER BY freq DESC
                """,
                (min_frequency,),
            ).fetchall()

        discovered: list[SkillChain] = []
        for from_skill, to_skill, freq in rows:
            chain_id = f"auto_{from_skill}_to_{to_skill}"
            if chain_id not in self._chains:
                chain = self.create_chain(
                    name=f"{from_skill} → {to_skill}",
                    description=f"Auto-discovered chain (frequency: {freq})",
                    steps=[
                        CompositionNode(skill_id=from_skill),
                        CompositionNode(skill_id=to_skill),
                    ],
                )
                discovered.append(chain)

        return discovered


