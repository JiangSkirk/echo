from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Episode:
    id: int
    session_id: str
    summary: str
    topics: list[str]
    tokens_used: int
    turn_count: int
    created_at: float
    importance: int


@dataclass
class SemanticMemory:
    id: int
    key: str
    value: str
    category: str
    confidence: float
    source: str
    created_at: float
    last_accessed: float
    access_count: int
    memory_path: str = ""
    entity_type: str = ""
    entity_name: str = ""
    parent_id: int | None = None
    relation_type: str = ""
    last_verified_at: float = 0.0
    evidence: str = ""
    session_id: str = ""
    owner_key_hash: str | None = None
