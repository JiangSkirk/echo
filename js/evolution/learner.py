"""Self-learning from interactions: semantic clustering, feedback parsing, strategy improvement."""

from __future__ import annotations

import json
import re
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from js.utils.db import db_connection
from js.utils.log import get_logger

logger = get_logger("js.evolution")

_DEFAULT_MAX_INTERACTIONS = 1_000
_DEFAULT_MAX_PATTERNS = 2_000
_DEFAULT_MAX_CLUSTERS = 500
_DEFAULT_MAX_ADJUSTMENTS = 1_000
_LEGACY_LOCAL_OWNER = "__legacy_local__"


@dataclass
class Interaction:
    id: str
    session_id: str
    user_input: str
    agent_output: str
    tool_calls: list[dict[str, Any]]
    success: bool
    feedback: str
    latency_ms: float
    tokens_used: int
    timestamp: float
    owner_key_hash: str = _LEGACY_LOCAL_OWNER


class SelfLearner:
    """Learns from past interactions to improve future performance via semantic clustering."""

    # Semantic learning parameters
    CLUSTER_THRESHOLD = 0.5  # Cosine similarity threshold for clustering
    MIN_CLUSTER_SIZE = 3

    def __init__(self, state_dir: Path) -> None:
        self.state_dir = state_dir
        self.db_path = state_dir / "learning.db"
        self._init_db()
        self._patterns: dict[str, list[str]] = {}
        self._strategies: dict[str, str] = {}
        self._migrate_private_interaction_text()

    def _init_db(self) -> None:
        with db_connection(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS interactions (
                    id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    user_input TEXT NOT NULL,
                    agent_output TEXT NOT NULL,
                    tool_calls TEXT NOT NULL,
                    success INTEGER DEFAULT 1,
                    feedback TEXT,
                    latency_ms REAL,
                    tokens_used INTEGER,
                    timestamp REAL NOT NULL,
                    owner_key_hash TEXT NOT NULL DEFAULT '__legacy_local__'
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS learned_patterns (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    pattern_type TEXT NOT NULL,
                    pattern TEXT NOT NULL,
                    frequency INTEGER DEFAULT 1,
                    success_rate REAL DEFAULT 1.0,
                    first_seen REAL NOT NULL,
                    last_seen REAL NOT NULL,
                    owner_key_hash TEXT NOT NULL DEFAULT '__legacy_local__'
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS strategy_adjustments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    context TEXT NOT NULL,
                    old_strategy TEXT NOT NULL,
                    new_strategy TEXT NOT NULL,
                    improvement REAL,
                    applied_at REAL NOT NULL,
                    owner_key_hash TEXT NOT NULL DEFAULT '__legacy_local__'
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS intent_clusters (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cluster_name TEXT NOT NULL,
                    keywords TEXT NOT NULL,
                    interaction_count INTEGER DEFAULT 0,
                    success_rate REAL DEFAULT 1.0,
                    avg_latency_ms REAL DEFAULT 0.0,
                    avg_tokens INTEGER DEFAULT 0,
                    created_at REAL NOT NULL,
                    last_seen REAL NOT NULL,
                    owner_key_hash TEXT NOT NULL DEFAULT '__legacy_local__'
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_interactions_session ON interactions(session_id)
            """)
            for table in (
                "interactions",
                "learned_patterns",
                "strategy_adjustments",
                "intent_clusters",
            ):
                columns = {str(row[1]) for row in conn.execute(f"PRAGMA table_info({table})")}
                if "owner_key_hash" not in columns:
                    conn.execute(
                        f"""
                        ALTER TABLE {table}
                        ADD COLUMN owner_key_hash TEXT NOT NULL
                        DEFAULT '{_LEGACY_LOCAL_OWNER}'
                        """
                    )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_interactions_owner_time
                ON interactions(owner_key_hash, timestamp DESC)
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_patterns_owner_pattern
                ON learned_patterns(owner_key_hash, pattern)
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_clusters_owner_seen
                ON intent_clusters(owner_key_hash, last_seen DESC)
                """
            )
            conn.execute(
                """
                DELETE FROM learned_patterns
                WHERE pattern LIKE 'task:%' OR pattern LIKE 'entity:%'
                """
            )
            conn.execute(
                """
                DELETE FROM intent_clusters
                WHERE keywords LIKE '%task:%' OR keywords LIKE '%entity:%'
                """
            )
            conn.commit()

    @staticmethod
    def _owner(owner_key_hash: str | None) -> str:
        return owner_key_hash or _LEGACY_LOCAL_OWNER

    @property
    def default_owner_key_hash(self) -> str:
        return _LEGACY_LOCAL_OWNER

    @property
    def _secrets(self) -> Any:
        if not hasattr(self, "_secrets_inst"):
            from js.security.secrets import SecretManager

            self._secrets_inst = SecretManager(self.state_dir)
        return self._secrets_inst

    def _migrate_private_interaction_text(self) -> None:
        """Encrypt text written by releases that predated at-rest protection."""
        prefix = "ENC:v1:"
        with db_connection(self.db_path) as conn:
            rows = conn.execute(
                "SELECT id, user_input, agent_output, feedback FROM interactions"
            ).fetchall()
            updates: list[tuple[str, str, str, str]] = []
            for interaction_id, user_input, agent_output, feedback in rows:
                values = [str(user_input or ""), str(agent_output or ""), str(feedback or "")]
                migrated: list[str] = [
                    value
                    if value.startswith(prefix)
                    else str(self._secrets.encrypt_blob(value.encode("utf-8")).decode("ascii"))
                    for value in values
                ]
                if migrated != values:
                    updates.append(
                        (
                            migrated[0],
                            migrated[1],
                            migrated[2],
                            str(interaction_id),
                        )
                    )
            if updates:
                conn.executemany(
                    """
                    UPDATE interactions
                    SET user_input = ?, agent_output = ?, feedback = ?
                    WHERE id = ?
                    """,
                    updates,
                )
                conn.commit()

    def record_interaction(
        self,
        session_id: str,
        user_input: str,
        agent_output: str,
        tool_calls: list[dict[str, Any]],
        success: bool = True,
        feedback: str = "",
        latency_ms: float = 0.0,
        tokens_used: int = 0,
        owner_key_hash: str | None = None,
    ) -> None:
        """Record an interaction for learning."""
        import uuid

        interaction_id = f"{session_id}_{uuid.uuid4().hex[:8]}"
        owner = self._owner(owner_key_hash)
        encrypted_user_input = self._secrets.encrypt_blob(user_input.encode("utf-8")).decode(
            "ascii"
        )
        encrypted_agent_output = self._secrets.encrypt_blob(agent_output.encode("utf-8")).decode(
            "ascii"
        )
        encrypted_feedback = self._secrets.encrypt_blob(feedback.encode("utf-8")).decode("ascii")
        with db_connection(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO interactions
                (id, session_id, user_input, agent_output, tool_calls, success,
                 feedback, latency_ms, tokens_used, timestamp, owner_key_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    interaction_id,
                    session_id,
                    encrypted_user_input,
                    encrypted_agent_output,
                    json.dumps(tool_calls),
                    int(success),
                    encrypted_feedback,
                    latency_ms,
                    tokens_used,
                    time.time(),
                    owner,
                ),
            )
            conn.commit()

        self._extract_patterns(user_input, success, owner)
        self._update_clusters(user_input, success, latency_ms, tokens_used, owner)

    def _extract_patterns(self, user_input: str, success: bool, owner: str) -> None:
        """Extract and store semantic patterns from user input."""
        # Use sentence-level features instead of just keywords
        features = self._extract_features(user_input)
        for feature in features:
            with db_connection(self.db_path) as conn:
                existing = conn.execute(
                    """
                    SELECT frequency, success_rate FROM learned_patterns
                    WHERE pattern = ? AND owner_key_hash = ?
                    """,
                    (feature, owner),
                ).fetchone()
                if existing:
                    freq, rate = existing
                    new_freq = freq + 1
                    new_rate = (rate * freq + (1.0 if success else 0.0)) / new_freq
                    conn.execute(
                        """
                        UPDATE learned_patterns
                        SET frequency = ?, success_rate = ?, last_seen = ?
                        WHERE pattern = ? AND owner_key_hash = ?
                        """,
                        (new_freq, new_rate, time.time(), feature, owner),
                    )
                else:
                    conn.execute(
                        """
                        INSERT INTO learned_patterns
                        (pattern_type, pattern, first_seen, last_seen, owner_key_hash)
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        ("feature", feature, time.time(), time.time(), owner),
                    )
                conn.commit()

    def _extract_features(self, text: str) -> list[str]:
        """Extract semantic features: noun phrases, action verbs, and domain terms."""
        text_lower = text.lower()

        # Extract action patterns (verb + object)
        action_patterns: list[str] = []
        action_verbs = [
            "write",
            "create",
            "build",
            "fix",
            "debug",
            "test",
            "run",
            "deploy",
            "analyze",
            "search",
            "find",
            "get",
            "set",
            "update",
            "delete",
            "convert",
            "generate",
            "parse",
            "extract",
            "summarize",
        ]
        for verb in action_verbs:
            if verb in text_lower:
                action_patterns.append(f"action:{verb}")

        # Extract domain terms
        domain_terms = [
            "python",
            "javascript",
            "java",
            "rust",
            "go",
            "sql",
            "docker",
            "kubernetes",
            "aws",
            "azure",
            "gcp",
            "api",
            "database",
            "frontend",
            "backend",
            "test",
            "excel",
            "pdf",
            "csv",
            "json",
            "yaml",
            "web",
            "scraping",
            "crawling",
            "search",
        ]
        for term in domain_terms:
            if term in text_lower:
                action_patterns.append(f"domain:{term}")

        return list(set(action_patterns))[:20]

    def _update_clusters(
        self,
        user_input: str,
        success: bool,
        latency_ms: float,
        tokens_used: int,
        owner: str,
    ) -> None:
        """Update intent clusters with new interaction."""
        features = self._extract_features(user_input)
        if not features:
            return

        feature_set = set(features)
        with db_connection(self.db_path) as conn:
            rows = conn.execute(
                """
                SELECT id, keywords, interaction_count, success_rate,
                       avg_latency_ms, avg_tokens
                FROM intent_clusters
                WHERE owner_key_hash = ?
                """,
                (owner,),
            ).fetchall()

            best_match: tuple[int, float] | None = None
            for row in rows:
                cid, keywords_str, count, rate, avg_lat, avg_tok = row
                cluster_features = set(keywords_str.split(","))
                similarity = self._jaccard_similarity(feature_set, cluster_features)
                if similarity >= self.CLUSTER_THRESHOLD and (
                    best_match is None or similarity > best_match[1]
                ):
                    best_match = (cid, similarity)

            if best_match:
                cid = best_match[0]
                # Update existing cluster
                row = conn.execute(
                    "SELECT interaction_count, success_rate, avg_latency_ms, avg_tokens FROM intent_clusters WHERE id = ?",
                    (cid,),
                ).fetchone()
                if row:
                    count, rate, avg_lat, avg_tok = row
                    new_count = count + 1
                    new_rate = (rate * count + (1.0 if success else 0.0)) / new_count
                    new_lat = (avg_lat * count + latency_ms) / new_count
                    new_tok = int((avg_tok * count + tokens_used) / new_count)
                    conn.execute(
                        """
                        UPDATE intent_clusters
                        SET interaction_count = ?, success_rate = ?, avg_latency_ms = ?, avg_tokens = ?, last_seen = ?
                        WHERE id = ?
                        """,
                        (new_count, new_rate, new_lat, new_tok, time.time(), cid),
                    )
            else:
                # Create new cluster
                cluster_name = self._generate_cluster_name(features)
                conn.execute(
                    """
                    INSERT INTO intent_clusters
                    (cluster_name, keywords, interaction_count, success_rate,
                     avg_latency_ms, avg_tokens, created_at, last_seen, owner_key_hash)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        cluster_name,
                        ",".join(features),
                        1,
                        1.0 if success else 0.0,
                        latency_ms,
                        tokens_used,
                        time.time(),
                        time.time(),
                        owner,
                    ),
                )
            conn.commit()

    def _jaccard_similarity(self, a: set[str], b: set[str]) -> float:
        """Compute Jaccard similarity between two sets."""
        if not a and not b:
            return 1.0
        intersection = len(a & b)
        union = len(a | b)
        return intersection / union if union > 0 else 0.0

    def _generate_cluster_name(self, features: list[str]) -> str:
        """Generate a human-readable cluster name from features."""
        actions = [f.split(":", 1)[1] for f in features if f.startswith("action:")]
        domains = [f.split(":", 1)[1] for f in features if f.startswith("domain:")]
        if actions and domains:
            return f"{actions[0]}_{domains[0]}"
        elif actions:
            return actions[0]
        elif domains:
            return domains[0]
        return "unknown"

    def get_insights(
        self,
        limit: int = 20,
        owner_key_hash: str | None = None,
    ) -> list[dict[str, Any]]:
        """Get learned insights including clusters."""
        owner = self._owner(owner_key_hash)
        with db_connection(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            pattern_rows = conn.execute(
                """
                SELECT pattern, frequency, success_rate
                FROM learned_patterns
                WHERE owner_key_hash = ?
                ORDER BY frequency DESC, success_rate DESC
                LIMIT ?
                """,
                (owner, limit),
            ).fetchall()
            cluster_rows = conn.execute(
                """
                SELECT cluster_name, keywords, interaction_count, success_rate, avg_latency_ms
                FROM intent_clusters
                WHERE owner_key_hash = ?
                ORDER BY interaction_count DESC
                LIMIT ?
                """,
                (owner, limit),
            ).fetchall()

        insights = []
        for r in pattern_rows:
            insights.append(
                {
                    "type": "pattern",
                    "pattern": r["pattern"],
                    "frequency": r["frequency"],
                    "success_rate": r["success_rate"],
                }
            )
        for r in cluster_rows:
            insights.append(
                {
                    "type": "cluster",
                    "name": r["cluster_name"],
                    "keywords": r["keywords"].split(","),
                    "count": r["interaction_count"],
                    "success_rate": r["success_rate"],
                    "avg_latency_ms": r["avg_latency_ms"],
                }
            )
        return insights

    def suggest_improvements(
        self,
        owner_key_hash: str | None = None,
    ) -> list[dict[str, Any]]:
        """Suggest improvements based on learned data with semantic context."""
        owner = self._owner(owner_key_hash)
        with db_connection(self.db_path) as conn:
            sr = conn.execute(
                "SELECT AVG(success) FROM interactions WHERE owner_key_hash = ?",
                (owner,),
            ).fetchone()[0]
            success_rate = float(sr) if sr is not None else 1.0
            al = conn.execute(
                "SELECT AVG(latency_ms) FROM interactions WHERE owner_key_hash = ?",
                (owner,),
            ).fetchone()[0]
            avg_latency = float(al) if al is not None else 0.0
            at = conn.execute(
                "SELECT AVG(tokens_used) FROM interactions WHERE owner_key_hash = ?",
                (owner,),
            ).fetchone()[0]
            avg_tokens = float(at) if at is not None else 0.0

            # Find low-performing clusters
            low_clusters = conn.execute(
                """
                SELECT cluster_name, success_rate, keywords
                FROM intent_clusters
                WHERE owner_key_hash = ?
                  AND success_rate < 0.7 AND interaction_count >= ?
                """,
                (owner, self.MIN_CLUSTER_SIZE),
            ).fetchall()

        suggestions = []
        if success_rate < 0.8:
            suggestions.append(
                {
                    "area": "success_rate",
                    "metric": success_rate,
                    "suggestion": "Consider adding more explicit instructions or breaking tasks into smaller steps",
                }
            )
        if avg_latency > 30000:
            suggestions.append(
                {
                    "area": "latency",
                    "metric": avg_latency,
                    "suggestion": "Tasks are taking too long, consider pre-caching common responses",
                }
            )
        if avg_tokens > 5000:
            suggestions.append(
                {
                    "area": "efficiency",
                    "metric": avg_tokens,
                    "suggestion": "High token usage detected, optimize prompts for conciseness",
                }
            )

        # Cluster-specific suggestions
        for name, rate, keywords in low_clusters:
            domain_terms = [
                k.split(":", 1)[1] for k in keywords.split(",") if k.startswith("domain:")
            ]
            action_terms = [
                k.split(":", 1)[1] for k in keywords.split(",") if k.startswith("action:")
            ]
            context = f"{action_terms[0] if action_terms else 'tasks'} involving {', '.join(domain_terms[:3])}"
            suggestions.append(
                {
                    "area": f"cluster:{name}",
                    "metric": rate,
                    "suggestion": f"Low success rate for {context}. Consider adding domain-specific examples or error handling.",
                    "keywords": keywords.split(","),
                }
            )

        return suggestions

    def get_stats(self, owner_key_hash: str | None = None) -> dict[str, Any]:
        """Get learning statistics."""
        owner = self._owner(owner_key_hash)
        with db_connection(self.db_path) as conn:
            total = conn.execute(
                "SELECT COUNT(*) FROM interactions WHERE owner_key_hash = ?",
                (owner,),
            ).fetchone()[0]
            patterns = conn.execute(
                "SELECT COUNT(*) FROM learned_patterns WHERE owner_key_hash = ?",
                (owner,),
            ).fetchone()[0]
            strategies = conn.execute(
                "SELECT COUNT(*) FROM strategy_adjustments WHERE owner_key_hash = ?",
                (owner,),
            ).fetchone()[0]
            clusters = conn.execute(
                "SELECT COUNT(*) FROM intent_clusters WHERE owner_key_hash = ?",
                (owner,),
            ).fetchone()[0]
        return {
            "total_interactions": total,
            "learned_patterns": patterns,
            "strategy_adjustments": strategies,
            "intent_clusters": clusters,
        }

    def prune(
        self,
        *,
        max_interactions: int = _DEFAULT_MAX_INTERACTIONS,
        max_patterns: int = _DEFAULT_MAX_PATTERNS,
        max_clusters: int = _DEFAULT_MAX_CLUSTERS,
        max_adjustments: int = _DEFAULT_MAX_ADJUSTMENTS,
    ) -> int:
        """Bound raw learning history while retaining the newest observations."""
        limits = {
            "max_interactions": max_interactions,
            "max_patterns": max_patterns,
            "max_clusters": max_clusters,
            "max_adjustments": max_adjustments,
        }
        for name, value in limits.items():
            if value < 0:
                raise ValueError(f"{name} must be non-negative")

        with db_connection(self.db_path) as conn:
            changes_before = conn.total_changes
            for table, order_by, limit in (
                ("interactions", "timestamp DESC, id DESC", max_interactions),
                ("learned_patterns", "last_seen DESC, id DESC", max_patterns),
                ("intent_clusters", "last_seen DESC, id DESC", max_clusters),
                (
                    "strategy_adjustments",
                    "applied_at DESC, id DESC",
                    max_adjustments,
                ),
            ):
                conn.execute(
                    f"""
                    DELETE FROM {table}
                    WHERE rowid IN (
                        SELECT rowid
                        FROM (
                            SELECT rowid,
                                   ROW_NUMBER() OVER (
                                       PARTITION BY owner_key_hash
                                       ORDER BY {order_by}
                                   ) AS owner_rank
                            FROM {table}
                        )
                        WHERE owner_rank > ?
                    )
                    """,
                    (limit,),
                )
                conn.execute(
                    f"""
                    DELETE FROM {table}
                    WHERE rowid IN (
                        SELECT rowid FROM {table}
                        ORDER BY {order_by}
                        LIMIT -1 OFFSET ?
                    )
                    """,
                    (limit * 10,),
                )
            conn.commit()
            return conn.total_changes - changes_before

    def generate_context_hint(
        self,
        user_input: str,
        owner_key_hash: str | None = None,
    ) -> str:
        """Generate a hint based on learned patterns for similar inputs."""
        features = self._extract_features(user_input)
        feature_set = set(features)
        owner = self._owner(owner_key_hash)

        with db_connection(self.db_path) as conn:
            hints = []
            # Check patterns
            for feature in features:
                row = conn.execute(
                    """
                    SELECT pattern, success_rate FROM learned_patterns
                    WHERE pattern = ? AND owner_key_hash = ? AND success_rate < 0.8
                    """,
                    (feature, owner),
                ).fetchone()
                if row:
                    hints.append(f"Previous '{row[0]}' tasks had {row[1] * 100:.0f}% success rate")

            # Check clusters
            rows = conn.execute(
                """
                SELECT cluster_name, keywords, success_rate FROM intent_clusters
                WHERE owner_key_hash = ?
                """,
                (owner,),
            ).fetchall()
            for name, keywords_str, rate in rows:
                if rate < 0.8:
                    cluster_features = set(keywords_str.split(","))
                    similarity = self._jaccard_similarity(feature_set, cluster_features)
                    if similarity >= self.CLUSTER_THRESHOLD:
                        hints.append(f"Similar '{name}' tasks had {rate * 100:.0f}% success rate")

        if hints:
            return "Learned insight: " + "; ".join(hints[:3])
        return ""

    def parse_feedback(self, feedback: str) -> dict[str, Any]:
        """Parse free-text feedback into structured signals."""
        feedback_lower = feedback.lower()
        signals: dict[str, Any] = {}

        # Latency signals
        latency_keywords = ["slow", "too long", "took too long", "fast", "quick", "speed"]
        if any(kw in feedback_lower for kw in latency_keywords):
            signals["latency_concern"] = True
            signals["latency_positive"] = "fast" in feedback_lower or "quick" in feedback_lower

        # Accuracy signals
        accuracy_keywords = ["wrong", "incorrect", "error", "mistake", "bug", "accurate", "correct"]
        if any(kw in feedback_lower for kw in accuracy_keywords):
            signals["accuracy_concern"] = True
            signals["accuracy_positive"] = bool(re.search(r"\baccurate\b", feedback_lower)) or bool(
                re.search(r"\bcorrect\b", feedback_lower)
            )

        # Clarity signals
        clarity_keywords = ["unclear", "confusing", "hard to understand", "clear", "easy to follow"]
        if any(kw in feedback_lower for kw in clarity_keywords):
            signals["clarity_concern"] = True
            signals["clarity_positive"] = "clear" in feedback_lower

        # Sentiment — use word boundaries to avoid matching substrings like "correct" inside "incorrect"
        positive_words = ["good", "great", "excellent", "perfect", "thanks", "helpful"]
        negative_words = [
            "bad",
            "terrible",
            "useless",
            "waste",
            "frustrating",
            "annoying",
            "slow",
            "incorrect",
        ]
        pos_count = sum(
            1 for w in positive_words if re.search(rf"\b{re.escape(w)}\b", feedback_lower)
        )
        neg_count = sum(
            1 for w in negative_words if re.search(rf"\b{re.escape(w)}\b", feedback_lower)
        )
        signals["sentiment_score"] = pos_count - neg_count

        return signals
