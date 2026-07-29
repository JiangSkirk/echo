"""Tests for self-learning evolution system."""

import sqlite3
from pathlib import Path

import pytest

from js.evolution.learner import SelfLearner
from js.evolution.optimizer import PromptOptimizer


class TestSelfLearner:
    @pytest.fixture
    def learner(self, tmp_path: Path) -> SelfLearner:
        return SelfLearner(tmp_path)

    def test_record_and_stats(self, learner: SelfLearner) -> None:
        learner.record_interaction("s1", "hello", "hi", [], success=True)
        learner.record_interaction("s1", "help", "ok", [], success=False)
        stats = learner.get_stats()
        assert stats["total_interactions"] == 2

    def test_insights(self, learner: SelfLearner) -> None:
        learner.record_interaction("s1", "write python code", "done", [], success=True)
        insights = learner.get_insights()
        assert len(insights) > 0

    def test_suggest_improvements(self, learner: SelfLearner) -> None:
        for _i in range(10):
            learner.record_interaction("s1", "x", "y", [], success=False)
        suggestions = learner.suggest_improvements()
        assert len(suggestions) > 0

    def test_context_hint(self, learner: SelfLearner) -> None:
        learner.record_interaction("s1", "python code", "ok", [], success=True)
        hint = learner.generate_context_hint("python code")
        assert isinstance(hint, str)

    def test_prune_bounds_raw_and_derived_learning_history(self, learner: SelfLearner) -> None:
        for index in range(8):
            learner.record_interaction(
                f"s{index}",
                f'write python "entity-{index}"',
                "ok",
                [],
                success=True,
            )
        with sqlite3.connect(learner.db_path) as conn:
            for index in range(5):
                conn.execute(
                    """
                    INSERT INTO strategy_adjustments
                    (context, old_strategy, new_strategy, improvement, applied_at)
                    VALUES (?, 'old', 'new', 1.0, ?)
                    """,
                    (f"context-{index}", float(index)),
                )

        removed = learner.prune(
            max_interactions=3,
            max_patterns=1,
            max_clusters=2,
            max_adjustments=2,
        )

        assert removed > 0
        with sqlite3.connect(learner.db_path) as conn:
            assert conn.execute("SELECT COUNT(*) FROM interactions").fetchone()[0] == 3
            assert conn.execute("SELECT COUNT(*) FROM learned_patterns").fetchone()[0] == 1
            assert conn.execute("SELECT COUNT(*) FROM intent_clusters").fetchone()[0] <= 2
            assert conn.execute("SELECT COUNT(*) FROM strategy_adjustments").fetchone()[0] == 2

    def test_prune_rejects_negative_limits(self, learner: SelfLearner) -> None:
        with pytest.raises(ValueError, match="max_interactions"):
            learner.prune(max_interactions=-1)

    def test_learning_hints_and_statistics_are_owner_isolated(self, learner: SelfLearner) -> None:
        for index in range(4):
            learner.record_interaction(
                f"a-{index}",
                "write python code",
                "failed",
                [],
                success=False,
                owner_key_hash="owner-a",
            )
        learner.record_interaction(
            "b-1",
            "write rust code",
            "ok",
            [],
            success=True,
            owner_key_hash="owner-b",
        )

        assert "Previous" in learner.generate_context_hint(
            "write python code",
            owner_key_hash="owner-a",
        )
        assert (
            learner.generate_context_hint(
                "write python code",
                owner_key_hash="owner-b",
            )
            == ""
        )
        assert learner.get_stats(owner_key_hash="owner-a")["total_interactions"] == 4
        assert learner.get_stats(owner_key_hash="owner-b")["total_interactions"] == 1

    def test_learning_prune_applies_limits_independently_per_owner(
        self, learner: SelfLearner
    ) -> None:
        for owner in ("owner-a", "owner-b"):
            for index in range(4):
                learner.record_interaction(
                    f"{owner}-{index}",
                    f'write python "{owner}-{index}"',
                    "ok",
                    [],
                    owner_key_hash=owner,
                )

        learner.prune(
            max_interactions=2,
            max_patterns=3,
            max_clusters=2,
            max_adjustments=2,
        )

        assert learner.get_stats(owner_key_hash="owner-a")["total_interactions"] == 2
        assert learner.get_stats(owner_key_hash="owner-b")["total_interactions"] == 2

    def test_interaction_text_is_encrypted_at_rest(self, learner: SelfLearner) -> None:
        marker = "synthetic-private-learning-marker"
        learner.record_interaction(
            "session",
            marker,
            f"answer-{marker}",
            [],
            feedback=f"feedback-{marker}",
            owner_key_hash="owner-a",
        )

        with sqlite3.connect(learner.db_path) as conn:
            row = conn.execute(
                """
                SELECT user_input, agent_output, feedback, owner_key_hash
                FROM interactions
                """
            ).fetchone()
        assert row is not None
        assert marker not in " ".join(str(value) for value in row[:3])
        assert row[3] == "owner-a"

    def test_restart_encrypts_legacy_text_and_removes_unsafe_features(
        self, learner: SelfLearner
    ) -> None:
        marker = "legacy-private-learning-marker"
        with sqlite3.connect(learner.db_path) as conn:
            conn.execute(
                """
                INSERT INTO interactions
                (id, session_id, user_input, agent_output, tool_calls, success,
                 feedback, latency_ms, tokens_used, timestamp, owner_key_hash)
                VALUES ('legacy', 'session', ?, ?, '[]', 1, ?, 0, 0, 1, 'owner-a')
                """,
                (marker, marker, marker),
            )
            conn.execute(
                """
                INSERT INTO learned_patterns
                (pattern_type, pattern, first_seen, last_seen, owner_key_hash)
                VALUES ('feature', ?, 1, 1, 'owner-a')
                """,
                (f"entity:{marker}",),
            )

        SelfLearner(learner.state_dir)

        with sqlite3.connect(learner.db_path) as conn:
            stored = conn.execute(
                "SELECT user_input, agent_output, feedback FROM interactions WHERE id = 'legacy'"
            ).fetchone()
            unsafe_count = conn.execute(
                "SELECT COUNT(*) FROM learned_patterns WHERE pattern LIKE 'entity:%'"
            ).fetchone()[0]
        assert stored is not None
        assert marker not in " ".join(stored)
        assert unsafe_count == 0


class TestPromptOptimizer:
    @pytest.fixture
    def optimizer(self, tmp_path: Path) -> PromptOptimizer:
        return PromptOptimizer(tmp_path)

    def test_register_and_select(self, optimizer: PromptOptimizer) -> None:
        v1 = optimizer.register_variant("ctx", "Prompt A")
        v2 = optimizer.register_variant("ctx", "Prompt B")

        optimizer.record_result(v1, True, 0.9)
        optimizer.record_result(v2, False, 0.3)

        best = optimizer.get_best_prompt("ctx")
        assert best == "Prompt A"

    @pytest.mark.asyncio
    async def test_optimize_cycle(self, optimizer: PromptOptimizer) -> None:
        result = await optimizer.optimize_cycle("ctx", "Base prompt")
        assert isinstance(result, str)

    def test_report(self, optimizer: PromptOptimizer) -> None:
        report = optimizer.get_report()
        assert "total_variants" in report

    def test_prune_bounds_prompt_results_and_variants(self, optimizer: PromptOptimizer) -> None:
        variants = [
            optimizer.register_variant("ctx", f"Prompt variant {index}") for index in range(4)
        ]
        for index in range(12):
            optimizer.record_result(variants[index % len(variants)], True, 1.0)

        removed = optimizer.prune(
            max_results=3,
            max_variants_per_context=2,
            max_variants_total=2,
        )

        assert removed > 0
        with sqlite3.connect(optimizer.db_path) as conn:
            assert conn.execute("SELECT COUNT(*) FROM prompt_results").fetchone()[0] <= 3
            assert conn.execute("SELECT COUNT(*) FROM prompt_variants").fetchone()[0] == 2
            retained_results = conn.execute("SELECT COUNT(*) FROM prompt_results").fetchone()[0]
            usage_count = conn.execute(
                "SELECT COALESCE(SUM(usage_count), 0) FROM prompt_variants"
            ).fetchone()[0]
        assert usage_count == retained_results

    def test_prune_rejects_negative_prompt_limits(self, optimizer: PromptOptimizer) -> None:
        with pytest.raises(ValueError, match="max_results"):
            optimizer.prune(max_results=-1)
