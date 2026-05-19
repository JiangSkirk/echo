"""Tests for self-learning evolution system."""

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
