"""Tests for LLM-powered evolution core."""

from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest

from js.evolution.learner import SelfLearner
from js.evolution.optimizer import PromptOptimizer
from js.skills.evolver import SkillEvolver


class TestSkillEvolverLLM:
    @pytest.fixture
    def evolver(self, tmp_path: Path) -> SkillEvolver:
        return SkillEvolver(tmp_path)

    def test_create_variant(self, evolver: SkillEvolver) -> None:
        v = evolver.create_variant("test_skill", "def main(): pass", "auto", [])
        assert v.skill_id == "test_skill"
        assert "main" in v.code

    def test_record_result_and_select_best(self, evolver: SkillEvolver) -> None:
        v1 = evolver.create_variant("s1", "code1", "p1", [])
        v2 = evolver.create_variant("s1", "code2", "p2", [])
        evolver.record_result(v1.id, True, 0.9)
        evolver.record_result(v1.id, True, 0.9)
        evolver.record_result(v2.id, False, 0.3)
        best = evolver.select_best_variant("s1")
        assert best is not None
        assert best.code == "code1"

    @pytest.mark.asyncio
    async def test_generate_improved_code_without_llm(self, evolver: SkillEvolver) -> None:
        result = await evolver.generate_improved_code("s1", "def main(): pass", "test feedback")
        assert "Auto-evolved" in result

    @pytest.mark.asyncio
    async def test_generate_improved_code_with_llm(self, evolver: SkillEvolver) -> None:
        async def fake_llm(prompt: str) -> str:
            return "def main():\n    return 42"

        result = await evolver.generate_improved_code("s1", "def main(): pass", "fix it", fake_llm)
        assert "def main" in result

    @pytest.mark.asyncio
    async def test_generate_improved_code_propagates_llm_failure_when_requested(
        self, evolver: SkillEvolver
    ) -> None:
        async def failing_llm(prompt: str) -> str:
            raise RuntimeError("provider unavailable")

        with pytest.raises(RuntimeError, match="provider unavailable"):
            await evolver.generate_improved_code(
                "s1",
                "def main(): pass",
                "fix it",
                failing_llm,
                propagate_llm_errors=True,
            )

    def test_should_evolve_low_success(self, evolver: SkillEvolver) -> None:
        v = evolver.create_variant("s1", "code", "prompt", [])
        for _ in range(10):
            evolver.record_result(v.id, False, 0.1)
        assert evolver.should_evolve("s1")

    def test_should_not_evolve_high_success(self, evolver: SkillEvolver) -> None:
        v = evolver.create_variant("s1", "code", "prompt", [])
        for _ in range(10):
            evolver.record_result(v.id, True, 0.9)
        assert not evolver.should_evolve("s1")

    def test_should_evolve_many_uses_one_database_connection(
        self,
        evolver: SkillEvolver,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import js.skills.evolver as evolver_module

        low = evolver.create_variant("low", "code", "prompt", [])
        high = evolver.create_variant("high", "code", "prompt", [])
        for _ in range(10):
            evolver.record_result(low.id, False, 0.1)
            evolver.record_result(high.id, True, 0.9)

        original_connection = evolver_module.db_connection
        connection_count = 0

        @contextmanager
        def counting_connection(*args: Any, **kwargs: Any):
            nonlocal connection_count
            connection_count += 1
            with original_connection(*args, **kwargs) as conn:
                yield conn

        monkeypatch.setattr(evolver_module, "db_connection", counting_connection)

        assert evolver.should_evolve_many(["low", "high", "missing"]) == {"low"}
        assert connection_count == 1

    def test_evolution_report(self, evolver: SkillEvolver) -> None:
        v = evolver.create_variant("s1", "code", "prompt", [])
        evolver.record_result(v.id, True, 0.8)
        report = evolver.get_evolution_report("s1")
        assert report["skill_id"] == "s1"
        assert report["total_variants"] >= 1


class TestPromptOptimizerLLM:
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

    def test_epsilon_greedy_selection(self, optimizer: PromptOptimizer) -> None:
        optimizer.register_variant("ctx", "Prompt A")
        optimizer.register_variant("ctx", "Prompt B")
        selected = optimizer.select_variant("ctx")
        assert selected is not None
        assert selected[1] in ("Prompt A", "Prompt B")

    @pytest.mark.asyncio
    async def test_generate_variant_without_llm(self, optimizer: PromptOptimizer) -> None:
        result = await optimizer.generate_variant("ctx", "Base prompt")
        assert isinstance(result, str)
        # Variant may be same length if word_replace mutation is chosen and no match
        assert len(result) >= len("Base prompt")

    @pytest.mark.asyncio
    async def test_generate_variant_with_llm(self, optimizer: PromptOptimizer) -> None:
        async def fake_llm(prompt: str) -> str:
            return (
                "VARIANT 1 [add_constraint]: Be concise. Base prompt.\n"
                "VARIANT 2 [add_example]: For example: foo. Base prompt."
            )

        result = await optimizer.generate_variant("ctx", "Base prompt", fake_llm)
        assert isinstance(result, str)

    @pytest.mark.asyncio
    async def test_optimize_cycle(self, optimizer: PromptOptimizer) -> None:
        result = await optimizer.optimize_cycle("ctx", "Base prompt")
        assert isinstance(result, str)

    def test_report(self, optimizer: PromptOptimizer) -> None:
        report = optimizer.get_report()
        assert "total_variants" in report


class TestSelfLearnerSemantic:
    @pytest.fixture
    def learner(self, tmp_path: Path) -> SelfLearner:
        return SelfLearner(tmp_path)

    def test_record_and_stats(self, learner: SelfLearner) -> None:
        learner.record_interaction("s1", "hello", "hi", [], success=True)
        learner.record_interaction("s1", "help", "ok", [], success=False)
        stats = learner.get_stats()
        assert stats["total_interactions"] == 2

    def test_semantic_features(self, learner: SelfLearner) -> None:
        learner.record_interaction("s1", "write python code for data analysis", "done", [], success=True)
        insights = learner.get_insights()
        assert len(insights) > 0
        # Should have action:write and domain:python features
        feature_insights = [i for i in insights if i.get("type") == "pattern"]
        assert any("action:write" in i["pattern"] for i in feature_insights)
        assert any("domain:python" in i["pattern"] for i in feature_insights)

    def test_clustering(self, learner: SelfLearner) -> None:
        # Record multiple similar interactions to form a cluster
        for _ in range(5):
            learner.record_interaction("s1", "write python script", "ok", [], success=True)
        stats = learner.get_stats()
        assert stats["intent_clusters"] >= 1

    def test_suggest_improvements(self, learner: SelfLearner) -> None:
        for _ in range(10):
            learner.record_interaction("s1", "x", "y", [], success=False)
        suggestions = learner.suggest_improvements()
        assert len(suggestions) > 0

    def test_context_hint(self, learner: SelfLearner) -> None:
        learner.record_interaction("s1", "python code", "ok", [], success=True)
        hint = learner.generate_context_hint("python script")
        assert isinstance(hint, str)

    def test_parse_feedback(self, learner: SelfLearner) -> None:
        signals = learner.parse_feedback("The response was too slow and incorrect")
        assert signals.get("latency_concern") is True
        assert signals.get("accuracy_concern") is True
        assert signals.get("sentiment_score", 0) < 0

    def test_parse_positive_feedback(self, learner: SelfLearner) -> None:
        signals = learner.parse_feedback("Great job, very accurate and fast!")
        assert signals.get("accuracy_positive") is True
        assert signals.get("sentiment_score", 0) > 0
