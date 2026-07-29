"""Tests for metacognition loop."""

import sqlite3
from pathlib import Path

import pytest

from js.compression.feedback import CompressionFeedback
from js.evolution.learner import SelfLearner
from js.evolution.metacognition import MetacognitionLoop
from js.evolution.optimizer import PromptOptimizer


class TestMetacognitionLoop:
    @pytest.fixture
    def loop(self, tmp_path: Path) -> MetacognitionLoop:
        learner = SelfLearner(tmp_path)
        optimizer = PromptOptimizer(tmp_path)
        feedback = CompressionFeedback(tmp_path)
        return MetacognitionLoop(
            tmp_path,
            learner=learner,
            optimizer=optimizer,
            compression_feedback=feedback,
        )

    def test_init(self, loop: MetacognitionLoop) -> None:
        assert loop.learner is not None
        assert loop.optimizer is not None

    def test_tick_interval(self, loop: MetacognitionLoop) -> None:
        # Should not trigger before interval
        result = None
        for _ in range(MetacognitionLoop.DEFAULT_INTERVAL - 1):
            result = loop.tick()
        assert result is None

        # Should trigger at interval
        result = loop.tick()
        assert result is not None
        assert hasattr(result, "overall_health_score")

    def test_reflect(self, loop: MetacognitionLoop) -> None:
        report = loop.reflect()
        assert report.overall_health_score >= 0.0
        assert report.overall_health_score <= 1.0
        assert isinstance(report.proposals, list)

    def test_reflect_with_compression_issues(self, loop: MetacognitionLoop) -> None:
        # Record compressions followed by failures
        for i in range(10):
            loop.compression_feedback.record_compression(f"s{i}", 1000, 600, "full", 10, 5, 0)
            loop.compression_feedback.record_outcome(f"s{i}", 1, False)
        report = loop.reflect()
        compression_proposals = [p for p in report.proposals if p["area"] == "compression"]
        assert len(compression_proposals) > 0

    def test_reflect_with_learning_issues(self, loop: MetacognitionLoop) -> None:
        for _ in range(10):
            loop.learner.record_interaction("s1", "x", "y", [], success=False)
        report = loop.reflect()
        learning_proposals = [p for p in report.proposals if p["area"] == "learning"]
        assert len(learning_proposals) > 0

    def test_recent_reports(self, loop: MetacognitionLoop) -> None:
        loop.reflect()
        reports = loop.get_recent_reports(limit=5)
        assert len(reports) >= 1
        assert "health_score" in reports[0]

    def test_get_proposals(self, loop: MetacognitionLoop) -> None:
        loop.reflect()
        proposals = loop.get_proposals()
        assert isinstance(proposals, list)

    def test_prune_bounds_reports_and_their_proposals(self, loop: MetacognitionLoop) -> None:
        for _index in range(5):
            loop.reflect()
        with sqlite3.connect(loop.db_path) as conn:
            newest_report = conn.execute("SELECT MAX(id) FROM reports").fetchone()[0]
            conn.executemany(
                "INSERT INTO proposals (report_id, area, proposal) VALUES (?, 'test', ?)",
                ((newest_report, f"proposal-{index}") for index in range(5)),
            )

        removed = loop.prune(max_reports=2, max_proposals=3)

        assert removed >= 5
        with sqlite3.connect(loop.db_path) as conn:
            assert conn.execute("SELECT COUNT(*) FROM reports").fetchone()[0] == 2
            assert conn.execute("SELECT COUNT(*) FROM proposals").fetchone()[0] == 3
            assert (
                conn.execute(
                    """
                SELECT COUNT(*) FROM proposals
                WHERE report_id NOT IN (SELECT id FROM reports)
                """
                ).fetchone()[0]
                == 0
            )

    def test_prune_rejects_negative_report_limits(self, loop: MetacognitionLoop) -> None:
        with pytest.raises(ValueError, match="max_reports"):
            loop.prune(max_reports=-1)


class TestMetacognitionComposerIntegration:
    """Verify Phase 1 wiring: composer parameter and composition analysis."""

    def test_composer_parameter_accepted(self, tmp_path: Path) -> None:
        from unittest.mock import MagicMock

        composer = MagicMock()
        loop = MetacognitionLoop(
            tmp_path,
            composer=composer,
        )
        assert loop.composer is composer

    def test_reflect_includes_composition_analysis(self, tmp_path: Path) -> None:
        from unittest.mock import MagicMock

        composer = MagicMock()
        chain = MagicMock()
        chain.id = "auto_a_to_b"
        chain.name = "a → b"
        composer.discover_chains.return_value = [chain]

        loop = MetacognitionLoop(
            tmp_path,
            composer=composer,
        )
        report = loop.reflect()

        composer.discover_chains.assert_called_once_with(min_frequency=3)
        composition_actions = [a for a in report.actions_taken if a["area"] == "composition"]
        assert len(composition_actions) == 1
        assert composition_actions[0]["chain_id"] == "auto_a_to_b"
