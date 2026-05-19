"""Tests for compression quality feedback loop."""

from pathlib import Path

import pytest

from js.compression.feedback import CompressionFeedback


class TestCompressionFeedback:
    @pytest.fixture
    def feedback(self, tmp_path: Path) -> CompressionFeedback:
        return CompressionFeedback(tmp_path)

    def test_record_and_stats(self, feedback: CompressionFeedback) -> None:
        feedback.record_compression("s1", 1000, 700, "full", 10, 5, 3)
        feedback.record_outcome("s1", 1, True)
        stats = feedback.get_stats()
        assert stats["total_compression_events"] == 1
        assert stats["total_task_outcomes"] == 1

    def test_analyze_empty(self, feedback: CompressionFeedback) -> None:
        analysis = feedback.analyze()
        assert analysis["total_events"] == 0

    def test_analyze_with_data(self, feedback: CompressionFeedback) -> None:
        feedback.record_compression("s1", 1000, 700, "full", 10, 5, 3)
        feedback.record_outcome("s1", 1, True)
        feedback.record_outcome("s1", 2, True)
        analysis = feedback.analyze()
        assert analysis["total_events"] == 1

    def test_adjustment_recommendations(self, feedback: CompressionFeedback) -> None:
        # Record many compressions followed by failures
        for i in range(10):
            feedback.record_compression(f"s{i}", 1000, 600, "full", 10, 5, 0)
            feedback.record_outcome(f"s{i}", 1, False)
        recs = feedback.get_adjustment_recommendations()
        assert "needs_adjustment" in recs

    def test_apply_adjustment(self, feedback: CompressionFeedback) -> None:
        feedback.apply_adjustment("protect_tail_turns", 8, "testing")
        stats = feedback.get_stats()
        assert stats["total_adjustments"] == 1
