"""Tests for compression quality feedback loop."""

import sqlite3
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

    def test_prune_bounds_all_feedback_histories(self, feedback: CompressionFeedback) -> None:
        for index in range(6):
            feedback.record_compression(f"s{index}", 1000, 600, "full", 10, 5)
            feedback.record_outcome(f"s{index}", index, True)
            feedback.apply_adjustment("protect_tail_turns", float(index), f"reason-{index}")

        removed = feedback.prune(
            max_events=2,
            max_outcomes=3,
            max_adjustments=1,
        )

        assert removed == 12
        with sqlite3.connect(feedback.db_path) as conn:
            assert conn.execute("SELECT COUNT(*) FROM compression_events").fetchone()[0] == 2
            assert conn.execute("SELECT COUNT(*) FROM task_outcomes").fetchone()[0] == 3
            assert conn.execute("SELECT COUNT(*) FROM parameter_adjustments").fetchone()[0] == 1

    def test_prune_rejects_negative_limits(self, feedback: CompressionFeedback) -> None:
        with pytest.raises(ValueError, match="max_events"):
            feedback.prune(max_events=-1)

    def test_feedback_analysis_and_statistics_are_owner_isolated(
        self, feedback: CompressionFeedback
    ) -> None:
        for index in range(4):
            feedback.record_compression(
                f"a-{index}",
                1000,
                600,
                "full",
                10,
                5,
                owner_key_hash="owner-a",
            )
            feedback.record_outcome(
                f"a-{index}",
                1,
                False,
                owner_key_hash="owner-a",
            )
        feedback.record_compression(
            "b-1",
            1000,
            600,
            "full",
            10,
            5,
            owner_key_hash="owner-b",
        )
        feedback.record_outcome(
            "b-1",
            1,
            True,
            owner_key_hash="owner-b",
        )

        assert feedback.analyze(owner_key_hash="owner-a")["suggestions"]
        assert feedback.analyze(owner_key_hash="owner-b")["suggestions"] == []
        assert feedback.get_stats(owner_key_hash="owner-a")["total_task_outcomes"] == 4
        assert feedback.get_stats(owner_key_hash="owner-b")["total_task_outcomes"] == 1

    def test_feedback_prune_applies_limits_independently_per_owner(
        self, feedback: CompressionFeedback
    ) -> None:
        for owner in ("owner-a", "owner-b"):
            for index in range(3):
                feedback.record_compression(
                    f"{owner}-{index}",
                    1000,
                    600,
                    "full",
                    10,
                    5,
                    owner_key_hash=owner,
                )
                feedback.record_outcome(
                    f"{owner}-{index}",
                    index,
                    True,
                    owner_key_hash=owner,
                )

        feedback.prune(max_events=1, max_outcomes=1, max_adjustments=1)

        assert feedback.get_stats(owner_key_hash="owner-a")["total_compression_events"] == 1
        assert feedback.get_stats(owner_key_hash="owner-b")["total_compression_events"] == 1

    def test_error_text_is_encrypted_at_rest(
        self, feedback: CompressionFeedback
    ) -> None:
        marker = "synthetic-private-compression-marker"
        feedback.record_outcome(
            "session",
            1,
            False,
            error_type=marker,
            owner_key_hash="owner-a",
        )

        with sqlite3.connect(feedback.db_path) as conn:
            error_type, owner = conn.execute(
                "SELECT error_type, owner_key_hash FROM task_outcomes"
            ).fetchone()
        assert marker not in error_type
        assert owner == "owner-a"

    def test_restart_encrypts_legacy_error_text(
        self, feedback: CompressionFeedback
    ) -> None:
        marker = "legacy-private-compression-marker"
        with sqlite3.connect(feedback.db_path) as conn:
            conn.execute(
                """
                INSERT INTO task_outcomes
                (session_id, turn_number, success, error_type, timestamp, owner_key_hash)
                VALUES ('session', 1, 0, ?, 1, 'owner-a')
                """,
                (marker,),
            )

        CompressionFeedback(feedback.state_dir)

        with sqlite3.connect(feedback.db_path) as conn:
            stored = conn.execute(
                "SELECT error_type FROM task_outcomes WHERE session_id = 'session'"
            ).fetchone()[0]
        assert marker not in stored
