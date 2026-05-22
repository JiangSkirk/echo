"""Tests for natural-language cron parser."""

from __future__ import annotations

import pytest

from js.cron.nlp import _generate_summary, parse_natural_language, suggest_cron_examples


class TestParseNaturalLanguage:
    @pytest.mark.parametrize(
        ("text", "expected_cron"),
        [
            ("每天早上8点", "0 8 * * *"),
            ("每天上午9点", "0 9 * * *"),
            ("每天中午12点", "0 12 * * *"),
            ("每天下午6点", "0 18 * * *"),
            ("每天凌晨0点", "0 0 * * *"),
            ("every day at 8am", "0 8 * * *"),
            ("every day at 9am", "0 9 * * *"),
            ("daily", "0 9 * * *"),
            ("每小时", "0 * * * *"),
            ("hourly", "0 * * * *"),
            ("每周一", "0 9 * * 1"),
            ("every monday", "0 9 * * 1"),
            ("每周日", "0 9 * * 0"),
            ("每周", "0 9 * * 1"),
            ("每月", "0 9 1 * *"),
            ("工作日", "0 9 * * 1-5"),
            ("weekdays", "0 9 * * 1-5"),
            ("周末", "0 9 * * 0,6"),
            ("每1小时", "0 * * * *"),
            ("每2小时", "0 */2 * * *"),
            ("每6小时", "0 */6 * * *"),
            ("每12小时", "0 */12 * * *"),
        ],
    )
    def test_known_patterns(self, text: str, expected_cron: str) -> None:
        result = parse_natural_language(text)
        assert result is not None
        assert result["cron_expr"] == expected_cron

    @pytest.mark.parametrize(
        ("text", "expected_cron"),
        [
            ("每5分钟", "*/5 * * * *"),
            ("every 10 minutes", "*/10 * * * *"),
            ("每30分钟", "*/30 * * * *"),
        ],
    )
    def test_minute_intervals(self, text: str, expected_cron: str) -> None:
        result = parse_natural_language(text)
        assert result is not None
        assert result["cron_expr"] == expected_cron

    def test_no_match_returns_none(self) -> None:
        assert parse_natural_language("something completely unrelated") is None

    def test_minute_interval_out_of_range(self) -> None:
        """Intervals > 59 or < 1 should not match minute pattern."""
        assert parse_natural_language("每60分钟") is None
        assert parse_natural_language("每0分钟") is None


class TestGenerateSummary:
    def test_known_expressions(self) -> None:
        assert _generate_summary("0 8 * * *") == "每天上午 8:00"
        assert _generate_summary("0 9 * * *") == "每天上午 9:00"
        assert _generate_summary("0 * * * *") == "每小时"

    def test_unknown_expression(self) -> None:
        assert _generate_summary("*/5 * * * *") == "Cron: */5 * * * *"


class TestSuggestCronExamples:
    def test_returns_non_empty_list(self) -> None:
        examples = suggest_cron_examples()
        assert len(examples) > 0
        for ex in examples:
            assert "text" in ex
            assert "cron" in ex
            assert "summary" in ex
