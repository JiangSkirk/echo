"""Regression tests for cron expression hardening.

Covers two audited issues in js/cron/engine.py:
- Out-of-bounds field values (e.g. the month range ``1-20000000``, measured at
  +1.7GB RSS during parsing) must be rejected with ValueError instead of being
  silently expanded into giant in-memory sets.
- day_of_week matching must follow the cron convention 0=Sunday (previously
  datetime.weekday()'s Monday=0 was used directly, shifting weekly jobs by one
  day and making Sunday schedules never fire).
"""

from __future__ import annotations

from datetime import datetime

import pytest

from js.cron.engine import CronExpression


class TestCronFieldBounds:
    """Out-of-range values and ranges raise ValueError at parse time."""

    @pytest.mark.parametrize(
        "expr",
        [
            "60 * * * *",  # minute > 59
            "* 24 * * *",  # hour > 23
            "0 0 0 * *",  # day_of_month < 1
            "0 0 32 * *",  # day_of_month > 31
            "0 0 * 13 *",  # month > 12
            "0 0 * * 7",  # day_of_week > 6
            "0-60 * * * *",  # range end above max
            "0 0 * 0-12 *",  # range start below min
            "5-1 * * * *",  # inverted range
            "*/0 * * * *",  # zero step
            "1-10/0 * * * *",  # zero step with explicit range
            "*/-1 * * * *",  # negative step
        ],
    )
    def test_out_of_bounds_values_raise(self, expr: str) -> None:
        with pytest.raises(ValueError):
            CronExpression(expr)

    def test_audited_memory_bomb_range_raises_before_expansion(self) -> None:
        """The audited DoS expression must fail fast with a clear error."""
        with pytest.raises(ValueError, match="out of range"):
            CronExpression("0 0 * 1-20000000 *")

    def test_out_of_bounds_step_range_raises(self) -> None:
        with pytest.raises(ValueError, match="out of range"):
            CronExpression("0 1-99 * * *")

    @pytest.mark.parametrize(
        "expr",
        [
            "* * * * *",
            "59 23 31 12 6",  # all boundary maxima
            "0 0 1 1 0",  # all boundary minima
            "0 9 * * 0",  # Sunday
            "0 9 * * 1-5",  # weekdays
            "0 9 * * 0,6",  # weekend
            "*/15 0-23/2 1-31 1-12 0-6",
            "@weekly",
            "@daily",
        ],
    )
    def test_valid_expressions_still_parse(self, expr: str) -> None:
        cron = CronExpression(expr)
        assert all(name in cron.fields for name in CronExpression.FIELD_NAMES)


class TestDayOfWeekMapping:
    """day_of_week uses the cron convention 0=Sunday..6=Saturday."""

    def test_sunday_schedule_matches_sunday(self) -> None:
        cron = CronExpression("0 9 * * 0")
        # 2024-01-07 was a Sunday; datetime.weekday() reports 6 for it.
        sunday = datetime(2024, 1, 7, 9, 0)
        assert sunday.weekday() == 6
        assert cron._matches(sunday)
        # Monday (weekday() == 0) must NOT match a Sunday schedule.
        assert not cron._matches(datetime(2024, 1, 8, 9, 0))

    def test_monday_schedule_matches_monday(self) -> None:
        cron = CronExpression("0 9 * * 1")
        monday = datetime(2024, 1, 8, 9, 0)
        assert monday.weekday() == 0
        assert cron._matches(monday)
        assert not cron._matches(datetime(2024, 1, 7, 9, 0))  # Sunday

    def test_saturday_schedule_matches_saturday(self) -> None:
        cron = CronExpression("0 9 * * 6")
        saturday = datetime(2024, 1, 6, 9, 0)
        assert saturday.weekday() == 5
        assert cron._matches(saturday)
        assert not cron._matches(datetime(2024, 1, 7, 9, 0))  # Sunday

    def test_weekend_range_matches_sat_and_sun_only(self) -> None:
        cron = CronExpression("0 9 * * 0,6")
        assert cron._matches(datetime(2024, 1, 6, 9, 0))  # Saturday
        assert cron._matches(datetime(2024, 1, 7, 9, 0))  # Sunday
        assert not cron._matches(datetime(2024, 1, 5, 9, 0))  # Friday

    def test_next_run_for_sunday_schedule_lands_on_sunday(self) -> None:
        cron = CronExpression("0 9 * * 0")
        monday = datetime(2024, 1, 8, 10, 0).timestamp()
        nxt = cron.next_run(after=monday)
        assert nxt is not None
        nxt_dt = datetime.fromtimestamp(nxt)
        assert nxt_dt.weekday() == 6  # Sunday
        assert (nxt_dt.year, nxt_dt.month, nxt_dt.day) == (2024, 1, 14)
        assert (nxt_dt.hour, nxt_dt.minute) == (9, 0)
