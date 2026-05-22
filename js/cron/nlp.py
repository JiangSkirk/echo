"""Natural-language schedule parser: 'every day at 8am' → cron expression."""

from __future__ import annotations

import re
from typing import Any

# Mapping of common time words to cron
_TIME_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # Exact times (中文时间表述中间可能没有空格，用 \s*)
    (re.compile(r"(?:每天|every\s+day)\s*(?:上午|早上|at)?\s*8\s*(?::00)?\s*(?:am|上午)?", re.I), "0 8 * * *"),
    (re.compile(r"(?:每天|every\s+day)\s*(?:上午|早上|at)?\s*9\s*(?::00)?\s*(?:am|上午)?", re.I), "0 9 * * *"),
    (re.compile(r"(?:每天|every\s+day)\s*(?:中午|at)?\s*12\s*(?::00)?\s*(?:pm|中午)?", re.I), "0 12 * * *"),
    (re.compile(r"(?:每天|every\s+day)\s*(?:下午|晚上|at)?\s*6\s*(?::00)?\s*(?:pm|下午)?", re.I), "0 18 * * *"),
    (re.compile(r"(?:每天|every\s+day)\s*(?:午夜|凌晨|at)?\s*0\s*(?::00)?\s*(?:am|午夜)?", re.I), "0 0 * * *"),
    (re.compile(r"(?:每天|every\s+day)\s*(?:午夜|凌晨|at)?\s*12\s*(?::00)?\s*(?:am|午夜)?", re.I), "0 0 * * *"),
    # Intervals
    (re.compile(r"(?:每|every\s+)1?\s*(?:小时|hourly)", re.I), "0 * * * *"),
    (re.compile(r"(?:每|every\s+)2\s*(?:小时|hours)", re.I), "0 */2 * * *"),
    (re.compile(r"(?:每|every\s+)6\s*(?:小时|hours)", re.I), "0 */6 * * *"),
    (re.compile(r"(?:每|every\s+)12\s*(?:小时|hours)", re.I), "0 */12 * * *"),
    # Daily/weekly shortcuts
    (re.compile(r"(?:每天|daily|every\s+day)", re.I), "0 9 * * *"),
    (re.compile(r"(?:每小时|hourly|every\s+hour)", re.I), "0 * * * *"),
    (re.compile(r"(?:每周一|every\s+monday|monday)", re.I), "0 9 * * 1"),
    (re.compile(r"(?:每周日|every\s+sunday|sunday)", re.I), "0 9 * * 0"),
    (re.compile(r"(?:每周|weekly|every\s+week)", re.I), "0 9 * * 1"),
    (re.compile(r"(?:每月|monthly|every\s+month)", re.I), "0 9 1 * *"),
    # Specific days
    (re.compile(r"(?:工作日|weekdays|every\s+weekday)", re.I), "0 9 * * 1-5"),
    (re.compile(r"(?:周末|weekends?)", re.I), "0 9 * * 0,6"),
]


def parse_natural_language(text: str) -> dict[str, Any] | None:
    """Parse a natural language schedule description into structured data.

    Returns a dict with 'cron_expr' and 'summary' keys, or None if no pattern matched.
    """
    text_lower = text.strip().lower()

    for pattern, cron_expr in _TIME_PATTERNS:
        if pattern.search(text):
            summary = _generate_summary(cron_expr)
            return {
                "cron_expr": cron_expr,
                "summary": summary,
                "matched_pattern": pattern.pattern[:50] + "...",
            }

    # Try numeric patterns: "every 5 minutes", "every 30 minutes"
    minute_match = re.search(r"(?:每|every)\s*(\d+)\s*(?:分钟|minutes?)", text_lower)
    if minute_match:
        mins = int(minute_match.group(1))
        if 1 <= mins <= 59:
            cron_expr = f"*/{mins} * * * *"
            return {
                "cron_expr": cron_expr,
                "summary": f"每 {mins} 分钟",
                "matched_pattern": "minute_interval",
            }

    return None


def _generate_summary(cron_expr: str) -> str:
    """Generate a human-readable summary for a cron expression."""
    summaries: dict[str, str] = {
        "0 8 * * *": "每天上午 8:00",
        "0 9 * * *": "每天上午 9:00",
        "0 12 * * *": "每天中午 12:00",
        "0 18 * * *": "每天下午 6:00",
        "0 0 * * *": "每天午夜",
        "0 * * * *": "每小时",
        "0 */2 * * *": "每 2 小时",
        "0 */6 * * *": "每 6 小时",
        "0 */12 * * *": "每 12 小时",
        "0 9 * * 1": "每周一上午 9:00",
        "0 9 * * 0": "每周日上午 9:00",
        "0 9 1 * *": "每月 1 日上午 9:00",
        "0 9 * * 1-5": "每个工作日上午 9:00",
        "0 9 * * 0,6": "每周末上午 9:00",
    }
    return summaries.get(cron_expr, f"Cron: {cron_expr}")


def suggest_cron_examples() -> list[dict[str, str]]:
    """Return a list of example natural-language inputs and their cron outputs."""
    return [
        {"text": "每天早上8点", "cron": "0 8 * * *", "summary": "每天上午 8:00"},
        {"text": "每小时", "cron": "0 * * * *", "summary": "每小时"},
        {"text": "每周一上午9点", "cron": "0 9 * * 1", "summary": "每周一上午 9:00"},
        {"text": "每天午夜", "cron": "0 0 * * *", "summary": "每天午夜"},
        {"text": "每30分钟", "cron": "*/30 * * * *", "summary": "每 30 分钟"},
        {"text": "工作日每天早上9点", "cron": "0 9 * * 1-5", "summary": "每个工作日上午 9:00"},
        {"text": "每周日晚上", "cron": "0 21 * * 0", "summary": "每周日晚上 9:00"},
    ]
