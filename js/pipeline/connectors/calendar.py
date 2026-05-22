"""Google Calendar connector via Calendar API."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from js.pipeline.connector import Connector, ConnectorResult


class CalendarConnector(Connector):
    """Fetch upcoming and recent calendar events."""

    @property
    def name(self) -> str:
        return "calendar"

    async def fetch(self) -> ConnectorResult:
        if self.config.mock_mode:
            now = datetime.now(UTC)
            return ConnectorResult(
                source=self.name,
                fetched_at=now,
                items=[
                    {
                        "id": "mock_cal_1",
                        "title": "Sprint Planning",
                        "content": (
                            f"# Sprint Planning\n\n"
                            f"- **Time**: {(now + timedelta(hours=2)).strftime('%Y-%m-%d %H:%M')} UTC\n"
                            f"- **Duration**: 1 hour\n"
                            f"- **Attendees**: Alice, Bob, Carol\n"
                            f"- **Agenda**:\n"
                            f"  1. Review last sprint\n"
                            f"  2. Estimate new stories\n"
                            f"  3. Assign owners\n"
                        ),
                        "url": "https://calendar.google.com/event/mock1",
                        "created_at": now.isoformat(),
                        "updated_at": now.isoformat(),
                        "metadata": {"calendar": "primary", "event_type": "meeting"},
                    },
                    {
                        "id": "mock_cal_2",
                        "title": "1:1 with Manager",
                        "content": (
                            f"# 1:1 with Manager\n\n"
                            f"- **Time**: {(now + timedelta(days=1)).strftime('%Y-%m-%d %H:%M')} UTC\n"
                            f"- **Duration**: 30 min\n"
                            f"- **Attendees**: You, Manager\n"
                            f"- **Notes**: Discuss career growth and Q3 goals\n"
                        ),
                        "url": "https://calendar.google.com/event/mock2",
                        "created_at": now.isoformat(),
                        "updated_at": now.isoformat(),
                        "metadata": {"calendar": "primary", "event_type": "meeting"},
                    },
                ],
            )

        # TODO: Implement Calendar events.list via httpx / google-auth
        return ConnectorResult(source=self.name, fetched_at=datetime.now(UTC), items=[])

    async def health_check(self) -> bool:
        return self.config.mock_mode or bool(self.config.credentials_path)
