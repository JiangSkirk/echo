"""Google Drive connector via Drive API."""

from __future__ import annotations

from datetime import UTC, datetime

from js.pipeline.connector import Connector, ConnectorResult


class DriveConnector(Connector):
    """Fetch recent documents from Google Drive."""

    @property
    def name(self) -> str:
        return "drive"

    async def fetch(self) -> ConnectorResult:
        if self.config.mock_mode:
            return ConnectorResult(
                source=self.name,
                fetched_at=datetime.now(UTC),
                items=[
                    {
                        "id": "mock_drive_1",
                        "title": "Q3 OKRs",
                        "content": (
                            "# Q3 OKRs\n\n"
                            "## Objective 1: Scale Platform\n"
                            "- KR1: 99.99% uptime\n"
                            "- KR2: <200ms p99 latency\n"
                            "- KR3: Support 10k concurrent users\n\n"
                            "## Objective 2: Developer Velocity\n"
                            "- KR1: CI pipeline <5 min\n"
                            "- KR2: 90% test coverage\n"
                        ),
                        "url": "https://drive.google.com/file/d/mock1/view",
                        "created_at": datetime.now(UTC).isoformat(),
                        "updated_at": datetime.now(UTC).isoformat(),
                        "metadata": {"mimeType": "application/vnd.google-apps.document", "folder": "Strategy"},
                    },
                ],
            )

        # TODO: Implement Drive files.list + export via httpx / google-auth
        return ConnectorResult(source=self.name, fetched_at=datetime.now(UTC), items=[])

    async def health_check(self) -> bool:
        return self.config.mock_mode or bool(self.config.credentials_path)
