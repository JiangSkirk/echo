"""Notion connector via Notion API."""

from __future__ import annotations

from datetime import UTC, datetime

from js.pipeline.connector import Connector, ConnectorResult


class NotionConnector(Connector):
    """Fetch recently updated pages from a Notion workspace."""

    @property
    def name(self) -> str:
        return "notion"

    async def fetch(self) -> ConnectorResult:
        if self.config.mock_mode:
            return ConnectorResult(
                source=self.name,
                fetched_at=datetime.now(UTC),
                items=[
                    {
                        "id": "mock_notion_1",
                        "title": "Product Requirements",
                        "content": (
                            "# Product Requirements\n\n"
                            "## Goals\n"
                            "- Launch v2 by Q2\n"
                            "- Reduce churn by 15%\n\n"
                            "## Non-goals\n"
                            "- Mobile app (Q3+)\n"
                        ),
                        "url": "https://notion.so/mock-page-1",
                        "created_at": datetime.now(UTC).isoformat(),
                        "updated_at": datetime.now(UTC).isoformat(),
                        "metadata": {"workspace": "Acme Corp", "parent": "Engineering"},
                    },
                ],
            )

        # TODO: Implement Notion API pagination via httpx
        return ConnectorResult(source=self.name, fetched_at=datetime.now(UTC), items=[])

    async def health_check(self) -> bool:
        return self.config.mock_mode or bool(self.config.api_key)
