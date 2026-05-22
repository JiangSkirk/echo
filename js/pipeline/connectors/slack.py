"""Slack connector via Web API."""

from __future__ import annotations

from datetime import UTC, datetime

from js.pipeline.connector import Connector, ConnectorResult


class SlackConnector(Connector):
    """Fetch recent messages from Slack channels."""

    @property
    def name(self) -> str:
        return "slack"

    async def fetch(self) -> ConnectorResult:
        if self.config.mock_mode:
            return ConnectorResult(
                source=self.name,
                fetched_at=datetime.now(UTC),
                items=[
                    {
                        "id": "mock_slack_1",
                        "title": "#engineering – Architecture decisions",
                        "content": (
                            "**alice** [09:00]:\n"
                            "> We decided to go with PostgreSQL over MySQL for the new service.\n\n"
                            "**bob** [09:05]:\n"
                            "> Agreed. I'll update the ADR doc.\n\n"
                            "**carol** [09:12]:\n"
                            "> Please also update the runbook with connection-pool settings.\n"
                        ),
                        "url": "https://acme.slack.com/archives/C123/mock1",
                        "created_at": datetime.now(UTC).isoformat(),
                        "updated_at": datetime.now(UTC).isoformat(),
                        "metadata": {"channel": "engineering", "authors": ["alice", "bob", "carol"]},
                    },
                ],
            )

        # TODO: Implement Slack conversations.history via httpx
        return ConnectorResult(source=self.name, fetched_at=datetime.now(UTC), items=[])

    async def health_check(self) -> bool:
        return self.config.mock_mode or bool(self.config.token)
