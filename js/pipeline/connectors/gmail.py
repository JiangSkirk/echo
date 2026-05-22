"""Gmail connector via IMAP or Gmail API."""

from __future__ import annotations

from datetime import UTC, datetime

from js.pipeline.connector import Connector, ConnectorResult


class GmailConnector(Connector):
    """Fetch recent emails from Gmail.

    Config:
        api_key  – OAuth2 access token or app password
        extra['query'] – Gmail search query (e.g. "is:unread")
        extra['imap_server'] – fallback IMAP host
    """

    @property
    def name(self) -> str:
        return "gmail"

    async def fetch(self) -> ConnectorResult:
        if self.config.mock_mode:
            return ConnectorResult(
                source=self.name,
                fetched_at=datetime.now(UTC),
                items=[
                    {
                        "id": "mock_email_1",
                        "title": "[Mock] Project Update",
                        "content": (
                            "From: alice@example.com\n"
                            "Subject: Project Update\n\n"
                            "Hey team,\n\n"
                            "The Q3 roadmap is finalized. Please review the attached doc.\n\n"
                            "- Alice"
                        ),
                        "url": "https://mail.google.com/mail/u/0/#inbox/mock1",
                        "created_at": datetime.now(UTC).isoformat(),
                        "updated_at": datetime.now(UTC).isoformat(),
                        "metadata": {"from": "alice@example.com", "labels": ["INBOX"]},
                    },
                    {
                        "id": "mock_email_2",
                        "title": "[Mock] Meeting Notes",
                        "content": (
                            "From: bob@example.com\n"
                            "Subject: Meeting Notes – Architecture Review\n\n"
                            "Attendees: Alice, Bob, Carol\n"
                            "Decisions:\n"
                            "- Move to microservices\n"
                            "- Adopt Kafka for events\n"
                            "Action items:\n"
                            "- Bob: Draft RFC by Friday\n"
                        ),
                        "url": "https://mail.google.com/mail/u/0/#inbox/mock2",
                        "created_at": datetime.now(UTC).isoformat(),
                        "updated_at": datetime.now(UTC).isoformat(),
                        "metadata": {"from": "bob@example.com", "labels": ["INBOX"]},
                    },
                ],
            )

        # Real implementation would use Gmail API via httpx / google-auth
        # TODO: Implement OAuth2 flow and API calls
        return ConnectorResult(source=self.name, fetched_at=datetime.now(UTC), items=[])

    async def health_check(self) -> bool:
        if self.config.mock_mode:
            return True
        return bool(self.config.api_key or self.config.token)
