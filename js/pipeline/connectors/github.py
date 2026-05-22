"""GitHub connector via REST API."""

from __future__ import annotations

from datetime import UTC, datetime

from js.pipeline.connector import Connector, ConnectorResult


class GitHubConnector(Connector):
    """Fetch recent issues, PRs, and discussions from GitHub."""

    @property
    def name(self) -> str:
        return "github"

    async def fetch(self) -> ConnectorResult:
        if self.config.mock_mode:
            return ConnectorResult(
                source=self.name,
                fetched_at=datetime.now(UTC),
                items=[
                    {
                        "id": "mock_gh_42",
                        "title": "[PR #42] Refactor auth middleware",
                        "content": (
                            "## Refactor auth middleware\n\n"
                            "### Changes\n"
                            "- Extract JWT validation to `AuthGuard`\n"
                            "- Add refresh-token rotation\n"
                            "- Update tests\n\n"
                            "### Review comments\n"
                            "- **alice**: LGTM, one nit on naming\n"
                            "- **bob**: Please add metrics hook\n"
                        ),
                        "url": "https://github.com/acme/app/pull/42",
                        "created_at": datetime.now(UTC).isoformat(),
                        "updated_at": datetime.now(UTC).isoformat(),
                        "metadata": {"repo": "acme/app", "type": "pull_request", "state": "open"},
                    },
                    {
                        "id": "mock_gh_99",
                        "title": "[Issue #99] Memory leak in worker pool",
                        "content": (
                            "## Memory leak in worker pool\n\n"
                            "**Description**\n"
                            "Under high load the worker pool leaks ~50MB/hour.\n\n"
                            "**Repro**\n"
                            "1. Start 100 concurrent jobs\n"
                            "2. Let run for 2 hours\n"
                            "3. Observe RSS growth\n\n"
                            "**Expected**: Stable memory\n"
                            "**Actual**: Linear growth\n"
                        ),
                        "url": "https://github.com/acme/app/issues/99",
                        "created_at": datetime.now(UTC).isoformat(),
                        "updated_at": datetime.now(UTC).isoformat(),
                        "metadata": {"repo": "acme/app", "type": "issue", "state": "open"},
                    },
                ],
            )

        # TODO: Implement GitHub API via httpx (issues, PRs, notifications)
        return ConnectorResult(source=self.name, fetched_at=datetime.now(UTC), items=[])

    async def health_check(self) -> bool:
        return self.config.mock_mode or bool(self.config.api_key or self.config.token)
