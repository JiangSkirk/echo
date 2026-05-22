"""External data connectors for the Auto-Fetch Memory Pipeline."""

from js.pipeline.connectors.calendar import CalendarConnector
from js.pipeline.connectors.drive import DriveConnector
from js.pipeline.connectors.file import FileConnector
from js.pipeline.connectors.github import GitHubConnector
from js.pipeline.connectors.gmail import GmailConnector
from js.pipeline.connectors.notion import NotionConnector
from js.pipeline.connectors.slack import SlackConnector

__all__ = [
    "CalendarConnector",
    "DriveConnector",
    "FileConnector",
    "GmailConnector",
    "GitHubConnector",
    "NotionConnector",
    "SlackConnector",
]
