"""Exception hierarchy for JS Agent.

All expected failures should raise a subclass of AgentError.
Unexpected exceptions propagate up to the framework/entrypoint.
"""

from __future__ import annotations


class AgentError(Exception):
    """Base for all agent-expected errors."""

    pass


class AuthRequiredError(AgentError):
    """API key is missing or invalid."""

    pass
