"""Exception hierarchy for JS Agent.

All expected failures should raise a subclass of AgentError.
Unexpected exceptions propagate up to the framework/entrypoint.
"""

from __future__ import annotations


class AgentError(Exception):
    """Base for all agent-expected errors."""

    pass


class ConfigError(AgentError):
    """Invalid configuration or settings."""

    pass


class RouterError(AgentError):
    """Model routing or provider failure."""

    pass


class ToolError(AgentError):
    """Tool execution failure."""

    pass


class ToolExecutionError(ToolError):
    """A tool raised an exception during execution."""

    pass


class ToolNotFoundError(ToolError):
    """Requested tool does not exist in the registry."""

    pass


class ToolBlockedError(ToolError):
    """Tool execution was blocked by security policy."""

    pass


class SecurityError(AgentError):
    """Security policy violation."""

    pass


class SecurityBlockedError(SecurityError):
    """Operation was blocked by the behavior guard."""

    pass


class SkillError(AgentError):
    """Skill lifecycle or execution failure."""

    pass


class SkillInstallError(SkillError):
    """Failed to install a skill."""

    pass


class SkillExecutionError(SkillError):
    """Failed to execute a skill."""

    pass


class MemoryError(AgentError):
    """Memory store operation failure."""

    pass


class MemoryNotFoundError(MemoryError):
    """Requested memory entry does not exist."""

    pass


class ProviderError(AgentError):
    """Model provider API failure."""

    pass


class ProviderUnavailableError(ProviderError):
    """No healthy provider available for the requested model."""

    pass


class AuthError(AgentError):
    """Authentication or authorization failure."""

    pass


class AuthRequiredError(AuthError):
    """API key is missing or invalid."""

    pass


class AuthForbiddenError(AuthError):
    """Authenticated but not authorized for this operation."""

    pass


class CronError(AgentError):
    """Cron scheduling or execution failure."""

    pass


class PluginError(AgentError):
    """Plugin lifecycle or execution failure."""

    pass


class PluginBlockedError(PluginError):
    """Plugin was blocked by security scan."""

    pass


class ValidationError(AgentError):
    """Input validation failure."""

    pass


class CancelledByUserError(AgentError):
    """Operation was cancelled by user request."""

    pass
