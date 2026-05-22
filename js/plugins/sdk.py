"""Plugin SDK — minimal interface for third-party extensions."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any


class PluginStatus(StrEnum):
    DISCOVERED = "discovered"    # Found on disk, not loaded
    LOADED = "loaded"            # Python module imported
    ENABLED = "enabled"          # Active and running
    DISABLED = "disabled"        # Loaded but inactive
    ERROR = "error"              # Failed to load


@dataclass
class PluginManifest:
    """Metadata for a plugin, read from plugin.json or __init__.py."""

    id: str
    name: str = ""
    version: str = "0.1.0"
    description: str = ""
    author: str = ""
    license: str = "MIT"
    homepage: str = ""
    min_agent_version: str = "0.1.0"
    categories: list[str] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    # Entry point
    entry_point: str = "plugin:Plugin"  # module:ClassName

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PluginManifest:
        return cls(
            id=data.get("id", ""),
            name=data.get("name", data.get("id", "")),
            version=data.get("version", "0.1.0"),
            description=data.get("description", ""),
            author=data.get("author", ""),
            license=data.get("license", "MIT"),
            homepage=data.get("homepage", ""),
            min_agent_version=data.get("min_agent_version", "0.1.0"),
            categories=data.get("categories", []),
            dependencies=data.get("dependencies", []),
            tags=data.get("tags", []),
            entry_point=data.get("entry_point", "plugin:Plugin"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "author": self.author,
            "license": self.license,
            "homepage": self.homepage,
            "min_agent_version": self.min_agent_version,
            "categories": self.categories,
            "dependencies": self.dependencies,
            "tags": self.tags,
            "entry_point": self.entry_point,
        }


@dataclass
class PluginContext:
    """Runtime context passed to a plugin during setup."""

    agent: Any  # JSAgent instance
    settings: Any  # JSSettings
    plugin_dir: Path
    data_dir: Path  # Plugin-private persistent storage
    logger: Any


@dataclass
class ToolContribution:
    """A tool contributed by a plugin."""

    name: str
    description: str
    parameters: dict[str, Any] = field(default_factory=dict)
    dangerous: bool = False
    handler: Callable[..., Any] | None = None


@dataclass
class SkillContribution:
    """A skill contributed by a plugin."""

    spec: Any  # SkillSpec


@dataclass
class HookContribution:
    """A hook contributed by a plugin."""

    event: str  # e.g. "before_tool_call", "after_agent_response"
    handler: Callable[..., Any]
    priority: int = 0  # Higher = earlier


class JSPlugin:
    """Base class for all JS Agent plugins.

    Minimal example:
        class MyPlugin(JSPlugin):
            manifest = PluginManifest(id="my-plugin", name="My Plugin")

            def setup(self, ctx: PluginContext) -> None:
                ctx.logger.info("MyPlugin loaded!")

            def get_tools(self) -> list[ToolContribution]:
                return [ToolContribution(name="my_tool", description="...")]
    """

    manifest: PluginManifest

    def __init__(self) -> None:
        pass

    def setup(self, ctx: PluginContext) -> None:
        """Called once when the plugin is enabled."""
        pass

    def teardown(self) -> None:
        """Called when the plugin is disabled or the agent shuts down."""
        pass

    def get_tools(self) -> list[ToolContribution]:
        """Return tools contributed by this plugin."""
        return []

    def get_skills(self) -> list[SkillContribution]:
        """Return skills contributed by this plugin."""
        return []

    def get_hooks(self) -> list[HookContribution]:
        """Return event hooks contributed by this plugin."""
        return []

    def health(self) -> dict[str, Any]:
        """Return health status for observability."""
        return {"status": "ok"}
