"""Plugin system for JS Agent — discover, load, and manage third-party extensions."""

from __future__ import annotations

from js.plugins.manager import PluginManager
from js.plugins.sdk import (
    HookContribution,
    JSPlugin,
    PluginContext,
    SkillContribution,
    ToolContribution,
)

__all__ = [
    "JSPlugin",
    "PluginContext",
    "ToolContribution",
    "SkillContribution",
    "HookContribution",
    "PluginManager",
]
