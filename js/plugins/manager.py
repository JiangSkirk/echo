"""Plugin manager: discovery, loading, lifecycle, and hook dispatch."""

from __future__ import annotations

import importlib.util
import json
import os
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from js.plugins.sdk import (
    HookContribution,
    JSPlugin,
    PluginContext,
    PluginManifest,
    PluginStatus,
)
from js.utils.log import get_logger

logger = get_logger("js.plugins")


class PluginRecord:
    """Runtime record of a plugin instance."""

    def __init__(self, manifest: PluginManifest, source_dir: Path) -> None:
        self.manifest = manifest
        self.source_dir = source_dir
        self.status = PluginStatus.DISCOVERED
        self.instance: JSPlugin | None = None
        self.error: str = ""
        self._tools: list[Any] = []
        self._skills: list[Any] = []
        self._hooks: list[HookContribution] = []

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.manifest.id,
            "name": self.manifest.name,
            "version": self.manifest.version,
            "description": self.manifest.description,
            "author": self.manifest.author,
            "status": self.status,
            "error": self.error,
            "categories": self.manifest.categories,
            "tags": self.manifest.tags,
            "tools_count": len(self._tools),
            "skills_count": len(self._skills),
            "hooks_count": len(self._hooks),
        }


class PluginManager:
    """Manages plugin lifecycle: discover → load → enable → disable → unload."""

    def __init__(self, agent: Any, settings: Any) -> None:
        self.agent = agent
        self.settings = settings
        self._plugins: dict[str, PluginRecord] = {}
        self._hooks: dict[str, list[tuple[int, Callable[..., Any]]]] = {}
        state_dir = Path(settings.state_dir).expanduser().resolve()
        self._user_plugin_dir = state_dir / "plugins"
        self._builtin_plugin_dir = Path(__file__).parent / "builtin"
        self._data_dir = state_dir / "plugin_data"
        self._data_dir.mkdir(parents=True, exist_ok=True)
        self._user_plugin_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------------

    def discover(self) -> list[PluginRecord]:
        """Scan plugin directories and discover available plugins."""
        discovered: list[PluginRecord] = []
        # Executable Python extensions are limited to the reviewed files
        # shipped in the release artifact. User directories are not imported.
        for root in [self._builtin_plugin_dir]:
            if not root.exists():
                continue
            for entry in root.iterdir():
                if not entry.is_dir() or entry.name.startswith("_") or entry.name.startswith("."):
                    continue
                record = self._discover_from_dir(entry)
                if record:
                    discovered.append(record)
                    self._plugins[record.manifest.id] = record
        logger.info(f"Discovered {len(discovered)} plugins")
        return discovered

    def _discover_from_dir(self, plugin_dir: Path) -> PluginRecord | None:
        """Try to read manifest from a plugin directory."""
        # Try plugin.json first
        manifest_path = plugin_dir / "plugin.json"
        if manifest_path.exists():
            try:
                data = json.loads(manifest_path.read_text(encoding="utf-8"))
                manifest = PluginManifest.from_dict(data)
                if not manifest.id:
                    manifest.id = plugin_dir.name
                return PluginRecord(manifest, plugin_dir)
            except Exception as e:
                logger.warning(f"Failed to parse manifest in {plugin_dir}: {e}")
                return None

        # Fallback: use directory name with defaults
        manifest = PluginManifest(id=plugin_dir.name, name=plugin_dir.name)
        return PluginRecord(manifest, plugin_dir)

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def load(self, plugin_id: str) -> bool:
        """Import the plugin module and instantiate the plugin class."""
        record = self._plugins.get(plugin_id)
        if not record:
            logger.warning(f"Plugin not found: {plugin_id}")
            return False
        if not self._is_builtin_record(record):
            logger.warning("External Python plugin load denied: %s", plugin_id)
            return False
        if record.status in (PluginStatus.LOADED, PluginStatus.ENABLED):
            return True

        try:
            module_name = f"js.plugins.runtime.{plugin_id}"
            entry = record.manifest.entry_point
            if ":" in entry:
                module_rel, class_name = entry.split(":", 1)
            else:
                module_rel, class_name = entry, "Plugin"

            plugin_file = record.source_dir / f"{module_rel}.py"
            if not plugin_file.exists():
                plugin_file = record.source_dir / module_rel / "__init__.py"

            # Security scan before loading (skip only for actual builtin plugins)
            try:
                resolved_source = record.source_dir.resolve()
                resolved_builtin = self._builtin_plugin_dir.resolve()
                is_builtin = resolved_source == resolved_builtin or str(
                    resolved_source
                ).startswith(str(resolved_builtin) + os.sep)
            except (OSError, ValueError):
                is_builtin = False

            if not is_builtin:
                from js.plugins.security import scan_plugin_file

                scan_result = scan_plugin_file(plugin_id, plugin_file)
                if scan_result.blocked:
                    raise RuntimeError(
                        f"Plugin '{plugin_id}' blocked by security scan: {scan_result.risk_flags}"
                    )
                if scan_result.risk_flags:
                    logger.warning(
                        f"Plugin '{plugin_id}' loaded with warnings: {scan_result.risk_flags}"
                    )

            spec = importlib.util.spec_from_file_location(module_name, plugin_file)
            if not spec or not spec.loader:
                raise RuntimeError(f"Cannot load module from {plugin_file}")
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)

            plugin_class = getattr(module, class_name, None)
            if plugin_class is None:
                raise RuntimeError(f"Class '{class_name}' not found in {plugin_file}")

            instance = plugin_class()
            if not hasattr(instance, "manifest"):
                instance.manifest = record.manifest

            record.instance = instance
            record.status = PluginStatus.LOADED
            logger.info(f"Plugin loaded: {plugin_id}")
            return True
        except Exception as e:
            record.status = PluginStatus.ERROR
            record.error = str(e)
            logger.error(f"Failed to load plugin {plugin_id}: {e}", exc_info=True)
            return False

    def unload(self, plugin_id: str) -> bool:
        """Unload a plugin."""
        record = self._plugins.get(plugin_id)
        if not record:
            return False
        if record.instance:
            try:
                record.instance.teardown()
            except Exception as e:
                logger.warning(f"Plugin {plugin_id} teardown error: {e}")
            record.instance = None
        record._tools.clear()
        record._skills.clear()
        self._remove_hooks(plugin_id)
        record.status = PluginStatus.DISCOVERED
        return True

    # ------------------------------------------------------------------
    # Enable / Disable
    # ------------------------------------------------------------------

    def enable(self, plugin_id: str) -> bool:
        """Enable a plugin: load + setup + register contributions."""
        record = self._plugins.get(plugin_id)
        if not record:
            return False
        if not self._is_builtin_record(record):
            logger.warning("External Python plugin enable denied: %s", plugin_id)
            return False
        if record.status == PluginStatus.ENABLED:
            return True

        if not self.load(plugin_id):
            return False
        assert record.instance is not None
        try:
            from js.utils.log import get_logger
            ctx = PluginContext(
                agent=self.agent,
                settings=self.settings,
                plugin_dir=record.source_dir,
                data_dir=self._data_dir / plugin_id,
                logger=get_logger(f"js.plugins.{plugin_id}"),
            )
            record.instance.setup(ctx)

            # Register contributions
            record._tools = record.instance.get_tools()
            record._skills = record.instance.get_skills()
            record._hooks = record.instance.get_hooks()
            for hook in record._hooks:
                self._register_hook(plugin_id, hook)

            record.status = PluginStatus.ENABLED
            logger.info(
                f"Plugin enabled: {plugin_id} "
                f"(+{len(record._tools)} tools, +{len(record._skills)} skills, +{len(record._hooks)} hooks)"
            )
            return True
        except Exception as e:
            record.status = PluginStatus.ERROR
            record.error = str(e)
            logger.error(f"Failed to enable plugin {plugin_id}: {e}", exc_info=True)
            return False

    def _is_builtin_record(self, record: PluginRecord) -> bool:
        try:
            source = record.source_dir.resolve()
            builtin = self._builtin_plugin_dir.resolve()
            source.relative_to(builtin)
        except (OSError, RuntimeError, ValueError):
            return False
        return source != builtin

    def disable(self, plugin_id: str) -> bool:
        """Disable a plugin: teardown + unregister contributions."""
        record = self._plugins.get(plugin_id)
        if not record:
            return False
        if record.status != PluginStatus.ENABLED:
            return True

        if record.instance:
            try:
                record.instance.teardown()
            except Exception as e:
                logger.warning(f"Plugin {plugin_id} teardown error: {e}")

        self._remove_hooks(plugin_id)
        record._tools.clear()
        record._skills.clear()
        record.status = PluginStatus.DISABLED
        logger.info(f"Plugin disabled: {plugin_id}")
        return True

    # ------------------------------------------------------------------
    # Hooks
    # ------------------------------------------------------------------

    def _register_hook(self, plugin_id: str, hook: HookContribution) -> None:
        event = hook.event
        if event not in self._hooks:
            self._hooks[event] = []
        self._hooks[event].append((hook.priority, hook.handler))
        self._hooks[event].sort(key=lambda x: -x[0])  # Higher priority first

    def _remove_hooks(self, plugin_id: str) -> None:
        # Remove all hooks from this plugin (simple heuristic: clear all and re-register)
        # In a production system we'd track ownership per handler.
        self._hooks.clear()
        for rec in self._plugins.values():
            if rec.status == PluginStatus.ENABLED and rec.instance:
                for hook in rec.instance.get_hooks():
                    self._register_hook(rec.manifest.id, hook)

    async def dispatch_hook(self, event: str, **kwargs: Any) -> list[Any]:
        """Dispatch an event to all registered hooks."""
        results: list[Any] = []
        for _priority, handler in self._hooks.get(event, []):
            try:
                if asyncio.iscoroutinefunction(handler):
                    result = await handler(**kwargs)
                else:
                    result = handler(**kwargs)
                results.append(result)
            except Exception as e:
                logger.warning(f"Hook error for event '{event}': {e}")
        return results

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def list_plugins(self) -> list[PluginRecord]:
        return list(self._plugins.values())

    def get_plugin(self, plugin_id: str) -> PluginRecord | None:
        return self._plugins.get(plugin_id)

    def get_all_tools(self) -> list[Any]:
        tools: list[Any] = []
        for rec in self._plugins.values():
            if rec.status == PluginStatus.ENABLED:
                tools.extend(rec._tools)
        return tools

    def get_all_skills(self) -> list[Any]:
        skills: list[Any] = []
        for rec in self._plugins.values():
            if rec.status == PluginStatus.ENABLED:
                skills.extend(rec._skills)
        return skills

    def health(self) -> dict[str, Any]:
        return {
            "total": len(self._plugins),
            "enabled": sum(1 for p in self._plugins.values() if p.status == PluginStatus.ENABLED),
            "disabled": sum(1 for p in self._plugins.values() if p.status == PluginStatus.DISABLED),
            "error": sum(1 for p in self._plugins.values() if p.status == PluginStatus.ERROR),
            "plugins": [p.to_dict() for p in self._plugins.values()],
        }

    # ------------------------------------------------------------------
    # Remote Install / Uninstall
    # ------------------------------------------------------------------

    def install_from_url(self, url: str, expected_hash: str | None = None) -> dict[str, Any]:
        """Fail closed: executable remote Python extensions are unsupported."""
        del url, expected_hash
        return {
            "success": False,
            "plugin_id": None,
            "message": (
                "Remote Python plugin installation is disabled; only reviewed "
                "plugins shipped in the release artifact may run"
            ),
        }

    def uninstall(self, plugin_id: str) -> dict[str, Any]:
        """Fail closed: release-shipped Python plugins are immutable."""
        del plugin_id
        return {
            "success": False,
            "message": "Plugin removal is disabled for release-shipped plugins",
        }




import asyncio  # noqa: E402
