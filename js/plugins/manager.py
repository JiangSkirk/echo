"""Plugin manager: discovery, loading, lifecycle, and hook dispatch."""

from __future__ import annotations

import importlib.util
import json
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
        self._user_plugin_dir = Path.home() / ".js" / "plugins"
        self._builtin_plugin_dir = Path(__file__).parent / "builtin"
        self._data_dir = Path.home() / ".js" / "plugin_data"
        self._data_dir.mkdir(parents=True, exist_ok=True)
        self._user_plugin_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------------

    def discover(self) -> list[PluginRecord]:
        """Scan plugin directories and discover available plugins."""
        discovered: list[PluginRecord] = []
        for root in [self._builtin_plugin_dir, self._user_plugin_dir]:
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

            # Security scan before loading (skip for builtin plugins)
            if not record.source_dir.name.startswith("builtin") and not str(record.source_dir).endswith("builtin"):
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

    def install_from_url(self, url: str) -> dict[str, Any]:
        """Download and install a plugin from a remote URL.

        Supports .zip and .tar.gz archives. The archive must contain a
        plugin.json manifest at its root (or in a single subdirectory).
        """
        import shutil
        import tarfile
        import tempfile
        import urllib.parse
        import urllib.request
        import zipfile

        result: dict[str, Any] = {"success": False, "plugin_id": None, "message": ""}

        # Parse URL to guess plugin id
        parsed = urllib.parse.urlparse(url)
        basename = Path(parsed.path).name or "plugin"
        guessed_id = basename.split(".")[0].replace("-", "_")

        # Download to temp file
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".download") as tmp:
                tmp_path = Path(tmp.name)
                urllib.request.urlretrieve(url, tmp_path)
        except Exception as e:
            result["message"] = f"下载失败: {e}"
            return result

        # Extract to temp dir
        try:
            extract_dir = Path(tempfile.mkdtemp(prefix="js_plugin_"))
            if basename.endswith(".tar.gz") or basename.endswith(".tgz"):
                with tarfile.open(tmp_path, "r:gz") as tf:
                    tf.extractall(extract_dir)
            elif basename.endswith(".zip"):
                with zipfile.ZipFile(tmp_path, "r") as zf:
                    zf.extractall(extract_dir)
            else:
                # Try zip first, then tar.gz
                try:
                    with zipfile.ZipFile(tmp_path, "r") as zf:
                        zf.extractall(extract_dir)
                except zipfile.BadZipFile:
                    with tarfile.open(tmp_path, "r:gz") as tf:
                        tf.extractall(extract_dir)
        except Exception as e:
            result["message"] = f"解压失败: {e}"
            shutil.rmtree(extract_dir, ignore_errors=True)
            tmp_path.unlink(missing_ok=True)
            return result
        finally:
            tmp_path.unlink(missing_ok=True)

        # Find plugin directory (may be nested one level)
        plugin_dirs = [d for d in extract_dir.iterdir() if d.is_dir() and not d.name.startswith(".")]
        if not plugin_dirs:
            result["message"] = "插件包为空"
            shutil.rmtree(extract_dir, ignore_errors=True)
            return result
        source_dir = plugin_dirs[0] if len(plugin_dirs) == 1 else extract_dir

        # Validate manifest
        manifest_path = source_dir / "plugin.json"
        if not manifest_path.exists():
            result["message"] = "缺少 plugin.json manifest 文件"
            shutil.rmtree(extract_dir, ignore_errors=True)
            return result

        try:
            data = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest = PluginManifest.from_dict(data)
            plugin_id = manifest.id or guessed_id
        except Exception as e:
            result["message"] = f"manifest 解析失败: {e}"
            shutil.rmtree(extract_dir, ignore_errors=True)
            return result

        # Check for duplicate
        if plugin_id in self._plugins:
            result["message"] = f"插件 '{plugin_id}' 已存在，请先卸载"
            shutil.rmtree(extract_dir, ignore_errors=True)
            return result

        # Security scan all .py files
        try:
            from js.plugins.security import scan_plugin_file
            py_files = list(source_dir.rglob("*.py"))
            for py_file in py_files:
                scan_result = scan_plugin_file(plugin_id, py_file)
                if scan_result.blocked:
                    result["message"] = (
                        f"安全扫描未通过: {scan_result.risk_flags}"
                    )
                    shutil.rmtree(extract_dir, ignore_errors=True)
                    return result
        except Exception as e:
            result["message"] = f"安全扫描失败: {e}"
            shutil.rmtree(extract_dir, ignore_errors=True)
            return result

        # Move to user plugin dir
        target_dir = self._user_plugin_dir / plugin_id
        try:
            if target_dir.exists():
                shutil.rmtree(target_dir)
            shutil.move(str(source_dir), str(target_dir))
            shutil.rmtree(extract_dir, ignore_errors=True)
        except Exception as e:
            result["message"] = f"安装失败: {e}"
            shutil.rmtree(extract_dir, ignore_errors=True)
            return result

        # Discover, load, enable
        record = self._discover_from_dir(target_dir)
        if not record:
            result["message"] = "插件发现失败"
            return result
        self._plugins[record.manifest.id] = record

        if self.enable(record.manifest.id):
            result["success"] = True
            result["plugin_id"] = record.manifest.id
            result["message"] = f"插件 '{record.manifest.id}' 安装并启用成功"
        else:
            result["success"] = True
            result["plugin_id"] = record.manifest.id
            result["message"] = f"插件 '{record.manifest.id}' 已安装但启用失败: {record.error}"

        return result

    def uninstall(self, plugin_id: str) -> dict[str, Any]:
        """Uninstall a plugin: disable + remove files."""
        result: dict[str, Any] = {"success": False, "message": ""}
        record = self._plugins.get(plugin_id)
        if not record:
            result["message"] = f"插件 '{plugin_id}' 不存在"
            return result

        # Disable first
        self.disable(plugin_id)
        self.unload(plugin_id)

        # Remove from registry
        del self._plugins[plugin_id]

        # Remove files if in user plugin dir (never delete builtin)
        if (
            not record.source_dir.name.startswith("builtin")
            and not str(record.source_dir).endswith("builtin")
        ):
            try:
                import shutil
                shutil.rmtree(record.source_dir, ignore_errors=True)
            except Exception as e:
                result["message"] = f"已禁用但文件删除失败: {e}"
                return result

        result["success"] = True
        result["message"] = f"插件 '{plugin_id}' 已卸载"
        return result


import asyncio  # noqa: E402
