"""Hermes-style config caching with stat-based hot reload."""

from __future__ import annotations

from pathlib import Path

from js.config import JSSettings
from js.utils.log import get_logger

logger = get_logger("js.config_cache")


class ConfigCache:
    """Caches config with filesystem stat checking to skip YAML re-parsing."""

    def __init__(self, config_path: Path | None = None) -> None:
        self.config_path = config_path
        self._cached_config: JSSettings | None = None
        self._cached_stat: tuple[float, int] | None = None  # (mtime_ns, size)

    def _get_stat(self, path: Path) -> tuple[float, int] | None:
        """Get filesystem stat for a path."""
        try:
            st = path.stat()
            return (st.st_mtime_ns, st.st_size)
        except (OSError, FileNotFoundError):
            return None

    def get(self, force_reload: bool = False) -> JSSettings:
        """Get config, reloading only if file changed."""
        path = self.config_path or self._find_config_path()

        if path is None:
            if self._cached_config is None:
                self._cached_config = JSSettings()
            return self._cached_config

        current_stat = self._get_stat(path)

        if not force_reload and self._cached_config is not None and self._cached_stat == current_stat:
            logger.debug("Config cache hit (stat unchanged)")
            return self._cached_config

        logger.debug(f"Config cache miss or file changed, reloading from {path}")
        self._cached_config = JSSettings.from_file(path)
        self._cached_stat = current_stat
        return self._cached_config

    def _find_config_path(self) -> Path | None:
        """Find the active config file."""
        for candidate in [
            Path.home() / ".config" / "js" / "config.yaml",
            Path.home() / ".config" / "js" / "config.toml",
        ]:
            if candidate.exists():
                return candidate
        return None

    def invalidate(self) -> None:
        """Force reload on next get()."""
        self._cached_stat = None
        logger.debug("Config cache invalidated")
