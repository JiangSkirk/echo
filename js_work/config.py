"""Configuration helpers for the JS Agent Work product line."""

from __future__ import annotations

import os
import tomllib
from pathlib import Path
from typing import Any

from pydantic import Field, PrivateAttr, field_validator, model_validator
from pydantic_settings import SettingsConfigDict

from js.config import (
    AgentFeatureConfig,
    JSSettings,
    PipelineConfig,
    SecurityConfig,
    _ensure_private_directory,
    _normalise_echo_engine,
)
from js.product_storage import (
    StorageRoots,
    assert_disjoint,
    assert_work_path_not_in_personal_namespace,
)

_MAIN_AGENT_HOME_NAME = ".js"
_WORK_PRODUCT_ID = "js-work"


def default_work_home(home: Path | None = None) -> Path:
    """Return the JS Agent Work home directory."""
    return (home or Path.home()) / ".js-work"


def default_work_config_path(home: Path | None = None) -> Path:
    """Return the default JS Agent Work config path."""
    return (home or Path.home()) / ".config" / "js-work" / "config.yaml"


def work_feature_config() -> AgentFeatureConfig:
    """Feature gates for Work: no skills, no evolution, no plugins, no daemon."""
    return AgentFeatureConfig(
        plugins_enabled=False,
        skills_enabled=False,
        skill_tools_enabled=False,
        hermes_skills_enabled=False,
        evolution_enabled=False,
        pipeline_enabled=False,
        daemon_enabled=False,
    )


def _resolve_path(path: Path | str) -> Path:
    return Path(path).expanduser().resolve()


def _is_main_agent_root_or_inside(path: Path) -> bool:
    """True if *path* is a ``.js`` main-agent root or lives inside one."""
    resolved = _resolve_path(path)
    for candidate in (resolved, *resolved.parents):
        if candidate.name == _MAIN_AGENT_HOME_NAME:
            return True
    return False


def _path_within(child: Path, parent: Path) -> bool:
    child_r = _resolve_path(child)
    parent_r = _resolve_path(parent)
    return child_r == parent_r or child_r.is_relative_to(parent_r)


class WorkSettings(JSSettings):
    """Independent settings for the JS Agent Work product line.

    Inherits field definitions from :class:`JSSettings` for call-site
    compatibility, but uses a separate env namespace, product identity,
    home layout, and fail-closed isolation from the main ``~/.js`` agent.
    """

    model_config = SettingsConfigDict(
        env_prefix="JS_WORK_",
        env_nested_delimiter="__",
        extra="ignore",
    )

    product_id: str = Field(default=_WORK_PRODUCT_ID)
    work_home: Path = Field(default_factory=lambda: Path.home() / ".js-work")
    workspace: Path = Field(default_factory=lambda: Path.home() / ".js-work" / "workspace")
    state_dir: Path = Field(default_factory=lambda: Path.home() / ".js-work" / "state")
    security: SecurityConfig = Field(
        default_factory=lambda: SecurityConfig(
            api_key_required=True,
            allow_private_model_providers=False,
        )
    )
    _personal_roots: StorageRoots | None = PrivateAttr(default=None)

    @field_validator("product_id")
    @classmethod
    def product_id_is_fixed(cls, value: str) -> str:
        if value != _WORK_PRODUCT_ID:
            raise ValueError(
                f"product_id is fixed to {_WORK_PRODUCT_ID!r} for WorkSettings, got {value!r}"
            )
        return value

    def _validate_work_isolation(self) -> None:
        """Raise on product identity or path isolation violations (no disk I/O)."""
        if self.product_id != _WORK_PRODUCT_ID:
            raise ValueError(f"product_id is fixed to {_WORK_PRODUCT_ID!r} for WorkSettings")

        for label, path in (
            ("work_home", self.work_home),
            ("workspace", self.workspace),
            ("state_dir", self.state_dir),
        ):
            if _is_main_agent_root_or_inside(path):
                raise ValueError(
                    f"WorkSettings {label} must not overlap a main-agent "
                    f"{_MAIN_AGENT_HOME_NAME!r} root: {path}"
                )

        if not _path_within(self.workspace, self.work_home):
            raise ValueError(
                f"WorkSettings workspace must be located within work_home "
                f"({self.work_home}), got {self.workspace}"
            )
        if not _path_within(self.state_dir, self.work_home):
            raise ValueError(
                f"WorkSettings state_dir must be located within work_home "
                f"({self.work_home}), got {self.state_dir}"
            )

    @model_validator(mode="after")
    def enforce_work_isolation(self) -> WorkSettings:
        """Fail closed on product identity and path isolation (no disk writes)."""
        self._validate_work_isolation()
        return self

    @model_validator(mode="after")
    def ensure_directories(self) -> WorkSettings:
        """Override parent: validate isolation first, mkdir only if valid.

        Parent :meth:`JSSettings.ensure_directories` creates workspace/state
        unconditionally. Work must fail closed so invalid ``.js`` paths are
        never created on disk.
        """
        self._validate_work_isolation()
        _ensure_private_directory(self.work_home, label="Work storage root")
        _ensure_private_directory(self.workspace, label="Work workspace")
        _ensure_private_directory(self.state_dir, label="Work state directory")
        return self

    def apply_runtime_engine_env(self) -> None:
        """Apply Work-only Echo runtime env (``JS_WORK_ECHO_ENGINE``).

        Never reads ``JS_ECHO_ENGINE`` from the main agent namespace.
        """
        echo_raw = os.getenv("JS_WORK_ECHO_ENGINE")
        if echo_raw is None:
            return

        self.echo_engine = _normalise_echo_engine(echo_raw)
        self.__pydantic_fields_set__.add("echo_engine")

    def with_runtime_engine_env(self) -> WorkSettings:
        """Return a copy with Work-only runtime engine env applied."""
        if os.getenv("JS_WORK_ECHO_ENGINE") is None:
            return self
        runtime = self.model_copy(deep=True)
        if hasattr(self, "_config_path"):
            runtime._config_path = self._config_path  # type: ignore[attr-defined]
        runtime.apply_runtime_engine_env()
        return runtime

    def save(
        self,
        path: Path | str | None = None,
        fields: list[str] | None = None,
    ) -> None:
        """Save Work settings without consulting ``JS_CONFIG_PATH``.

        Resolution order:
        1. Explicit *path* argument
        2. ``JS_WORK_CONFIG_PATH`` environment variable
        3. ``_config_path`` attribute (set by :func:`load_work_settings`)
        4. Default ``~/.config/js-work/config.yaml``
        """
        if path:
            target = Path(path)
        elif env_path := os.getenv("JS_WORK_CONFIG_PATH"):
            target = Path(env_path)
        elif hasattr(self, "_config_path") and self._config_path is not None:
            target = Path(self._config_path)
        else:
            target = default_work_config_path()

        assert_work_path_not_in_personal_namespace(target)
        if self._personal_roots is not None:
            assert_disjoint(
                personal=self._personal_roots,
                work=StorageRoots(
                    config_path=target,
                    workspace=self.workspace,
                    state_dir=self.state_dir,
                ),
            )

        new_data = self.model_dump(mode="json", exclude={"providers": {"__all__": {"api_key"}}})

        for provider in new_data.get("providers", []):
            if isinstance(provider, dict):
                provider.pop("api_key", None)

        from js.utils.atomic_config import save_yaml_config

        save_yaml_config(target, new_data, fields=fields)


def load_work_settings(
    config_path: str | Path | None = None,
    *,
    home: Path | None = None,
    personal_roots: StorageRoots | None = None,
) -> WorkSettings:
    """Load JS Agent Work settings without touching the regular ``~/.js`` state.

    Does not merge ``~/.hermes``, does not consult ``JS_CONFIG_PATH`` /
    ``JS_ECHO_ENGINE``, and does not set legacy architecture fields.
    Forces Work feature gates and pipeline off, then ensures directories exist.

    Config path resolution (never ``JS_CONFIG_PATH``):
    1. Explicit *config_path* argument
    2. ``JS_WORK_CONFIG_PATH`` environment variable
    3. Default ``~/.config/js-work/config.yaml`` (relative to *home*)
    """
    base_home = home or Path.home()
    work_home = default_work_home(base_home)
    if config_path:
        resolved_config = Path(config_path).expanduser()
    elif env_config := os.getenv("JS_WORK_CONFIG_PATH"):
        resolved_config = Path(env_config).expanduser()
    else:
        resolved_config = default_work_config_path(base_home)

    assert_work_path_not_in_personal_namespace(resolved_config)
    candidate_roots = StorageRoots(
        config_path=resolved_config,
        workspace=work_home / "workspace",
        state_dir=work_home / "state",
    )
    if personal_roots is not None:
        assert_disjoint(personal=personal_roots, work=candidate_roots)

    if resolved_config.exists():
        data: dict[str, Any] = {}
        if resolved_config.suffix in (".yaml", ".yml"):
            import yaml

            with open(resolved_config, encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
        elif resolved_config.suffix == ".toml":
            with open(resolved_config, "rb") as f:
                data = tomllib.load(f)
        data.setdefault("work_home", work_home)
        data.setdefault("workspace", work_home / "workspace")
        data.setdefault("state_dir", work_home / "state")
        data["product_id"] = _WORK_PRODUCT_ID
        data["echo_engine"] = "on"
        final_roots = StorageRoots(
            config_path=resolved_config,
            workspace=Path(data["workspace"]),
            state_dir=Path(data["state_dir"]),
        )
        for value in final_roots.__dict__.values():
            assert_work_path_not_in_personal_namespace(value)
        if personal_roots is not None:
            assert_disjoint(personal=personal_roots, work=final_roots)
        settings = WorkSettings(**data)
    else:
        settings = WorkSettings(
            product_id=_WORK_PRODUCT_ID,
            work_home=work_home,
            workspace=work_home / "workspace",
            state_dir=work_home / "state",
            echo_engine="on",
        )

    _ensure_private_directory(settings.work_home, label="Work storage root")
    _ensure_private_directory(settings.workspace, label="Work workspace")
    _ensure_private_directory(settings.state_dir, label="Work state directory")
    settings.features = work_feature_config()
    settings.pipeline = PipelineConfig(enabled=False)
    settings.echo_engine = "on"
    settings._config_path = resolved_config  # type: ignore[attr-defined]
    settings._personal_roots = personal_roots
    return settings.with_runtime_engine_env()
