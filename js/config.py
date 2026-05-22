"""Configuration management with validation, defaults, and environment overrides."""

from __future__ import annotations

import os
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class LogLevel(StrEnum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class DefenseMode(StrEnum):
    OFF = "off"
    OBSERVE = "observe"
    ENFORCE = "enforce"


class ModelProviderConfig(BaseModel):
    """Configuration for a single model provider."""

    name: str = Field(description="Provider identifier")
    base_url: str = Field(description="API base URL")
    api_key: str | None = Field(default=None, description="API key (prefer env var)")
    api_key_env: str | None = Field(
        default=None, description="Environment variable name for API key"
    )
    timeout: float = Field(default=120.0, ge=1.0)
    max_retries: int = Field(default=3, ge=0)
    default_model: str = Field(default="")
    embedding_model: str | None = Field(
        default=None, description="Optional embedding model override for this provider"
    )
    models: list[ModelConfig] = Field(default_factory=list)

    @model_validator(mode="after")
    def resolve_api_key(self) -> ModelProviderConfig:
        if self.api_key_env and not self.api_key:
            self.api_key = os.getenv(self.api_key_env, "")
        return self


class ModelConfig(BaseModel):
    """Configuration for a specific model."""

    id: str
    name: str = ""
    provider: str = ""
    context_window: int = Field(default=128000, gt=0)
    max_tokens: int = Field(default=4096, gt=0)
    supports_vision: bool = False
    supports_tools: bool = True
    cost_input: float = Field(default=0.0, ge=0.0)
    cost_output: float = Field(default=0.0, ge=0.0)
    reasoning_effort: Literal["low", "medium", "high"] = "medium"


class ToolLimits(BaseModel):
    """Resource limits for tool execution."""

    shell_timeout: float = Field(default=300.0, ge=1.0)
    shell_max_output_bytes: int = Field(default=50_000, ge=1024)
    shell_max_output_lines: int = Field(default=2000, ge=100)
    file_read_max_chars: int = Field(default=100_000, ge=1000)
    file_write_max_chars: int = Field(default=500_000, ge=1000)
    browser_timeout: float = Field(default=60.0, ge=1.0)
    max_concurrent_tools: int = Field(default=4, ge=1)


class SecurityConfig(BaseModel):
    """Security and sandbox configuration."""

    defense_mode: DefenseMode = DefenseMode.ENFORCE
    protected_paths: list[str] = Field(
        default_factory=lambda: [
            "/",
            "/etc",
            "/usr",
            "/bin",
            "/sbin",
            "/lib",
            "/lib64",
            "/sys",
            "/dev",
            "/proc",
        ]
    )
    protected_commands: list[str] = Field(
        default_factory=lambda: [
            "rm -rf /",
            "dd if=/dev/zero",
            ":(){ :|:& };:",
            "curl .*\\|.*sh",
            "wget .*\\|.*sh",
        ]
    )
    allow_workspace_delete: bool = False
    secret_redaction: bool = True
    audit_enabled: bool = True
    audit_retention_days: int = Field(default=90, ge=1)
    max_loop_iterations: int = Field(default=10, ge=1)
    encoding_guard: bool = True
    script_provenance: bool = True
    tool_result_scan: bool = True

    # API authentication
    api_key_required: bool = Field(default=False, description="Require X-API-Key for all web API endpoints")
    api_key_auto_bootstrap: bool = Field(default=True, description="Allow first access without key to bootstrap admin key")

    @field_validator("protected_paths")
    @classmethod
    def validate_paths(cls, v: list[str]) -> list[str]:
        return [os.path.expanduser(p) for p in v]


class MemoryConfig(BaseModel):
    """Memory and context management."""

    enabled: bool = True
    max_memory_chars: int = Field(default=2000, ge=0)
    compression_threshold: float = Field(default=0.7, ge=0.0, le=1.0)
    context_window_target: float = Field(default=0.8, ge=0.1, le=1.0)
    auto_summarize: bool = True
    persistent_store: bool = True


class DisplayConfig(BaseModel):
    """UI and display preferences."""

    compact: bool = False
    show_cost: bool = False
    show_reasoning: bool = False
    streaming: bool = True
    theme: Literal["default", "dark", "light"] = "default"


class PipelineConfig(BaseModel):
    """Auto-Fetch Memory Pipeline configuration."""

    enabled: bool = True
    poll_interval_minutes: int = Field(default=30, ge=1)
    token_limit: int = Field(default=3000, ge=500)
    vault_dir: str = ""
    # Per-source configs keyed by connector name
    sources: dict[str, dict[str, Any]] = Field(default_factory=dict)


class JSSettings(BaseSettings):
    """Main application settings."""

    model_config = SettingsConfigDict(
        env_prefix="JS_",
        env_nested_delimiter="__",
        extra="ignore",
    )

    # Core
    version: str = "0.1.0"
    workspace: Path = Field(default_factory=lambda: Path.home() / ".js" / "workspace")
    state_dir: Path = Field(default_factory=lambda: Path.home() / ".js" / "state")
    log_level: LogLevel = LogLevel.INFO

    # Agent behavior
    max_turns: int = Field(default=50, ge=1)
    auto_delegate: bool = True
    delegation_threshold: Literal["simple", "complex", "always"] = "complex"

    # Sub-configs
    models: list[ModelConfig] = Field(default_factory=list)
    providers: list[ModelProviderConfig] = Field(default_factory=list)
    tools: ToolLimits = Field(default_factory=ToolLimits)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    memory: MemoryConfig = Field(default_factory=MemoryConfig)
    display: DisplayConfig = Field(default_factory=DisplayConfig)
    pipeline: PipelineConfig = Field(default_factory=PipelineConfig)
    search_configured: bool = False
    first_run_completed: bool = False

    @model_validator(mode="after")
    def ensure_directories(self) -> JSSettings:
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        return self

    def get_provider(self, name: str) -> ModelProviderConfig | None:
        for p in self.providers:
            if p.name == name:
                return p
        return None

    def get_model(self, model_id: str) -> ModelConfig | None:
        for m in self.models:
            if m.id == model_id:
                return m
        return None

    @classmethod
    def from_file(cls, path: Path | str | None = None) -> JSSettings:
        """Load settings from file, or create defaults.

        Priority:
        1. Explicit *path* argument
        2. JS_CONFIG_PATH environment variable
        3. Default locations (~/.config/js/config.{yaml,toml})
        """
        if path:
            p = Path(path).expanduser().resolve()
        elif env_path := os.getenv("JS_CONFIG_PATH"):
            p = Path(env_path).expanduser().resolve()
        else:
            p = None

        if p is not None:
            # Guard against path traversal attempts
            if ".." in str(p):
                raise ValueError(f"Path traversal not allowed: {p}")
            if not p.exists():
                # Graceful fallback: return defaults so the app can still start
                # (setup wizard will guide the user to create a proper config)
                instance = cls()
                instance._config_path = p  # type: ignore[attr-defined]
                return instance
            if p.suffix in (".yaml", ".yml"):
                import yaml

                with open(p) as f:
                    data = yaml.safe_load(f) or {}
                instance = cls(**data)
                instance._config_path = p  # type: ignore[attr-defined]
                return instance
            elif p.suffix == ".toml":
                import tomllib

                with open(p, "rb") as f:
                    data = tomllib.load(f)
                instance = cls(**data)
                instance._config_path = p  # type: ignore[attr-defined]
                return instance

        # Try default locations
        for candidate in [
            Path.home() / ".config" / "js" / "config.yaml",
            Path.home() / ".config" / "js" / "config.toml",
        ]:
            if candidate.exists():
                instance = cls.from_file(candidate)
                instance._config_path = candidate  # type: ignore[attr-defined]
                return instance

        instance = cls()
        instance._config_path = Path.home() / ".config" / "js" / "config.yaml"  # type: ignore[attr-defined]
        return instance

    def save(
        self,
        path: Path | str | None = None,
        fields: list[str] | None = None,
    ) -> None:
        """Save current settings to file.

        Resolution order for target path:
        1. Explicit *path* argument
        2. JS_CONFIG_PATH environment variable
        3. _config_path attribute (set by from_file)
        4. Default ~/.config/js/config.yaml

        If *fields* is provided, only those top-level fields are updated in
        the existing file (merge mode). This prevents accidental clobbering
        of providers, models, or paths that were set by auto-discovery or
        loaded from the original config.
        """
        if path:
            target = Path(path)
        elif env_path := os.getenv("JS_CONFIG_PATH"):
            target = Path(env_path)
        elif hasattr(self, "_config_path"):
            target = Path(self._config_path)
        else:
            target = Path.home() / ".config" / "js" / "config.yaml"

        target = target.expanduser().resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        import yaml

        # Build the new data dict
        new_data = self.model_dump(mode="json", exclude={"providers": {"__all__": {"api_key"}}})

        # Field-restricted merge mode: update only specified fields
        if fields and target.exists():
            try:
                with open(target) as f:
                    existing = yaml.safe_load(f) or {}
                for key in fields:
                    if key in new_data:
                        existing[key] = new_data[key]
                new_data = existing
            except Exception:
                pass  # If read fails, fall back to full overwrite

        with open(target, "w") as f:
            yaml.safe_dump(new_data, f, default_flow_style=False, sort_keys=False)
