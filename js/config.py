"""Configuration management with validation, defaults, and environment overrides."""

from __future__ import annotations

import os
from enum import StrEnum
from pathlib import Path
from typing import Literal

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

    @field_validator("protected_paths")
    @classmethod
    def validate_paths(cls, v: list[str]) -> list[str]:
        return [os.path.expanduser(p) for p in v]


class MemoryConfig(BaseModel):
    """Memory and context management."""

    enabled: bool = True
    max_memory_chars: int = Field(default=8000, ge=0)
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
    search_configured: bool = False

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
        """Load settings from file, or create defaults."""
        if path:
            p = Path(path).expanduser()
            if not p.exists():
                raise FileNotFoundError(f"Config file not found: {p}")
            if p.suffix in (".yaml", ".yml"):
                import yaml

                with open(p) as f:
                    data = yaml.safe_load(f) or {}
                return cls(**data)
            elif p.suffix == ".toml":
                import tomllib

                with open(p, "rb") as f:
                    data = tomllib.load(f)
                return cls(**data)

        # Try default locations
        for candidate in [
            Path.home() / ".config" / "js" / "config.yaml",
            Path.home() / ".config" / "js" / "config.toml",
        ]:
            if candidate.exists():
                return cls.from_file(candidate)

        return cls()

    def save(self, path: Path | str | None = None) -> None:
        """Save current settings to file."""
        target = Path(path or Path.home() / ".config" / "js" / "config.yaml")
        target.parent.mkdir(parents=True, exist_ok=True)
        import yaml

        with open(target, "w") as f:
            yaml.safe_dump(
                self.model_dump(mode="json", exclude={"providers": {"__all__": {"api_key"}}}),
                f,
                default_flow_style=False,
                sort_keys=False,
            )
