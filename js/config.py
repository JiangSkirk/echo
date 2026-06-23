"""Configuration management with validation, defaults, and environment overrides."""

from __future__ import annotations

import os
from enum import StrEnum
from pathlib import Path
from typing import Any

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
    api_key: str | None = Field(default=None, description="API key (prefer env var)", repr=False)
    api_key_env: str | None = Field(
        default=None, description="Environment variable name for API key"
    )
    timeout: float = Field(default=120.0, ge=1.0)
    max_retries: int = Field(default=3, ge=0)
    default_model: str = Field(default="")
    embedding_model: str | None = Field(
        default=None, description="Optional embedding model override for this provider"
    )
    transport_type: str = Field(
        default="chat_completions",
        description="Transport protocol: chat_completions, anthropic, bedrock",
    )
    auth_adapter: str | None = Field(
        default=None,
        description="Auth adapter: bearer (default) or query_param",
    )
    query_param_name: str | None = Field(
        default=None,
        description="Query parameter name for auth_adapter=query_param",
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


class ToolLimits(BaseModel):
    """Resource limits for tool execution."""

    shell_timeout: float = Field(default=300.0, ge=1.0)
    shell_max_output_bytes: int = Field(default=50_000, ge=1024)
    file_read_max_chars: int = Field(default=100_000, ge=1000)
    file_write_max_chars: int = Field(default=500_000, ge=1000)
    browser_timeout: float = Field(default=60.0, ge=1.0)
    max_concurrent_tools: int = Field(default=4, ge=1)
    tool_output_budget_chars: int = Field(
        default=20_000,
        ge=1000,
        description="Max chars returned by a single tool call before reference truncation",
    )


class SecurityConfig(BaseModel):
    """Security and sandbox configuration."""

    defense_mode: DefenseMode = DefenseMode.ENFORCE
    protected_paths: list[str] = Field(
        default_factory=lambda: [
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
    audit_retention_days: int = Field(default=90, ge=1)
    max_loop_iterations: int = Field(default=10, ge=1)
    # Hard cap on total messages per run to prevent entropy death spirals
    # (OpenClaw trap defense: 7,069 msg / 170k token per heartbeat).
    max_messages_hard_limit: int = Field(default=200, ge=10)
    # Block after N calls to the same tool name regardless of args
    # (catches weak FC models that spam the same tool name).
    tool_name_loop_threshold: int = Field(default=4, ge=1)
    encoding_guard: bool = True
    script_provenance: bool = True
    tool_result_scan: bool = True

    # API authentication — defaults to True for production security.
    # Set JS_API_KEY_REQUIRED=false env var to disable for local test/dev.
    api_key_required: bool = Field(
        default_factory=lambda: os.environ.get("JS_API_KEY_REQUIRED", "true").lower() != "false",
        description="Require X-API-Key for all web API endpoints",
    )

    # Model discovery defaults to loopback-only (LM Studio / Ollama on
    # 127.0.0.1).  Reaching private-network model servers (e.g. a LAN GPU
    # box) is an SSRF-capable action, so it must be opted in explicitly.
    # Link-local / metadata / reserved ranges are ALWAYS rejected regardless
    # of this flag.
    allow_private_model_providers: bool = Field(
        default_factory=lambda: (
            os.environ.get("JS_ALLOW_PRIVATE_MODEL_PROVIDERS", "false").lower() == "true"
        ),
        description="Allow model discovery to reach private-network (RFC1918) hosts",
    )

    @field_validator("protected_paths")
    @classmethod
    def validate_paths(cls, v: list[str]) -> list[str]:
        return [os.path.expanduser(p) for p in v]


class MemoryConfig(BaseModel):
    """Memory and context management."""

    enabled: bool = True
    max_memory_chars: int = Field(default=2000, ge=0)
    compression_threshold: float = Field(default=0.7, ge=0.0, le=1.0)
    # Hierarchical memory library: auto-extraction + proposal gating.
    auto_extract: bool = True
    extract_confirm_paths: list[str] = Field(
        default_factory=lambda: ["/user/identity", "/people/family", "/user/body"],
        description="Block path prefixes whose auto-extracted memories require user confirmation",
    )
    auto_apply_confidence: float = Field(default=0.75, ge=0.0, le=1.0)
    context_recency_weight: float = Field(default=0.15, ge=0.0, le=1.0)
    context_recency_half_life_days: float = Field(default=30.0, gt=0.0)
    # Session Capsule: lightweight context summary for long conversations
    capsule_enabled: bool = Field(
        default=True,
        description="Enable session capsule generation for long conversations",
    )
    capsule_token_threshold: int = Field(
        default=1500,
        ge=0,
        description="Estimated token threshold to trigger capsule generation",
    )
    capsule_recent_turns: int = Field(
        default=6,
        ge=1,
        le=20,
        description="Number of recent user/assistant turns to keep verbatim when capsule is used",
    )


class DisplayConfig(BaseModel):
    """UI and display preferences."""

    show_cost: bool = False


class PipelineConfig(BaseModel):
    """Auto-Fetch Memory Pipeline configuration."""

    enabled: bool = True
    poll_interval_minutes: int = Field(default=30, ge=1)
    token_limit: int = Field(default=3000, ge=500)
    vault_dir: str = ""
    # Per-source configs keyed by connector name
    sources: dict[str, dict[str, Any]] = Field(default_factory=dict)


# Module-level cache for parsed config files: path -> (mtime, instance)
_settings_file_cache: dict[Path, tuple[float, JSSettings]] = {}


class JSSettings(BaseSettings):
    """Main application settings."""

    model_config = SettingsConfigDict(
        env_prefix="JS_",
        env_nested_delimiter="__",
        extra="ignore",
    )

    # Core
    version: str = "0.1.3"
    workspace: Path = Field(default_factory=lambda: Path.home() / ".js" / "workspace")
    state_dir: Path = Field(default_factory=lambda: Path.home() / ".js" / "state")
    # Agent behavior
    max_turns: int = Field(default=50, ge=1)

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
    desktop_control_enabled: bool = False

    @model_validator(mode="after")
    def ensure_directories(self) -> JSSettings:
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        return self

    @model_validator(mode="after")
    def dedupe_providers(self) -> JSSettings:
        """Remove duplicate providers by name, keeping the first occurrence.

        Duplicate providers can appear when the config file is edited
        manually or when dynamic providers are merged back into the
        settings list.
        """
        seen: set[str] = set()
        unique: list[ModelProviderConfig] = []
        for p in self.providers:
            if p.name not in seen:
                seen.add(p.name)
                unique.append(p)
        self.providers = unique
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
        4. Hermes config fallback (~/.hermes/config.yaml)

        Parsed instances are cached by file mtime to avoid repeated I/O.
        """
        if path:
            p = Path(path).expanduser().resolve()
        elif env_path := os.getenv("JS_CONFIG_PATH"):
            p = Path(env_path).expanduser().resolve()
        else:
            p = None

        instance: JSSettings | None = None
        config_path: Path | None = None

        if p is not None:
            if ".." in str(p):
                raise ValueError(f"Path traversal not allowed: {p}")
            if not p.exists():
                instance = cls()
                config_path = p
            elif p.suffix in (".yaml", ".yml"):
                # Check cache first
                if p in _settings_file_cache:
                    mtime, cached = _settings_file_cache[p]
                    try:
                        if p.stat().st_mtime == mtime:
                            return cached
                    except Exception:
                        pass
                import yaml

                with open(p) as f:
                    data = yaml.safe_load(f) or {}
                instance = cls(**data)
                config_path = p
            elif p.suffix == ".toml":
                if p in _settings_file_cache:
                    mtime, cached = _settings_file_cache[p]
                    try:
                        if p.stat().st_mtime == mtime:
                            return cached
                    except Exception:
                        pass
                import tomllib

                with open(p, "rb") as f:
                    data = tomllib.load(f)
                instance = cls(**data)
                config_path = p

        if instance is None:
            for candidate in [
                Path.home() / ".config" / "js" / "config.yaml",
                Path.home() / ".config" / "js" / "config.toml",
            ]:
                if candidate.exists():
                    instance = cls.from_file(candidate)
                    config_path = candidate
                    break

        if instance is None:
            instance = cls()
            config_path = Path.home() / ".config" / "js" / "config.yaml"

        instance._config_path = config_path  # type: ignore[attr-defined]
        instance._merge_hermes()

        # Cache by mtime
        if config_path is not None and config_path.exists():
            try:
                _settings_file_cache[config_path] = (config_path.stat().st_mtime, instance)
            except Exception:
                pass

        return instance

    def _merge_hermes(self) -> None:
        """Overlay Hermes config (~/.hermes/config.yaml) when JS config is default."""
        hermes_path = Path.home() / ".hermes" / "config.yaml"
        if not hermes_path.exists():
            return
        try:
            import yaml

            with open(hermes_path, encoding="utf-8") as f:
                raw = yaml.safe_load(f) or {}
        except Exception:
            return

        # Map Hermes model/provider → JS providers
        existing_names = {p.name for p in self.providers}
        model = raw.get("model", {})
        default_model = model.get("default", "")
        provider_name = model.get("provider", "")
        base_url = model.get("base_url", "")
        if provider_name and base_url and provider_name not in existing_names:
            self.providers.append(
                ModelProviderConfig(
                    name=provider_name,
                    base_url=base_url,
                    default_model=default_model,
                    models=[
                        ModelConfig(id=default_model, name=default_model, provider=provider_name)
                    ]
                    if default_model
                    else [],
                )
            )
            existing_names.add(provider_name)
        for fb in raw.get("fallback_providers", []):
            if isinstance(fb, dict):
                fb_name = fb.get("provider", "")
                fb_model = fb.get("model", "")
                if fb_name and fb_name not in existing_names:
                    self.providers.append(
                        ModelProviderConfig(
                            name=fb_name,
                            base_url="",
                            default_model=fb_model,
                            models=[ModelConfig(id=fb_model, name=fb_model, provider=fb_name)]
                            if fb_model
                            else [],
                        )
                    )
                    existing_names.add(fb_name)

        # Map Hermes agent.max_turns → JS max_turns
        agent = raw.get("agent", {})
        hermes_turns = agent.get("max_turns")
        if hermes_turns is not None and self.max_turns == 50:
            self.max_turns = int(hermes_turns)

        # Map Hermes terminal/tool limits → JS ToolLimits
        terminal = raw.get("terminal", {})
        tool_output = raw.get("tool_output", {})
        if self.tools == ToolLimits():
            self.tools = ToolLimits(
                shell_timeout=float(terminal.get("timeout", 300.0)),
                shell_max_output_bytes=int(tool_output.get("max_bytes", 50_000)),
                file_read_max_chars=int(raw.get("file_read_max_chars", 100_000)),
            )

        # Map Hermes compression → JS MemoryConfig
        compression = raw.get("compression", {})
        if self.memory == MemoryConfig():
            self.memory = MemoryConfig(
                enabled=compression.get("enabled", True),
                compression_threshold=float(compression.get("threshold", 0.7)),
            )

        # Map Hermes guardrails → JS SecurityConfig
        guardrails = raw.get("tool_loop_guardrails", {})
        hard = guardrails.get("hard_stop_after", {})
        if self.security == SecurityConfig():
            max_loop = max(
                int(hard.get("exact_failure", 5)),
                int(hard.get("same_tool_failure", 8)),
                int(hard.get("idempotent_no_progress", 5)),
            )
            self.security = SecurityConfig(max_loop_iterations=max_loop)

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

        # Defensive: strip any lingering api_key values from providers before writing
        for provider in new_data.get("providers", []):
            if isinstance(provider, dict):
                provider.pop("api_key", None)

        with open(target, "w") as f:
            yaml.safe_dump(new_data, f, default_flow_style=False, sort_keys=False)
