"""Configuration management with validation, defaults, and environment overrides."""

from __future__ import annotations

import errno
import ipaddress
import os
import re
import sys
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field, ValidationInfo, field_validator, model_validator
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
    draft_model: str | None = Field(
        default=None,
        description=(
            "Optional local draft model for speculative decoding (P3-3). "
            "Default off. Router chat does not read this field."
        ),
    )

    @field_validator("name")
    @classmethod
    def validate_provider_name_chars(cls, value: str) -> str:
        from js.web.ids import InvalidRuntimeIdError, validate_provider_name

        try:
            return validate_provider_name(value)
        except InvalidRuntimeIdError as exc:
            raise ValueError(str(exc)) from exc

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

    @field_validator("max_tokens", mode="before")
    @classmethod
    def reject_boolean_max_tokens(cls, value: Any) -> Any:
        if isinstance(value, bool):
            raise ValueError("max_tokens must be a positive integer, not a boolean")
        return value

    @field_validator("id", "provider")
    @classmethod
    def validate_ids(cls, value: str, info: ValidationInfo) -> str:
        from js.web.ids import InvalidRuntimeIdError, validate_runtime_id

        label = "model id" if info.field_name == "id" else "provider name"
        if info.field_name == "provider" and value == "":
            return value
        try:
            return validate_runtime_id(value, label=label)
        except InvalidRuntimeIdError as exc:
            raise ValueError(str(exc)) from exc

    # --- v0.1.6 capability fields (all default-on for backward compat) ---
    supports_streaming: bool = Field(
        default=True,
        description="Whether the model supports streaming responses (token deltas)",
    )
    supports_thinking: bool = Field(
        default=False,
        description="Whether the model emits structured thinking/reasoning deltas",
    )
    max_output_tokens: int | None = Field(
        default=None,
        gt=0,
        description="Maximum tokens the model can generate in a single response (None = use max_tokens)",
    )
    context_source: str = Field(
        default="heuristic",
        description="Where context_window came from: api | preset | heuristic",
        pattern=r"^(api|preset|heuristic)$",
    )
    probed_at: float | None = Field(
        default=None,
        description="Unix timestamp when this capability profile was last probed",
    )
    draft_model: str | None = Field(
        default=None,
        description=(
            "Optional speculative-decoding draft model id for a local server "
            "(Ollama/LM Studio). Default off; the router does not consume this."
        ),
    )


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
    csv_read_max_bytes: int = Field(
        default=10 * 1024 * 1024,
        ge=1024,
        description="Maximum CSV file size accepted by csv_read before streaming parse",
    )
    csv_read_max_rows: int = Field(default=10_000, ge=1)
    csv_read_max_columns: int = Field(default=256, ge=1)
    csv_read_max_field_chars: int = Field(default=10_000, ge=1)
    csv_read_max_cells: int = Field(default=500_000, ge=1)
    code_search_max_pattern_chars: int = Field(default=256, ge=1)
    code_search_max_files: int = Field(default=2_000, ge=1)
    code_search_max_bytes: int = Field(default=20 * 1024 * 1024, ge=1024)
    code_search_max_line_chars: int = Field(default=8_192, ge=64)
    code_search_regex_timeout_seconds: float = Field(default=2.0, ge=0.1)
    # NOTE (F-09): ``find`` and ``awk`` were removed from the default
    # allowlist — both carry trivial command-execution / file-write bypasses
    # (find -exec/-delete, awk system()/getline/pipes).  Operators can
    # re-enable them explicitly; argument-level deny rules in
    # ``js.tools.shell`` still constrain them when re-enabled.
    shell_command_allowlist: list[str] = Field(
        default_factory=lambda: [
            "basename",
            "cat",
            "cut",
            "date",
            "diff",
            "dirname",
            "du",
            "echo",
            "false",
            "git",
            "grep",
            "head",
            "jq",
            "ls",
            "mkdir",
            "mv",
            "printf",
            "pwd",
            "rg",
            "sed",
            "sort",
            "stat",
            "tail",
            "tar",
            "test",
            "touch",
            "tr",
            "true",
            "uniq",
            "wc",
        ],
        description="Exact bare executable names permitted by the shell tool",
    )

    @field_validator("shell_command_allowlist")
    @classmethod
    def validate_shell_command_allowlist(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []
        for raw in values:
            name = raw.strip()
            if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.+-]{0,63}", name) is None:
                raise ValueError("shell_command_allowlist entries must be bare executable names")
            if name not in normalized:
                normalized.append(name)
        if not normalized:
            raise ValueError("shell_command_allowlist must not be empty")
        return normalized


class EchoBudgetConfig(BaseModel):
    """Hard per-run limits enforced by Echo's live BudgetClock."""

    max_prompt_tokens: int = Field(default=200_000, ge=1)
    max_completion_tokens: int = Field(default=32_768, ge=1)
    max_tool_calls: int = Field(default=32, ge=0)
    max_journal_appends: int = Field(default=128, ge=1)
    max_elapsed_ms: int = Field(default=900_000, ge=1_000)


class EchoLedgerConfig(BaseModel):
    """Bounded retention policy for Echo's durable file journals."""

    retain_records: int = Field(default=2_048, ge=1)
    trigger_records: int = Field(default=4_096, ge=2)
    max_archives: int = Field(default=1, ge=1)
    max_open_effects_per_tenant: int = Field(default=1_024, ge=1)
    max_session_partitions_per_owner: int = Field(default=64, ge=2)
    max_retired_session_receipts_per_owner: int = Field(default=256, ge=1)
    max_retired_artifact_refs_per_owner: int = Field(
        default=1_024,
        ge=1,
        le=65_536,
    )
    max_retired_artifact_bytes_per_owner: int = Field(
        default=4 * 1024 * 1024,
        ge=1,
        le=64 * 1024 * 1024,
    )
    lease_compact_trigger_records: int = Field(
        default=512,
        ge=8,
        description="Governor compact() when the lease JSONL seq reaches this count",
    )
    lease_compact_trigger_bytes: int = Field(
        default=256 * 1024,
        ge=1024,
        description="Governor compact() when the lease JSONL exceeds this size",
    )
    lease_compact_trigger_full_reloads: int = Field(
        default=8,
        ge=1,
        description="Governor compact() after this many full ledger reloads",
    )
    external_tip_anchor: bool = Field(
        default=False,
        description=(
            "Use an AnchorBackend outside the journal directory (Keychain on "
            "Darwin, sibling file otherwise). Not TPM. Default off."
        ),
    )

    @model_validator(mode="after")
    def validate_trigger_exceeds_retention(self) -> EchoLedgerConfig:
        if self.trigger_records <= self.retain_records:
            raise ValueError("trigger_records must be greater than retain_records")
        return self


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
    network_enabled: bool = Field(
        default=False,
        description="Permit Echo tool network leases; disabled by default",
    )
    # F-14: shell/python are excluded from Echo's always-on core tool schema.
    # They re-join the core subset only when the operator explicitly opts in.
    echo_exec_tools: bool = Field(
        default=False,
        description="Advertise shell/python in Echo's core tool schema subset",
    )
    network_allowlist: list[str] = Field(
        default_factory=list,
        description="Exact public DNS hosts permitted for Echo network tools",
    )
    untrusted_ingestion_policy: Literal["warn", "enforce"] = Field(
        default="warn",
        description=(
            "warn: untrusted inbound surfaces may start on a native host and "
            "keep a status warning. enforce: refuse those surfaces unless the "
            "runtime posture is container-full."
        ),
    )
    upload_owner_max_bytes: int = Field(default=2 * 1024 * 1024 * 1024, ge=1024)
    upload_owner_max_files: int = Field(default=5_000, ge=1)
    upload_session_max_bytes: int = Field(default=512 * 1024 * 1024, ge=1024)
    upload_session_max_files: int = Field(default=1_000, ge=1)
    upload_min_free_disk_bytes: int = Field(default=256 * 1024 * 1024, ge=0)

    @field_validator("protected_paths")
    @classmethod
    def validate_paths(cls, v: list[str]) -> list[str]:
        return [os.path.expanduser(p) for p in v]

    @field_validator("network_allowlist")
    @classmethod
    def validate_network_allowlist(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []
        for raw in values:
            host = raw.strip().lower().rstrip(".")
            if not host or "\x00" in host or "://" in host or "/" in host or "*" in host:
                raise ValueError("network_allowlist entries must be exact DNS hostnames")
            if host == "localhost" or host.endswith(".localhost"):
                raise ValueError("network_allowlist cannot grant localhost")
            try:
                ipaddress.ip_address(host)
            except ValueError:
                try:
                    host = host.encode("idna").decode("ascii")
                except UnicodeError as exc:
                    raise ValueError("network_allowlist hostname is invalid") from exc
                if (
                    re.fullmatch(
                        r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
                        r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?",
                        host,
                    )
                    is None
                ):
                    raise ValueError("network_allowlist hostname is invalid") from None
            else:
                raise ValueError("network_allowlist entries must be DNS hostnames, not IPs")
            if host not in normalized:
                normalized.append(host)
        return normalized


class OrinKeyboxTier(StrEnum):
    """Orin keybox hardware anchoring tier."""

    DEV = "dev"
    PRODUCTION = "production"


class OrinFailMode(StrEnum):
    """Behavior when orind is unreachable while ``orin_enabled`` is on."""

    CLOSED = "closed"
    READONLY = "readonly"


class OrinPolicyProfile(StrEnum):
    """Lease policy table profile served by orind."""

    CONSERVATIVE = "conservative"
    COMPAT = "compat"


class OrinConfig(BaseModel):
    """Orin Stage A gatekeeper (orind) configuration.

    Orin moves lease issuance / consumption / revocation into a separate
    daemon. Stage A claims only model-layer hardening — never process-RCE
    containment (tool handlers still run in-process). All defaults keep
    pre-Orin behavior: ``orin_enabled=False`` routes every lease call
    through the in-process ``LeaseAuthority`` exactly as before.
    """

    enabled: bool = Field(
        default=False,
        description=(
            "Route lease issue/consume/revoke through orind. Disabled by default "
            "until merge; must keep pre-Orin behavior when False."
        ),
    )
    fail_mode: OrinFailMode = Field(
        default=OrinFailMode.CLOSED,
        description=(
            "orind unreachable: 'closed' stops issuing new leases (chat-only "
            "continues); 'readonly' additionally allows read-only leases."
        ),
    )
    socket_path: Path | None = Field(
        default=None,
        description=(
            "Unix domain socket path for orind. Defaults to <state_dir>/orin/orind.sock when unset."
        ),
    )
    keybox_tier: OrinKeyboxTier = Field(
        default=OrinKeyboxTier.DEV,
        description=(
            "Key storage tier: 'dev' = 0600 key file (adopts the legacy "
            "echo_tool_lease.key on first start); 'production' = macOS "
            "Keychain controlled extraction."
        ),
    )
    shadow_mode: bool = Field(
        default=False,
        description=(
            "Log Orin policy verdicts without changing enforcement outcome "
            "(calibration aid; verdict fields still recorded)."
        ),
    )
    policy_profile: OrinPolicyProfile = Field(
        default=OrinPolicyProfile.CONSERVATIVE,
        description=(
            "Policy table profile: 'conservative' (fallback row requires "
            "approval) or 'compat' (legacy behavior + logging only)."
        ),
    )
    canary_enabled: bool = Field(
        default=True,
        description="WP3 honeytoken matching. Independent rollback: set False to disable.",
    )
    responder_lock_l0: bool = Field(
        default=False,
        description="WP3 ladder rollback: keep Responder at L0 (observe only).",
    )
    patrol_record_only: bool = Field(
        default=False,
        description="WP3 patrol rollback: record signals, never emit tighten advice.",
    )
    # -- stage B (ORIN_STAGE_B_SPEC.md §3/§4): every switch defaults off and
    # rolls back independently. With stage_b=False the main path is exactly
    # Stage A: in-process LeaseAuthority + orind lease online-ization only.
    stage_b: bool = Field(
        default=False,
        description=(
            "Master switch for Effect Kernel stage B (intents/handles/drafts/"
            "cells). Disabled by default; must keep pre-stage-B behavior."
        ),
    )
    cell_build: bool = Field(
        default=False,
        description=(
            "WP7 Build Cell: route shell/code execution through the orind-"
            "scheduled sandboxed cell instead of in-process subprocesses."
        ),
    )
    cell_secret: bool = Field(
        default=False,
        description=(
            "WP8 Secret Cell: SecretHandle-bound credential use without "
            "plaintext passthrough to Echo."
        ),
    )
    cell_net: bool = Field(
        default=False,
        description=(
            "WP8 Network/Connector Cell: signed Endpoint Manifest enforcement "
            "and egress export passes outside the Echo process."
        ),
    )
    cell_file: bool = Field(
        default=False,
        description=(
            "WP9 File Cell: handle-scoped staging writes with atomic "
            "rename/CAS commit outside the Echo process."
        ),
    )
    commit_membrane: bool = Field(
        default=False,
        description=(
            "WP10 commit membrane: durable prepare / UNKNOWN_COMMIT "
            "reconciliation for workspace commits and connector sends."
        ),
    )
    # -- stage C (ORIN_STAGE_C_SPEC.md): parsed now.  Product routes stay
    # inert while enforce is off.  The master switch fail-fasts unless the
    # §6.1 conjunction (including external #8/#9/TCC bits) is fully observed.
    enforce: bool = Field(
        default=False,
        description=(
            "Stage-C production enforce mode. Fail-fast unless the §6.1 "
            "conjunction is fully observed."
        ),
    )
    cell_identity_enforce: bool = Field(
        default=False,
        description=(
            "Require the WP-C1 Cell OS/launch/protocol identity contract. "
            "Lazy on product routes unless Stage-C enforce is active."
        ),
    )
    cell_desktop: bool = Field(
        default=False,
        description=(
            "WP-C2 Desktop Cell switch. Inert on product routes unless "
            "orin.enforce is active; the C2 harness may still exercise it."
        ),
    )
    cell_memory: bool = Field(
        default=False,
        description=(
            "WP-C3 Memory Cell switch. Inert on product routes unless "
            "orin.enforce is active; the C3 harness may still exercise it."
        ),
    )
    echo_minimal_os: bool = Field(
        default=False,
        description=(
            "Launch Echo through the optional deny-default OS carrier. "
            "Not official TCC/notary evidence. Default off."
        ),
    )
    cell_model_transport: bool = Field(
        default=False,
        description=(
            "Opt-in model connector via Services Cell. Echo must not hydrate "
            "provider tokens when this is observed. Default off; not enforce."
        ),
    )

    @model_validator(mode="after")
    def reject_unfinished_stage_c_enforce(self) -> OrinConfig:
        if self.enforce:
            from js.orin.stage_c import require_stage_c_enforce

            require_stage_c_enforce(self)
        return self


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
    # Layered Entity/Claim side-car (Phase A+B). Legacy semantic tables remain
    # authoritative; dual-write is best-effort and must not break old reads.
    layered_memory_dual_write: bool = Field(
        default=True,
        description="Best-effort dual-write semantic stores into Entity/Claim tables",
    )
    layered_memory_retrieve: bool = Field(
        default=False,
        description="When true, merge active layered claims into get_context_string",
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


class AgentFeatureConfig(BaseModel):
    """Feature gates for product variants built on the JSAgent core."""

    plugins_enabled: bool = True
    skills_enabled: bool = True
    skill_tools_enabled: bool = True
    # Opt-in only: never auto-scan ~/.hermes/skills on isolated/privacy-safe starts.
    hermes_skills_enabled: bool = False
    evolution_enabled: bool = True
    pipeline_enabled: bool = True
    daemon_enabled: bool = True


class GatewayChannelConfig(BaseModel):
    """One messaging channel. Disabled unless both the gateway and the channel are on."""

    name: str
    enabled: bool = False
    bot_id: str | None = None
    owner: str = "local"
    dm_scope: Literal["main", "per-peer"] = "per-peer"

    @field_validator("enabled", mode="before")
    @classmethod
    def require_exact_boolean_channel_gate(cls, value: object) -> bool:
        if type(value) is not bool:
            raise ValueError("gateway channel enabled must be an exact boolean")
        return value


class GatewayConfig(BaseModel):
    """Messaging gateway surface. Default off; unpaired senders are discarded."""

    enabled: bool = False
    pairing_ttl_seconds: int = Field(default=600, ge=1)
    discard_log_min_interval_seconds: float = Field(default=5.0, ge=0.0)
    max_pairing_attempts_per_peer: int = Field(default=8, ge=1)
    webhook_secret: str = Field(default="", repr=False)
    webhook_max_skew_seconds: int = Field(default=300, ge=1)
    channels: list[GatewayChannelConfig] = Field(default_factory=list)
    # Empty = built-in read-only set (file_read/list_dir/glob/grep/memory_search).
    tool_allowlist: list[str] = Field(default_factory=list)

    @field_validator("enabled", mode="before")
    @classmethod
    def require_exact_boolean_gateway_gate(cls, value: object) -> bool:
        if type(value) is not bool:
            raise ValueError("gateway.enabled must be an exact boolean")
        return value

    @field_validator("tool_allowlist")
    @classmethod
    def validate_gateway_tool_allowlist(cls, value: list[str]) -> list[str]:
        names: list[str] = []
        seen: set[str] = set()
        for item in value:
            if not isinstance(item, str) or not item.strip():
                raise ValueError("gateway.tool_allowlist entries must be non-empty strings")
            name = item.strip()
            if name not in seen:
                names.append(name)
                seen.add(name)
        return names


class EchoPlanCommitConfig(BaseModel):
    """Plan-then-execute mode. Default off; explicit false is a degrade (P0-4)."""

    enabled: bool = False
    remaining_rebind: bool = True

    @field_validator("enabled", "remaining_rebind", mode="before")
    @classmethod
    def require_exact_boolean_plan_commit(cls, value: object) -> bool:
        if type(value) is not bool:
            raise ValueError("echo_plan_commit flags must be exact booleans")
        return value


class ModelCascadeConfig(BaseModel):
    """Light-path local-first routing. Does not disable the heavy-path local ban."""

    enabled: bool = True

    @field_validator("enabled", mode="before")
    @classmethod
    def require_exact_boolean_cascade(cls, value: object) -> bool:
        if type(value) is not bool:
            raise ValueError("model_cascade.enabled must be an exact boolean")
        return value


# Module-level cache for parsed config files: path -> (mtime, instance)
_settings_file_cache: dict[Path, tuple[float, JSSettings]] = {}

_PRIVATE_DIRECTORY_MODE = 0o700
_MACOS_TRUSTED_PRIVATE_ALIASES = {
    "tmp": Path("/private/tmp"),
    "var": Path("/private/var"),
}


def _absolute_without_resolving(path: Path) -> Path:
    """Return an absolute lexical path without following user-controlled links.

    macOS exposes ``/tmp`` and ``/var`` as root-owned compatibility symlinks to
    ``/private``.  Treat only those exact, verified system aliases as canonical
    prefixes; all later components are still opened with ``O_NOFOLLOW``.
    """
    absolute = Path(os.path.abspath(os.fspath(path.expanduser())))
    if sys.platform != "darwin" or len(absolute.parts) < 3:
        return absolute

    alias_name = absolute.parts[1]
    expected = _MACOS_TRUSTED_PRIVATE_ALIASES.get(alias_name)
    if expected is None:
        return absolute

    alias = Path(absolute.anchor) / alias_name
    try:
        metadata = alias.lstat()
        if (
            not alias.is_symlink()
            or metadata.st_uid != 0
            or Path(os.path.realpath(alias)) != expected
            or not expected.is_dir()
        ):
            return absolute
    except OSError:
        return absolute
    return expected.joinpath(*absolute.parts[2:])


def _ensure_private_directory(path: Path, *, label: str) -> None:
    """Create or tighten a managed directory without following symlinks.

    Walking one component at a time relative to an already-open directory
    prevents a managed leaf (or one of its parents) from redirecting chmod to
    an unrelated target. Existing ordinary directories are tightened to 0700;
    symlinks and non-directories fail closed.
    """
    absolute = _absolute_without_resolving(path)
    if absolute == Path(absolute.anchor):
        raise ValueError(f"{label} must be a private directory below the filesystem root")

    directory_flag = getattr(os, "O_DIRECTORY", 0)
    no_follow_flag = getattr(os, "O_NOFOLLOW", 0)
    if not directory_flag or not no_follow_flag:
        raise RuntimeError("private directory creation requires O_DIRECTORY and O_NOFOLLOW")

    current_fd = os.open(absolute.anchor, os.O_RDONLY | directory_flag)
    try:
        for component in absolute.parts[1:]:
            try:
                os.mkdir(component, _PRIVATE_DIRECTORY_MODE, dir_fd=current_fd)
            except FileExistsError:
                pass

            try:
                child_fd = os.open(
                    component,
                    os.O_RDONLY | directory_flag | no_follow_flag,
                    dir_fd=current_fd,
                )
            except OSError as exc:
                if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
                    raise ValueError(
                        f"{label} must be a private directory, not a symlink or non-directory"
                    ) from exc
                raise
            os.close(current_fd)
            current_fd = child_fd

        os.fchmod(current_fd, _PRIVATE_DIRECTORY_MODE)
    finally:
        os.close(current_fd)


def _personal_storage_roots(*paths: Path) -> tuple[Path, ...]:
    """Return lexical ``.js`` ancestors that are managed Personal roots."""
    roots: set[Path] = set()
    for path in paths:
        absolute = _absolute_without_resolving(path)
        for candidate in (absolute, *absolute.parents):
            if candidate.name == ".js":
                roots.add(candidate)
                break
    return tuple(sorted(roots, key=lambda candidate: len(candidate.parts)))


def _normalise_echo_engine(value: str) -> str:
    normalised = (value or "on").strip().lower()
    if normalised != "on":
        raise ValueError(
            f"Echo is the only supported architecture; echo_engine must be 'on', got {value!r}"
        )
    return normalised


class JSSettings(BaseSettings):
    """Main application settings."""

    model_config = SettingsConfigDict(
        env_prefix="JS_",
        env_nested_delimiter="__",
        extra="ignore",
    )

    # Core
    version: str = "0.1.5"
    workspace: Path = Field(default_factory=lambda: Path.home() / ".js" / "workspace")
    state_dir: Path = Field(default_factory=lambda: Path.home() / ".js" / "state")
    # Agent behavior
    max_turns: int = Field(default=50, ge=1)
    max_empty_response_retries: int = Field(
        default=3,
        ge=1,
        description="Max consecutive empty model responses before failing the run",
    )

    # Sub-configs
    models: list[ModelConfig] = Field(default_factory=list)
    providers: list[ModelProviderConfig] = Field(default_factory=list)
    tools: ToolLimits = Field(default_factory=ToolLimits)
    echo_budget: EchoBudgetConfig = Field(default_factory=EchoBudgetConfig)
    echo_ledger: EchoLedgerConfig = Field(default_factory=EchoLedgerConfig)
    # Nested name is echo_plan_commit (not `echo`) so JS_ECHO__* does not
    # collide with echo_budget / echo_engine / echo_ledger.
    echo_plan_commit: EchoPlanCommitConfig = Field(default_factory=EchoPlanCommitConfig)
    model_cascade: ModelCascadeConfig = Field(default_factory=ModelCascadeConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    orin: OrinConfig = Field(default_factory=OrinConfig)
    memory: MemoryConfig = Field(default_factory=MemoryConfig)
    display: DisplayConfig = Field(default_factory=DisplayConfig)
    pipeline: PipelineConfig = Field(default_factory=PipelineConfig)
    features: AgentFeatureConfig = Field(default_factory=AgentFeatureConfig)
    gateway: GatewayConfig = Field(default_factory=GatewayConfig)
    search_configured: bool = False
    first_run_completed: bool = False
    # Server-authoritative first-run wizard state. ``first_run_completed`` remains
    # for backward compatibility and is kept in sync:
    # pending|in_progress → first_run_completed=False
    # completed|skipped → first_run_completed=True
    onboarding_status: str = Field(
        default="pending",
        description="Onboarding lifecycle: pending | in_progress | completed | skipped",
    )
    desktop_control_enabled: bool = False
    # Deferred product surfaces stay fail-closed until a future release explicitly enables them.
    mobile_enabled: bool = False
    friends_enabled: bool = False
    remote_collaboration_enabled: bool = False
    mcp_manifest: Path | None = Field(
        default=None,
        description="Optional Echo-controlled MCP manifest path",
    )
    appshell_process_split: bool = Field(
        default=False,
        description=(
            "Opt-in AppShell/Echo OS process split. Default off (C-I01). "
            "Does not flip orin.enforce or claim Stage C is implemented."
        ),
    )

    # Echo engine mode. Echo is the only supported runtime architecture.
    # The model/tool adapters remain available under Echo's gates because they
    # perform the actual provider and tool calls; old off/shadow rollout modes
    # are intentionally removed.
    # Set via env var ``JS_ECHO_ENGINE`` (auto-bound by ``env_prefix="JS_"``).
    # Type is plain ``str`` + validator (rather than ``Literal``) because
    # ``from __future__ import annotations`` defers evaluation and confuses
    # Pydantic's forward-ref resolution for ``Literal[...]`` strings.
    echo_engine: str = Field(
        default="on",
        description="Echo engine mode: on",
    )

    @field_validator(
        "mobile_enabled", "friends_enabled", "remote_collaboration_enabled", mode="before"
    )
    @classmethod
    def require_exact_boolean_deferred_feature_gate(cls, value: object) -> bool:
        """Reject coercion so deferred product surfaces remain fail-closed."""
        if type(value) is not bool:
            raise ValueError("deferred feature gate must be an exact boolean")
        return value

    @field_validator("echo_engine")
    @classmethod
    def validate_echo_engine(cls, v: str) -> str:
        """Reject removed rollout/rollback modes and unknown values."""
        return _normalise_echo_engine(v)

    @field_validator("onboarding_status", mode="before")
    @classmethod
    def validate_onboarding_status(cls, value: object) -> str:
        allowed = {"pending", "in_progress", "completed", "skipped"}
        if value is None or value == "":
            return "pending"
        text = str(value).strip().lower()
        if text not in allowed:
            raise ValueError(f"onboarding_status must be one of {sorted(allowed)}, got {value!r}")
        return text

    @model_validator(mode="after")
    def sync_onboarding_with_first_run(self) -> JSSettings:
        """Migrate legacy first_run_completed and keep both fields coherent.

        Terminal states (completed/skipped) always imply first_run_completed.
        ``in_progress`` may keep first_run_completed=True when the wizard is
        reopened from Settings after a prior dismiss (bootstrap must stay closed).
        Legacy configs with only the boolean true migrate pending → completed.
        """
        status = self.onboarding_status
        if status in {"completed", "skipped"}:
            self.first_run_completed = True
            return self
        if status == "pending" and self.first_run_completed:
            # Legacy: only the boolean existed.
            self.onboarding_status = "completed"
            return self
        # pending + first_run false: first boot
        # in_progress + first_run false: first-time wizard mid-flow
        # in_progress + first_run true: reopen after skip/complete
        return self

    @model_validator(mode="after")
    def ensure_directories(self) -> JSSettings:
        # Fail closed when the state directory is the workspace or nested
        # inside it: tool writes are confined to the workspace, and the
        # durable ledger / secret stores under state_dir must stay out of
        # their reach.  Compare resolved paths so symlink aliases cannot
        # hide the nesting.
        workspace_resolved = self.workspace.expanduser().resolve()
        state_resolved = self.state_dir.expanduser().resolve()
        if state_resolved == workspace_resolved or workspace_resolved in state_resolved.parents:
            raise ValueError(
                "workspace must not be the state directory or one of its ancestors: "
                f"workspace={workspace_resolved} state_dir={state_resolved}"
            )
        for root in _personal_storage_roots(self.workspace, self.state_dir):
            _ensure_private_directory(root, label="Personal storage root")
        _ensure_private_directory(self.workspace, label="Personal workspace")
        _ensure_private_directory(self.state_dir, label="Personal state directory")
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

    def apply_runtime_engine_env(self) -> None:
        """Let runtime env vars confirm Echo-only mode.

        Removed rollout values such as ``off`` and ``shadow`` fail closed so
        old architecture paths cannot be re-enabled by environment variables.
        """
        echo_raw = os.getenv("JS_ECHO_ENGINE")
        if echo_raw is None:
            return

        self.echo_engine = _normalise_echo_engine(echo_raw)
        self.__pydantic_fields_set__.add("echo_engine")

    def with_runtime_engine_env(self) -> JSSettings:
        if os.getenv("JS_ECHO_ENGINE") is None:
            return self
        runtime = self.model_copy(deep=True)
        if hasattr(self, "_config_path"):
            runtime._config_path = self._config_path  # type: ignore[attr-defined]
        runtime.apply_runtime_engine_env()
        return runtime

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
    def from_file(
        cls,
        path: Path | str | None = None,
        *,
        allow_hermes_merge: bool | None = None,
    ) -> JSSettings:
        """Load settings from file, or create defaults.

        Priority:
        1. Explicit *path* argument
        2. JS_CONFIG_PATH environment variable
        3. Default locations (~/.config/js/config.{yaml,toml})
        4. Hermes config fallback (~/.hermes/config.yaml) — only when
           ``allow_hermes_merge`` is true (default-compat mode).

        Parsed instances are cached by file mtime to avoid repeated I/O.
        """
        env_path = os.getenv("JS_CONFIG_PATH")
        if allow_hermes_merge is None:
            allow_hermes_merge = path is None and not env_path

        if path:
            p = Path(path).expanduser().resolve()
        elif env_path:
            p = Path(env_path).expanduser().resolve()
        else:
            p = None

        if p is not None:
            from js.product_storage import assert_personal_path_not_in_work_namespace

            assert_personal_path_not_in_work_namespace(p)

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
                            return cached.with_runtime_engine_env()
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
                            return cached.with_runtime_engine_env()
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
                    return cls.from_file(candidate, allow_hermes_merge=True)

        if instance is None:
            instance = cls()
            config_path = Path.home() / ".config" / "js" / "config.yaml"

        instance._config_path = config_path  # type: ignore[attr-defined]
        if allow_hermes_merge:
            instance._merge_hermes()

        # Cache by mtime
        if config_path is not None and config_path.exists():
            try:
                _settings_file_cache[config_path] = (config_path.stat().st_mtime, instance)
            except Exception:
                pass

        return instance.with_runtime_engine_env()

    @property
    def config_source_path(self) -> Path:
        """Resolved source used to load or save this Personal configuration."""
        if hasattr(self, "_config_path") and self._config_path is not None:
            return Path(self._config_path).expanduser().resolve(strict=False)
        return (Path.home() / ".config" / "js" / "config.yaml").resolve(strict=False)

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

        from js.product_storage import assert_personal_path_not_in_work_namespace

        assert_personal_path_not_in_work_namespace(target)

        # Build the new data dict
        new_data = self.model_dump(mode="json", exclude={"providers": {"__all__": {"api_key"}}})

        # Defensive: strip any lingering api_key values from providers before writing
        for provider in new_data.get("providers", []):
            if isinstance(provider, dict):
                provider.pop("api_key", None)

        from js.utils.atomic_config import save_yaml_config

        save_yaml_config(target, new_data, fields=fields)
