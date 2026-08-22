"""Tool registry with schema validation and execution."""

from __future__ import annotations

import asyncio
import contextvars
import copy
import ipaddress
import json
import threading
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from js.config import ToolLimits
from js.echo.primitives import stable_payload_hash
from js.echo.turn_context import current_runtime_context
from js.security.guard import BehaviorGuard, SecurityDecisionType
from js.utils.log import get_logger
from js.utils.metrics import get_metrics, start_span


@dataclass(frozen=True)
class ToolParam:
    name: str
    type: str
    description: str
    required: bool = True
    enum: list[str] | None = None


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    parameters: list[ToolParam]
    dangerous: bool = False  # Requires extra confirmation
    read_only: bool = False  # Safe to retry
    model_visible: bool = True

    def to_openai_schema(self) -> dict[str, Any]:
        """Convert to OpenAI function calling schema."""
        properties: dict[str, Any] = {}
        required: list[str] = []
        seen: set[str] = set()
        for p in self.parameters:
            # Deduplicate by parameter name — some Hermes scripts define the
            # same flag in multiple sub-parsers and our regex scanner picks
            # them all up. OpenAI rejects duplicate property names.
            if p.name in seen:
                continue
            seen.add(p.name)
            prop: dict[str, Any] = {"type": p.type, "description": p.description}
            if p.enum:
                prop["enum"] = p.enum
            properties[p.name] = prop
            if p.required:
                required.append(p.name)

        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": properties,
                    "required": required,
                },
            },
        }


@dataclass
class ToolResult:
    success: bool
    output: str = ""
    error: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_text(self) -> str:
        if self.success:
            return self.output
        return f"Error: {self.error}"


ToolHandler = Callable[..., Awaitable[ToolResult]]
ToolArgumentPolicy = Callable[[dict[str, Any]], dict[str, Any] | ToolResult]
ToolResultPolicy = Callable[[ToolResult], ToolResult]


@dataclass(frozen=True)
class _ArgumentPolicyRegistration:
    """A parameter-only policy that can never capture a raw handler."""

    policy: ToolArgumentPolicy
    path_defaults: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class _ResultPolicyRegistration:
    """A result-only policy that cannot capture or invoke a raw handler."""

    policy: ToolResultPolicy


@dataclass(frozen=True)
class _ToolRegistration:
    """A schema and handler published together in one registry generation."""

    spec: ToolSpec
    handler: ToolHandler
    owner: object | None = None
    generation: int = 0
    argument_policies: tuple[_ArgumentPolicyRegistration, ...] = ()
    result_policies: tuple[_ResultPolicyRegistration, ...] = ()


@dataclass(frozen=True)
class ToolExecutionContext:
    owner_key_hash: str
    run_id: str
    tool_name: str
    args_hash: str
    fs_roots: tuple[str, ...]
    network_policy: str
    max_bytes: int
    max_duration_ms: int
    resource_scope: str = ""
    lease_id: str = ""
    lease_mac: str = ""
    signature: str = ""
    product_id: str = ""
    session_id: str = ""
    profile: str = ""
    network_hosts: tuple[str, ...] = ()


EchoToolExecutionContext = ToolExecutionContext

_CURRENT_TOOL_EXECUTION_CONTEXT: contextvars.ContextVar[
    ToolExecutionContext | None
] = contextvars.ContextVar("echo_tool_execution_context", default=None)


def current_tool_execution_context() -> ToolExecutionContext | None:
    """Return the already-verified context bound to the active handler only."""

    return _CURRENT_TOOL_EXECUTION_CONTEXT.get()


def _argument_policy_binding(value: Any) -> tuple[bool, str | None]:
    """Read an optional immutable path binding exposed by trusted adapters."""
    binding_method = getattr(value, "_registry_argument_policy_binding", None)
    if binding_method is None:
        return False, None
    if not callable(binding_method):
        return True, None
    try:
        binding = binding_method()
    except Exception:
        return True, None
    if type(binding) is not str or not binding:
        return True, None
    return True, binding


def _path_is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _fs_candidates(path: Path, roots: tuple[Path, ...]) -> tuple[Path, ...]:
    """Resolve owner-relative paths and explicit workspace-relative roots."""
    if not path.parts:
        return tuple(root / path for root in roots)

    explicit_root_name = path.parts[0]
    if explicit_root_name in {"local", "owners", "uploads"}:
        candidates: list[Path] = []
        for root in roots:
            for ancestor in (root, *root.parents):
                if ancestor.name == explicit_root_name:
                    candidates.append(ancestor.parent / path)
                    break
        if candidates:
            return tuple(candidates)
    return tuple(root / path for root in roots)


_PATH_ARGUMENT_NAMES = frozenset(
    {
        "path",
        "file",
        "filename",
        "dest",
        "destination",
        "source",
        "src",
        "target",
        "to",
        "dir",
        "directory",
        "cwd",
    }
)


def _is_path_argument(name: str) -> bool:
    return name in _PATH_ARGUMENT_NAMES or name.endswith("_path")


def _cancel_token_requested(token: Any) -> bool:
    """Read common cancellation-token contracts without running user code twice."""
    if token is None:
        return False
    for attribute in ("is_set", "cancelled", "is_cancelled"):
        value = getattr(token, attribute, None)
        if callable(value):
            try:
                value = value()
            except Exception:
                # A broken cancellation token is not proof of cancellation; the
                # authoritative task cancellation check still applies below.
                continue
        if value is True:
            return True
    return False


def tool_requires_network(
    tool_name: str,
    arguments: dict[str, Any] | None = None,
) -> bool:
    normalized = tool_name.replace("-", "_").lower()
    if normalized in {
        "control_clawhub_discover",
        "control_clawhub_install",
        "control_provider_discover",
    }:
        return True
    if normalized == "control_skill_install":
        source = (arguments or {}).get("source", "")
        if isinstance(source, str):
            normalized_source = source.strip().lower()
            return normalized_source.startswith(("http://", "https://", "git@", "git+"))
        return False
    if normalized.startswith(("file_", "code_", "mcp_")):
        return False
    return normalized.startswith(
        ("browser_", "fetch_", "http_", "tavily_", "url_", "web_")
    ) or normalized.endswith(("_fetch", "_http", "_url"))


_SEARCH_NETWORK_HOSTS = (
    "api.tavily.com",
    "cn.bing.com",
    "duckduckgo.com",
    "google.serper.dev",
    "html.duckduckgo.com",
    "lite.duckduckgo.com",
    "www.bing.com",
)


def _canonical_network_host(value: str) -> str:
    host = value.strip().lower().rstrip(".")
    if not host or "\x00" in host:
        raise ValueError("network destination host is missing")
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("network destination host is invalid") from exc


def _network_host_from_resource(value: str) -> str:
    resource = value.strip()
    if resource.startswith("git@") and ":" in resource:
        return _canonical_network_host(resource[4:].split(":", 1)[0])
    parsed = urlsplit(resource)
    if parsed.scheme.lower() not in {"http", "https", "git", "git+https"}:
        raise ValueError("network destination must use an approved URL scheme")
    if not parsed.hostname or parsed.username is not None or parsed.password is not None:
        raise ValueError("network destination URL host is invalid")
    return _canonical_network_host(parsed.hostname)


def _unsafe_network_host_error(host: str) -> str | None:
    canonical = _canonical_network_host(host)
    if canonical == "localhost" or canonical.endswith(".localhost"):
        return "unsafe localhost network destination denied"
    try:
        address = ipaddress.ip_address(canonical)
    except ValueError:
        if not all(
            label
            and len(label) <= 63
            and label[0].isalnum()
            and label[-1].isalnum()
            and all(char.isalnum() or char == "-" for char in label)
            for label in canonical.split(".")
        ):
            return "invalid network destination host denied"
        return None
    if not address.is_global:
        return "unsafe private or metadata network destination denied"
    return None


def required_network_hosts(
    tool_name: str,
    arguments: dict[str, Any] | None = None,
) -> tuple[str, ...]:
    """Return the exact outbound hosts a network-capable tool may contact."""

    args = arguments or {}
    normalized = tool_name.replace("-", "_").lower()
    if not tool_requires_network(normalized, args):
        return ()
    if normalized == "web_search":
        return _SEARCH_NETWORK_HOSTS
    if normalized == "control_clawhub_discover":
        return ("api.github.com", "raw.githubusercontent.com")
    if normalized == "control_clawhub_install":
        return ("api.github.com", "codeload.github.com", "github.com")
    if normalized == "control_provider_discover":
        base_url = args.get("base_url", "")
        if not isinstance(base_url, str) or not base_url.strip():
            raise ValueError("provider discovery requires an exact base_url")
        return (_network_host_from_resource(base_url),)
    if normalized == "control_skill_install":
        return ("api.github.com", "codeload.github.com", "github.com")
    if normalized.startswith("web_") and normalized not in {"web_fetch", "web_search"}:
        # WebBridge is a loopback daemon. Model-controlled localhost access is
        # deliberately never grantable through the normal network lease.
        return ("127.0.0.1",)

    resources = [
        value
        for key, value in args.items()
        if key in {"url", "uri", "source"}
        and isinstance(value, str)
        and value.strip()
    ]
    if not resources:
        raise ValueError("network tool has no inspectable destination")
    return tuple(dict.fromkeys(_network_host_from_resource(value) for value in resources))


def network_authorization_error(
    tool_name: str,
    arguments: dict[str, Any],
    allowed_hosts: tuple[str, ...],
) -> str | None:
    """Validate a tool's exact network destinations against a host allowlist."""

    if not tool_requires_network(tool_name, arguments):
        return None
    try:
        required = required_network_hosts(tool_name, arguments)
        allowed = tuple(_canonical_network_host(host) for host in allowed_hosts)
    except ValueError as exc:
        return f"Echo network allowlist denied: {exc}"
    normalized = tool_name.replace("-", "_").lower()
    for host in (*required, *allowed):
        if normalized == "control_provider_discover":
            canonical = _canonical_network_host(host)
            try:
                address = ipaddress.ip_address(canonical)
            except ValueError:
                unsafe = (
                    None
                    if canonical == "localhost"
                    else _unsafe_network_host_error(canonical)
                )
            else:
                explicit_loopback = address.is_loopback and canonical in {
                    "127.0.0.1",
                    "::1",
                }
                explicit_private = bool(arguments.get("allow_private")) and any(
                    address in network
                    for network in (
                        ipaddress.ip_network("10.0.0.0/8"),
                        ipaddress.ip_network("172.16.0.0/12"),
                        ipaddress.ip_network("192.168.0.0/16"),
                    )
                )
                unsafe = (
                    None
                    if explicit_loopback or explicit_private or address.is_global
                    else "unsafe private or metadata network destination denied"
                )
        else:
            unsafe = _unsafe_network_host_error(host)
        if unsafe is not None:
            return f"Echo network allowlist denied: {unsafe}"
    missing = sorted(set(required) - set(allowed))
    if missing:
        return "Echo network allowlist denied destination: " + ", ".join(missing)
    return None


class ToolRegistry:
    """Central registry for all available tools.

    Features:
    - Self-registration of tool schemas and handlers
    - Concurrent execution limiting via semaphore
    - Result caching for idempotent read-only tools
    - Security guard integration (loop detection, result scanning)
    """

    def __init__(self, limits: ToolLimits, guard: BehaviorGuard) -> None:
        self.limits = limits
        self.guard = guard
        self._tools: dict[str, ToolSpec] = {}
        self._handlers: dict[str, ToolHandler] = {}
        self._call_counts: dict[str, int] = {}
        self._registrations: dict[str, _ToolRegistration] = {}
        self._lock = threading.RLock()
        self._semaphore = asyncio.Semaphore(limits.max_concurrent_tools)
        self.logger = get_logger("js.tools.registry")
        # Simple LRU cache for tool results: (tool_name, args_key) -> ToolResult
        self._result_cache: dict[tuple[str, str], tuple[ToolResult, float]] = {}
        self._cache_ttl_seconds = 30.0
        self._cache_max_size = 128
        self._echo_context_verifier: Callable[[ToolExecutionContext], str | None] | None = None
        self._echo_context_verifier_locked = False

    @property
    def echo_context_verifier(
        self,
    ) -> Callable[[ToolExecutionContext], str | None] | None:
        return self._echo_context_verifier

    @echo_context_verifier.setter
    def echo_context_verifier(
        self,
        value: Callable[[ToolExecutionContext], str | None] | None,
    ) -> None:
        raise RuntimeError(
            "ToolRegistry.echo_context_verifier is read-only; use "
            "install_echo_context_verifier() so the lease verifier cannot "
            "be replaced by a forged callable."
        )

    def install_echo_context_verifier(
        self,
        verifier: Callable[[ToolExecutionContext], str | None],
    ) -> None:
        """Bind the Echo lease verifier exactly once.

        After the first call the verifier is locked: subsequent calls with a
        *different* verifier raise ``RuntimeError`` so external code cannot
        swap in a forged verifier that approves fake leases.  Re-installing
        the exact same callable is a no-op so test fixtures that re-issue
        signed contexts on the same registry remain composable.
        """
        if self._echo_context_verifier_locked:
            if self._echo_context_verifier is verifier:
                return
            raise RuntimeError(
                "ToolRegistry.echo_context_verifier is already locked and "
                "cannot be replaced by a different verifier."
            )
        self._echo_context_verifier = verifier
        self._echo_context_verifier_locked = True

    def register(
        self,
        spec: ToolSpec,
        handler: ToolHandler,
        *,
        owner: object | None = None,
        generation: int = 0,
    ) -> None:
        """Register a tool with its specification and handler."""
        registration = _ToolRegistration(spec, handler, owner, generation)
        with self._lock:
            self._invalidate_cache_locked(spec.name)
            self._registrations[spec.name] = registration
            self._tools[spec.name] = spec
            self._handlers[spec.name] = handler
            self._call_counts[spec.name] = 0

    def replace_owned(
        self,
        owner: object,
        generation: int,
        registrations: list[tuple[ToolSpec, ToolHandler]],
    ) -> frozenset[str]:
        """Atomically replace a manager's tools without touching other owners.

        Names already owned by another component are preserved.  This gives a
        lifecycle owner a way to publish a complete generation and later remove
        exactly that generation, without globally closing the registry.
        """
        desired = {
            spec.name: _ToolRegistration(spec, handler, owner, generation)
            for spec, handler in registrations
        }
        with self._lock:
            previous = self._registrations
            next_registrations = {
                name: registration
                for name, registration in previous.items()
                if registration.owner is not owner
            }
            accepted: set[str] = set()
            for name, registration in desired.items():
                current = previous.get(name)
                if current is not None and current.owner is not owner:
                    continue
                next_registrations[name] = registration
                accepted.add(name)

            changed_names = {
                name
                for name in set(previous) | set(next_registrations)
                if previous.get(name) is not next_registrations.get(name)
            }
            self._registrations = next_registrations
            self._tools = {
                name: registration.spec for name, registration in next_registrations.items()
            }
            self._handlers = {
                name: registration.handler for name, registration in next_registrations.items()
            }
            self._call_counts = {
                name: self._call_counts.get(name, 0) if name in previous else 0
                for name in next_registrations
            }
            for name in changed_names:
                self._invalidate_cache_locked(name)
            return frozenset(accepted)

    def unregister(
        self,
        name: str,
        *,
        owner: object | None = None,
        generation: int | None = None,
    ) -> bool:
        """Unregister a tool, optionally only when its owner/generation matches."""
        with self._lock:
            registration = self._registrations.get(name)
            if registration is None:
                return False
            if owner is not None and registration.owner is not owner:
                return False
            if generation is not None and registration.generation != generation:
                return False
            self._invalidate_cache_locked(name)
            self._registrations.pop(name, None)
            self._tools.pop(name, None)
            self._handlers.pop(name, None)
            self._call_counts.pop(name, None)
            return True

    def get(self, name: str) -> ToolSpec | None:
        with self._lock:
            return self._tools.get(name)

    def get_handler(self, name: str) -> ToolHandler | None:
        """Return a fail-closed compatibility proxy, never a raw handler.

        Tool execution must pass through :meth:`execute`, where the Echo
        execution context and single-use capability lease are validated.  The
        compatibility proxy deliberately cannot be upgraded into an execution
        path, even if a caller happens to hold a runtime context.
        """
        with self._lock:
            if name not in self._registrations:
                return None

        async def _deny_direct_handler_access(**_arguments: Any) -> ToolResult:
            return ToolResult(
                success=False,
                error=(
                    "Echo execution context required; direct tool handler access "
                    "is disabled, use ToolRegistry.execute"
                ),
            )

        return _deny_direct_handler_access

    def register_argument_policy(
        self,
        name: str,
        policy: ToolArgumentPolicy,
        *,
        path_defaults: dict[str, str] | None = None,
    ) -> bool:
        """Register a parameter-only policy for one tool.

        Policies receive a deep copy of the model-authorized arguments.  They
        never receive a handler or a continuation, so Python closure reflection
        cannot recover a raw execution path.  Any transformation is revalidated
        against the consumed Echo lease before the business handler starts.
        """
        if not callable(policy):
            raise TypeError("tool argument policy must be callable")
        defaults = dict(path_defaults or {})
        if any(not _is_path_argument(key) for key in defaults):
            raise ValueError("tool argument policy defaults must be path arguments")
        if any(not isinstance(value, str) or not value.strip() for value in defaults.values()):
            raise ValueError("tool argument policy path defaults must be non-empty strings")

        with self._lock:
            registration = self._registrations.get(name)
            if registration is None:
                return False
            replacement = _ToolRegistration(
                registration.spec,
                registration.handler,
                registration.owner,
                registration.generation,
                registration.argument_policies
                + (_ArgumentPolicyRegistration(policy, tuple(sorted(defaults.items()))),),
                registration.result_policies,
            )
            self._invalidate_cache_locked(name)
            self._registrations[name] = replacement
            self._handlers[name] = replacement.handler
            return True

    def register_result_policy(self, name: str, policy: ToolResultPolicy) -> bool:
        """Register a post-handler policy without exposing the underlying handler."""
        if not callable(policy):
            raise TypeError("tool result policy must be callable")
        with self._lock:
            registration = self._registrations.get(name)
            if registration is None:
                return False
            replacement = _ToolRegistration(
                registration.spec,
                registration.handler,
                registration.owner,
                registration.generation,
                registration.argument_policies,
                registration.result_policies + (_ResultPolicyRegistration(policy),),
            )
            self._invalidate_cache_locked(name)
            self._registrations[name] = replacement
            self._handlers[name] = replacement.handler
            return True

    async def _invoke_registration(
        self,
        registration: _ToolRegistration,
        arguments: dict[str, Any],
        execution_context: ToolExecutionContext,
    ) -> ToolResult:
        cancellation_error = self._execution_cancellation_error(execution_context)
        if cancellation_error is not None:
            return ToolResult(success=False, error=cancellation_error)
        with self._lock:
            if self._registrations.get(registration.spec.name) is not registration:
                return ToolResult(success=False, error=f"Unknown tool: {registration.spec.name}")
        token = _CURRENT_TOOL_EXECUTION_CONTEXT.set(execution_context)
        try:
            result = await registration.handler(**arguments)
            if not isinstance(result, ToolResult):
                return ToolResult(success=False, error="Tool handler returned an invalid result")
            for configured in registration.result_policies:
                cancellation_error = self._execution_cancellation_error(execution_context)
                if cancellation_error is not None:
                    return ToolResult(success=False, error=cancellation_error)
                try:
                    decision = configured.policy(copy.deepcopy(result))
                except Exception as exc:
                    return ToolResult(
                        success=False,
                        error=f"Tool result policy failed closed: {type(exc).__name__}",
                    )
                if not isinstance(decision, ToolResult):
                    return ToolResult(
                        success=False,
                        error="Tool result policy returned an invalid result",
                    )
                result = decision
            return result
        finally:
            _CURRENT_TOOL_EXECUTION_CONTEXT.reset(token)

    def _apply_argument_policies(
        self,
        registration: _ToolRegistration,
        arguments: dict[str, Any],
        execution_context: ToolExecutionContext,
    ) -> tuple[dict[str, Any] | None, ToolResult | None]:
        effective = copy.deepcopy(arguments)
        for configured in registration.argument_policies:
            cancellation_error = self._execution_cancellation_error(execution_context)
            if cancellation_error is not None:
                return None, ToolResult(success=False, error=cancellation_error)
            try:
                decision = configured.policy(copy.deepcopy(effective))
            except Exception as exc:
                return None, ToolResult(
                    success=False,
                    error=f"Tool argument policy failed closed: {type(exc).__name__}",
                )
            cancellation_error = self._execution_cancellation_error(execution_context)
            if cancellation_error is not None:
                return None, ToolResult(success=False, error=cancellation_error)
            if isinstance(decision, ToolResult):
                if decision.success:
                    return None, ToolResult(
                        success=False,
                        error="Tool argument policy returned an invalid success result",
                    )
                return None, decision
            if not isinstance(decision, dict) or any(
                not isinstance(key, str) for key in decision
            ):
                return None, ToolResult(
                    success=False,
                    error="Tool argument policy must return a string-keyed argument mapping",
                )

            mutation_error = self._validate_policy_mutation(
                tool_name=registration.spec.name,
                before=effective,
                after=decision,
                path_defaults=dict(configured.path_defaults),
                execution_context=execution_context,
            )
            if mutation_error is not None:
                return None, ToolResult(success=False, error=mutation_error)
            resource_error = self._validate_resource_arguments(
                registration.spec.name,
                decision,
                execution_context,
            )
            if resource_error is not None:
                return None, ToolResult(success=False, error=resource_error)
            effective = copy.deepcopy(decision)

        return effective, None

    def _validate_policy_mutation(
        self,
        *,
        tool_name: str,
        before: dict[str, Any],
        after: dict[str, Any],
        path_defaults: dict[str, str],
        execution_context: ToolExecutionContext,
    ) -> str | None:
        if (
            execution_context.network_policy != "allow"
            and not tool_requires_network(tool_name, before)
            and tool_requires_network(tool_name, after)
        ):
            return "Echo execution context network_policy denied downstream arguments"

        missing = object()
        for key in set(before) | set(after):
            previous = before.get(key, missing)
            current = after.get(key, missing)
            if not _is_path_argument(key):
                if previous is missing or current is missing or previous != current:
                    return "Tool argument policy changed lease-bound non-path arguments"
                continue
            if current is missing:
                return "Tool argument policy removed a lease-bound path argument"
            if previous is missing:
                previous = path_defaults.get(key, missing)
                if previous is missing:
                    return "Tool argument policy added an unauthorized path argument"
            previous_bound, previous_binding = _argument_policy_binding(previous)
            current_bound, current_binding = _argument_policy_binding(current)
            if (previous_bound and previous_binding is None) or (
                current_bound and current_binding is None
            ):
                return "Tool argument policy returned an invalid path snapshot binding"
            if previous_bound and (
                not current_bound or current_binding != previous_binding
            ):
                return "Tool argument policy changed a lease-bound path snapshot binding"
            if previous == current:
                continue
            if not isinstance(previous, str) or not isinstance(current, str):
                return "Tool argument policy path arguments must remain strings"
            previous_resource = self._canonical_fs_resource(previous, execution_context)
            current_resource = self._canonical_fs_resource(current, execution_context)
            if previous_resource is None or current_resource != previous_resource:
                return "Tool argument policy changed the canonical resource"
        return None

    @staticmethod
    def _canonical_fs_resource(
        value: str,
        execution_context: ToolExecutionContext,
    ) -> Path | None:
        if not value.strip():
            return None
        roots = tuple(Path(root).expanduser().resolve() for root in execution_context.fs_roots)
        if not roots:
            return None
        path = Path(value).expanduser()
        candidates = (path,) if path.is_absolute() else _fs_candidates(path, roots)
        if not candidates:
            return None
        try:
            resolved = candidates[0].resolve()
        except (OSError, RuntimeError, ValueError):
            return None
        if not any(_path_is_within(resolved, root) for root in roots):
            return None
        return resolved

    @staticmethod
    def _execution_cancellation_error(
        execution_context: ToolExecutionContext,
    ) -> str | None:
        task = asyncio.current_task()
        if task is not None and task.cancelling():
            return "Echo tool execution cancelled before handler start"
        runtime_context = current_runtime_context()
        if (
            runtime_context is not None
            and runtime_context.run_id == execution_context.run_id
            and runtime_context.owner_key_hash == execution_context.owner_key_hash
            and _cancel_token_requested(runtime_context.cancel_token)
        ):
            return "Echo tool execution cancelled before handler start"
        return None

    def _validate_resource_arguments(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        execution_context: ToolExecutionContext,
    ) -> str | None:
        if (
            tool_requires_network(tool_name, arguments)
            and execution_context.network_policy != "allow"
        ):
            return "Echo execution context network_policy denied"
        network_error = network_authorization_error(
            tool_name,
            arguments,
            execution_context.network_hosts,
        )
        if network_error is not None:
            return network_error
        return self._validate_fs_arguments(arguments, execution_context)

    def list_tools(self) -> list[ToolSpec]:
        with self._lock:
            return list(self._tools.values())

    def to_openai_schemas(self) -> list[dict[str, Any]]:
        with self._lock:
            tools = tuple(self._tools.values())
        return [tool.to_openai_schema() for tool in tools if tool.model_visible]

    def _cache_key(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        execution_context: ToolExecutionContext | None = None,
    ) -> tuple[str, str]:
        """Build a cache key for a tool call."""
        scope: dict[str, Any] = {"arguments": arguments}
        if execution_context is not None:
            scope["echo"] = self._cache_scope(execution_context)
        return (tool_name, json.dumps(scope, sort_keys=True))

    @staticmethod
    def _cache_scope(execution_context: ToolExecutionContext) -> dict[str, Any]:
        """Return the Echo partition which owns one cached read result."""
        return {
            "product_id": execution_context.product_id,
            "owner": execution_context.owner_key_hash,
            "session_id": execution_context.session_id,
            "profile": execution_context.profile,
            "run_id": execution_context.run_id,
            "resource_scope": execution_context.resource_scope,
            "fs_roots": execution_context.fs_roots,
            "network_policy": execution_context.network_policy,
            "network_hosts": execution_context.network_hosts,
        }

    def _get_cached(self, key: tuple[str, str]) -> ToolResult | None:
        """Get a cached result if fresh."""
        with self._lock:
            entry = self._result_cache.get(key)
            if not entry:
                return None
            result, timestamp = entry
            if time.monotonic() - timestamp > self._cache_ttl_seconds:
                del self._result_cache[key]
                return None
            return copy.deepcopy(result)

    def _set_cached(self, key: tuple[str, str], result: ToolResult) -> None:
        """Cache a tool result, evicting oldest if at capacity."""
        with self._lock:
            if len(self._result_cache) >= self._cache_max_size:
                # Evict oldest entry
                oldest = min(self._result_cache, key=lambda k: self._result_cache[k][1])
                del self._result_cache[oldest]
            self._result_cache[key] = (copy.deepcopy(result), time.monotonic())

    def invalidate_cache(self, tool_name: str | None = None) -> None:
        """Invalidate cached read results after tool or runtime configuration changes."""
        with self._lock:
            if tool_name is None:
                self._result_cache.clear()
                return
            self._invalidate_cache_locked(tool_name)

    def _invalidate_cache_locked(self, tool_name: str) -> None:
        for key in tuple(self._result_cache):
            if key[0] == tool_name:
                self._result_cache.pop(key, None)

    def _invalidate_scoped_read_cache_locked(
        self,
        execution_context: ToolExecutionContext,
    ) -> None:
        """Forget cached reads only in the successful mutation's Echo scope."""
        scope = json.dumps(self._cache_scope(execution_context), sort_keys=True)
        for key in tuple(self._result_cache):
            try:
                cached_scope = json.loads(key[1]).get("echo")
            except (TypeError, ValueError, json.JSONDecodeError):
                continue
            if json.dumps(cached_scope, sort_keys=True) == scope:
                self._result_cache.pop(key, None)

    def _is_cacheable(self, tool_name: str) -> bool:
        """Determine if a tool's results can be safely cached."""
        with self._lock:
            spec = self._tools.get(tool_name)
            registration = self._registrations.get(tool_name)
        if not spec:
            return False
        # Parameter policies are security middleware.  They must run for every
        # invocation and their decision must never be replaced by stale output.
        if registration is not None and registration.argument_policies:
            return False
        # Cache read-only tools (file_read, browser_fetch, etc.)
        if spec.read_only:
            return True
        # Cache safe built-ins by name heuristic
        cacheable_names = {"file_read", "file_list", "file_search", "browser_fetch", "web_search"}
        return tool_name in cacheable_names or tool_name.replace("skill_", "") in cacheable_names

    def _is_mutating_tool(self, tool_name: str) -> bool:
        """Return whether a successful tool can invalidate filesystem read data."""
        with self._lock:
            spec = self._tools.get(tool_name)
        return spec is not None and not spec.read_only and not self._is_cacheable(tool_name)

    async def execute(
        self,
        run_id: str,
        tool_name: str,
        arguments: dict[str, Any],
        *,
        echo_mode: str | None = None,
        execution_context: ToolExecutionContext | None = None,
        echo_context: ToolExecutionContext | None = None,
    ) -> ToolResult:
        """Execute a tool with security checks, caching, and limits."""
        if execution_context is None:
            execution_context = echo_context
        context_error = self._validate_echo_context(
            run_id=run_id,
            tool_name=tool_name,
            arguments=arguments,
            echo_mode=echo_mode,
            execution_context=execution_context,
        )
        if context_error is not None:
            return ToolResult(success=False, error=context_error)
        assert execution_context is not None

        with self._lock:
            registration = self._registrations.get(tool_name)
        if registration is None:
            return ToolResult(success=False, error=f"Unknown tool: {tool_name}")
        cancellation_error = self._execution_cancellation_error(execution_context)
        if cancellation_error is not None:
            return ToolResult(success=False, error=cancellation_error)
        effective_arguments, policy_error = self._apply_argument_policies(
            registration,
            arguments,
            execution_context,
        )
        if policy_error is not None:
            return policy_error
        assert effective_arguments is not None
        cancellation_error = self._execution_cancellation_error(execution_context)
        if cancellation_error is not None:
            return ToolResult(success=False, error=cancellation_error)
        # Security: loop detection
        args_key = json.dumps(effective_arguments, sort_keys=True)
        loop_decision = self.guard.check_loop(run_id, tool_name, args_key)
        if loop_decision.decision == SecurityDecisionType.BLOCK:
            return ToolResult(success=False, error=f"Security: {loop_decision.reason}")

        # Check cache for idempotent tools
        cache_key = self._cache_key(tool_name, effective_arguments, execution_context)
        if self._is_cacheable(tool_name):
            cached = self._get_cached(cache_key)
            if cached is not None:
                self.logger.debug(f"Cache hit for {tool_name}")
                if (
                    execution_context is not None
                    and cached.output
                    and len(cached.output.encode("utf-8")) > execution_context.max_bytes
                ):
                    return ToolResult(
                        success=False,
                        error="Echo execution context max_bytes exceeded",
                    )
                with self._lock:
                    if self._registrations.get(tool_name) is registration:
                        return cached

        async with self._semaphore:
            try:
                # A lifecycle owner may have replaced or revoked this tool
                # while the call waited for a concurrency slot.
                with self._lock:
                    if self._registrations.get(tool_name) is not registration:
                        return ToolResult(success=False, error=f"Unknown tool: {tool_name}")
                cancellation_error = self._execution_cancellation_error(execution_context)
                if cancellation_error is not None:
                    return ToolResult(success=False, error=cancellation_error)
                try:
                    get_metrics().tool_calls_total.labels(tool_name=tool_name).inc()
                except Exception:
                    self.logger.warning("Suppressed error", exc_info=True)
                start = time.perf_counter()
                with start_span("tool.execute", {"tool_name": tool_name}):
                    try:
                        if execution_context is not None and execution_context.max_duration_ms > 0:
                            result = await asyncio.wait_for(
                                self._invoke_registration(
                                    registration,
                                    effective_arguments,
                                    execution_context,
                                ),
                                timeout=execution_context.max_duration_ms / 1000.0,
                            )
                        else:
                            result = await self._invoke_registration(
                                registration,
                                effective_arguments,
                                execution_context,
                            )
                        with self._lock:
                            if self._registrations.get(tool_name) is registration:
                                self._call_counts[tool_name] = (
                                    self._call_counts.get(tool_name, 0) + 1
                                )

                        if (
                            execution_context is not None
                            and result.output
                            and len(result.output.encode("utf-8")) > execution_context.max_bytes
                        ):
                            return ToolResult(
                                success=False,
                                error="Echo execution context max_bytes exceeded",
                            )

                        # Enforce tool output budget
                        budget = int(getattr(self.limits, "tool_output_budget_chars", 20_000))
                        if result.output and len(result.output) > budget:
                            original_len = len(result.output)
                            result.output = (
                                result.output[:budget]
                                + f"\n... [output truncated: {original_len} chars; use file_read with offset/limit to paginate]"
                            )
                            result.metadata["truncated"] = True
                            result.metadata["original_len"] = original_len

                        # Scan tool result
                        if result.output:
                            scan = self.guard.check_tool_result(result.output)
                            if scan.decision == SecurityDecisionType.BLOCK:
                                # Fail closed: high-confidence injection in a tool
                                # result never reaches the model.
                                self.logger.warning(
                                    "Tool result blocked by security scan (%s): %s",
                                    tool_name,
                                    scan.reason,
                                )
                                return ToolResult(
                                    success=False,
                                    error=f"Security: tool result blocked ({scan.reason})",
                                )
                            if scan.decision == SecurityDecisionType.WARN:
                                result.output = (
                                    f"[Security Warning: {scan.reason}]\n{result.output}"
                                )

                        # Cache successful reads. A successful mutating call may
                        # have changed any filesystem result in this one Echo
                        # partition, so conservatively discard its read cache.
                        if result.success:
                            if self._is_cacheable(tool_name):
                                with self._lock:
                                    still_registered = (
                                        self._registrations.get(tool_name) is registration
                                    )
                                if still_registered:
                                    self._set_cached(cache_key, result)
                            elif self._is_mutating_tool(tool_name):
                                with self._lock:
                                    self._invalidate_scoped_read_cache_locked(execution_context)

                        latency = time.perf_counter() - start
                        try:
                            get_metrics().tool_latency_seconds.labels(tool_name=tool_name).observe(
                                latency
                            )
                        except Exception:
                            self.logger.warning("Suppressed error", exc_info=True)
                        return result
                    except asyncio.CancelledError:
                        raise
                    except Exception as exc:
                        latency = time.perf_counter() - start
                        try:
                            get_metrics().tool_latency_seconds.labels(tool_name=tool_name).observe(
                                latency
                            )
                            get_metrics().tool_errors_total.labels(tool_name=tool_name).inc()
                        except Exception:
                            self.logger.warning("Metrics error", exc_info=True)
                        self.logger.error(
                            "Tool execution failed for %s: %s",
                            tool_name,
                            type(exc).__name__,
                        )
                        return ToolResult(success=False, error="Tool execution failed safely")
            except Exception as exc:
                # Outer guard: metrics/span machinery failed; still report the error
                self.logger.warning(
                    "Tool registry outer error for %s: %s",
                    tool_name,
                    type(exc).__name__,
                )
                return ToolResult(success=False, error="Tool execution failed safely")

    def _validate_echo_context(
        self,
        *,
        run_id: str,
        tool_name: str,
        arguments: dict[str, Any],
        echo_mode: str | None,
        execution_context: ToolExecutionContext | None,
    ) -> str | None:
        mode = self._effective_echo_mode(echo_mode)
        if mode != "on":
            return "Echo is the only supported architecture for tool execution"
        if execution_context is None:
            return "Echo execution context required for tool execution"
        if execution_context.run_id != run_id:
            return "Echo execution context run_id mismatch"
        if execution_context.tool_name != tool_name:
            return "Echo execution context tool_name mismatch"
        expected_args_hash = stable_payload_hash(arguments)
        if execution_context.args_hash != expected_args_hash:
            return "Echo execution context args_hash mismatch"
        if execution_context.max_bytes < 0:
            return "Echo execution context max_bytes invalid"
        if execution_context.max_duration_ms < 0:
            return "Echo execution context max_duration_ms invalid"
        if not execution_context.signature:
            return "Echo execution context signature required"
        if not execution_context.lease_id:
            return "Echo execution context lease_id required"
        if not execution_context.lease_mac:
            return "Echo execution context lease_mac required"
        if self.echo_context_verifier is None:
            return "Echo execution context lease verifier required"
        if (
            tool_requires_network(tool_name, arguments)
            and execution_context.network_policy != "allow"
        ):
            return "Echo execution context network_policy denied"
        network_error = network_authorization_error(
            tool_name,
            arguments,
            execution_context.network_hosts,
        )
        if network_error is not None:
            return network_error
        fs_error = self._validate_fs_arguments(arguments, execution_context)
        if fs_error is not None:
            return fs_error
        verifier_error = self.echo_context_verifier(execution_context)
        if verifier_error is not None:
            return verifier_error
        return None

    def _effective_echo_mode(self, echo_mode: str | None) -> str:
        if echo_mode:
            return echo_mode
        return "on"

    @staticmethod
    def _validate_fs_arguments(
        arguments: dict[str, Any],
        execution_context: ToolExecutionContext,
    ) -> str | None:
        roots = tuple(Path(root).expanduser().resolve() for root in execution_context.fs_roots)
        path_aliases = {
            "path",
            "file",
            "filename",
            "dest",
            "destination",
            "source",
            "src",
            "target",
            "to",
            "dir",
            "directory",
            "cwd",
        }
        has_path_argument = any(
            (
                key in path_aliases
                or key.endswith("_path")
            )
            and isinstance(value, str)
            and value.strip()
            and not value.startswith(("http://", "https://", "ftp://", "ws://", "wss://"))
            for key, value in arguments.items()
        )
        if not roots:
            if has_path_argument:
                return "Echo execution context fs_roots required for path arguments (fail-closed)"
            return None
        for key, value in arguments.items():
            if (
                key not in path_aliases
                and not key.endswith("_path")
            ) or not isinstance(value, str) or not value.strip():
                continue
            if value.startswith(("http://", "https://", "ftp://", "ws://", "wss://")):
                continue
            candidate = Path(value).expanduser()
            candidates = (candidate,) if candidate.is_absolute() else _fs_candidates(
                candidate,
                roots,
            )
            if not any(
                _path_is_within(resolved, root)
                for candidate in candidates
                for resolved in (candidate.resolve(),)
                for root in roots
            ):
                return "Echo execution context fs_roots denied"
        return None

    def get_stats(self) -> dict[str, int]:
        with self._lock:
            return dict(self._call_counts)


class ParallelToolExecutor:
    """Intelligent parallel execution scheduler for tool calls.

    Groups tool calls so that:
    - Independent read-only tools run in parallel
    - Mutating tools or tools touching the same path run sequentially
    - NEVER_PARALLEL_TOOLS (shell, file_write, etc.) never run concurrently
    """

    NEVER_PARALLEL_TOOLS: frozenset[str] = frozenset(
        {
            "file_write",
            "shell",
            "python",
            "code_execute",
            "file_delete",
            "file_edit",
            "file_append",
            "file_move",
            # Desktop control: sequential to avoid interference
            "desktop_click",
            "desktop_move",
            "desktop_scroll",
            "desktop_drag",
            "desktop_type",
            "desktop_key",
            "desktop_app",
            "desktop_window",
            "desktop_set_mode",
            "desktop_emergency_stop",
            "desktop_clear_stop",
        }
    )
    KNOWN_READ_ONLY_TOOLS: frozenset[str] = frozenset(
        {
            "browser_fetch",
            "code_search",
            "csv_read",
            "excel_read",
            "file_list",
            "file_read",
            "file_search",
            "file_view",
            "web_list_tabs",
            "web_search",
            "web_snapshot",
        }
    )

    def __init__(
        self,
        max_parallel: int = 4,
        *,
        registry: Any | None = None,
        workspace: Path | None = None,
    ) -> None:
        self.max_parallel = max_parallel
        self.registry = registry
        self.workspace = workspace.expanduser().resolve() if workspace is not None else None

    @staticmethod
    def _get_tool_name(call: dict[str, Any]) -> str:
        func = call.get("function", {}) if isinstance(call, dict) else {}
        return func.get("name", "") if isinstance(func, dict) else ""

    @staticmethod
    def _get_arguments(call: dict[str, Any]) -> dict[str, Any]:
        func = call.get("function", {}) if isinstance(call, dict) else {}
        raw = func.get("arguments", "{}") if isinstance(func, dict) else "{}"
        if isinstance(raw, dict):
            return raw
        try:
            result: dict[str, Any] = json.loads(raw)
            return result
        except Exception:
            return {}

    def _has_path_overlap(self, call1: dict[str, Any], call2: dict[str, Any]) -> bool:
        """Check canonical paths across every recognized path argument."""
        return bool(self._argument_paths(call1) & self._argument_paths(call2))

    def _argument_paths(self, call: dict[str, Any]) -> set[Path]:
        paths: set[Path] = set()
        for key, value in self._get_arguments(call).items():
            if not _is_path_argument(str(key)) or not isinstance(value, str) or not value:
                continue
            path = Path(value).expanduser()
            if not path.is_absolute() and self.workspace is not None:
                path = self.workspace / path
            try:
                paths.add(path.resolve(strict=False))
            except (OSError, RuntimeError):
                # An uncanonicalizable path is unsafe to parallelize; map all
                # such arguments to one sentinel so they always conflict.
                paths.add(Path("/__echo_uncanonicalizable_path__"))
        return paths

    def _is_safe_parallel(self, call: dict[str, Any]) -> bool:
        """Determine if a single tool call can safely run in parallel with others."""
        tool_name = self._get_tool_name(call)
        if not tool_name or tool_name in self.NEVER_PARALLEL_TOOLS:
            return False
        if self.registry is not None:
            spec = self.registry.get(tool_name)
            return bool(spec is not None and spec.read_only)
        return tool_name in self.KNOWN_READ_ONLY_TOOLS

    def group(self, tool_calls: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
        """Group tool_calls into batches that can run concurrently.

        Returns a list of batches. Each batch is safe to asyncio.gather().
        Batches must be executed sequentially.
        """
        if not tool_calls:
            return []

        # If any call is in NEVER_PARALLEL, run everything sequentially
        if any(not self._is_safe_parallel(tc) for tc in tool_calls):
            return [[tc] for tc in tool_calls]

        batches: list[list[dict[str, Any]]] = []
        pending = list(tool_calls)

        while pending:
            batch = [pending.pop(0)]
            i = 0
            while i < len(pending) and len(batch) < self.max_parallel:
                candidate = pending[i]
                # Check overlap with every member of current batch
                if not any(self._has_path_overlap(candidate, member) for member in batch):
                    batch.append(candidate)
                    pending.pop(i)
                else:
                    i += 1
            batches.append(batch)

        return batches
