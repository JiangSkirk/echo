"""Echo tool execution context enforcement tests."""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from js.agent.tool_executor import ToolExecutorMixin
from js.echo import stable_payload_hash
from js.echo.capability import LeaseAuthority, sign_tool_execution_context
from js.echo.durable_thread import EchoDurableExecutor
from js.echo.ledger.service import EchoSafetyService
from js.echo.turn_context import RuntimeContext, reset_runtime_context, set_runtime_context
from js.security.guard import BehaviorGuard
from js.tools.registry import (
    ToolExecutionContext,
    ToolRegistry,
    ToolResult,
    ToolSpec,
    current_tool_execution_context,
)

_TEST_DURABLE_EXECUTOR = EchoDurableExecutor(
    max_claim_pending=4,
    max_finish_pending=4,
    claim_workers=2,
    finish_workers=2,
    thread_name_prefix="echo-tool-context-test",
)


@pytest.fixture(scope="module", autouse=True)
def _close_test_durable_executor() -> Iterator[None]:
    yield
    _TEST_DURABLE_EXECUTOR.shutdown(wait=True)


class _SecurityConfig:
    defense_mode = "enforce"
    protected_commands: list[str] = []
    protected_paths: list[str] = []
    allow_workspace_delete = False
    encoding_guard = True
    tool_result_scan = True
    script_provenance = False
    max_loop_iterations = 5
    tool_name_loop_threshold = 4


def _registry(tmp_path: Path) -> ToolRegistry:
    limits = SimpleNamespace(max_concurrent_tools=4, tool_output_budget_chars=10_000)
    guard = BehaviorGuard(_SecurityConfig(), tmp_path)
    return ToolRegistry(limits, guard)


def _context(**overrides: Any) -> ToolExecutionContext:
    data = {
        "product_id": "js-agent",
        "session_id": "session-a",
        "profile": "default",
        "owner_key_hash": "owner-a",
        "run_id": "run-a",
        "tool_name": "file_read",
        "args_hash": stable_payload_hash({"path": "a.txt"}),
        "fs_roots": ("/tmp/workspace",),
        "network_policy": "deny",
        "network_hosts": (),
        "max_bytes": 100,
        "max_duration_ms": 1_000,
    }
    data.update(overrides)
    return ToolExecutionContext(**data)


_TOOL_LEASE_AUTHORITY = LeaseAuthority(
    mac_key=b"test-tool-lease-key-32-bytes!!", now_fn=lambda: 1_000
)


def _tool_consume_context(execution_context: ToolExecutionContext) -> str | None:
    try:
        _TOOL_LEASE_AUTHORITY.consume_execution_context(execution_context, now=1_000)
    except Exception as exc:
        return f"Echo execution context lease denied: {type(exc).__name__}"
    return None


def _signed_context(
    registry: ToolRegistry,
    **overrides: Any,
) -> ToolExecutionContext:
    context = _context(**overrides)
    authority = _TOOL_LEASE_AUTHORITY
    lease = authority.issue(
        product_id=context.product_id,
        session_id=context.session_id,
        owner_key_hash=context.owner_key_hash,
        run_id=context.run_id,
        tool_name=context.tool_name,
        args_schema=context.args_hash,
        resource_scope=context.resource_scope,
        fs_roots=context.fs_roots,
        network_policy=context.network_policy,
        network_hosts=context.network_hosts,
        max_bytes=context.max_bytes,
        max_duration_ms=context.max_duration_ms,
        ttl_ms=60_000,
    )
    signed = sign_tool_execution_context(
        context,
        lease=lease,
        authority=authority,
        now=1_000,
    )

    registry.install_echo_context_verifier(_tool_consume_context)
    return signed


def test_tool_context_signing_requires_lease_authority() -> None:
    context = _context()
    authority = LeaseAuthority(mac_key=b"test-tool-lease-key-32-bytes!!", now_fn=lambda: 1_000)
    lease = authority.issue(
        product_id=context.product_id,
        session_id=context.session_id,
        owner_key_hash=context.owner_key_hash,
        run_id=context.run_id,
        tool_name=context.tool_name,
        args_schema=context.args_hash,
        resource_scope=context.resource_scope,
        fs_roots=context.fs_roots,
        network_policy=context.network_policy,
        network_hosts=context.network_hosts,
        max_bytes=context.max_bytes,
        max_duration_ms=context.max_duration_ms,
        ttl_ms=60_000,
    )

    with pytest.raises(ValueError, match="authority"):
        sign_tool_execution_context(context, lease=lease, now=1_000)


@pytest.mark.asyncio
async def test_echo_on_direct_registry_execute_without_context_fails_closed(
    tmp_path: Path,
) -> None:
    registry = _registry(tmp_path)

    async def handler(path: str) -> ToolResult:
        return ToolResult(success=True, output=f"read {path}")

    registry.register(
        ToolSpec(name="file_read", description="read", parameters=[], read_only=True),
        handler,
    )

    result = await registry.execute("run-a", "file_read", {"path": "a.txt"}, echo_mode="on")

    assert not result.success
    assert "Echo execution context required" in result.error


@pytest.mark.asyncio
async def test_public_handler_access_without_echo_context_fails_before_business_handler(
    tmp_path: Path,
) -> None:
    registry = _registry(tmp_path)
    calls = 0

    async def handler(path: str) -> ToolResult:
        nonlocal calls
        calls += 1
        return ToolResult(success=True, output=f"read {path}")

    registry.register(
        ToolSpec(name="file_read", description="read", parameters=[], read_only=True),
        handler,
    )
    public_handler = registry.get_handler("file_read")
    assert public_handler is not None

    result = await public_handler(path="a.txt")

    assert not result.success
    assert "Echo execution context required" in result.error
    assert calls == 0


@pytest.mark.asyncio
async def test_consumed_context_is_bound_only_while_the_business_handler_runs(
    tmp_path: Path,
) -> None:
    registry = _registry(tmp_path)
    observed: list[ToolExecutionContext | None] = []

    async def handler(path: str) -> ToolResult:
        del path
        observed.append(current_tool_execution_context())
        await asyncio.sleep(0)
        observed.append(current_tool_execution_context())
        return ToolResult(success=True, output="ok")

    registry.register(
        ToolSpec(name="file_read", description="read", parameters=[], read_only=True),
        handler,
    )
    assert current_tool_execution_context() is None
    context = _signed_context(registry)

    result = await registry.execute(
        "run-a",
        "file_read",
        {"path": "a.txt"},
        execution_context=context,
    )

    assert result.success is True
    assert observed == [context, context]
    assert current_tool_execution_context() is None


@pytest.mark.asyncio
async def test_registry_sanitizes_unexpected_handler_exception(
    tmp_path: Path,
) -> None:
    registry = _registry(tmp_path)
    private_detail = "/Users/private/Documents/customer.xlsx secret-token"

    async def handler(path: str) -> ToolResult:
        del path
        raise RuntimeError(private_detail)

    registry.register(
        ToolSpec(name="file_read", description="read", parameters=[], read_only=True),
        handler,
    )

    result = await registry.execute(
        "run-a",
        "file_read",
        {"path": "a.txt"},
        execution_context=_signed_context(registry),
    )

    assert result.success is False
    assert result.error == "Tool execution failed safely"
    assert private_detail not in str(result)


def test_registry_exposes_no_raw_handler_chaining_api(tmp_path: Path) -> None:
    registry = _registry(tmp_path)

    # A Python callable passed to middleware can be reflected through closure
    # variables.  Security policies therefore receive arguments only and can
    # never receive a raw or chained handler.
    assert not hasattr(registry, "wrap_handler")


@pytest.mark.asyncio
@pytest.mark.parametrize("mutated_key", ["content", "encoding"])
async def test_argument_policy_cannot_change_lease_bound_non_path_arguments(
    tmp_path: Path,
    mutated_key: str,
) -> None:
    registry = _registry(tmp_path)
    root = tmp_path / "allowed"
    root.mkdir()
    calls = 0

    async def handler(**arguments: Any) -> ToolResult:
        nonlocal calls
        calls += 1
        return ToolResult(success=True, output=str(arguments))

    def mutate_argument(arguments: dict[str, Any]) -> dict[str, Any]:
        return {**arguments, mutated_key: "mutated"}

    registry.register(
        ToolSpec(name="file_write", description="write", parameters=[]),
        handler,
    )
    assert registry.register_argument_policy("file_write", mutate_argument)
    arguments = {
        "path": "result.txt",
        "content": "authorized",
        "encoding": "utf-8",
    }

    result = await registry.execute(
        "run-a",
        "file_write",
        arguments,
        execution_context=_signed_context(
            registry,
            tool_name="file_write",
            args_hash=stable_payload_hash(arguments),
            fs_roots=(str(root),),
        ),
    )

    assert result.success is False
    assert "non-path" in result.error.lower()
    assert calls == 0


@pytest.mark.asyncio
async def test_argument_policy_cannot_retarget_path_outside_lease_root(
    tmp_path: Path,
) -> None:
    registry = _registry(tmp_path)
    root = tmp_path / "allowed"
    root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("outside", encoding="utf-8")
    calls = 0

    async def handler(path: str) -> ToolResult:
        nonlocal calls
        calls += 1
        return ToolResult(success=True, output=Path(path).read_text(encoding="utf-8"))

    def escape(arguments: dict[str, Any]) -> dict[str, Any]:
        return {**arguments, "path": str(outside)}

    registry.register(ToolSpec(name="file_read", description="read", parameters=[]), handler)
    assert registry.register_argument_policy("file_read", escape)
    arguments = {"path": "allowed.txt"}

    result = await registry.execute(
        "run-a",
        "file_read",
        arguments,
        execution_context=_signed_context(
            registry,
            args_hash=stable_payload_hash(arguments),
            fs_roots=(str(root),),
        ),
    )

    assert result.success is False
    assert "canonical resource" in result.error.lower()
    assert calls == 0


@pytest.mark.asyncio
async def test_argument_policy_cannot_turn_local_source_into_network_source(
    tmp_path: Path,
) -> None:
    registry = _registry(tmp_path)
    root = tmp_path / "allowed"
    root.mkdir()
    calls = 0

    async def handler(source: str) -> ToolResult:
        nonlocal calls
        calls += 1
        return ToolResult(success=True, output=source)

    def escape_to_network(arguments: dict[str, Any]) -> dict[str, Any]:
        return {**arguments, "source": "https://example.invalid/skill"}

    registry.register(
        ToolSpec(name="control_skill_install", description="install", parameters=[]),
        handler,
    )
    assert registry.register_argument_policy("control_skill_install", escape_to_network)
    arguments = {"source": "local-skill"}

    result = await registry.execute(
        "run-a",
        "control_skill_install",
        arguments,
        execution_context=_signed_context(
            registry,
            tool_name="control_skill_install",
            args_hash=stable_payload_hash(arguments),
            fs_roots=(str(root),),
            network_policy="deny",
        ),
    )

    assert result.success is False
    assert "network_policy" in result.error
    assert calls == 0


@pytest.mark.asyncio
async def test_multiple_argument_policies_cannot_escape_after_safe_normalization(
    tmp_path: Path,
) -> None:
    registry = _registry(tmp_path)
    root = tmp_path / "allowed"
    root.mkdir()
    outside = tmp_path / "outside.txt"
    calls = 0

    async def handler(path: str) -> ToolResult:
        nonlocal calls
        calls += 1
        return ToolResult(success=True, output=path)

    def normalize(arguments: dict[str, Any]) -> dict[str, Any]:
        return {**arguments, "path": str(root / arguments["path"])}

    def escape(arguments: dict[str, Any]) -> dict[str, Any]:
        return {**arguments, "path": str(outside)}

    registry.register(ToolSpec(name="file_read", description="read", parameters=[]), handler)
    assert registry.register_argument_policy("file_read", normalize)
    assert registry.register_argument_policy("file_read", escape)
    arguments = {"path": "allowed.txt"}

    result = await registry.execute(
        "run-a",
        "file_read",
        arguments,
        execution_context=_signed_context(
            registry,
            args_hash=stable_payload_hash(arguments),
            fs_roots=(str(root),),
        ),
    )

    assert result.success is False
    assert "canonical resource" in result.error.lower()
    assert calls == 0


@pytest.mark.asyncio
async def test_argument_policy_runs_before_each_read_only_cache_decision(
    tmp_path: Path,
) -> None:
    registry = _registry(tmp_path)
    root = tmp_path / "allowed"
    root.mkdir()
    calls = 0
    policy_calls = 0
    allowed = True

    async def handler(path: str) -> ToolResult:
        nonlocal calls
        calls += 1
        return ToolResult(success=True, output=path)

    def policy(arguments: dict[str, Any]) -> dict[str, Any] | ToolResult:
        nonlocal policy_calls
        policy_calls += 1
        if not allowed:
            return ToolResult(success=False, error="policy revoked")
        return arguments

    registry.register(
        ToolSpec(name="file_read", description="read", parameters=[], read_only=True),
        handler,
    )
    assert registry.register_argument_policy("file_read", policy)
    arguments = {"path": "allowed.txt"}
    context_overrides = {
        "args_hash": stable_payload_hash(arguments),
        "fs_roots": (str(root),),
    }

    first = await registry.execute(
        "run-a",
        "file_read",
        arguments,
        execution_context=_signed_context(registry, **context_overrides),
    )
    allowed = False
    second = await registry.execute(
        "run-a",
        "file_read",
        arguments,
        execution_context=_signed_context(registry, **context_overrides),
    )

    assert first.success is True
    assert second.success is False
    assert second.error == "policy revoked"
    assert policy_calls == 2
    assert calls == 1


@pytest.mark.asyncio
async def test_cancelling_task_cannot_start_handler_after_argument_policy(
    tmp_path: Path,
) -> None:
    registry = _registry(tmp_path)
    root = tmp_path / "allowed"
    root.mkdir()
    calls = 0

    async def handler(path: str) -> ToolResult:
        nonlocal calls
        calls += 1
        return ToolResult(success=True, output=path)

    def cancel_and_continue(arguments: dict[str, Any]) -> dict[str, Any]:
        task = asyncio.current_task()
        assert task is not None
        task.cancel()
        return arguments

    registry.register(ToolSpec(name="file_read", description="read", parameters=[]), handler)
    assert registry.register_argument_policy("file_read", cancel_and_continue)
    arguments = {"path": "allowed.txt"}
    execution = asyncio.create_task(
        registry.execute(
            "run-a",
            "file_read",
            arguments,
            execution_context=_signed_context(
                registry,
                args_hash=stable_payload_hash(arguments),
                fs_roots=(str(root),),
            ),
        )
    )

    with pytest.raises(asyncio.CancelledError):
        await execution
    assert calls == 0


@pytest.mark.asyncio
async def test_runtime_cancel_token_cannot_start_raw_tool_handler(tmp_path: Path) -> None:
    registry = _registry(tmp_path)
    root = tmp_path / "allowed"
    root.mkdir()
    calls = 0

    async def handler(path: str) -> ToolResult:
        nonlocal calls
        calls += 1
        return ToolResult(success=True, output=path)

    registry.register(ToolSpec(name="file_read", description="read", parameters=[]), handler)
    arguments = {"path": "allowed.txt"}
    cancel_token = asyncio.Event()
    cancel_token.set()
    runtime_context = RuntimeContext(
        product_id="js-agent",
        channel="test",
        owner_key_hash="owner-a",
        session_id="session-a",
        run_id="run-a",
        role="user",
        profile="default",
        capabilities=("file_read",),
        workspace=root,
        state_dir=tmp_path / "state",
        fs_roots=(root,),
        cancel_token=cancel_token,
    )

    token = set_runtime_context(runtime_context)
    try:
        result = await registry.execute(
            "run-a",
            "file_read",
            arguments,
            execution_context=_signed_context(
                registry,
                args_hash=stable_payload_hash(arguments),
                fs_roots=(str(root),),
            ),
        )
    finally:
        reset_runtime_context(token)

    assert result.success is False
    assert "cancelled" in result.error.lower()
    assert calls == 0


@pytest.mark.asyncio
async def test_echo_env_on_direct_registry_execute_without_context_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("JS_ECHO_ENGINE", "on")
    registry = _registry(tmp_path)

    async def handler(path: str) -> ToolResult:
        return ToolResult(success=True, output=f"read {path}")

    registry.register(
        ToolSpec(name="file_read", description="read", parameters=[], read_only=True),
        handler,
    )

    result = await registry.execute("run-a", "file_read", {"path": "a.txt"})

    assert not result.success
    assert "Echo execution context required" in result.error


@pytest.mark.asyncio
async def test_echo_off_registry_execute_is_rejected(tmp_path: Path) -> None:
    registry = _registry(tmp_path)

    async def handler(path: str) -> ToolResult:
        return ToolResult(success=True, output=f"read {path}")

    registry.register(
        ToolSpec(name="file_read", description="read", parameters=[], read_only=True),
        handler,
    )

    result = await registry.execute("run-a", "file_read", {"path": "a.txt"}, echo_mode="off")

    assert not result.success
    assert "Echo is the only supported architecture" in result.error


@pytest.mark.asyncio
async def test_echo_context_enforces_tool_name_and_args_hash(tmp_path: Path) -> None:
    registry = _registry(tmp_path)

    async def handler(path: str) -> ToolResult:
        return ToolResult(success=True, output=f"read {path}")

    registry.register(
        ToolSpec(name="file_read", description="read", parameters=[], read_only=True),
        handler,
    )

    wrong_tool = await registry.execute(
        "run-a",
        "file_read",
        {"path": "a.txt"},
        echo_mode="on",
        execution_context=_context(tool_name="file_write"),
    )
    wrong_args = await registry.execute(
        "run-a",
        "file_read",
        {"path": "b.txt"},
        echo_mode="on",
        execution_context=_context(),
    )

    assert not wrong_tool.success
    assert "tool_name mismatch" in wrong_tool.error
    assert not wrong_args.success
    assert "args_hash mismatch" in wrong_args.error


@pytest.mark.asyncio
async def test_echo_context_enforces_output_limit(tmp_path: Path) -> None:
    registry = _registry(tmp_path)

    async def handler() -> ToolResult:
        return ToolResult(success=True, output="x" * 20)

    registry.register(ToolSpec(name="file_read", description="read", parameters=[]), handler)

    result = await registry.execute(
        "run-a",
        "file_read",
        {},
        echo_mode="on",
        execution_context=_signed_context(
            registry,
            args_hash=stable_payload_hash({}),
            max_bytes=10,
        ),
    )

    assert not result.success
    assert "max_bytes" in result.error
    assert result.output == ""


@pytest.mark.asyncio
async def test_echo_registry_rejects_forged_unsigned_execution_context(
    tmp_path: Path,
) -> None:
    registry = _registry(tmp_path)

    async def handler(path: str) -> ToolResult:
        return ToolResult(success=True, output=f"read {path}")

    registry.register(
        ToolSpec(name="file_read", description="read", parameters=[], read_only=True),
        handler,
    )

    forged = _context(fs_roots=("/",), signature="")
    result = await registry.execute(
        "run-a",
        "file_read",
        {"path": "a.txt"},
        echo_mode="on",
        execution_context=forged,
    )

    assert not result.success
    assert "signature" in result.error


@pytest.mark.asyncio
async def test_echo_registry_rejects_signed_context_without_lease_verifier(
    tmp_path: Path,
) -> None:
    registry = _registry(tmp_path)

    async def handler(path: str) -> ToolResult:
        return ToolResult(success=True, output=f"read {path}")

    registry.register(
        ToolSpec(name="file_read", description="read", parameters=[], read_only=True),
        handler,
    )

    context = _context()
    authority = LeaseAuthority(mac_key=b"test-tool-lease-key-32-bytes!!", now_fn=lambda: 1_000)
    lease = authority.issue(
        product_id=context.product_id,
        session_id=context.session_id,
        owner_key_hash=context.owner_key_hash,
        run_id=context.run_id,
        tool_name=context.tool_name,
        args_schema=context.args_hash,
        resource_scope=context.resource_scope,
        fs_roots=context.fs_roots,
        network_policy=context.network_policy,
        max_bytes=context.max_bytes,
        max_duration_ms=context.max_duration_ms,
        ttl_ms=60_000,
    )
    signed = sign_tool_execution_context(
        context,
        lease=lease,
        authority=authority,
        now=1_000,
    )
    result = await registry.execute(
        "run-a",
        "file_read",
        {"path": "a.txt"},
        echo_mode="on",
        execution_context=signed,
    )

    assert not result.success
    assert "lease verifier required" in result.error


@pytest.mark.asyncio
async def test_echo_registry_rejects_replayed_signed_execution_context(
    tmp_path: Path,
) -> None:
    registry = _registry(tmp_path)
    calls = 0

    async def handler(path: str) -> ToolResult:
        nonlocal calls
        calls += 1
        return ToolResult(success=True, output=f"read {path}")

    registry.register(
        ToolSpec(name="file_read", description="read", parameters=[], read_only=False),
        handler,
    )
    context = _context()
    authority = LeaseAuthority(
        mac_key=b"test-tool-lease-key-32-bytes!!",
        now_fn=lambda: 1_000,
        ledger_path=tmp_path / "leases.jsonl",
    )
    lease = authority.issue(
        product_id=context.product_id,
        session_id=context.session_id,
        owner_key_hash=context.owner_key_hash,
        run_id=context.run_id,
        tool_name=context.tool_name,
        args_schema=context.args_hash,
        resource_scope=context.resource_scope,
        fs_roots=context.fs_roots,
        network_policy=context.network_policy,
        max_bytes=context.max_bytes,
        max_duration_ms=context.max_duration_ms,
        ttl_ms=60_000,
    )
    signed = sign_tool_execution_context(
        context,
        lease=lease,
        authority=authority,
        now=1_000,
    )

    def consume_context(execution_context: ToolExecutionContext) -> str | None:
        try:
            authority.consume_execution_context(execution_context, now=1_000)
        except Exception as exc:  # the registry converts policy errors to a safe result
            return f"Echo execution context lease denied: {type(exc).__name__}"
        return None

    registry.install_echo_context_verifier(consume_context)

    first = await registry.execute(
        "run-a",
        "file_read",
        {"path": "a.txt"},
        echo_mode="on",
        execution_context=signed,
    )
    replay = await registry.execute(
        "run-a",
        "file_read",
        {"path": "a.txt"},
        echo_mode="on",
        execution_context=signed,
    )

    assert first.success
    assert not replay.success
    assert "LeaseNonceReplay" in replay.error
    assert calls == 1


@pytest.mark.asyncio
async def test_dangerous_network_tool_requires_explicit_allow_policy(
    tmp_path: Path,
) -> None:
    registry = _registry(tmp_path)

    async def handler(url: str) -> ToolResult:
        return ToolResult(success=True, output=f"fetched {url}")

    registry.register(
        ToolSpec(name="web_fetch", description="fetch", parameters=[], dangerous=True),
        handler,
    )

    denied = await registry.execute(
        "run-a",
        "web_fetch",
        {"url": "https://example.com"},
        echo_mode="on",
        execution_context=_signed_context(
            registry,
            tool_name="web_fetch",
            args_hash=stable_payload_hash({"url": "https://example.com"}),
            network_policy="deny",
        ),
    )
    allowed = await registry.execute(
        "run-a",
        "web_fetch",
        {"url": "https://example.com"},
        echo_mode="on",
        execution_context=_signed_context(
            registry,
            tool_name="web_fetch",
            args_hash=stable_payload_hash({"url": "https://example.com"}),
            network_policy="allow",
            network_hosts=("example.com",),
        ),
    )

    assert not denied.success
    assert "network_policy" in denied.error
    assert allowed.success
    assert allowed.output == "fetched https://example.com"


@pytest.mark.asyncio
async def test_network_allow_policy_without_matching_host_allowlist_fails_closed(
    tmp_path: Path,
) -> None:
    registry = _registry(tmp_path)
    calls = 0

    async def handler(url: str) -> ToolResult:
        nonlocal calls
        calls += 1
        return ToolResult(success=True, output=f"fetched {url}")

    registry.register(
        ToolSpec(name="browser_fetch", description="fetch", parameters=[]),
        handler,
    )
    arguments = {"url": "https://example.com/private"}

    missing = await registry.execute(
        "run-a",
        "browser_fetch",
        arguments,
        echo_mode="on",
        execution_context=_signed_context(
            registry,
            tool_name="browser_fetch",
            args_hash=stable_payload_hash(arguments),
            network_policy="allow",
            network_hosts=(),
        ),
    )
    mismatched = await registry.execute(
        "run-a",
        "browser_fetch",
        arguments,
        echo_mode="on",
        execution_context=_signed_context(
            registry,
            tool_name="browser_fetch",
            args_hash=stable_payload_hash(arguments),
            network_policy="allow",
            network_hosts=("other.example",),
        ),
    )

    assert missing.success is False
    assert mismatched.success is False
    assert "allowlist" in missing.error.lower()
    assert "allowlist" in mismatched.error.lower()
    assert calls == 0


@pytest.mark.asyncio
async def test_network_allowlist_cannot_grant_loopback_even_with_valid_lease(
    tmp_path: Path,
) -> None:
    registry = _registry(tmp_path)
    calls = 0

    async def handler(url: str) -> ToolResult:
        nonlocal calls
        calls += 1
        return ToolResult(success=True, output=url)

    registry.register(
        ToolSpec(name="browser_fetch", description="fetch", parameters=[]),
        handler,
    )
    arguments = {"url": "http://127.0.0.1:8080/secret"}

    result = await registry.execute(
        "run-a",
        "browser_fetch",
        arguments,
        echo_mode="on",
        execution_context=_signed_context(
            registry,
            tool_name="browser_fetch",
            args_hash=stable_payload_hash(arguments),
            network_policy="allow",
            network_hosts=("127.0.0.1",),
        ),
    )

    assert result.success is False
    assert "unsafe" in result.error.lower() or "private" in result.error.lower()
    assert calls == 0


@pytest.mark.asyncio
async def test_any_network_tool_requires_explicit_allow_policy(tmp_path: Path) -> None:
    registry = _registry(tmp_path)

    async def handler(url: str) -> ToolResult:
        return ToolResult(success=True, output=f"fetched {url}")

    registry.register(
        ToolSpec(name="web_fetch", description="fetch", parameters=[], dangerous=False),
        handler,
    )

    denied = await registry.execute(
        "run-a",
        "web_fetch",
        {"url": "https://example.com"},
        echo_mode="on",
        execution_context=_signed_context(
            registry,
            tool_name="web_fetch",
            args_hash=stable_payload_hash({"url": "https://example.com"}),
            network_policy="deny",
        ),
    )

    assert not denied.success
    assert "network_policy" in denied.error


@pytest.mark.asyncio
async def test_registry_validates_named_source_and_output_paths_against_lease_roots(
    tmp_path: Path,
) -> None:
    registry = _registry(tmp_path)
    calls: list[dict[str, Any]] = []

    async def handler(**arguments: Any) -> ToolResult:
        calls.append(arguments)
        return ToolResult(success=True, output="unexpected")

    registry.register(
        ToolSpec(name="excel_precise_edit", description="edit", parameters=[], dangerous=True),
        handler,
    )
    owner_root = tmp_path / "owners" / "owner-a"
    upload_root = tmp_path / "uploads" / "owner-a"
    arguments = {
        "source_path": str(tmp_path / "owners" / "owner-b" / "secret.xlsx"),
        "output_path": "reports/result.xlsx",
        "operations": "[]",
    }

    result = await registry.execute(
        "run-a",
        "excel_precise_edit",
        arguments,
        echo_mode="on",
        execution_context=_signed_context(
            registry,
            tool_name="excel_precise_edit",
            args_hash=stable_payload_hash(arguments),
            fs_roots=(str(owner_root), str(upload_root)),
        ),
    )

    assert result.success is False
    assert "fs_roots" in (result.error or "")
    assert calls == []


@pytest.mark.asyncio
async def test_tool_executor_passes_consumed_lease_context_to_registry(
    tmp_path: Path,
) -> None:
    captured: dict[str, Any] = {}

    class _Registry:
        def __init__(self) -> None:
            self.echo_context_verifier = None

        def install_echo_context_verifier(self, verifier: Any) -> None:
            self.echo_context_verifier = verifier

        def get(self, _name: str) -> ToolSpec:
            return ToolSpec(name="file_read", description="read", parameters=[])

        async def execute(
            self,
            run_id: str,
            tool_name: str,
            arguments: dict[str, Any],
            **kwargs: Any,
        ) -> ToolResult:
            captured.update(
                {
                    "run_id": run_id,
                    "tool_name": tool_name,
                    "arguments": arguments,
                    **kwargs,
                }
            )
            return ToolResult(success=True, output="ok")

    class _FakeExecutor(ToolExecutorMixin):
        pass

    class _Defense:
        def evaluate(self, _ctx: Any) -> Any:
            return SimpleNamespace(blocked=False)

    class _Audit:
        def log(self, *_args: Any, **_kwargs: Any) -> None:
            return None

    class _Events:
        def emit(self, _event: Any) -> None:
            return None

    class _Secrets:
        def detect_and_redact(self, value: str, _scope: str) -> str:
            return value

    class _Guard:
        def check_repeated_failure(self, *_args: Any, **_kwargs: Any) -> Any:
            return SimpleNamespace(decision="allow")

    executor = _FakeExecutor()
    executor.settings = SimpleNamespace(
        echo_engine="on",
        workspace=tmp_path,
        state_dir=tmp_path,
        tools=SimpleNamespace(tool_output_budget_chars=4321, shell_timeout=7.5),
        security=_SecurityConfig(),
    )
    executor.registry = _Registry()
    executor.defense_strategies = _Defense()
    executor.audit = _Audit()
    executor.event_store = _Events()
    executor.secrets = _Secrets()
    executor.guard = _Guard()
    executor.logger = SimpleNamespace(debug=lambda *_args, **_kwargs: None)
    executor._role = None
    executor._echo_durable_executor = _TEST_DURABLE_EXECUTOR
    executor.echo_safety_service = EchoSafetyService(state_dir=tmp_path)
    executor._tool_lease_authority = LeaseAuthority(
        mac_key=b"test-tool-lease-key-32-bytes!!",
        now_fn=lambda: 1_000,
    )

    _message, result = await executor._execute_tool_call(
        {
            "id": "call-1",
            "function": {"name": "file_read", "arguments": '{"path":"a.txt"}'},
        },
        session_id="sess-a",
        run_id="run-a",
        user_input="read a",
        owner_key_hash="owner-a",
    )

    ctx = captured["execution_context"]
    assert result.success
    assert captured["echo_mode"] == "on"
    assert ctx.owner_key_hash == "owner-a"
    assert ctx.product_id == "js-agent"
    assert ctx.session_id == "sess-a"
    assert ctx.profile == "default"
    assert ctx.run_id == "run-a"
    assert ctx.tool_name == "file_read"
    assert ctx.args_hash == stable_payload_hash({"path": "a.txt"})
    assert ctx.resource_scope == (
        "product-session:"
        + stable_payload_hash(
            {"product_id": "js-agent", "session_id": "sess-a"}
        )
    )
    assert ctx.fs_roots == (str(tmp_path),)
    assert ctx.network_policy == "deny"
    assert ctx.network_hosts == ()
    assert ctx.max_bytes == 4321
    assert ctx.max_duration_ms == 7500


@pytest.mark.asyncio
async def test_tool_executor_echo_mode_always_requires_context(
    tmp_path: Path,
) -> None:
    captured: dict[str, Any] = {}

    class _Registry:
        def __init__(self) -> None:
            self.echo_context_verifier = None

        def install_echo_context_verifier(self, verifier: Any) -> None:
            self.echo_context_verifier = verifier

        def get(self, _name: str) -> ToolSpec:
            return ToolSpec(name="file_read", description="read", parameters=[])

        async def execute(
            self,
            run_id: str,
            tool_name: str,
            arguments: dict[str, Any],
            **kwargs: Any,
        ) -> ToolResult:
            captured.update(
                {
                    "run_id": run_id,
                    "tool_name": tool_name,
                    "arguments": arguments,
                    **kwargs,
                }
            )
            return ToolResult(success=True, output="ok")

    class _FakeExecutor(ToolExecutorMixin):
        pass

    class _Defense:
        def evaluate(self, _ctx: Any) -> Any:
            return SimpleNamespace(blocked=False)

    class _Audit:
        def log(self, *_args: Any, **_kwargs: Any) -> None:
            return None

    class _Events:
        def emit(self, _event: Any) -> None:
            return None

    class _Secrets:
        def detect_and_redact(self, value: str, _scope: str) -> str:
            return value

    class _Guard:
        def check_repeated_failure(self, *_args: Any, **_kwargs: Any) -> Any:
            return SimpleNamespace(decision="allow")

    executor = _FakeExecutor()
    executor.settings = SimpleNamespace(
        echo_engine="on",
        workspace=tmp_path,
        state_dir=tmp_path,
        tools=SimpleNamespace(tool_output_budget_chars=1234, shell_timeout=3.0),
        security=_SecurityConfig(),
    )
    executor.registry = _Registry()
    executor.defense_strategies = _Defense()
    executor.audit = _Audit()
    executor.event_store = _Events()
    executor.secrets = _Secrets()
    executor.guard = _Guard()
    executor.logger = SimpleNamespace(debug=lambda *_args, **_kwargs: None)
    executor._role = None
    executor._echo_durable_executor = _TEST_DURABLE_EXECUTOR
    executor.echo_safety_service = EchoSafetyService(state_dir=tmp_path)
    executor._tool_lease_authority = LeaseAuthority(
        mac_key=b"test-tool-lease-key-32-bytes!!",
        now_fn=lambda: 1_000,
    )

    _message, result = await executor._execute_tool_call(
        {
            "id": "call-1",
            "function": {"name": "file_read", "arguments": '{"path":"a.txt"}'},
        },
        session_id="sess-a",
        run_id="run-a",
        user_input="read a",
        owner_key_hash="owner-a",
    )

    assert result.success
    assert captured["echo_mode"] == "on"
    assert captured["execution_context"] is not None
