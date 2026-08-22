from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from js.agent.tool_executor import ToolExecutorMixin
from js.config import ToolLimits
from js.echo import stable_payload_hash
from js.echo.capability import LeaseAuthority, sign_tool_execution_context
from js.mcp.controlled import ControlledMCPConnector, load_mcp_manifest
from js.security.guard import BehaviorGuard
from js.tools.registry import ToolExecutionContext, ToolRegistry


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
    limits = ToolLimits()
    guard = BehaviorGuard(_SecurityConfig(), tmp_path)
    return ToolRegistry(limits, guard)


def _manifest(path: Path) -> Path:
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "servers": [
                    {
                        "id": "docs",
                        "enabled": True,
                        "transport": "stdio",
                        "command": ["python", "server.py"],
                        "allow_execute": False,
                        "tools": [
                            {
                                "name": "search",
                                "description": "Search docs",
                                "read_only": True,
                                "input_schema": {
                                    "type": "object",
                                    "properties": {
                                        "query": {
                                            "type": "string",
                                            "description": "Search query",
                                        }
                                    },
                                    "required": ["query"],
                                },
                            }
                        ],
                    },
                    {
                        "id": "not-enabled",
                        "enabled": False,
                        "transport": "stdio",
                        "command": ["python", "disabled.py"],
                        "tools": [{"name": "hidden", "input_schema": {}}],
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    return path


def test_load_mcp_manifest_imports_only_enabled_allowlisted_tools(tmp_path: Path) -> None:
    manifest = load_mcp_manifest(_manifest(tmp_path / "mcp.json"))

    assert [server.server_id for server in manifest.servers] == ["docs"]
    assert manifest.servers[0].tools[0].public_name == "mcp_docs_search"
    assert manifest.servers[0].tools[0].read_only is True


@pytest.mark.asyncio
async def test_controlled_mcp_tool_default_execution_is_disabled(tmp_path: Path) -> None:
    registry = _registry(tmp_path)
    manifest = load_mcp_manifest(_manifest(tmp_path / "mcp.json"))

    connector = ControlledMCPConnector(manifest)
    connector.register_tools(registry)

    spec = registry.get("mcp_docs_search")
    assert spec is not None
    assert spec.dangerous is True
    assert spec.read_only is True

    args = {"query": "echo"}
    context = ToolExecutionContext(
        owner_key_hash="owner-a",
        run_id="run-a",
        tool_name="mcp_docs_search",
        args_hash=stable_payload_hash(args),
        fs_roots=(str(tmp_path),),
        network_policy="allow",
        max_bytes=1000,
        max_duration_ms=1000,
    )
    authority = LeaseAuthority(mac_key=b"tool-lease-test-key", now_fn=lambda: 1_000)
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
        except Exception as exc:
            return f"Echo execution context lease denied: {type(exc).__name__}"
        return None

    registry.install_echo_context_verifier(consume_context)
    result = await registry.execute(
        "run-a",
        "mcp_docs_search",
        args,
        echo_mode="on",
        execution_context=signed,
    )

    assert result.success is False
    assert "disabled by Echo MCP policy" in result.error


def test_mcp_manifest_rejects_unallowlisted_tool_name(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "servers": [
                    {
                        "id": "docs",
                        "enabled": True,
                        "transport": "stdio",
                        "command": ["python", "server.py"],
                        "tools": [{"name": "../escape", "input_schema": {}}],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Invalid MCP tool name"):
        load_mcp_manifest(path)


@pytest.mark.parametrize(
    "server",
    [
        {"id": "stdio", "enabled": True, "transport": "stdio", "tools": []},
        {
            "id": "sse-http",
            "enabled": True,
            "transport": "sse",
            "url": "http://example.com/events",
            "tools": [],
        },
        {
            "id": "sse-local",
            "enabled": True,
            "transport": "sse",
            "url": "https://127.0.0.1/events",
            "tools": [],
        },
        # Obfuscated inet_aton-style IP forms (decimal, hex, octal, short)
        # must be rejected even though they all resolve to 127.0.0.1.
        {
            "id": "sse-decimal-ip",
            "enabled": True,
            "transport": "sse",
            "url": "https://2130706433/events",
            "tools": [],
        },
        {
            "id": "sse-hex-ip",
            "enabled": True,
            "transport": "sse",
            "url": "https://0x7f000001/events",
            "tools": [],
        },
        {
            "id": "sse-octal-ip",
            "enabled": True,
            "transport": "sse",
            "url": "https://0177.0.0.1/events",
            "tools": [],
        },
        {
            "id": "sse-short-ip",
            "enabled": True,
            "transport": "sse",
            "url": "https://127.1/events",
            "tools": [],
        },
    ],
)
def test_mcp_manifest_rejects_incomplete_or_unsafe_transport(
    tmp_path: Path,
    server: dict[str, object],
) -> None:
    path = tmp_path / "bad-transport.json"
    path.write_text(json.dumps({"version": 1, "servers": [server]}), encoding="utf-8")

    with pytest.raises(ValueError, match="MCP"):
        load_mcp_manifest(path)


def test_mcp_manifest_rejects_execute_grant_without_runtime_adapter(tmp_path: Path) -> None:
    path = tmp_path / "execute.json"
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "servers": [
                    {
                        "id": "docs",
                        "enabled": True,
                        "transport": "stdio",
                        "command": ["python", "server.py"],
                        "allow_execute": True,
                        "tools": [
                            {
                                "name": "search",
                                "allow_execute": True,
                                "input_schema": {},
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="runtime adapter"):
        load_mcp_manifest(path)


def test_mcp_manifest_rejects_tool_execute_grant_without_server_grant(tmp_path: Path) -> None:
    path = tmp_path / "tool-execute.json"
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "servers": [
                    {
                        "id": "docs",
                        "enabled": True,
                        "transport": "stdio",
                        "command": ["python", "server.py"],
                        "allow_execute": False,
                        "tools": [
                            {
                                "name": "search",
                                "allow_execute": True,
                                "input_schema": {},
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="runtime adapter"):
        load_mcp_manifest(path)


def test_agent_fails_closed_when_configured_mcp_manifest_is_invalid(tmp_path: Path) -> None:
    path = tmp_path / "invalid.json"
    path.write_text("not-json", encoding="utf-8")
    agent = SimpleNamespace(
        settings=SimpleNamespace(mcp_manifest=path),
        registry=_registry(tmp_path),
        logger=SimpleNamespace(warning=lambda *_args, **_kwargs: None),
    )

    with pytest.raises(RuntimeError, match="Controlled MCP manifest"):
        ToolExecutorMixin._register_controlled_mcp_tools(agent)


def test_public_mcp_package_exposes_only_controlled_connector() -> None:
    import js.mcp as mcp

    assert not hasattr(mcp, "MCPClient")
    assert not hasattr(mcp, "MCPToolAdapter")


def test_legacy_raw_mcp_client_and_adapter_fail_closed() -> None:
    from js.mcp.client import MCPClient
    from js.mcp.tools import MCPToolAdapter

    with pytest.raises(RuntimeError, match="disabled by Echo"):
        MCPClient(command=["python", "untrusted_server.py"])
    with pytest.raises(RuntimeError, match="disabled by Echo"):
        MCPToolAdapter(object())  # type: ignore[arg-type]
