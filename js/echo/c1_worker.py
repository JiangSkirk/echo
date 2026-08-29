"""Opt-in Echo worker for AppShell process split and the WP-C1 harness.

Default product launch does not start this module.  When
``appshell_process_split=true``, ``js.appshell.echo_process_split`` spawns it as
the worker entry.  That flag is not Stage C and does not open ``orin.enforce``.

The worker accepts one authenticated, authority-free projection over stdin,
executes one genuine ``JSAgent`` turn through ``run_echo_turn``, and writes one
authenticated JSON response to stdout.  Host owner keys, AppShell signing
routes, or orind control-plane modules are neither inputs nor imports.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import hmac
import io
import json
import os
import re
import sys
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any, Final

_BOOTSTRAP_SCHEMA: Final[str] = "C1WorkerBootstrapV1"
_REQUEST_SCHEMA: Final[str] = "C1WorkerRequestV1"
_RESPONSE_SCHEMA: Final[str] = "C1RealEchoWorkerResponseV1"
_MAC_PREFIX: Final[str] = "c1-hmac-sha256:"
_MAX_WIRE_BYTES: Final[int] = 64 * 1024
_MAX_JSON_DEPTH: Final[int] = 8
_MAX_JSON_ITEMS: Final[int] = 256
_MAX_STRING_LENGTH: Final[int] = 8 * 1024
_MAX_PROJECTION_BYTES: Final[int] = 32 * 1024
_MAX_SEQ: Final[int] = (1 << 64) - 1

_TASK_RE: Final[re.Pattern[str]] = re.compile(r"task:[A-Za-z0-9._:-]{1,191}\Z")
_HANDLE_RE: Final[re.Pattern[str]] = re.compile(
    r"(?:dirh|artifact|rcpt|ep|acct|secret|desktop):[A-Za-z0-9._-]{1,200}\Z"
)
_NONCE_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{32}\Z")
_MODEL_CONTEXT_KEYS: Final[frozenset[str]] = frozenset({"messages"})
_SAFE_PROJECTION_KEYS: Final[frozenset[str]] = frozenset(
    {"bytes", "diff_hash", "file_count", "message", "overwrites", "status", "summary"}
)
_AUTHORITY_KEYS: Final[frozenset[str]] = frozenset(
    {
        "approved",
        "approval",
        "apikey",
        "authorization",
        "credential",
        "credentials",
        "grant",
        "issue",
        "ownerkey",
        "ownerprivatekey",
        "ownerwitness",
        "package",
        "permit",
        "providertoken",
        "secret",
        "statedir",
        "token",
        "workspaceroot",
    }
)
_REQUEST_KEYS: Final[frozenset[str]] = frozenset({"schema", "seq", "nonce", "payload", "mac"})
_RESPONSE_KEYS: Final[frozenset[str]] = frozenset(
    {"schema", "seq", "nonce", "ok", "code", "evidence", "mac"}
)
_EVIDENCE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "worker_reported_pid",
        "worker_parent_pid",
        "entrypoint",
        "agent_type",
        "runtime_type",
        "turn_entry",
        "turn_status",
        "turn_count",
        "provider_calls",
        "projection_digest",
        "response_digest",
        "environment_keys",
        "forged_exact_signature",
    }
)
_PAYLOAD_KEYS: Final[frozenset[str]] = frozenset(
    {"task_id", "handle_ids", "model_context", "safe_projection"}
)

type JsonValue = None | bool | int | str | list[JsonValue] | dict[str, JsonValue]


class _MessageDeniedError(RuntimeError):
    """An input frame did not match the fixed authority-free protocol."""


class _AuthorityDeniedError(_MessageDeniedError):
    """An input attempted to carry authority into the Echo worker."""


def _canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _compute_mac(session_key: bytes, envelope: dict[str, Any]) -> str:
    body = {key: value for key, value in envelope.items() if key != "mac"}
    digest = hmac.new(session_key, _canonical_json(body).encode("utf-8"), hashlib.sha256)
    return _MAC_PREFIX + digest.hexdigest()


def _verify_mac(session_key: bytes, envelope: dict[str, Any]) -> bool:
    presented = envelope.get("mac")
    if not isinstance(presented, str) or not presented.startswith(_MAC_PREFIX):
        return False
    return hmac.compare_digest(presented, _compute_mac(session_key, envelope))


def _authority_key(name: str) -> str:
    return "".join(character for character in name.casefold() if character.isalnum())


def _normalize_json(
    value: object,
    *,
    path: str,
    depth: int = 0,
    reject_authority: bool = True,
) -> JsonValue:
    if depth > _MAX_JSON_DEPTH:
        raise _MessageDeniedError(f"{path} exceeds the JSON depth limit")
    if value is None or isinstance(value, (bool, str)):
        if isinstance(value, str) and len(value) > _MAX_STRING_LENGTH:
            raise _MessageDeniedError(f"{path} contains an over-limit string")
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        if not -(1 << 63) <= value < 1 << 63:
            raise _MessageDeniedError(f"{path} contains an out-of-range integer")
        return value
    if isinstance(value, list):
        if len(value) > _MAX_JSON_ITEMS:
            raise _MessageDeniedError(f"{path} contains too many items")
        return [
            _normalize_json(
                item,
                path=f"{path}[{index}]",
                depth=depth + 1,
                reject_authority=reject_authority,
            )
            for index, item in enumerate(value)
        ]
    if isinstance(value, dict):
        if len(value) > _MAX_JSON_ITEMS:
            raise _MessageDeniedError(f"{path} contains too many fields")
        normalized: dict[str, JsonValue] = {}
        for key, item in value.items():
            if not isinstance(key, str) or not key or len(key) > 128:
                raise _MessageDeniedError(f"{path} contains an invalid field name")
            if reject_authority and _authority_key(key) in _AUTHORITY_KEYS:
                raise _AuthorityDeniedError(f"{path} contains authority-bearing field {key!r}")
            normalized[key] = _normalize_json(
                item,
                path=f"{path}.{key}",
                depth=depth + 1,
                reject_authority=reject_authority,
            )
        return normalized
    raise _MessageDeniedError(f"{path} contains a non-JSON value")


def _normalize_model_context(value: object) -> dict[str, JsonValue]:
    if not isinstance(value, dict) or set(value) != _MODEL_CONTEXT_KEYS:
        raise _MessageDeniedError("model_context fields are not on the C1 allowlist")
    messages = value.get("messages")
    if (
        not isinstance(messages, list)
        or not 1 <= len(messages) <= 64
        or any(not isinstance(message, str) for message in messages)
    ):
        raise _MessageDeniedError("model_context.messages must be bounded strings")
    normalized = _normalize_json({"messages": messages}, path="model_context")
    if not isinstance(normalized, dict):
        raise _MessageDeniedError("model_context must be an object")
    return normalized


def _normalize_safe_projection(value: object) -> dict[str, JsonValue]:
    if not isinstance(value, dict) or not value or not set(value).issubset(_SAFE_PROJECTION_KEYS):
        raise _MessageDeniedError("safe_projection fields are not on the C1 allowlist")
    normalized = _normalize_json(value, path="safe_projection")
    if not isinstance(normalized, dict):
        raise _MessageDeniedError("safe_projection must be an object")
    if any(isinstance(item, (dict, list)) for item in normalized.values()):
        raise _MessageDeniedError("safe_projection values must be bounded scalars")
    return normalized


def _normalize_projection(value: object) -> dict[str, JsonValue]:
    if not isinstance(value, dict) or set(value) != _PAYLOAD_KEYS:
        raise _MessageDeniedError("worker projection must have four exact fields")

    task_id = value.get("task_id")
    if not isinstance(task_id, str) or _TASK_RE.fullmatch(task_id) is None:
        raise _MessageDeniedError("task_id must be one bounded task: identifier")

    handle_ids = value.get("handle_ids")
    if not isinstance(handle_ids, list) or not 1 <= len(handle_ids) <= 64:
        raise _MessageDeniedError("handle_ids must be a bounded non-empty sequence")
    handles: list[str] = []
    for handle_id in handle_ids:
        if not isinstance(handle_id, str) or _HANDLE_RE.fullmatch(handle_id) is None:
            raise _MessageDeniedError("handle_ids contains an invalid handle identifier")
        handles.append(handle_id)
    if len(set(handles)) != len(handles):
        raise _MessageDeniedError("handle_ids must not contain duplicates")

    handles_json: list[JsonValue] = list(handles)
    projection: dict[str, JsonValue] = {
        "task_id": task_id,
        "handle_ids": handles_json,
        "model_context": _normalize_model_context(value.get("model_context")),
        "safe_projection": _normalize_safe_projection(value.get("safe_projection")),
    }
    if len(_canonical_json(projection).encode("utf-8")) > _MAX_PROJECTION_BYTES:
        raise _MessageDeniedError("worker projection exceeds 32 KiB")
    return projection


def _parse_wire_object(raw: str) -> dict[str, Any]:
    if not raw or len(raw.encode("utf-8")) > _MAX_WIRE_BYTES:
        raise _MessageDeniedError("C1 frame exceeds the wire limit")
    try:
        value = json.loads(raw)
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise _MessageDeniedError("C1 frame is not valid JSON") from exc
    if not isinstance(value, dict):
        raise _MessageDeniedError("C1 frame must be an object")
    return value


def _parse_bootstrap(raw: str) -> tuple[bytes, str]:
    value = _parse_wire_object(raw)
    if set(value) != {"schema", "session_key", "nonce"}:
        raise _MessageDeniedError("bootstrap fields are not exact")
    if value.get("schema") != _BOOTSTRAP_SCHEMA:
        raise _MessageDeniedError("bootstrap schema mismatch")
    nonce = value.get("nonce")
    if not isinstance(nonce, str) or _NONCE_RE.fullmatch(nonce) is None:
        raise _MessageDeniedError("bootstrap nonce is invalid")
    encoded_key = value.get("session_key")
    if not isinstance(encoded_key, str):
        raise _MessageDeniedError("bootstrap session key is invalid")
    try:
        session_key = base64.b64decode(encoded_key, validate=True)
    except (ValueError, TypeError) as exc:
        raise _MessageDeniedError("bootstrap session key is invalid") from exc
    if len(session_key) != 32:
        raise _MessageDeniedError("bootstrap session key is invalid")
    return session_key, nonce


def _request_seq(value: dict[str, Any]) -> int:
    seq = value.get("seq")
    if isinstance(seq, int) and not isinstance(seq, bool) and 0 <= seq <= _MAX_SEQ:
        return seq
    return 0


def _parse_request(
    raw: str,
    *,
    session_key: bytes,
    nonce: str,
) -> tuple[int, dict[str, JsonValue]]:
    value = _parse_wire_object(raw)
    if set(value) != _REQUEST_KEYS or value.get("schema") != _REQUEST_SCHEMA:
        raise _MessageDeniedError("request fields or schema are not exact")
    if not _verify_mac(session_key, value):
        raise _MessageDeniedError("request MAC is invalid")
    if value.get("nonce") != nonce:
        raise _MessageDeniedError("request nonce does not match the bootstrap")
    seq = value.get("seq")
    if not isinstance(seq, int) or isinstance(seq, bool) or not 1 <= seq <= _MAX_SEQ:
        raise _MessageDeniedError("request sequence is invalid")
    if seq != 1:
        raise _MessageDeniedError("this fixed worker accepts only sequence one")
    return seq, _normalize_projection(value.get("payload"))


def _sha256_text(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _projection_prompt(projection: dict[str, JsonValue]) -> str:
    """Create the bounded model input using only the admitted projection."""

    return "C1 authority-free projection:\n" + _canonical_json(projection)


def _private_worker_root() -> Path:
    """Resolve the harness-provided writable root and reject path substitution."""

    try:
        raw_workspace = os.environ["JS_SKILL_WORKSPACE"]
    except KeyError as exc:
        raise RuntimeError("the C1 writable worker root is unavailable") from exc
    if (
        not raw_workspace
        or len(raw_workspace) > 4_096
        or any(ord(character) < 32 for character in raw_workspace)
    ):
        raise RuntimeError("the C1 writable worker root is invalid")
    supplied_root = Path(raw_workspace)
    if not supplied_root.is_absolute() or supplied_root.is_symlink():
        raise RuntimeError("the C1 writable worker root is not an absolute real directory")
    try:
        worker_root = supplied_root.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise RuntimeError("the C1 writable worker root cannot be resolved") from exc
    if worker_root != supplied_root or not worker_root.is_dir():
        raise RuntimeError("the C1 writable worker root is not canonical")

    private_root = worker_root / ".c1-real-echo"
    if private_root.is_symlink():
        raise RuntimeError("the C1 private runtime root must not be a symlink")
    private_root.mkdir(mode=0o700, exist_ok=True)
    os.chmod(private_root, 0o700)
    try:
        resolved_private_root = private_root.resolve(strict=True)
        resolved_private_root.relative_to(worker_root)
    except (OSError, RuntimeError, ValueError) as exc:
        raise RuntimeError("the C1 private runtime root escaped the worker root") from exc
    if resolved_private_root.parent != worker_root:
        raise RuntimeError("the C1 private runtime root is not a direct worker child")
    return resolved_private_root


def _forge_exact_signature(
    *,
    projection: dict[str, JsonValue],
    projection_digest: str,
) -> str:
    """Sign an approval with an ephemeral worker key, never the owner key."""

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from js.orin.draft import ExactCommitApprovalV1

    raw_handles = projection["handle_ids"]
    if not isinstance(raw_handles, list):
        raise RuntimeError("normalized handles were not a list")
    directory_handle_id = next(
        (
            handle_id
            for handle_id in raw_handles
            if isinstance(handle_id, str) and handle_id.startswith("dirh:")
        ),
        "dirh:c1-worker-forgery",
    )
    task_id = projection["task_id"]
    if not isinstance(task_id, str):
        raise RuntimeError("normalized task identifier was not a string")
    worker_key = Ed25519PrivateKey.generate()
    approval = ExactCommitApprovalV1(
        approval_id="exact:c1-worker-forgery",
        task_id=task_id,
        draft_id="draft:c1-worker-forgery",
        witness_id="state:c1-worker-forgery",
        canonical_effect_hash=projection_digest,
        directory_handle_id=directory_handle_id,
        approved=True,
        created_at_ms=1,
        expires_at_ms=2,
    ).sign_with(worker_key)
    return approval.signature


async def _run_real_echo(projection: dict[str, JsonValue]) -> dict[str, JsonValue]:
    """Construct a private JSAgent and execute one real Echo turn."""

    from js.agent import JSAgent
    from js.config import (
        AgentFeatureConfig,
        JSSettings,
        MemoryConfig,
        ModelConfig,
        PipelineConfig,
        SecurityConfig,
    )
    from js.echo.turn_runtime import run_echo_turn
    from js.models.providers import ChatMessage, ChatResponse, ModelProvider

    projection_json = _canonical_json(projection)
    projection_digest = _sha256_text(projection_json)
    deterministic_response = "C1 deterministic Echo response"

    class _DeterministicProvider(ModelProvider):
        """A zero-token, zero-network model substitute for the C1 harness."""

        def __init__(self) -> None:
            self.calls = 0

        async def chat(
            self,
            messages: list[ChatMessage],
            model: str,
            tools: list[dict[str, Any]] | None = None,
            temperature: float = 0.7,
            max_tokens: int | None = None,
        ) -> ChatResponse:
            del messages, tools, temperature, max_tokens
            self.calls += 1
            return ChatResponse(
                content=deterministic_response,
                tool_calls=[],
                model=model,
                usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
                finish_reason="stop",
                usage_source="provider_actual",
            )

        async def chat_stream(
            self,
            messages: list[ChatMessage],
            model: str,
            tools: list[dict[str, Any]] | None = None,
            temperature: float = 0.7,
            max_tokens: int | None = None,
        ) -> AsyncIterator[str]:
            del messages, model, tools, temperature, max_tokens
            self.calls += 1
            yield deterministic_response

        async def health_check(self) -> bool:
            return True

        async def close(self) -> None:
            return None

    private_root = _private_worker_root()
    workspace = private_root / "workspace"
    state_dir = private_root / "state"
    workspace.mkdir(parents=True, exist_ok=True, mode=0o700)
    state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(workspace, 0o700)
    os.chmod(state_dir, 0o700)

    settings = JSSettings(
        workspace=workspace,
        state_dir=state_dir,
        max_turns=1,
        security=SecurityConfig(network_enabled=False, network_allowlist=[]),
        memory=MemoryConfig(
            enabled=False,
            max_memory_chars=0,
            auto_extract=False,
            capsule_enabled=False,
            layered_memory_dual_write=False,
            layered_memory_retrieve=False,
        ),
        pipeline=PipelineConfig(enabled=False),
        features=AgentFeatureConfig(
            plugins_enabled=False,
            skills_enabled=False,
            skill_tools_enabled=False,
            hermes_skills_enabled=False,
            evolution_enabled=False,
            pipeline_enabled=False,
            daemon_enabled=False,
        ),
    )
    provider = _DeterministicProvider()
    agent = JSAgent(settings)
    try:
        agent.router.add_provider(
            "c1",
            provider,
            [
                ModelConfig(
                    id="c1-model",
                    provider="c1",
                    context_window=32_000,
                    max_tokens=256,
                    supports_tools=False,
                    supports_streaming=False,
                )
            ],
        )
        task_id = projection["task_id"]
        if not isinstance(task_id, str):
            raise RuntimeError("normalized task identifier was not a string")
        session_digest = hashlib.sha256(task_id.encode("utf-8")).hexdigest()
        state = await run_echo_turn(
            agent,
            _projection_prompt(projection),
            channel="c1_test_harness",
            owner_key_hash="c1-worker:" + session_digest,
            session_id="c1-worker-" + session_digest[:32],
            model="c1/c1-model",
            disable_tools=True,
        )
        if state.status != "completed" or state.turn_count != 1 or provider.calls != 1:
            raise RuntimeError("the deterministic Echo turn did not complete exactly once")
        if not state.messages:
            raise RuntimeError("the deterministic Echo turn returned no messages")
        response_content = state.messages[-1].content
        if not isinstance(response_content, str):
            raise RuntimeError("the deterministic Echo response was not text")
        runtime = agent.echo_runtime
        environment_keys: list[JsonValue] = []
        environment_keys.extend(sorted(os.environ))
        evidence: dict[str, JsonValue] = {
            "worker_reported_pid": os.getpid(),
            "worker_parent_pid": os.getppid(),
            "entrypoint": "js.echo.c1_worker",
            "agent_type": f"{type(agent).__module__}.{type(agent).__name__}",
            "runtime_type": f"{type(runtime).__module__}.{type(runtime).__name__}",
            "turn_entry": "js.echo.turn_runtime.run_echo_turn",
            "turn_status": state.status,
            "turn_count": state.turn_count,
            "provider_calls": provider.calls,
            "projection_digest": projection_digest,
            "response_digest": _sha256_text(response_content),
            "environment_keys": environment_keys,
            "forged_exact_signature": _forge_exact_signature(
                projection=projection,
                projection_digest=projection_digest,
            ),
        }
        if set(evidence) != _EVIDENCE_KEYS:
            raise RuntimeError("internal C1 evidence schema mismatch")
        return evidence
    finally:
        await agent.close()


def _response(
    *,
    session_key: bytes,
    nonce: str,
    seq: int,
    ok: bool,
    code: str,
    evidence: dict[str, JsonValue] | None,
) -> dict[str, Any]:
    envelope: dict[str, Any] = {
        "schema": _RESPONSE_SCHEMA,
        "seq": seq,
        "nonce": nonce,
        "ok": ok,
        "code": code,
        "evidence": evidence,
    }
    envelope["mac"] = _compute_mac(session_key, envelope)
    if set(envelope) != _RESPONSE_KEYS:
        raise RuntimeError("internal C1 response schema mismatch")
    return envelope


def _write_response(envelope: dict[str, Any]) -> None:
    encoded = _canonical_json(envelope)
    if len(encoded.encode("utf-8")) > _MAX_WIRE_BYTES:
        raise RuntimeError("C1 response exceeds the wire limit")
    sys.stdout.write(encoded + "\n")
    sys.stdout.flush()


def main() -> int:
    """Read one authenticated request, run Echo once, and emit one safe frame."""

    try:
        bootstrap_line = sys.stdin.readline()
        session_key, nonce = _parse_bootstrap(bootstrap_line)
    except Exception:  # noqa: BLE001 - no authenticated channel exists yet
        return 64

    request_line = sys.stdin.readline()
    seq = 0
    try:
        raw_request = _parse_wire_object(request_line)
        seq = _request_seq(raw_request)
        parsed_seq, projection = _parse_request(
            request_line,
            session_key=session_key,
            nonce=nonce,
        )
        seq = parsed_seq
    except _AuthorityDeniedError:
        _write_response(
            _response(
                session_key=session_key,
                nonce=nonce,
                seq=seq,
                ok=False,
                code="authority_denied",
                evidence=None,
            )
        )
        return 0
    except _MessageDeniedError as exc:
        reason = str(exc)
        if "MAC" in reason:
            code = "mac_invalid"
        elif "nonce" in reason:
            code = "nonce_mismatch"
        elif "sequence" in reason:
            code = "seq_invalid"
        else:
            code = "bad_message"
        _write_response(
            _response(
                session_key=session_key,
                nonce=nonce,
                seq=seq,
                ok=False,
                code=code,
                evidence=None,
            )
        )
        return 0

    try:
        # Application loggers are initialized while redirected, so stdout stays
        # a one-line authenticated protocol rather than an unframed log stream.
        with (
            contextlib.redirect_stdout(io.StringIO()),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            evidence = asyncio.run(_run_real_echo(projection))
    except Exception:  # noqa: BLE001 - never disclose worker internals on the wire
        _write_response(
            _response(
                session_key=session_key,
                nonce=nonce,
                seq=seq,
                ok=False,
                code="turn_failed",
                evidence=None,
            )
        )
        return 0

    _write_response(
        _response(
            session_key=session_key,
            nonce=nonce,
            seq=seq,
            ok=True,
            code="",
            evidence=evidence,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
