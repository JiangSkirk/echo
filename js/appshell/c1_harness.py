"""Explicit WP-C1 process-boundary evidence harness.

This module is deliberately absent from the AppShell launcher, server, routes,
and desktop sidecar.  It is a construction/test helper only: the trusted test
host launches a restricted worker through anonymous stdin/stdout pipes, while
the existing production AppShell remains unchanged with ``orin.enforce`` off.
It is not evidence that the production AppShell/Echo split has shipped.

The worker is an actual subprocess under the existing deny-default
``SandboxExecutor`` filesystem policy.  No isolation backend means no worker:
the harness fails closed instead of treating process separation, file modes, or
an empty environment as an authority boundary.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import socket
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from js.echo.os_sandbox import SandboxExecutor

_BOOTSTRAP_SCHEMA: Final[str] = "C1WorkerBootstrapV1"
_REQUEST_SCHEMA: Final[str] = "C1WorkerRequestV1"
_RESPONSE_SCHEMA: Final[str] = "C1WorkerResponseV1"
_REAL_RESPONSE_SCHEMA: Final[str] = "C1RealEchoWorkerResponseV1"
_MAC_PREFIX: Final[str] = "c1-hmac-sha256:"
_MAX_WIRE_BYTES: Final[int] = 64 * 1024
_MAX_JSON_DEPTH: Final[int] = 8
_MAX_JSON_ITEMS: Final[int] = 256
_MAX_STRING_LENGTH: Final[int] = 8 * 1024
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
        "worker_pid",
        "parent_pid",
        "received",
        "environment_keys",
        "host_state_readable",
        "owner_key_readable",
        "provider_token_readable",
        "control_plane_importable",
        "privileged_surface",
    }
)
_RESPONSE_CODES: Final[frozenset[str]] = frozenset(
    {
        "",
        "authority_denied",
        "bad_message",
        "mac_invalid",
        "nonce_mismatch",
        "replay",
        "seq_invalid",
    }
)
_REAL_EVIDENCE_KEYS: Final[frozenset[str]] = frozenset(
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
_REAL_RESPONSE_CODES: Final[frozenset[str]] = frozenset(
    {
        "",
        "authority_denied",
        "bad_message",
        "mac_invalid",
        "nonce_mismatch",
        "seq_invalid",
        "turn_failed",
    }
)
_SHA256_VALUE_RE: Final[re.Pattern[str]] = re.compile(r"sha256:[0-9a-f]{64}\Z")
_DETERMINISTIC_RESPONSE: Final[str] = "C1 deterministic Echo response"
_AUTHORITY_MODULES: Final[tuple[str, ...]] = (
    "js.appshell.c1_harness",
    "js.appshell.launcher",
    "js.appshell.routers",
    "js.appshell.server",
    "js.appshell.switch_api",
    "js.orin.testing",
    "js.orin.witness",
    "js.orind.__main__",
    "js.orind.broker",
    "js.orind.daemon",
)
_RUNTIME_HASH_PATHS: Final[tuple[str, ...]] = (
    "agent/__init__.py",
    "agent/runner.py",
    "echo/c1_worker.py",
    "echo/turn_runtime.py",
    "echo/turn_loop/__init__.py",
    "echo/turn_loop/helpers.py",
    "echo/turn_loop/loop.py",
    "echo/turn_loop/model_gate.py",
    "echo/turn_loop/schema.py",
    "echo/turn_loop/stream_tools.py",
    "echo/turn_loop/telemetry.py",
)

type JsonValue = None | bool | int | str | list[JsonValue] | dict[str, JsonValue]


class C1HarnessDeniedError(RuntimeError):
    """The C1 test-only projection or IPC frame was not safe and exact."""


class C1HarnessUnavailableError(RuntimeError):
    """No enforceable deny-default subprocess backend is available."""


def _canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _compute_mac(session_key: bytes, envelope: dict[str, Any]) -> str:
    body = {key: value for key, value in envelope.items() if key != "mac"}
    digest = hmac.new(session_key, _canonical_json(body).encode("utf-8"), hashlib.sha256)
    return _MAC_PREFIX + digest.hexdigest()


def _authority_key(name: str) -> str:
    return "".join(character for character in name.casefold() if character.isalnum())


def _verify_mac(session_key: bytes, envelope: dict[str, Any]) -> bool:
    presented = envelope.get("mac")
    if not isinstance(presented, str) or not presented.startswith(_MAC_PREFIX):
        return False
    return hmac.compare_digest(presented, _compute_mac(session_key, envelope))


def _normalize_json(
    value: object,
    *,
    path: str,
    depth: int = 0,
    reject_authority: bool = True,
) -> JsonValue:
    if depth > _MAX_JSON_DEPTH:
        raise C1HarnessDeniedError(f"{path} exceeds the JSON depth limit")
    if value is None or isinstance(value, (bool, str)):
        if isinstance(value, str) and len(value) > _MAX_STRING_LENGTH:
            raise C1HarnessDeniedError(f"{path} contains an over-limit string")
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        if not -(1 << 63) <= value < 1 << 63:
            raise C1HarnessDeniedError(f"{path} contains an out-of-range integer")
        return value
    if isinstance(value, (list, tuple)):
        if len(value) > _MAX_JSON_ITEMS:
            raise C1HarnessDeniedError(f"{path} contains too many items")
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
            raise C1HarnessDeniedError(f"{path} contains too many fields")
        normalized: dict[str, JsonValue] = {}
        for key, item in value.items():
            if not isinstance(key, str) or not key or len(key) > 128:
                raise C1HarnessDeniedError(f"{path} contains an invalid field name")
            if reject_authority and _authority_key(key) in _AUTHORITY_KEYS:
                raise C1HarnessDeniedError(f"{path} contains authority-bearing field {key!r}")
            normalized[key] = _normalize_json(
                item,
                path=f"{path}.{key}",
                depth=depth + 1,
                reject_authority=reject_authority,
            )
        return normalized
    raise C1HarnessDeniedError(f"{path} contains a non-JSON value")


def _normalize_json_object(value: object, *, path: str) -> dict[str, JsonValue]:
    normalized = _normalize_json(value, path=path)
    if not isinstance(normalized, dict):
        raise C1HarnessDeniedError(f"{path} must be an object")
    return normalized


def _normalize_model_context(value: object) -> dict[str, JsonValue]:
    if not isinstance(value, dict) or set(value) != _MODEL_CONTEXT_KEYS:
        raise C1HarnessDeniedError("model_context fields are not on the C1 allowlist")
    messages = value.get("messages")
    if (
        not isinstance(messages, (list, tuple))
        or not 1 <= len(messages) <= 64
        or any(not isinstance(message, str) for message in messages)
    ):
        raise C1HarnessDeniedError("model_context.messages must be bounded strings")
    return _normalize_json_object({"messages": list(messages)}, path="model_context")


def _normalize_safe_projection(value: object) -> dict[str, JsonValue]:
    if not isinstance(value, dict) or not value or not set(value).issubset(_SAFE_PROJECTION_KEYS):
        raise C1HarnessDeniedError("safe_projection fields are not on the C1 allowlist")
    normalized = _normalize_json_object(value, path="safe_projection")
    if any(isinstance(item, (dict, list)) for item in normalized.values()):
        raise C1HarnessDeniedError("safe_projection values must be bounded scalars")
    return normalized


@dataclass(frozen=True, slots=True)
class C1WorkerProjection:
    """The complete authority-free view accepted by the C1 worker."""

    task_id: str
    handle_ids: tuple[str, ...]
    model_context: dict[str, JsonValue]
    safe_projection: dict[str, JsonValue]

    @classmethod
    def from_values(
        cls,
        *,
        task_id: object,
        handle_ids: object,
        model_context: object,
        safe_projection: object,
    ) -> C1WorkerProjection:
        if not isinstance(task_id, str) or _TASK_RE.fullmatch(task_id) is None:
            raise C1HarnessDeniedError("task_id must be one bounded task: identifier")
        if not isinstance(handle_ids, (list, tuple)) or not 1 <= len(handle_ids) <= 64:
            raise C1HarnessDeniedError("handle_ids must be a bounded non-empty sequence")
        handles: list[str] = []
        for handle_id in handle_ids:
            if not isinstance(handle_id, str) or _HANDLE_RE.fullmatch(handle_id) is None:
                raise C1HarnessDeniedError("handle_ids contains an invalid handle identifier")
            handles.append(handle_id)
        if len(set(handles)) != len(handles):
            raise C1HarnessDeniedError("handle_ids must not contain duplicates")
        result = cls(
            task_id=task_id,
            handle_ids=tuple(handles),
            model_context=_normalize_model_context(model_context),
            safe_projection=_normalize_safe_projection(safe_projection),
        )
        if len(_canonical_json(result.to_dict()).encode("utf-8")) > 32 * 1024:
            raise C1HarnessDeniedError("worker projection exceeds 32 KiB")
        return result

    @classmethod
    def from_dict(cls, value: object) -> C1WorkerProjection:
        if not isinstance(value, dict) or set(value) != {
            "task_id",
            "handle_ids",
            "model_context",
            "safe_projection",
        }:
            raise C1HarnessDeniedError("worker projection must have four exact fields")
        return cls.from_values(
            task_id=value["task_id"],
            handle_ids=value["handle_ids"],
            model_context=value["model_context"],
            safe_projection=value["safe_projection"],
        )

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "task_id": self.task_id,
            "handle_ids": list(self.handle_ids),
            "model_context": self.model_context,
            "safe_projection": self.safe_projection,
        }


@dataclass(frozen=True, slots=True)
class C1WorkerFrameResponse:
    """One authenticated worker response from the anonymous pipe."""

    seq: int
    ok: bool
    code: str
    evidence: dict[str, Any] | None


@dataclass(frozen=True, slots=True)
class C1WorkerEvidence:
    """Bounded, untrusted probe observations; never authorization or attestation."""

    worker_pid: int
    parent_pid: int
    received: C1WorkerProjection
    environment_keys: tuple[str, ...]
    host_state_readable: bool
    owner_key_readable: bool
    provider_token_readable: bool
    control_plane_importable: bool
    privileged_surface: tuple[str, ...]

    @classmethod
    def from_dict(cls, value: object) -> C1WorkerEvidence:
        if not isinstance(value, dict) or set(value) != _EVIDENCE_KEYS:
            raise C1HarnessDeniedError("worker evidence has an unexpected shape")
        worker_pid = value["worker_pid"]
        parent_pid = value["parent_pid"]
        environment_keys = value["environment_keys"]
        privileged_surface = value["privileged_surface"]
        booleans = (
            value["host_state_readable"],
            value["owner_key_readable"],
            value["provider_token_readable"],
            value["control_plane_importable"],
        )
        if (
            not isinstance(worker_pid, int)
            or isinstance(worker_pid, bool)
            or worker_pid <= 1
            or not isinstance(parent_pid, int)
            or isinstance(parent_pid, bool)
            or parent_pid <= 0
        ):
            raise C1HarnessDeniedError("worker evidence contains invalid process IDs")
        if not isinstance(environment_keys, list) or any(
            not isinstance(key, str) for key in environment_keys
        ):
            raise C1HarnessDeniedError("worker evidence contains invalid environment keys")
        if environment_keys != sorted(set(environment_keys)):
            raise C1HarnessDeniedError("worker evidence environment keys are not canonical")
        if not isinstance(privileged_surface, list) or any(
            not isinstance(item, str) for item in privileged_surface
        ):
            raise C1HarnessDeniedError("worker evidence contains an invalid privileged surface")
        if any(not isinstance(item, bool) for item in booleans):
            raise C1HarnessDeniedError("worker evidence contains a pseudo-boolean")
        return cls(
            worker_pid=worker_pid,
            parent_pid=parent_pid,
            received=C1WorkerProjection.from_dict(value["received"]),
            environment_keys=tuple(environment_keys),
            host_state_readable=booleans[0],
            owner_key_readable=booleans[1],
            provider_token_readable=booleans[2],
            control_plane_importable=booleans[3],
            privileged_surface=tuple(privileged_surface),
        )


@dataclass(frozen=True, slots=True)
class C1HostAuthorityEvidence:
    """Host-only use of the already-ratified Stage-B owner schemas."""

    host_pid: int
    intent_signature_valid: bool
    exact_approval_signature_valid: bool
    export_pass_signature_valid: bool
    unfreeze_signature_valid: bool
    worker_forgery_trusted: bool


@dataclass(frozen=True, slots=True)
class C1AuthorityIsolationEvidence:
    """Parent-selected attacks run under the same worker sandbox contract."""

    host_state_readable: bool
    owner_key_readable: bool
    repo_authority_source_readable: bool
    orind_socket_connectable: bool
    worker_client_has_signing_surface: bool
    missing_authority_modules: tuple[str, ...]
    runtime_hashes_verified: bool


@dataclass(frozen=True, slots=True)
class C1RealEchoWorkerEvidence:
    """Combined host observations and bounded output from a real Echo turn."""

    host_pid: int
    worker_pid: int
    worker_reported_pid: int
    worker_parent_pid: int
    entrypoint: str
    agent_type: str
    runtime_type: str
    turn_entry: str
    turn_status: str
    turn_count: int
    provider_calls: int
    projection_digest: str
    response_digest: str
    environment_keys: tuple[str, ...]
    host_authority: C1HostAuthorityEvidence
    isolation: C1AuthorityIsolationEvidence


def sign_c1_worker_request_for_test(
    envelope: dict[str, Any],
    session_key: bytes,
) -> dict[str, Any]:
    """Sign one C1 harness request; exposed only for protocol-negative tests."""

    signed = dict(envelope)
    signed["mac"] = _compute_mac(session_key, signed)
    return signed


def make_c1_worker_request_for_test(
    *,
    projection: C1WorkerProjection,
    session_key: bytes,
    nonce: str,
    seq: int,
) -> dict[str, Any]:
    """Build one exact request for the C1 test-only anonymous-pipe protocol."""

    if len(session_key) != 32:
        raise C1HarnessDeniedError("session key must be exactly 32 bytes")
    if _NONCE_RE.fullmatch(nonce) is None:
        raise C1HarnessDeniedError("session nonce must be 16 bytes of lowercase hex")
    if not isinstance(seq, int) or isinstance(seq, bool) or not 1 <= seq < 1 << 64:
        raise C1HarnessDeniedError("sequence must be a positive u64 integer")
    envelope: dict[str, Any] = {
        "schema": _REQUEST_SCHEMA,
        "seq": seq,
        "nonce": nonce,
        "payload": projection.to_dict(),
    }
    return sign_c1_worker_request_for_test(envelope, session_key)


def c1_harness_backend_available() -> bool:
    """Whether this machine can run the deny-default C1 evidence worker."""

    executor = SandboxExecutor(workspace=Path.cwd(), strict_isolation=True)
    return executor.filesystem_isolation_available()


def c1_real_echo_harness_backend_available() -> bool:
    """Whether parent-observed real-worker PID evidence is supported.

    Stage C is macOS-first.  The current Darwin ``sandbox-exec`` wrapper execs
    the payload in the parent-observed PID; Linux bwrap may supervise a nested
    PID namespace, so it must not be mislabeled as the Echo worker PID.
    """

    return sys.platform == "darwin" and c1_harness_backend_available()


def _prepare_harness_root(root: Path) -> tuple[Path, Path]:
    try:
        resolved_root = root.expanduser().resolve()
    except (OSError, RuntimeError, ValueError) as exc:
        raise C1HarnessDeniedError("C1 harness root is invalid") from exc
    host_state = resolved_root / "host-state"
    if not host_state.is_dir() or host_state.is_symlink():
        raise C1HarnessDeniedError("C1 harness requires a real host-state sibling")
    worker_root = resolved_root / "worker"
    worker_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if worker_root.is_symlink() or worker_root.resolve() != worker_root:
        raise C1HarnessDeniedError("C1 worker root must not be a symlink")
    os.chmod(worker_root, 0o700)
    return resolved_root, worker_root


def _sha256_text(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _prepare_real_harness_root(root: Path) -> tuple[Path, Path, Path]:
    """Create a fresh host/runtime/worker split for one C1 evidence run."""

    raw = root.expanduser()
    if raw.exists() or raw.is_symlink():
        raise C1HarnessDeniedError("real C1 harness root must be fresh")
    try:
        resolved = raw.resolve()
        resolved.mkdir(mode=0o700, parents=True, exist_ok=False)
        os.chmod(resolved, 0o700)
        host_state = resolved / "host-state"
        host_state.mkdir(mode=0o700)
        os.chmod(host_state, 0o700)
    except (OSError, RuntimeError, ValueError) as exc:
        raise C1HarnessDeniedError("real C1 harness root could not be created") from exc
    _resolved, worker_root = _prepare_harness_root(resolved)
    return resolved, host_state, worker_root


def _build_read_only_runtime_image(resolved_root: Path) -> tuple[Path, bool]:
    """Copy the real Echo runtime while omitting every host authority module.

    The image is a sibling of the writable worker root and is passed to the OS
    sandbox as an explicit read-only root.  A regular ``js`` package anchors
    imports here, so an editable-install ``.pth`` cannot extend ``js.__path__``
    back into the repository.
    """

    repository_root = Path(__file__).resolve().parents[2]
    source_js = repository_root / "js"
    runtime_image = resolved_root / "runtime-image"
    runtime_js = runtime_image / "js"
    runtime_image.mkdir(mode=0o700)

    def ignore(source: str, names: list[str]) -> set[str]:
        relative = Path(source).resolve().relative_to(source_js.resolve())
        ignored = {
            name
            for name in names
            if name == "__pycache__" or name.endswith((".pyc", ".pyo")) or name == ".DS_Store"
        }
        if relative == Path("appshell"):
            ignored.update(name for name in names if name not in {"__init__.py", "principal.py"})
        elif relative == Path("orin"):
            ignored.update(
                name for name in names if name in {"client.py", "testing.py", "witness.py"}
            )
        elif relative == Path("orind"):
            ignored.update(name for name in names if name not in {"__init__.py", "canary.py"})
        return ignored

    try:
        shutil.copytree(source_js, runtime_js, ignore=ignore)
        shutil.copytree(
            repository_root / "resources" / "tokenizer",
            runtime_image / "resources" / "tokenizer",
        )
        # Package facades are files in the host-built, read-only image.  They
        # preserve only the imports required by JSAgent initialization and do
        # not expose registration, grant, approval, issue, or admin methods.
        (runtime_js / "appshell" / "__init__.py").write_text(
            '"""C1 worker AppShell DTO package; no host control plane."""\n',
            encoding="utf-8",
        )
        (runtime_js / "orin" / "client.py").write_text(
            '"""Fail-closed Orin facade for the isolated C1 Echo worker."""\n\n'
            "class OrinUnavailable(RuntimeError):\n"
            "    pass\n\n"
            "class OrinLeaseClientAdapter:\n"
            "    def __init__(self, *args: object, **kwargs: object) -> None:\n"
            "        raise OrinUnavailable('Orin authority is host-only in the C1 worker')\n",
            encoding="utf-8",
        )
        (runtime_js / "orind" / "canary.py").write_text(
            '"""Constant-only canary facade for the isolated C1 Echo worker."""\n\n'
            'REFUSAL_TEXT = "This action is not permitted."\n'
            'FREEZE_TEXT = "This session is paused pending review."\n',
            encoding="utf-8",
        )
    except (OSError, RuntimeError, shutil.Error) as exc:
        raise C1HarnessUnavailableError("C1 runtime image could not be built") from exc

    for module in _AUTHORITY_MODULES:
        module_stem = runtime_image.joinpath(*module.split("."))
        module_candidates = (module_stem, module_stem.with_suffix(".py"))
        sibling_candidates = tuple(module_stem.parent.glob(module_stem.name + ".*"))
        if any(
            candidate.exists() or candidate.is_symlink()
            for candidate in (*module_candidates, *sibling_candidates)
        ):
            raise C1HarnessDeniedError(f"C1 runtime image retained authority module {module}")

    hashes_verified = True
    for relative in _RUNTIME_HASH_PATHS:
        source = source_js / relative
        copied = runtime_js / relative
        try:
            hashes_verified = hashes_verified and source.is_file() and copied.is_file()
            hashes_verified = hashes_verified and (
                hashlib.sha256(source.read_bytes()).digest()
                == hashlib.sha256(copied.read_bytes()).digest()
            )
        except OSError as exc:
            raise C1HarnessUnavailableError("C1 runtime image hash check failed") from exc
    if not hashes_verified:
        raise C1HarnessDeniedError("C1 runtime image changed an authoritative Echo entry")

    try:
        for path in sorted(runtime_image.rglob("*"), reverse=True):
            os.chmod(path, 0o555 if path.is_dir() else 0o444)
        os.chmod(runtime_image, 0o555)
    except OSError as exc:
        raise C1HarnessUnavailableError("C1 runtime image could not be frozen") from exc
    return runtime_image, hashes_verified


def _sign_host_authority(
    host_state: Path,
    projection: C1WorkerProjection,
) -> tuple[C1HostAuthorityEvidence, str]:
    """Use four existing Stage-B schemas with the host owner-witness key."""

    from js.orin.draft import ExactCommitApprovalV1, ExportPass
    from js.orin.intent import Budgets, IntentEnvelope, request_hash_of
    from js.orin.witness import build_intent_from_template, ensure_witness_keypair

    private_key, public_key_b64 = ensure_witness_keypair(host_state)
    owner_key_hash = _sha256_text(public_key_b64)
    directory_handle = next(
        (handle for handle in projection.handle_ids if handle.startswith("dirh:")),
        "dirh:c1-host-authority",
    )
    now_ms = int(time.time() * 1000)
    intent = build_intent_from_template(
        template="personal",
        task_id=projection.task_id,
        raw_request="C1 host authority boundary evidence",
        owner_key_hash=owner_key_hash,
        resource_handles=(directory_handle,),
        now_ms=now_ms,
    ).sign_with(private_key)
    exact = ExactCommitApprovalV1(
        approval_id="exact:c1-host-authority",
        task_id=projection.task_id,
        draft_id="draft:c1-host-authority",
        witness_id="state:c1-host-authority",
        canonical_effect_hash="sha256:" + "a" * 64,
        directory_handle_id=directory_handle,
        approved=True,
        created_at_ms=now_ms - 1_000,
        expires_at_ms=now_ms + 60_000,
    ).sign_with(private_key)
    export_pass = ExportPass(
        pass_id="export:c1-host-authority",
        task_id=projection.task_id,
        payload_hash="sha256:" + "b" * 64,
        destination_handles=("acct:c1-host-destination",),
        witness_id="state:c1-host-export",
        created_at_ms=now_ms - 1_000,
        expires_at_ms=now_ms + 60_000,
    ).sign_with(private_key)
    unfreeze = IntentEnvelope(
        intent_id="intent:c1-host-unfreeze",
        owner_key_hash=owner_key_hash,
        product_id="js-agent",
        profile="admin",
        task_id="task:c1-host-unfreeze",
        raw_request_hash=request_hash_of("C1 admin unfreeze evidence"),
        allowed_effect_classes=("admin.unfreeze",),
        allowed_resource_handles=(),
        allowed_sink_handles=(),
        budgets=Budgets(),
        approval_policy="dual_control",
        issued_by="appshell:admin-witness",
        issued_at_ms=now_ms - 1_000,
        expires_at_ms=now_ms + 60_000,
    ).sign_with(private_key)
    return (
        C1HostAuthorityEvidence(
            host_pid=os.getpid(),
            intent_signature_valid=intent.verify(public_key_b64),
            exact_approval_signature_valid=exact.verify(public_key_b64),
            export_pass_signature_valid=export_pass.verify(public_key_b64),
            unfreeze_signature_valid=unfreeze.verify(public_key_b64),
            worker_forgery_trusted=False,
        ),
        public_key_b64,
    )


def _bootstrap(session_key: bytes, nonce: str) -> dict[str, object]:
    return {
        "schema": _BOOTSTRAP_SCHEMA,
        "session_key": base64.b64encode(session_key).decode("ascii"),
        "nonce": nonce,
    }


def _parse_worker_response(
    raw: str,
    *,
    session_key: bytes,
    nonce: str,
    expected_seq: int,
) -> C1WorkerFrameResponse:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise C1HarnessDeniedError("worker response was not valid JSON") from exc
    if not isinstance(value, dict) or set(value) != _RESPONSE_KEYS:
        raise C1HarnessDeniedError("worker response did not match the exact schema")
    if value["schema"] != _RESPONSE_SCHEMA or value["nonce"] != nonce:
        raise C1HarnessDeniedError("worker response identity mismatch")
    if not _verify_mac(session_key, value):
        raise C1HarnessDeniedError("worker response MAC was invalid")
    seq = value["seq"]
    ok = value["ok"]
    code = value["code"]
    evidence = value["evidence"]
    if (
        not isinstance(seq, int)
        or isinstance(seq, bool)
        or not 0 <= seq < 1 << 64
        or not isinstance(ok, bool)
        or not isinstance(code, str)
        or code not in _RESPONSE_CODES
    ):
        raise C1HarnessDeniedError("worker response fields were invalid")
    if seq != expected_seq:
        raise C1HarnessDeniedError("worker response sequence did not match its request")
    if ok:
        if code or not isinstance(evidence, dict):
            raise C1HarnessDeniedError("successful worker response was malformed")
    elif not code or evidence is not None:
        raise C1HarnessDeniedError("denied worker response was malformed")
    return C1WorkerFrameResponse(seq=seq, ok=ok, code=code, evidence=evidence)


async def run_c1_worker_frames_for_test(
    *,
    root: Path,
    session_key: bytes,
    nonce: str,
    frames: tuple[dict[str, Any], ...],
) -> tuple[C1WorkerFrameResponse, ...]:
    """Run exact frames through the isolated worker for C1 negative tests."""

    if len(session_key) != 32 or _NONCE_RE.fullmatch(nonce) is None:
        raise C1HarnessDeniedError("invalid C1 harness session material")
    if not frames or len(frames) > 32:
        raise C1HarnessDeniedError("C1 harness requires between one and 32 frames")
    _resolved_root, worker_root = _prepare_harness_root(root)
    executor = SandboxExecutor(
        workspace=worker_root,
        timeout=15.0,
        max_output_bytes=_MAX_WIRE_BYTES,
        max_memory_mb=128,
        env_passthrough=[],
        strict_isolation=True,
        trusted_executables=[Path(sys.executable)],
    )
    if not executor.filesystem_isolation_available():
        raise C1HarnessUnavailableError("C1 requires enforced deny-default filesystem isolation")
    input_lines = [_canonical_json(_bootstrap(session_key, nonce))]
    for frame in frames:
        encoded = _canonical_json(frame)
        if len(encoded.encode("utf-8")) > _MAX_WIRE_BYTES:
            raise C1HarnessDeniedError("C1 request frame exceeds 64 KiB")
        input_lines.append(encoded)
    result = await executor.execute(
        [sys.executable, "-c", _WORKER_PROGRAM],
        stdin="\n".join(input_lines) + "\n",
        network_allowed=False,
        fs_restricted=True,
    )
    if result.returncode != 0:
        raise C1HarnessUnavailableError("C1 isolated worker could not complete")
    output_lines = result.stdout.splitlines()
    if len(output_lines) != len(frames):
        raise C1HarnessDeniedError("C1 worker returned an unexpected response count")
    parsed: list[C1WorkerFrameResponse] = []
    for line, frame in zip(output_lines, frames, strict=True):
        raw_seq = frame.get("seq")
        expected_seq = (
            raw_seq
            if isinstance(raw_seq, int) and not isinstance(raw_seq, bool) and 0 <= raw_seq < 1 << 64
            else 0
        )
        parsed.append(
            _parse_worker_response(
                line,
                session_key=session_key,
                nonce=nonce,
                expected_seq=expected_seq,
            )
        )
    return tuple(parsed)


async def run_c1_process_harness(
    *,
    root: Path,
    projection: C1WorkerProjection,
) -> C1WorkerEvidence:
    """Collect a synthetic real-process probe result without production wiring.

    The fixed worker is not the Echo runtime, and its self-reported booleans do
    not attest that production secrets or privileged host surfaces are absent.
    """

    session_key = secrets.token_bytes(32)
    nonce = secrets.token_hex(16)
    request = make_c1_worker_request_for_test(
        projection=projection,
        session_key=session_key,
        nonce=nonce,
        seq=1,
    )
    responses = await run_c1_worker_frames_for_test(
        root=root,
        session_key=session_key,
        nonce=nonce,
        frames=(request,),
    )
    response = responses[0]
    if not response.ok or response.evidence is None:
        raise C1HarnessDeniedError(f"C1 worker denied the host projection: {response.code}")
    evidence = C1WorkerEvidence.from_dict(response.evidence)
    if evidence.received != projection:
        raise C1HarnessDeniedError("C1 worker projection round trip changed")
    return evidence


def _parse_real_echo_response(
    raw: str,
    *,
    session_key: bytes,
    nonce: str,
    expected_projection_digest: str,
) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise C1HarnessDeniedError("real Echo worker response was not valid JSON") from exc
    if not isinstance(value, dict) or set(value) != _RESPONSE_KEYS:
        raise C1HarnessDeniedError("real Echo worker response shape was not exact")
    if value.get("schema") != _REAL_RESPONSE_SCHEMA or value.get("nonce") != nonce:
        raise C1HarnessDeniedError("real Echo worker response identity mismatch")
    if not _verify_mac(session_key, value):
        raise C1HarnessDeniedError("real Echo worker response MAC was invalid")
    if value.get("seq") != 1 or type(value.get("ok")) is not bool:
        raise C1HarnessDeniedError("real Echo worker response sequence was invalid")
    code = value.get("code")
    if not isinstance(code, str) or code not in _REAL_RESPONSE_CODES:
        raise C1HarnessDeniedError("real Echo worker response code was invalid")
    if not value["ok"]:
        if value.get("evidence") is not None or not code:
            raise C1HarnessDeniedError("real Echo worker denial was malformed")
        raise C1HarnessUnavailableError(f"real Echo worker failed closed: {code}")
    if code:
        raise C1HarnessDeniedError("successful real Echo worker returned an error code")
    evidence = value.get("evidence")
    if not isinstance(evidence, dict) or set(evidence) != _REAL_EVIDENCE_KEYS:
        raise C1HarnessDeniedError("real Echo evidence shape was not exact")

    integer_fields = {
        "worker_reported_pid": 2,
        "worker_parent_pid": 1,
        "turn_count": 0,
        "provider_calls": 0,
    }
    for field, minimum in integer_fields.items():
        item = evidence[field]
        if not isinstance(item, int) or isinstance(item, bool) or item < minimum:
            raise C1HarnessDeniedError(f"real Echo evidence {field} was invalid")
    expected_strings = {
        "entrypoint": "js.echo.c1_worker",
        "agent_type": "js.agent.JSAgent",
        "runtime_type": "js.echo.turn_runtime.EchoRuntime",
        "turn_entry": "js.echo.turn_runtime.run_echo_turn",
        "turn_status": "completed",
    }
    for field, expected in expected_strings.items():
        if evidence[field] != expected:
            raise C1HarnessDeniedError(f"real Echo evidence {field} was unexpected")
    if evidence["turn_count"] != 1 or evidence["provider_calls"] != 1:
        raise C1HarnessDeniedError("real Echo worker did not execute exactly one model turn")
    if evidence["projection_digest"] != expected_projection_digest:
        raise C1HarnessDeniedError("real Echo worker projection digest mismatch")
    if evidence["response_digest"] != _sha256_text(_DETERMINISTIC_RESPONSE):
        raise C1HarnessDeniedError("real Echo worker response digest mismatch")
    for field in ("projection_digest", "response_digest"):
        if (
            not isinstance(evidence[field], str)
            or _SHA256_VALUE_RE.fullmatch(evidence[field]) is None
        ):
            raise C1HarnessDeniedError(f"real Echo evidence {field} was malformed")
    environment_keys = evidence["environment_keys"]
    if not isinstance(environment_keys, list) or environment_keys != sorted(set(environment_keys)):
        raise C1HarnessDeniedError("real Echo worker environment keys were not canonical")
    if any(not isinstance(key, str) or len(key) > 128 for key in environment_keys):
        raise C1HarnessDeniedError("real Echo worker environment key was invalid")
    forged_signature = evidence["forged_exact_signature"]
    if not isinstance(forged_signature, str) or not 1 <= len(forged_signature) <= 256:
        raise C1HarnessDeniedError("real Echo worker forgery evidence was invalid")
    try:
        decoded_signature = base64.b64decode(forged_signature, validate=True)
    except (ValueError, TypeError) as exc:
        raise C1HarnessDeniedError("real Echo worker forgery was not base64") from exc
    if len(decoded_signature) != 64:
        raise C1HarnessDeniedError("real Echo worker forgery signature length was invalid")
    return evidence


def _parse_real_echo_frame_response(
    raw: str,
    *,
    session_key: bytes,
    nonce: str,
    expected_seq: int,
) -> C1WorkerFrameResponse:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise C1HarnessDeniedError("real Echo worker frame response was not JSON") from exc
    if not isinstance(value, dict) or set(value) != _RESPONSE_KEYS:
        raise C1HarnessDeniedError("real Echo worker frame response shape was not exact")
    if value.get("schema") != _REAL_RESPONSE_SCHEMA or value.get("nonce") != nonce:
        raise C1HarnessDeniedError("real Echo worker frame response identity mismatch")
    if not _verify_mac(session_key, value):
        raise C1HarnessDeniedError("real Echo worker frame response MAC was invalid")
    seq = value.get("seq")
    ok = value.get("ok")
    code = value.get("code")
    evidence = value.get("evidence")
    if (
        not isinstance(seq, int)
        or isinstance(seq, bool)
        or seq != expected_seq
        or type(ok) is not bool
        or not isinstance(code, str)
        or code not in _REAL_RESPONSE_CODES
    ):
        raise C1HarnessDeniedError("real Echo worker frame response fields were invalid")
    if ok:
        if code or not isinstance(evidence, dict):
            raise C1HarnessDeniedError("real Echo worker success frame was malformed")
    elif not code or evidence is not None:
        raise C1HarnessDeniedError("real Echo worker denial frame was malformed")
    return C1WorkerFrameResponse(seq=seq, ok=ok, code=code, evidence=evidence)


async def run_c1_real_echo_frame_for_test(
    *,
    root: Path,
    session_key: bytes,
    nonce: str,
    frame: dict[str, Any],
) -> C1WorkerFrameResponse:
    """Send one raw frame to the fixed real worker for IPC rejection tests."""

    if not c1_real_echo_harness_backend_available():
        raise C1HarnessUnavailableError(
            "real Echo C1 evidence currently requires macOS sandbox-exec"
        )
    if len(session_key) != 32 or _NONCE_RE.fullmatch(nonce) is None:
        raise C1HarnessDeniedError("invalid real Echo harness session material")
    _resolved_root, _host_state, worker_root = _prepare_real_harness_root(root)
    runtime_image, _hashes_verified = _build_read_only_runtime_image(_resolved_root)
    executor = SandboxExecutor(
        workspace=worker_root,
        timeout=20.0,
        max_output_bytes=_MAX_WIRE_BYTES,
        max_memory_mb=512,
        env_passthrough=[],
        strict_isolation=True,
        trusted_executables=[Path(sys.executable)],
    )
    encoded_frame = _canonical_json(frame)
    if len(encoded_frame.encode("utf-8")) > _MAX_WIRE_BYTES:
        raise C1HarnessDeniedError("real Echo request frame exceeds 64 KiB")
    input_text = "\n".join((_canonical_json(_bootstrap(session_key, nonce)), encoded_frame, ""))
    result = await executor.execute(
        [sys.executable, "-m", "js.echo.c1_worker"],
        cwd=os.fspath(runtime_image),
        stdin=input_text,
        network_allowed=False,
        fs_restricted=True,
        read_only_paths=(runtime_image,),
    )
    if result.returncode != 0:
        raise C1HarnessUnavailableError("real Echo IPC rejection worker could not complete")
    lines = result.stdout.splitlines()
    if len(lines) != 1:
        raise C1HarnessDeniedError("real Echo IPC rejection worker returned extra output")
    raw_seq = frame.get("seq")
    expected_seq = (
        raw_seq
        if isinstance(raw_seq, int) and not isinstance(raw_seq, bool) and 0 <= raw_seq < 1 << 64
        else 0
    )
    return _parse_real_echo_frame_response(
        lines[0],
        session_key=session_key,
        nonce=nonce,
        expected_seq=expected_seq,
    )


async def _run_c1_authority_attacks(
    *,
    executor: SandboxExecutor,
    runtime_image: Path,
    socket_path: Path,
) -> dict[str, Any]:
    """Run host-selected escape attempts under the worker's exact OS policy."""

    repository_router = Path(__file__).resolve().parent / "routers.py"
    attack_input = _canonical_json(
        {
            "repo_authority_source": os.fspath(repository_router),
            "authority_modules": list(_AUTHORITY_MODULES),
            "orind_socket": os.fspath(socket_path),
        }
    )
    result = await executor.execute(
        [sys.executable, "-c", _AUTHORITY_ATTACK_PROGRAM],
        cwd=os.fspath(runtime_image),
        stdin=attack_input + "\n",
        network_allowed=False,
        fs_restricted=True,
        read_only_paths=(runtime_image,),
    )
    if result.returncode != 0:
        raise C1HarnessUnavailableError("C1 authority attack process could not complete")
    lines = result.stdout.splitlines()
    if len(lines) != 1:
        raise C1HarnessDeniedError("C1 authority attack returned unexpected output")
    try:
        evidence = json.loads(lines[0])
    except json.JSONDecodeError as exc:
        raise C1HarnessDeniedError("C1 authority attack output was not JSON") from exc
    expected_fields = {
        "host_state_readable",
        "owner_key_readable",
        "repo_authority_source_readable",
        "orind_socket_connectable",
        "missing_authority_modules",
    }
    if not isinstance(evidence, dict) or set(evidence) != expected_fields:
        raise C1HarnessDeniedError("C1 authority attack output shape was not exact")
    for field in expected_fields - {"missing_authority_modules"}:
        if type(evidence[field]) is not bool:
            raise C1HarnessDeniedError("C1 authority attack returned a pseudo-boolean")
    missing = evidence["missing_authority_modules"]
    if missing != list(_AUTHORITY_MODULES):
        raise C1HarnessDeniedError("C1 runtime exposed a host authority module")
    if any(
        evidence[field]
        for field in (
            "host_state_readable",
            "owner_key_readable",
            "repo_authority_source_readable",
            "orind_socket_connectable",
        )
    ):
        raise C1HarnessDeniedError("C1 OS boundary exposed host authority")
    if not socket_path.is_socket():
        raise C1HarnessDeniedError("C1 authority socket control was not live")
    return evidence


async def run_c1_real_echo_process_harness(
    *,
    root: Path,
    projection: C1WorkerProjection,
) -> C1RealEchoWorkerEvidence:
    """Execute one real JSAgent/Echo turn in the explicit C1-only boundary.

    This helper is deliberately not imported by any product launcher.  It
    proves the first C1 construction gate only for this harness; production
    AppShell remains single-process and ``orin.enforce`` remains fail-fast.
    The caller owns ``root`` and its test-only key/runtime/state artifacts.
    """

    if not c1_real_echo_harness_backend_available():
        raise C1HarnessUnavailableError(
            "real Echo C1 evidence currently requires macOS sandbox-exec"
        )

    resolved_root, host_state, worker_root = _prepare_real_harness_root(root)
    runtime_image, runtime_hashes_verified = _build_read_only_runtime_image(resolved_root)
    host_authority, public_key_b64 = _sign_host_authority(host_state, projection)
    executor = SandboxExecutor(
        workspace=worker_root,
        timeout=45.0,
        max_output_bytes=_MAX_WIRE_BYTES,
        max_memory_mb=512,
        env_passthrough=[],
        strict_isolation=True,
        trusted_executables=[Path(sys.executable)],
    )
    if not executor.filesystem_isolation_available():
        raise C1HarnessUnavailableError("C1 requires enforced deny-default filesystem isolation")

    session_key = secrets.token_bytes(32)
    nonce = secrets.token_hex(16)
    request = make_c1_worker_request_for_test(
        projection=projection,
        session_key=session_key,
        nonce=nonce,
        seq=1,
    )
    projection_digest = _sha256_text(_canonical_json(projection.to_dict()))
    input_text = "\n".join(
        (_canonical_json(_bootstrap(session_key, nonce)), _canonical_json(request), "")
    )
    short_socket_root = Path("/private/tmp") if sys.platform == "darwin" else Path("/tmp")
    socket_path = short_socket_root / f"orin-c1-{secrets.token_hex(8)}.sock"
    if socket_path.exists() or socket_path.is_symlink():
        raise C1HarnessDeniedError("C1 authority socket path was not fresh")
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        listener.bind(os.fspath(socket_path))
        os.chmod(socket_path, 0o600)
        listener.listen(1)
        result = await executor.execute(
            [sys.executable, "-m", "js.echo.c1_worker"],
            cwd=os.fspath(runtime_image),
            stdin=input_text,
            network_allowed=False,
            fs_restricted=True,
            read_only_paths=(runtime_image,),
        )
        if result.returncode != 0 or result.spawned_pid is None:
            raise C1HarnessUnavailableError("real Echo worker could not complete")
        output_lines = result.stdout.splitlines()
        if len(output_lines) != 1:
            raise C1HarnessDeniedError("real Echo worker returned unexpected output")
        worker = _parse_real_echo_response(
            output_lines[0],
            session_key=session_key,
            nonce=nonce,
            expected_projection_digest=projection_digest,
        )
        if worker["worker_reported_pid"] != result.spawned_pid:
            raise C1HarnessDeniedError("worker PID did not match the parent-observed PID")
        attacks = await _run_c1_authority_attacks(
            executor=executor,
            runtime_image=runtime_image,
            socket_path=socket_path,
        )
    finally:
        listener.close()
        socket_path.unlink(missing_ok=True)

    from js.orin.draft import ExactCommitApprovalV1

    directory_handle = next(
        (handle for handle in projection.handle_ids if handle.startswith("dirh:")),
        "dirh:c1-worker-forgery",
    )
    worker_forgery = ExactCommitApprovalV1(
        approval_id="exact:c1-worker-forgery",
        task_id=projection.task_id,
        draft_id="draft:c1-worker-forgery",
        witness_id="state:c1-worker-forgery",
        canonical_effect_hash=projection_digest,
        directory_handle_id=directory_handle,
        approved=True,
        created_at_ms=1,
        expires_at_ms=2,
        signature=worker["forged_exact_signature"],
    )
    forgery_trusted = worker_forgery.verify(public_key_b64)
    if forgery_trusted:
        raise C1HarnessDeniedError("worker-created exact approval matched the host owner key")
    host_authority = C1HostAuthorityEvidence(
        host_pid=host_authority.host_pid,
        intent_signature_valid=host_authority.intent_signature_valid,
        exact_approval_signature_valid=host_authority.exact_approval_signature_valid,
        export_pass_signature_valid=host_authority.export_pass_signature_valid,
        unfreeze_signature_valid=host_authority.unfreeze_signature_valid,
        worker_forgery_trusted=forgery_trusted,
    )
    client_source = (runtime_image / "js" / "orin" / "client.py").read_text(encoding="utf-8")
    client_has_signing_surface = any(
        marker in client_source
        for marker in ("approved=True", "grant_exact", "grant_export", "admin_unfreeze")
    )
    isolation = C1AuthorityIsolationEvidence(
        host_state_readable=attacks["host_state_readable"],
        owner_key_readable=attacks["owner_key_readable"],
        repo_authority_source_readable=attacks["repo_authority_source_readable"],
        orind_socket_connectable=attacks["orind_socket_connectable"],
        worker_client_has_signing_surface=client_has_signing_surface,
        missing_authority_modules=tuple(attacks["missing_authority_modules"]),
        runtime_hashes_verified=runtime_hashes_verified,
    )
    if isolation.worker_client_has_signing_surface:
        raise C1HarnessDeniedError("C1 worker client facade retained a signing method")
    return C1RealEchoWorkerEvidence(
        host_pid=os.getpid(),
        worker_pid=result.spawned_pid,
        worker_reported_pid=worker["worker_reported_pid"],
        worker_parent_pid=worker["worker_parent_pid"],
        entrypoint=worker["entrypoint"],
        agent_type=worker["agent_type"],
        runtime_type=worker["runtime_type"],
        turn_entry=worker["turn_entry"],
        turn_status=worker["turn_status"],
        turn_count=worker["turn_count"],
        provider_calls=worker["provider_calls"],
        projection_digest=worker["projection_digest"],
        response_digest=worker["response_digest"],
        environment_keys=tuple(worker["environment_keys"]),
        host_authority=host_authority,
        isolation=isolation,
    )


# Parent-selected escape attempts.  This fixed program is not the Echo worker
# and is never accepted as runtime evidence; it only asks the OS sandbox to
# deny concrete reads/imports/socket access under the identical launch policy.
_AUTHORITY_ATTACK_PROGRAM: Final[str] = r"""
import importlib.util
import json
import socket
from pathlib import Path

request = json.loads(input())
if not isinstance(request, dict) or set(request) != {
    "repo_authority_source", "authority_modules", "orind_socket"
}:
    raise SystemExit(64)
repo_source = request["repo_authority_source"]
modules = request["authority_modules"]
orind_socket_raw = request["orind_socket"]
if (
    not isinstance(repo_source, str)
    or not isinstance(modules, list)
    or not isinstance(orind_socket_raw, str)
):
    raise SystemExit(64)
if any(not isinstance(module, str) for module in modules):
    raise SystemExit(64)

root = Path.cwd().parent
host_state = root / "host-state"
owner_key = host_state / "orin" / "appshell_witness" / ".signing_key"
orind_socket = Path(orind_socket_raw)

def can_list(path):
    try:
        list(path.iterdir())
    except (OSError, RuntimeError):
        return False
    return True

def can_read(path):
    try:
        with path.open("rb") as stream:
            stream.read(1)
    except (OSError, RuntimeError):
        return False
    return True

missing = []
for module in modules:
    try:
        spec = importlib.util.find_spec(module)
    except Exception:
        continue
    if spec is None:
        missing.append(module)

connectable = False
client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
client.settimeout(0.2)
try:
    client.connect(str(orind_socket))
except OSError:
    pass
else:
    connectable = True
finally:
    client.close()

evidence = {
    "host_state_readable": can_list(host_state),
    "owner_key_readable": can_read(owner_key),
    "repo_authority_source_readable": can_read(Path(repo_source)),
    "orind_socket_connectable": connectable,
    "missing_authority_modules": missing,
}
print(json.dumps(evidence, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
"""


# The worker uses stdlib only.  Keeping it in ``python -c`` means the
# deny-default sandbox need not read the application checkout or AppShell state.
# The only IPC transport is the child process's inherited anonymous stdin/stdout.
_WORKER_PROGRAM: Final[str] = r"""
import base64
import hashlib
import hmac
import json
import os
import re
from pathlib import Path

BOOTSTRAP_SCHEMA = "C1WorkerBootstrapV1"
REQUEST_SCHEMA = "C1WorkerRequestV1"
RESPONSE_SCHEMA = "C1WorkerResponseV1"
MAC_PREFIX = "c1-hmac-sha256:"
AUTHORITY_KEYS = {
    "approved", "approval", "apikey", "authorization", "credential", "credentials",
    "grant", "issue", "ownerkey", "ownerprivatekey", "ownerwitness", "package",
    "permit", "providertoken", "secret", "statedir", "token", "workspaceroot",
}
REQUEST_KEYS = {"schema", "seq", "nonce", "payload", "mac"}
PAYLOAD_KEYS = {"task_id", "handle_ids", "model_context", "safe_projection"}
MODEL_CONTEXT_KEYS = {"messages"}
SAFE_PROJECTION_KEYS = {
    "bytes", "diff_hash", "file_count", "message", "overwrites", "status", "summary",
}
TASK_RE = re.compile(r"task:[A-Za-z0-9._:-]{1,191}\Z")
HANDLE_RE = re.compile(
    r"(?:dirh|artifact|rcpt|ep|acct|secret|desktop):[A-Za-z0-9._-]{1,200}\Z"
)

class AuthorityDenied(Exception):
    pass

def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

def compute_mac(key, envelope):
    body = {name: value for name, value in envelope.items() if name != "mac"}
    digest = hmac.new(key, canonical(body).encode("utf-8"), hashlib.sha256).hexdigest()
    return MAC_PREFIX + digest

def verify_mac(key, envelope):
    presented = envelope.get("mac")
    return (
        isinstance(presented, str)
        and presented.startswith(MAC_PREFIX)
        and hmac.compare_digest(presented, compute_mac(key, envelope))
    )

def authority_key(name):
    return "".join(character for character in name.casefold() if character.isalnum())

def validate_json(value, depth=0):
    if depth > 8:
        raise ValueError("depth")
    if value is None or isinstance(value, (bool, str)):
        if isinstance(value, str) and len(value) > 8192:
            raise ValueError("string")
        return
    if isinstance(value, int) and not isinstance(value, bool):
        if not -(1 << 63) <= value < (1 << 63):
            raise ValueError("integer")
        return
    if isinstance(value, list):
        if len(value) > 256:
            raise ValueError("items")
        for item in value:
            validate_json(item, depth + 1)
        return
    if isinstance(value, dict):
        if len(value) > 256:
            raise ValueError("fields")
        for name, item in value.items():
            if not isinstance(name, str) or not name or len(name) > 128:
                raise ValueError("field")
            if authority_key(name) in AUTHORITY_KEYS:
                raise AuthorityDenied(name)
            validate_json(item, depth + 1)
        return
    raise ValueError("type")

def validate_payload(payload):
    if not isinstance(payload, dict) or set(payload) != PAYLOAD_KEYS:
        raise ValueError("payload shape")
    task_id = payload["task_id"]
    handles = payload["handle_ids"]
    if not isinstance(task_id, str) or TASK_RE.fullmatch(task_id) is None:
        raise ValueError("task")
    if not isinstance(handles, list) or not 1 <= len(handles) <= 64:
        raise ValueError("handles")
    if len(set(handles)) != len(handles):
        raise ValueError("duplicate handles")
    if any(not isinstance(item, str) or HANDLE_RE.fullmatch(item) is None for item in handles):
        raise ValueError("handle")
    model_context = payload["model_context"]
    if not isinstance(model_context, dict) or set(model_context) != MODEL_CONTEXT_KEYS:
        raise AuthorityDenied("model context allowlist")
    messages = model_context["messages"]
    if (
        not isinstance(messages, list)
        or not 1 <= len(messages) <= 64
        or any(not isinstance(message, str) for message in messages)
    ):
        raise ValueError("model context")
    safe_projection = payload["safe_projection"]
    if (
        not isinstance(safe_projection, dict)
        or not safe_projection
        or not set(safe_projection).issubset(SAFE_PROJECTION_KEYS)
    ):
        raise AuthorityDenied("safe projection allowlist")
    if any(isinstance(item, (dict, list)) for item in safe_projection.values()):
        raise ValueError("safe projection")
    validate_json(model_context)
    validate_json(safe_projection)
    if len(canonical(payload).encode("utf-8")) > 32768:
        raise ValueError("payload size")

def can_list(path):
    try:
        list(path.iterdir())
    except (OSError, RuntimeError):
        return False
    return True

def can_read(path):
    try:
        with path.open("rb") as stream:
            stream.read(1)
    except (OSError, RuntimeError):
        return False
    return True

def send(key, nonce, seq, ok, code, evidence):
    response = {
        "schema": RESPONSE_SCHEMA,
        "seq": seq,
        "nonce": nonce,
        "ok": ok,
        "code": code,
        "evidence": evidence,
    }
    response["mac"] = compute_mac(key, response)
    print(canonical(response), flush=True)

bootstrap_line = input()
bootstrap = json.loads(bootstrap_line)
if not isinstance(bootstrap, dict) or set(bootstrap) != {
    "schema", "session_key", "nonce"
}:
    raise SystemExit(64)
if bootstrap["schema"] != BOOTSTRAP_SCHEMA:
    raise SystemExit(64)
if not isinstance(bootstrap["session_key"], str) or not isinstance(bootstrap["nonce"], str):
    raise SystemExit(64)
try:
    session_key = base64.b64decode(bootstrap["session_key"], validate=True)
except (ValueError, TypeError):
    raise SystemExit(64)
if len(session_key) != 32 or re.fullmatch(r"[0-9a-f]{32}", bootstrap["nonce"]) is None:
    raise SystemExit(64)
session_nonce = bootstrap["nonce"]
last_seq = 0

for line in __import__("sys").stdin:
    if not line.strip():
        continue
    try:
        request = json.loads(line)
    except json.JSONDecodeError:
        send(session_key, session_nonce, 0, False, "bad_message", None)
        continue
    raw_seq = request.get("seq", 0) if isinstance(request, dict) else 0
    response_seq = raw_seq if isinstance(raw_seq, int) and not isinstance(raw_seq, bool) else 0
    if not isinstance(request, dict) or set(request) != REQUEST_KEYS:
        send(session_key, session_nonce, response_seq, False, "bad_message", None)
        continue
    if request["schema"] != REQUEST_SCHEMA:
        send(session_key, session_nonce, response_seq, False, "bad_message", None)
        continue
    if not verify_mac(session_key, request):
        send(session_key, session_nonce, response_seq, False, "mac_invalid", None)
        continue
    if request["nonce"] != session_nonce:
        send(session_key, session_nonce, response_seq, False, "nonce_mismatch", None)
        continue
    seq = request["seq"]
    if not isinstance(seq, int) or isinstance(seq, bool) or not 1 <= seq < (1 << 64):
        send(session_key, session_nonce, response_seq, False, "seq_invalid", None)
        continue
    if seq <= last_seq:
        send(session_key, session_nonce, seq, False, "replay", None)
        continue
    if seq != last_seq + 1:
        send(session_key, session_nonce, seq, False, "seq_invalid", None)
        continue
    try:
        validate_payload(request["payload"])
    except AuthorityDenied:
        send(session_key, session_nonce, seq, False, "authority_denied", None)
        continue
    except (TypeError, ValueError):
        send(session_key, session_nonce, seq, False, "bad_message", None)
        continue
    last_seq = seq
    host_state = Path.cwd().parent / "host-state"
    try:
        __import__("js.appshell.routers")
    except (ImportError, OSError, RuntimeError):
        control_plane_importable = False
    else:
        control_plane_importable = True
    evidence = {
        "worker_pid": os.getpid(),
        "parent_pid": os.getppid(),
        "received": request["payload"],
        "environment_keys": sorted(os.environ),
        "host_state_readable": can_list(host_state),
        "owner_key_readable": can_read(
            host_state / "orin" / "appshell_witness" / ".signing_key"
        ),
        "provider_token_readable": can_read(host_state / "provider-token"),
        "control_plane_importable": control_plane_importable,
        "privileged_surface": [],
    }
    send(session_key, session_nonce, seq, True, "", evidence)
"""


__all__ = [
    "C1AuthorityIsolationEvidence",
    "C1HarnessDeniedError",
    "C1HarnessUnavailableError",
    "C1HostAuthorityEvidence",
    "C1RealEchoWorkerEvidence",
    "C1WorkerEvidence",
    "C1WorkerFrameResponse",
    "C1WorkerProjection",
    "c1_harness_backend_available",
    "c1_real_echo_harness_backend_available",
    "make_c1_worker_request_for_test",
    "run_c1_process_harness",
    "run_c1_real_echo_frame_for_test",
    "run_c1_real_echo_process_harness",
    "run_c1_worker_frames_for_test",
    "sign_c1_worker_request_for_test",
]
