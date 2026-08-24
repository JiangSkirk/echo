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
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from js.echo.os_sandbox import SandboxExecutor

_BOOTSTRAP_SCHEMA: Final[str] = "C1WorkerBootstrapV1"
_REQUEST_SCHEMA: Final[str] = "C1WorkerRequestV1"
_RESPONSE_SCHEMA: Final[str] = "C1WorkerResponseV1"
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
_REQUEST_KEYS: Final[frozenset[str]] = frozenset(
    {"schema", "seq", "nonce", "payload", "mac"}
)
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
    if (
        not isinstance(value, dict)
        or not value
        or not set(value).issubset(_SAFE_PROJECTION_KEYS)
    ):
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
        raise C1HarnessUnavailableError(
            "C1 requires enforced deny-default filesystem isolation"
        )
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


# The worker uses stdlib only.  Keeping it in ``python -c`` means the
# deny-default sandbox need not read the application checkout or AppShell state.
# The only IPC transport is the child process's inherited anonymous stdin/stdout.
_WORKER_PROGRAM: Final[str] = r'''
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
'''


__all__ = [
    "C1HarnessDeniedError",
    "C1HarnessUnavailableError",
    "C1WorkerEvidence",
    "C1WorkerFrameResponse",
    "C1WorkerProjection",
    "c1_harness_backend_available",
    "make_c1_worker_request_for_test",
    "run_c1_process_harness",
    "run_c1_worker_frames_for_test",
    "sign_c1_worker_request_for_test",
]
