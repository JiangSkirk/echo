"""Network / Connector / Secret cells (WP8) in one resident services process.

- **Network Cell** (``cell.net``): fetches ONLY hosts sealed in the Endpoint
  Manifest; DNS + redirects + final target go through
  ``js.security.net_guard.resolve_and_validate`` (no second SSRF checker);
  cross-host redirects are denied. Response bodies come back as untrusted
  TOOL_RESULT data, size-capped.
- **Connector Cell** (``cell.connector``): sends exact payloads bound by an
  approved export pass — idempotency key dedupe in a local outbox; tokens
  are pulled from the SecretStore and NEVER appear in results.
- **Secret Cell** (``cell.secret``): stores credentials under sealed
  ``SecretHandle`` ids at ``<state_dir>/orin/secrets.jsonl`` (0600).
  Production deployments swap this file for Keychain ACL lookups; the
  interface (audience/op/count binding via handle capabilities) is stable.
"""

from __future__ import annotations

import asyncio
import fcntl
import hashlib
import json
import os
import platform
import secrets as secret_tokens
import stat
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

import httpx

from js.orin import taint
from js.orin.draft import CellPackage, CommitPermit, Impact, StateWitness
from js.orin.handles import OriginHandle, handle_from_dict
from js.orin.hooks import inspect_canary_text
from js.orin.protocol import ProtocolError, canonical_json
from js.orind.cells.base import CellBase
from js.orind.private_paths import (
    PathIdentity,
    PrivatePathError,
    ensure_private_dir,
    open_private_file,
    verify_private_file,
    write_private_file_exclusive,
)
from js.security.net_guard import PinnedTransport, resolve_and_validate

_MAX_BODY_CHARS = 48 * 1024
_MAX_WIRE_BODY_BYTES = 256 * 1024
_MAX_REDIRECTS = 5
_WITNESS_TTL_MS = 60_000
_REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})


def _now_ms() -> int:
    return time.time_ns() // 1_000_000


def _canonical_origin(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
        raise ProtocolError("URL must use http or https and include a host")
    if parsed.username is not None or parsed.password is not None:
        raise ProtocolError("URL credentials are forbidden")
    try:
        host = parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".")
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    except (UnicodeError, ValueError) as exc:
        raise ProtocolError("URL host or port is invalid") from exc
    return f"{parsed.scheme.lower()}://{host}:{port}"


def _hostname(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    if not parsed.hostname:
        raise ProtocolError("URL has no host")
    try:
        return parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".")
    except UnicodeError as exc:
        raise ProtocolError("URL hostname is invalid") from exc


def _target_version(url: str, addresses: Sequence[str]) -> str:
    material = canonical_json(
        {"origin": _canonical_origin(url), "addresses": sorted(set(addresses))}
    )
    return "net:" + hashlib.sha256(material.encode("utf-8")).hexdigest()


class SecretStore:
    """0600 JSONL dev fallback of ``{handle_id, token}``.

    L2 Keychain probing is deliberately separate and optional: it is not
    treated as proof of controlled cross-process extraction.
    """

    def __init__(self, state_dir: Path, *, strict_paths: bool = False) -> None:
        self._path = state_dir / "orin" / "secrets.jsonl"
        self._strict_paths = bool(strict_paths)
        self._identity: PathIdentity | None = None
        if self._strict_paths:
            ensure_private_dir(self._path.parent)
            try:
                self._identity = verify_private_file(self._path)
            except PrivatePathError:
                try:
                    self._path.lstat()
                except FileNotFoundError:
                    self._identity = write_private_file_exclusive(self._path, b"")
                else:
                    raise
        else:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            if not self._path.exists():
                fd = os.open(self._path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                os.close(fd)
            else:
                os.chmod(self._path, 0o600)

    def _open_strict(self, flags: int) -> int:
        assert self._identity is not None
        fd, identity = open_private_file(self._path, flags, expected=self._identity)
        if identity != self._identity:
            os.close(fd)
            raise PrivatePathError("SecretStore file identity changed")
        return fd

    def _verify_strict(self) -> None:
        assert self._identity is not None
        verify_private_file(self._path, expected=self._identity)

    def put(self, handle_id: str, token: str) -> None:
        if self._strict_paths:
            fd = self._open_strict(os.O_WRONLY | os.O_APPEND)
            fh = os.fdopen(fd, "a", encoding="utf-8")
        else:
            fh = self._path.open("a", encoding="utf-8")
        with fh:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            fh.write(json.dumps({"handle_id": handle_id, "token": token}) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        if self._strict_paths:
            self._verify_strict()

    def get(self, handle_id: str) -> str | None:
        if not self._strict_paths and not self._path.exists():
            return None
        found: str | None = None
        if self._strict_paths:
            fd = self._open_strict(os.O_RDONLY)
            fh = os.fdopen(fd, "r", encoding="utf-8")
        else:
            fh = self._path.open("r", encoding="utf-8")
        with fh:
            fcntl.flock(fh.fileno(), fcntl.LOCK_SH)
            for line in fh:
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if str(row.get("handle_id")) == handle_id:
                    found = str(row.get("token") or "")
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        if self._strict_paths:
            self._verify_strict()
        return found


def _verify_sealed_handle(
    raw: Any,
    mac_key: bytes,
    *,
    kind: str | None = None,
    capability: str | None = None,
    now_ms: int | None = None,
) -> OriginHandle | None:
    try:
        data = raw if isinstance(raw, dict) else {"handle_id": str(raw)}
        handle = handle_from_dict(data, require_signature=True)
    except Exception:  # noqa: BLE001 - malformed handles fail closed
        return None
    if kind is not None and handle.kind != kind:
        return None
    if not handle.verify_seal(mac_key):
        return None
    now = _now_ms() if now_ms is None else now_ms
    if now >= handle.expires_at_ms:
        return None
    if capability is not None and capability not in handle.capabilities:
        return None
    return handle


class NetCell(CellBase):
    """``cell.net``: signed-endpoint GET with DNS pinning per hop."""

    def __init__(
        self,
        *,
        socket_path: Path,
        state_dir: Path,
        mac_key: bytes,
        allowed_hosts: frozenset[str] = frozenset(),
    ) -> None:
        self._mac_key = mac_key
        self._allowed_hosts = frozenset(host.lower().rstrip(".") for host in allowed_hosts)

        super().__init__(
            cap="cell.net",
            socket_path=socket_path,
            state_dir=state_dir,
            handler=self._commit_package,
            preflight_handler=self._preflight_package,
            strict_effect_protocol=True,
        )

    def _fetch(self, permit: dict[str, Any]) -> dict[str, Any]:
        """Synchronous unit/admin probe; the authenticated path is async."""

        try:
            url, _endpoint, timeout_s, max_chars = self._prepare_request(permit)
            addresses = resolve_and_validate(url)
            # Kept solely for the injected redirect-handler unit probe.  The
            # real guard always returns a non-empty list, and strict commits
            # reject a broken/None validator result before network access.
            if addresses is None:  # type: ignore[comparison-overlap]
                return self._legacy_redirect_probe(url, timeout_s)
            if not addresses:
                return {"status": "FAILED", "error": "egress blocked: no safe addresses"}
            return asyncio.run(
                self._fetch_http(
                    url,
                    timeout_s=timeout_s,
                    max_chars=max_chars,
                    first_addresses=addresses,
                )
            )
        except Exception as exc:  # noqa: BLE001 - direct probe fails closed
            return {"status": "FAILED", "error": f"egress blocked: {exc}"}

    def _prepare_request(
        self,
        raw: dict[str, Any],
    ) -> tuple[str, OriginHandle, float, int]:
        allowed = {"url", "endpoint_handle", "timeout_s", "max_chars"}
        unknown = set(raw) - allowed
        if unknown:
            raise ProtocolError("net.fetch forbids request body, credentials, and extra fields")
        url = raw.get("url")
        if not isinstance(url, str) or not url or len(url) > 4_096:
            raise ProtocolError("fetch requires a bounded url")
        origin = _canonical_origin(url)
        host = _hostname(url)
        endpoint = _verify_sealed_handle(
            raw.get("endpoint_handle"),
            self._mac_key,
            kind="EndpointHandle",
            capability="read",
        )
        if endpoint is None:
            raise ProtocolError("endpoint handle missing, expired, unsealed, or unauthorized")
        digest = "sha256:" + hashlib.sha256(origin.encode("utf-8")).hexdigest()
        if endpoint.object_digest not in {host, origin, digest}:
            raise ProtocolError("URL origin differs from sealed endpoint")
        if self._allowed_hosts and host not in self._allowed_hosts:
            raise ProtocolError("host not in endpoint manifest")
        raw_timeout = raw.get("timeout_s", 15)
        raw_max = raw.get("max_chars", _MAX_BODY_CHARS)
        if isinstance(raw_timeout, bool) or not isinstance(raw_timeout, (int, float)):
            raise ProtocolError("timeout_s must be numeric")
        if isinstance(raw_max, bool) or not isinstance(raw_max, int):
            raise ProtocolError("max_chars must be an integer")
        timeout_s = min(max(float(raw_timeout), 0.1), 30.0)
        max_chars = min(max(raw_max, 1), _MAX_BODY_CHARS)
        return url, endpoint, timeout_s, max_chars

    def _package_request(self, package: CellPackage) -> dict[str, Any]:
        if package.draft.effect_type != "net.fetch":
            raise ProtocolError("Network Cell accepts only net.fetch drafts")
        endpoints = [
            handle for handle in package.resolved_handles if handle.kind == "EndpointHandle"
        ]
        if len(endpoints) != 1:
            raise ProtocolError("net.fetch requires exactly one EndpointHandle")
        raw = dict(package.draft.arguments)
        raw["endpoint_handle"] = endpoints[0].to_dict()
        return raw

    def _preflight_package(self, package: CellPackage) -> StateWitness:
        raw = self._package_request(package)
        url, _endpoint, _timeout_s, _max_chars = self._prepare_request(raw)
        addresses = resolve_and_validate(url)
        if not addresses:
            raise ProtocolError("endpoint did not resolve to a safe address")
        now = _now_ms()
        return StateWitness(
            witness_id=f"state:{secret_tokens.token_hex(16)}",
            draft_id=package.draft.draft_id,
            executor_id=package.executor_id,
            target_version=_target_version(url, addresses),
            canonical_effect_hash=package.canonical_effect_hash,
            impact=Impact(),
            reversibility="reversible_until_stage",
            idempotency_support="none",
            created_at_ms=now,
            expires_at_ms=now + _WITNESS_TTL_MS,
        )

    async def _commit_package(
        self,
        _permit: CommitPermit,
        package: CellPackage,
    ) -> dict[str, Any]:
        raw = self._package_request(package)
        url, _endpoint, timeout_s, max_chars = self._prepare_request(raw)
        addresses = resolve_and_validate(url)
        if not addresses:
            return {"status": "FAILED", "error": "endpoint has no safe address"}
        witness = package.state_witness
        if witness is None or witness.target_version != _target_version(url, addresses):
            return {"status": "FAILED", "error": "endpoint state changed after preflight"}
        return await self._fetch_http(
            url,
            timeout_s=timeout_s,
            max_chars=max_chars,
            first_addresses=addresses,
        )

    async def _fetch_http(
        self,
        url: str,
        *,
        timeout_s: float,
        max_chars: int,
        first_addresses: Sequence[str],
    ) -> dict[str, Any]:
        initial_origin = _canonical_origin(url)
        current_url = url
        addresses = list(first_addresses)
        redirects = 0
        try:
            while True:
                if not addresses:
                    raise ProtocolError("redirect target has no safe address")
                host = _hostname(current_url)
                if self._allowed_hosts and host not in self._allowed_hosts:
                    raise ProtocolError("redirect target not in endpoint manifest")
                transport = PinnedTransport(str(addresses[0]))
                timeout = httpx.Timeout(timeout_s)
                async with (
                    httpx.AsyncClient(
                        transport=transport,
                        trust_env=False,
                        follow_redirects=False,
                        timeout=timeout,
                        headers={"Accept-Encoding": "identity"},
                    ) as client,
                    client.stream("GET", current_url) as response,
                ):
                    if response.status_code in _REDIRECT_CODES:
                        location = response.headers.get("location")
                        if not location:
                            raise ProtocolError("redirect response is missing Location")
                        if redirects >= _MAX_REDIRECTS:
                            raise ProtocolError("too many redirects")
                        next_url = urllib.parse.urljoin(current_url, location)
                        if _canonical_origin(next_url) != initial_origin:
                            raise ProtocolError("cross-host redirect denied")
                        # Re-resolve and re-pin before sending the next hop.
                        addresses = resolve_and_validate(next_url)
                        current_url = next_url
                        redirects += 1
                        continue
                    if response.status_code >= 400:
                        return {
                            "status": "FAILED",
                            "error": f"http {response.status_code}",
                            "output": "",
                        }
                    body = bytearray()
                    async for chunk in response.aiter_bytes():
                        remaining = _MAX_WIRE_BODY_BYTES - len(body)
                        if remaining <= 0:
                            break
                        body.extend(chunk[:remaining])
                    text = bytes(body).decode(response.encoding or "utf-8", errors="replace")
                    bounded = text[:max_chars]
                    return {
                        "status": "COMMITTED",
                        "output": bounded,
                        "content_hash": "sha256:" + hashlib.sha256(bytes(body)).hexdigest(),
                        "final_url": current_url[:512],
                    }
        except (ProtocolError, httpx.HTTPError, OSError, ValueError) as exc:
            return {"status": "FAILED", "error": f"fetch failed: {exc}"}

    def _legacy_redirect_probe(self, url: str, timeout_s: float) -> dict[str, Any]:
        """Exercise only the injected urllib redirect handler unit probe."""

        request = urllib.request.Request(url, method="GET")
        opener = urllib.request.build_opener(_StrictRedirects(self))
        try:
            opener.open(request, timeout=timeout_s)
        except (urllib.error.URLError, OSError, ValueError) as exc:
            return {"status": "FAILED", "error": f"fetch failed: {exc}"}
        return {"status": "FAILED", "error": "unsafe test transport returned unexpectedly"}


class _StrictRedirects(urllib.request.HTTPRedirectHandler):
    """Compatibility probe; production redirects use pinned httpx above."""

    def __init__(self, cell: NetCell) -> None:
        super().__init__()
        self._cell = cell

    def redirect_request(
        self,
        req: Any,
        fp: Any,
        code: Any,
        msg: Any,
        headers: Any,
        newurl: Any,
    ) -> Any:  # noqa: ANN401
        original_host = str(req.host or "").lower().rstrip(".")
        new_host = _hostname(str(newurl))
        if new_host != original_host:
            raise urllib.error.URLError(f"cross-host redirect denied: {new_host}")
        if self._cell._allowed_hosts and new_host not in self._cell._allowed_hosts:  # noqa: SLF001
            raise urllib.error.URLError(f"redirect target not in endpoint manifest: {new_host}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class ConnectorCell(CellBase):
    """cell.connector: exact-payload egress with idempotency dedupe.

    The local outbox (`<state_dir>/orin/connector_outbox.jsonl`) models the
    provider contract for stage B: same idempotency key ⇒ one effect. Real
    service adapters plug into `_dispatch_provider` later; the security
    envelope (handles, export pass, token isolation) does not change.
    """

    def __init__(
        self,
        *,
        socket_path: Path,
        state_dir: Path,
        mac_key: bytes,
        secrets: SecretStore,
    ) -> None:
        self._mac_key = mac_key
        self._secrets = secrets
        self._outbox_path = state_dir / "orin" / "connector_outbox.jsonl"

        super().__init__(
            cap="cell.connector",
            socket_path=socket_path,
            state_dir=state_dir,
            handler=self._commit_package,
            preflight_handler=self._preflight_package,
            reconcile_handler=self._reconcile_outbox,
            strict_effect_protocol=True,
        )

    def _send_exact(self, permit: dict[str, Any]) -> dict[str, Any]:
        try:
            validated = self._validate_send_request(permit, require_commit_fields=True)
        except ProtocolError as exc:
            return {"status": "FAILED", "error": str(exc)}
        idem, payload_hash, recipients, _secret, token, subject, body, task_id = validated
        blocked = inspect_canary_text(
            subject + "\n" + body,
            surface="connector",
            session_id=task_id,
        )
        if blocked is not None:
            return {"status": "FAILED", "error": blocked}

        # The provider adapter may use this local token, but neither the ack
        # nor the durable outbox records it (or a correlatable digest).
        _ = token
        return self._append_outbox_once(
            idempotency_key=idem,
            payload_hash=payload_hash,
            recipients=recipients,
            bytes_out=len((subject + body).encode("utf-8")),
        )

    def _validate_send_request(
        self,
        raw: dict[str, Any],
        *,
        require_commit_fields: bool,
    ) -> tuple[
        str,
        str,
        tuple[OriginHandle, ...],
        OriginHandle | None,
        str | None,
        str,
        str,
        str,
    ]:
        allowed = {
            "op",
            "idempotency_key",
            "payload_hash",
            "recipient_handles",
            "secret_handle",
            "subject",
            "body_draft",
            "task_id",
        }
        if set(raw) - allowed:
            raise ProtocolError("connector request contains unsupported authority fields")
        if raw.get("op", "send_exact") != "send_exact":
            raise ProtocolError("Connector Cell accepts only send_exact")
        idem = raw.get("idempotency_key", "")
        payload_hash = raw.get("payload_hash", "")
        if require_commit_fields:
            if not isinstance(idem, str) or not idem or len(idem) > 256:
                raise ProtocolError("send requires a bounded idempotency key")
            if (
                not isinstance(payload_hash, str)
                or len(payload_hash) != 71
                or not payload_hash.startswith("sha256:")
                or any(char not in "0123456789abcdef" for char in payload_hash[7:])
            ):
                raise ProtocolError("send requires a canonical payload hash")
        dests = raw.get("recipient_handles")
        if not isinstance(dests, list) or not dests or len(dests) > 64:
            raise ProtocolError("send requires one to 64 recipient handles")
        recipients: list[OriginHandle] = []
        seen: set[str] = set()
        for item in dests:
            handle = _verify_sealed_handle(
                item,
                self._mac_key,
                kind="RecipientHandle",
                capability="send",
            )
            if handle is None:
                raise ProtocolError("recipient handle is expired, unsealed, or unauthorized")
            if handle.handle_id in seen:
                raise ProtocolError("recipient handles must not contain duplicates")
            seen.add(handle.handle_id)
            recipients.append(handle)
        owners = {handle.owner_key_hash for handle in recipients}
        tenants = {handle.tenant for handle in recipients}
        if len(owners) != 1 or len(tenants) != 1:
            raise ProtocolError("recipient handles cross an owner or tenant boundary")

        secret_handle: OriginHandle | None = None
        token: str | None = None
        secret_ref = raw.get("secret_handle")
        if secret_ref is not None:
            secret_handle = _verify_sealed_handle(
                secret_ref,
                self._mac_key,
                kind="SecretHandle",
                capability="use",
            )
            if secret_handle is None:
                raise ProtocolError("secret handle is expired, unsealed, or unauthorized")
            if secret_handle.tenant not in tenants:
                raise ProtocolError("secret audience does not match connector destination")
            token = self._secrets.get(secret_handle.handle_id)
            if token is None:
                raise ProtocolError("credential not provisioned")

        subject = raw.get("subject", "")
        body = raw.get("body_draft", "")
        task_id = raw.get("task_id", "")
        for name, value, limit in (
            ("subject", subject, 2_048),
            ("body_draft", body, _MAX_WIRE_BODY_BYTES),
            ("task_id", task_id, 256),
        ):
            if not isinstance(value, str) or len(value.encode("utf-8")) > limit:
                raise ProtocolError(f"{name} must be a bounded string")
        return (
            str(idem),
            str(payload_hash),
            tuple(recipients),
            secret_handle,
            token,
            subject,
            body,
            task_id,
        )

    def _package_send_request(self, package: CellPackage) -> dict[str, Any]:
        if package.draft.effect_type != "email.send_exact":
            raise ProtocolError("Connector Cell accepts only email.send_exact drafts")
        recipients = [
            handle for handle in package.resolved_handles if handle.kind == "RecipientHandle"
        ]
        secrets = [handle for handle in package.resolved_handles if handle.kind == "SecretHandle"]
        if len(secrets) > 1 or len(recipients) + len(secrets) != len(package.resolved_handles):
            raise ProtocolError("connector package contains an unsupported handle kind")
        raw = {
            "op": "send_exact",
            "recipient_handles": [handle.to_dict() for handle in recipients],
            "subject": package.draft.arguments.get("subject", ""),
            "body_draft": package.draft.arguments.get("body_draft", ""),
            "task_id": package.draft.task_id,
        }
        if secrets:
            raw["secret_handle"] = secrets[0].to_dict()
        return raw

    def _preflight_package(self, package: CellPackage) -> StateWitness:
        raw = self._package_send_request(package)
        validated = self._validate_send_request(raw, require_commit_fields=False)
        recipients = validated[2]
        subject, body = validated[5], validated[6]
        now = _now_ms()
        return StateWitness(
            witness_id=f"state:{secret_tokens.token_hex(16)}",
            draft_id=package.draft.draft_id,
            executor_id=package.executor_id,
            target_version="connector-outbox:v1",
            canonical_effect_hash=package.canonical_effect_hash,
            impact=Impact(
                writes=1,
                recipients=len(recipients),
                bytes_out=len((subject + body).encode("utf-8")),
            ),
            reversibility="irreversible_after_provider_accept",
            idempotency_support="client_key",
            created_at_ms=now,
            expires_at_ms=now + _WITNESS_TTL_MS,
        )

    def _commit_package(
        self,
        permit: CommitPermit,
        package: CellPackage,
    ) -> dict[str, Any]:
        raw = self._package_send_request(package)
        raw["idempotency_key"] = permit.idempotency_key
        raw["payload_hash"] = permit.canonical_effect_hash
        return self._send_exact(raw)

    def _append_outbox_once(
        self,
        *,
        idempotency_key: str,
        payload_hash: str,
        recipients: tuple[OriginHandle, ...],
        bytes_out: int,
    ) -> dict[str, Any]:
        self._outbox_path.parent.mkdir(parents=True, exist_ok=True)
        remote_operation_id = self._remote_operation_id(idempotency_key, payload_hash)
        flags = os.O_RDWR | os.O_CREAT | os.O_APPEND
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(self._outbox_path, flags, 0o600)
        except OSError:
            return {"status": "FAILED", "error": "connector outbox is unavailable"}
        if not self._outbox_fd_is_private(fd):
            os.close(fd)
            return {"status": "FAILED", "error": "connector outbox is not private"}
        try:
            with os.fdopen(fd, "a+", encoding="utf-8") as fh:
                fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
                try:
                    if not self._outbox_fd_is_private(fh.fileno()):
                        return {
                            "status": "FAILED",
                            "error": "connector outbox is not private",
                        }
                    fh.seek(0)
                    matching: list[dict[str, Any]] = []
                    for line in fh:
                        row = self._parse_outbox_record(line)
                        if row is None:
                            return {
                                "status": "FAILED",
                                "error": "connector outbox integrity check failed",
                            }
                        if row["idempotency_key"] == idempotency_key:
                            matching.append(row)
                    if len(matching) > 1:
                        return {
                            "status": "FAILED",
                            "error": "connector outbox contains conflicting idempotency records",
                        }
                    prior = matching[0] if matching else None
                    expected_recipients = sorted(handle.handle_id for handle in recipients)
                    if prior is not None:
                        if (
                            prior["payload_hash"] != payload_hash
                            or prior["recipients"] != expected_recipients
                        ):
                            return {
                                "status": "FAILED",
                                "error": "idempotency key is already bound to another effect",
                            }
                        return {
                            "status": "RECONCILED_COMMITTED",
                            "remote_operation_id": prior["remote_operation_id"],
                            "duplicate": True,
                            "recipients": len(recipients),
                        }
                    if not self._outbox_fd_is_private(fh.fileno()):
                        return {
                            "status": "FAILED",
                            "error": "connector outbox is not private",
                        }
                    record = {
                        "idempotency_key": idempotency_key,
                        "remote_operation_id": remote_operation_id,
                        "payload_hash": payload_hash,
                        "recipients": expected_recipients,
                        "committed_at_ms": _now_ms(),
                    }
                    fh.seek(0, os.SEEK_END)
                    fh.write(json.dumps(record, sort_keys=True) + "\n")
                    fh.flush()
                    os.fsync(fh.fileno())
                finally:
                    fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        except (OSError, UnicodeError):
            return {"status": "FAILED", "error": "connector outbox is unavailable"}
        return {
            "status": "COMMITTED",
            "remote_operation_id": remote_operation_id,
            "recipients": len(recipients),
            "bytes_out": bytes_out,
            "duplicate": False,
        }

    @staticmethod
    def _remote_operation_id(idempotency_key: str, payload_hash: str) -> str:
        digest = hashlib.sha256((idempotency_key + payload_hash).encode("utf-8")).hexdigest()
        return "op-" + digest[:24]

    @staticmethod
    def _outbox_fd_is_private(fd: int) -> bool:
        try:
            metadata = os.fstat(fd)
        except OSError:
            return False
        return (
            stat.S_ISREG(metadata.st_mode)
            and metadata.st_nlink == 1
            and metadata.st_uid == os.geteuid()
            and stat.S_IMODE(metadata.st_mode) == 0o600
        )

    @classmethod
    def _parse_outbox_record(cls, line: str) -> dict[str, Any] | None:
        try:
            raw = json.loads(line)
        except (json.JSONDecodeError, TypeError):
            return None
        required = {
            "idempotency_key",
            "remote_operation_id",
            "payload_hash",
            "recipients",
            "committed_at_ms",
        }
        if not isinstance(raw, dict) or set(raw) != required:
            return None
        idem = raw.get("idempotency_key")
        payload_hash = raw.get("payload_hash")
        remote_operation_id = raw.get("remote_operation_id")
        recipients = raw.get("recipients")
        committed_at_ms = raw.get("committed_at_ms")
        if not isinstance(idem, str) or not idem or len(idem) > 256:
            return None
        if not isinstance(payload_hash, str) or not cls._valid_payload_hash(payload_hash):
            return None
        if not isinstance(
            remote_operation_id, str
        ) or remote_operation_id != cls._remote_operation_id(idem, payload_hash):
            return None
        if (
            not isinstance(recipients, list)
            or not recipients
            or len(recipients) > 64
            or any(
                not isinstance(recipient, str) or not recipient or len(recipient) > 256
                for recipient in recipients
            )
            or recipients != sorted(recipients)
            or len(set(recipients)) != len(recipients)
        ):
            return None
        if (
            isinstance(committed_at_ms, bool)
            or not isinstance(committed_at_ms, int)
            or committed_at_ms < 0
        ):
            return None
        return raw

    @staticmethod
    def _valid_payload_hash(value: Any) -> bool:
        return (
            isinstance(value, str)
            and len(value) == 71
            and value.startswith("sha256:")
            and all(char in "0123456789abcdef" for char in value[7:])
        )

    def _reconcile_outbox(
        self,
        effect_id: str,
        probe: dict[str, Any],
    ) -> dict[str, str]:
        """Observe the mock provider outbox without dispatching an effect."""

        expected_fields = {
            "idempotency_key",
            "canonical_effect_hash",
            "destination_handles",
        }
        if not isinstance(effect_id, str) or not effect_id or len(effect_id) > 256:
            return {"state": "UNKNOWN_COMMIT"}
        if not isinstance(probe, dict) or set(probe) != expected_fields:
            return {"state": "UNKNOWN_COMMIT"}
        idempotency_key = probe.get("idempotency_key")
        payload_hash = probe.get("canonical_effect_hash")
        destinations = probe.get("destination_handles")
        if (
            not isinstance(idempotency_key, str)
            or not idempotency_key
            or len(idempotency_key) > 256
            or not self._valid_payload_hash(payload_hash)
            or not isinstance(destinations, list)
            or not destinations
            or len(destinations) > 64
            or any(
                not isinstance(destination, str) or not destination or len(destination) > 256
                for destination in destinations
            )
            or len(set(destinations)) != len(destinations)
        ):
            return {"state": "UNKNOWN_COMMIT"}
        canonical_destinations = sorted(destinations)

        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(self._outbox_path, flags)
        except FileNotFoundError:
            return {"state": "PREPARED"}
        except OSError:
            return {"state": "UNKNOWN_COMMIT"}
        try:
            if not self._outbox_fd_is_private(fd):
                return {"state": "UNKNOWN_COMMIT"}
            with os.fdopen(fd, "r", encoding="utf-8") as fh:
                fd = -1
                fcntl.flock(fh.fileno(), fcntl.LOCK_SH)
                try:
                    matching: list[dict[str, Any]] = []
                    for line in fh:
                        row = self._parse_outbox_record(line)
                        if row is None:
                            return {"state": "UNKNOWN_COMMIT"}
                        if row["idempotency_key"] == idempotency_key:
                            matching.append(row)
                finally:
                    fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        except (OSError, UnicodeError):
            return {"state": "UNKNOWN_COMMIT"}
        finally:
            if fd >= 0:
                os.close(fd)

        if not matching:
            return {"state": "PREPARED"}
        if len(matching) != 1:
            return {"state": "UNKNOWN_COMMIT"}
        record = matching[0]
        if record["payload_hash"] != payload_hash or record["recipients"] != canonical_destinations:
            return {"state": "UNKNOWN_COMMIT"}
        return {"state": "COMMITTED"}


class SecretCell(CellBase):
    """cell.secret: credential custody behind sealed handles."""

    def __init__(
        self,
        *,
        socket_path: Path,
        state_dir: Path,
        mac_key: bytes,
        secrets: SecretStore,
    ) -> None:
        self._mac_key = mac_key
        self._secrets = secrets

        super().__init__(
            cap="cell.secret",
            socket_path=socket_path,
            state_dir=state_dir,
            handler=self._commit_package,
            preflight_handler=self._preflight_package,
            strict_effect_protocol=True,
        )

    def _resolve(self, permit: dict[str, Any]) -> dict[str, Any]:
        raw_clearance = permit.get("clearance", taint.CLEARANCE_INTERNAL)
        if isinstance(raw_clearance, bool) or not isinstance(raw_clearance, int):
            return {"status": "FAILED", "error": "clearance must be an integer"}
        if raw_clearance < taint.CLEARANCE_SECRET:
            return {"status": "FAILED", "error": "clearance is below SECRET"}
        handle = _verify_sealed_handle(
            permit.get("secret_handle"),
            self._mac_key,
            kind="SecretHandle",
            capability="use",
        )
        if handle is None:
            return {
                "status": "FAILED",
                "error": "secret handle is expired, unsealed, or unauthorized",
            }
        audience = str(permit.get("audience") or "")
        if audience and handle.tenant and handle.tenant != audience:
            return {"status": "FAILED", "error": "audience mismatch"}
        token = self._secrets.get(handle.handle_id)
        if token is None:
            return {"status": "FAILED", "error": "credential not provisioned"}
        # Even the authenticated ack returns availability only. Connector
        # adapters use SecretStore privately inside this services process.
        _ = token
        return {
            "status": "COMMITTED",
            "available": True,
            "handle": handle.handle_id,
        }

    def _package_resolve_request(self, package: CellPackage) -> dict[str, Any]:
        secret_handles = [
            handle for handle in package.resolved_handles if handle.kind == "SecretHandle"
        ]
        if len(secret_handles) != 1 or len(package.resolved_handles) != 1:
            raise ProtocolError("Secret Cell requires exactly one SecretHandle")
        return {
            "secret_handle": secret_handles[0].to_dict(),
            "audience": secret_handles[0].tenant,
            "clearance": package.clearance,
        }

    def _preflight_package(self, package: CellPackage) -> StateWitness:
        result = self._resolve(self._package_resolve_request(package))
        if result.get("status") != "COMMITTED":
            raise ProtocolError(str(result.get("error") or "secret is unavailable"))
        now = _now_ms()
        return StateWitness(
            witness_id=f"state:{secret_tokens.token_hex(16)}",
            draft_id=package.draft.draft_id,
            executor_id=package.executor_id,
            target_version="secret-store:v1",
            canonical_effect_hash=package.canonical_effect_hash,
            impact=Impact(),
            reversibility="reversible_until_stage",
            idempotency_support="none",
            created_at_ms=now,
            expires_at_ms=now + _WITNESS_TTL_MS,
        )

    def _commit_package(
        self,
        _permit: CommitPermit,
        package: CellPackage,
    ) -> dict[str, Any]:
        return self._resolve(self._package_resolve_request(package))


def l2_keychain_probe_commands(
    *,
    service: str,
    account: str,
    secret_hex: str,
    app_path: Path,
) -> tuple[list[str], list[str], list[str]]:
    """Build an ACL-scoped one-shot Keychain probe without secret output."""

    common = ["-a", account, "-s", service]
    add = [
        "security",
        "add-generic-password",
        "-U",
        *common,
        "-X",
        secret_hex,
        "-T",
        str(app_path),
    ]
    find = ["security", "find-generic-password", *common]
    delete = ["security", "delete-generic-password", *common]
    return add, find, delete


def run_optional_l2_keychain_smoke(
    app_path: Path,
    *,
    enabled: bool = False,
    runner: Callable[..., Any] = subprocess.run,
) -> dict[str, str]:
    """Opt-in Darwin smoke only; never used as the real SecretStore backend."""

    if not enabled:
        return {"status": "untested", "reason": "explicit opt-in required"}
    if platform.system() != "Darwin":
        return {"status": "untested", "reason": "Darwin Keychain is unavailable"}
    if not app_path.is_absolute() or not app_path.exists():
        return {"status": "failed", "reason": "ACL target must be an existing absolute path"}
    marker = secret_tokens.token_hex(12)
    service = f"orin-l2-smoke-{marker}"
    account = f"probe-{marker}"
    commands = l2_keychain_probe_commands(
        service=service,
        account=account,
        secret_hex=secret_tokens.token_hex(32),
        app_path=app_path,
    )
    cleanup_failed = False
    try:
        runner(commands[0], check=True, capture_output=True, text=True, timeout=10)
        runner(commands[1], check=True, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return {"status": "failed", "reason": "Keychain ACL smoke failed"}
    finally:
        try:
            runner(commands[2], check=False, capture_output=True, text=True, timeout=10)
        except (OSError, subprocess.SubprocessError):
            cleanup_failed = True
    if cleanup_failed:
        return {"status": "failed", "reason": "Keychain ACL smoke cleanup failed"}
    return {"status": "passed", "reason": "one-shot ACL item existed and was removed"}


def provision_secret(
    state_dir: Path,
    mac_key: bytes,
    *,
    name: str,
    token: str,
    audience: str = "",
    strict_paths: bool = False,
) -> OriginHandle:
    """Admin path (AppShell): mint a SecretHandle + store the credential."""

    store = SecretStore(state_dir, strict_paths=strict_paths)
    digest = "sha256:" + hashlib.sha256(token.encode()).hexdigest()
    ts = int(time.time() * 1000)
    base = OriginHandle(
        handle_id=f"secret:{name}",
        kind="SecretHandle",
        owner_key_hash="sha256:" + hashlib.sha256(state_dir.name.encode()).hexdigest(),
        tenant=audience,
        source_class="USER_AUTHENTICATED",
        integrity="trusted_local_object",
        confidentiality="SECRET",
        object_digest=digest,
        capabilities=("use",),
        issuer="orind:broker",
        created_at_ms=ts,
        expires_at_ms=ts + 365 * 24 * 60 * 60 * 1000,
    )
    sealed = base.sealed_by(mac_key, "orind:broker", ts)
    store.put(sealed.handle_id, token)
    return sealed


def main() -> None:  # pragma: no cover - subprocess entry
    socket_path = os.environ.get("ORIN_CELLS_SOCKET")
    state_dir_env = os.environ.get("ORIN_STATE_DIR")
    caps_env = os.environ.get("ORIN_CELLS_CAPS", "")
    if not socket_path or not state_dir_env:
        raise SystemExit("ORIN_CELLS_SOCKET and ORIN_STATE_DIR are required")
    from js.orind.keybox import KeyBox

    strict_paths = os.environ.get("ORIN_CELL_IDENTITY_ENFORCE") == "1"
    keybox_tier = os.environ.get("ORIN_KEYBOX_TIER")
    if strict_paths and keybox_tier not in {"dev", "production"}:
        raise SystemExit("ORIN_KEYBOX_TIER must be explicit in Cell identity enforce mode")
    keybox = KeyBox(
        Path(state_dir_env),
        tier=keybox_tier or "dev",
        strict_paths=strict_paths,
    )
    secrets = SecretStore(Path(state_dir_env), strict_paths=strict_paths)
    cells: list[CellBase] = []
    wanted = [cap for cap in caps_env.split(",") if cap]
    unknown = set(wanted) - {"cell.net", "cell.secret", "cell.connector"}
    if unknown or not wanted:
        raise SystemExit("ORIN_CELLS_CAPS must name at least one known services cap")
    if "cell.net" in wanted:
        cells.append(
            NetCell(
                socket_path=Path(socket_path), state_dir=Path(state_dir_env), mac_key=keybox.key
            )
        )
    if "cell.secret" in wanted:
        cells.append(
            SecretCell(
                socket_path=Path(socket_path),
                state_dir=Path(state_dir_env),
                mac_key=keybox.key,
                secrets=secrets,
            )
        )
    if "cell.connector" in wanted:
        cells.append(
            ConnectorCell(
                socket_path=Path(socket_path),
                state_dir=Path(state_dir_env),
                mac_key=keybox.key,
                secrets=secrets,
            )
        )
    # One shared pid ⇒ one session-key filename: handshakes MUST be
    # serialized or the daemon's key-file publish races between siblings.
    for cell in cells:
        cell.start()
        deadline = time.time() + 10.0
        while not cell.healthy() and time.time() < deadline:
            time.sleep(0.05)
        if not cell.healthy():
            raise SystemExit(f"services cell failed health check: {cell.cap}")
    try:
        while True:
            time.sleep(1)
            unhealthy = [cell.cap for cell in cells if not cell.healthy()]
            if unhealthy:
                raise SystemExit(f"services cell unhealthy: {','.join(unhealthy)}")
    except KeyboardInterrupt:
        pass
    finally:
        for cell in cells:
            cell.stop()


def relay_model_chat(
    *,
    state_dir: Path,
    destination: str,
    secret_handle: str,
    body: dict[str, Any],
    allowlist: frozenset[str] = frozenset(),
    timeout_s: float = 30.0,
) -> dict[str, Any]:
    """Services-Cell model connector. Token never appears in the result."""

    from js.models.cell_transport import destination_is_allowed

    if not destination_is_allowed(destination, allowlist=tuple(allowlist)):
        raise ProtocolError("model connector destination is not allowed")
    store = SecretStore(state_dir)
    token = store.get(secret_handle)
    if not token:
        raise ProtocolError("model connector secret handle is unknown")
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    try:
        with httpx.Client(timeout=timeout_s) as client:
            response = client.post(destination, json=body, headers=headers)
    except httpx.HTTPError as exc:
        raise ProtocolError(f"model connector transport failed: {exc}") from exc
    payload = (
        response.json()
        if response.headers.get("content-type", "").startswith("application/json")
        else {"text": response.text}
    )
    if isinstance(payload, dict):
        for key in ("token", "api_key", "authorization", "secret"):
            payload.pop(key, None)
    return {"status": "COMMITTED", "http_status": response.status_code, "body": payload}


if __name__ == "__main__":  # pragma: no cover
    main()


__all__ = [
    "ConnectorCell",
    "NetCell",
    "SecretCell",
    "SecretStore",
    "l2_keychain_probe_commands",
    "provision_secret",
    "relay_model_chat",
    "run_optional_l2_keychain_smoke",
]
