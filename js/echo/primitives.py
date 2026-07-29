"""Shared Echo 2.0 primitives used by Echo and its compatibility ledger."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
from dataclasses import dataclass, replace
from typing import Any

import rfc8785

ECHO_2_ARCHITECTURE = "echo-2.0"

_DATA_URL_BASE64_RE = re.compile(
    r"data:[^;,\s]+;base64,(?P<data>[A-Za-z0-9+/=\r\n]+)",
    re.IGNORECASE,
)
_SECRET_PATTERNS = (
    re.compile(r"\bsk-[A-Za-z0-9_-]{12,}\b"),
    re.compile(r"\bBearer\s+[A-Za-z0-9._=-]{10,}\b", re.IGNORECASE),
    re.compile(r"\b(api[_-]?key|secret|token)\s*[:=]\s*[A-Za-z0-9._=-]{8,}\b", re.IGNORECASE),
)


def stable_payload_hash(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def canonical_json_bytes(value: Any) -> bytes:
    """Serialize one permit payload with RFC 8785/JCS canonical JSON."""
    try:
        return rfc8785.dumps(value)
    except rfc8785.CanonicalizationError as exc:
        raise ValueError("value is not representable as RFC 8785 canonical JSON") from exc


def canonical_payload_hash(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _stable_mac(key: bytes, value: Any) -> bytes:
    return hmac.new(key, canonical_json_bytes(value), hashlib.sha256).digest()


@dataclass(frozen=True)
class ScopeRequest:
    owner_id: str
    session_id: str
    run_id: str
    provider_id: str
    model_id: str
    messages: tuple[Any, ...]
    tools_schema: tuple[Any, ...]
    attachments: tuple[Any, ...]
    requested_scopes: tuple[str, ...]


@dataclass(frozen=True)
class ScopePermit:
    architecture: str
    owner_id: str
    session_id: str
    run_id: str
    provider_id: str
    model_id: str
    granted_scopes: tuple[str, ...]
    messages_hash: str
    tools_schema_hash: str
    attachments_hash: str
    request_hash: str
    mac: bytes

    def verify(self, signing_key: bytes) -> bool:
        return hmac.compare_digest(_stable_mac(signing_key, self._mac_payload()), self.mac)

    def _mac_payload(self) -> dict[str, Any]:
        return {
            "architecture": self.architecture,
            "owner_id": self.owner_id,
            "session_id": self.session_id,
            "run_id": self.run_id,
            "provider_id": self.provider_id,
            "model_id": self.model_id,
            "granted_scopes": self.granted_scopes,
            "messages_hash": self.messages_hash,
            "tools_schema_hash": self.tools_schema_hash,
            "attachments_hash": self.attachments_hash,
            "request_hash": self.request_hash,
        }


class ScopeGate:
    def __init__(self, *, signing_key: bytes) -> None:
        self._signing_key = signing_key

    def authorize_model_request(self, request: ScopeRequest) -> ScopePermit:
        if "model:invoke" not in request.requested_scopes:
            raise PermissionError("model request missing model:invoke scope")
        if not request.provider_id or not request.model_id:
            raise PermissionError("model request missing provider or model identity")
        secret_text = "\n".join(_strings_from_value(request))
        if _contains_secret(secret_text):
            raise PermissionError("secret data cannot enter Echo 2.0 model path")
        prompt_text = "\n".join(_strings_from_value(request.messages))
        if _prompt_appears_to_grant_scope(prompt_text) and any(
            scope != "model:invoke" for scope in request.requested_scopes
        ):
            raise PermissionError("prompt text cannot grant scope escalation")

        messages_hash = canonical_payload_hash(request.messages)
        tools_schema_hash = canonical_payload_hash(request.tools_schema)
        attachments_hash = canonical_payload_hash(request.attachments)
        request_hash = canonical_payload_hash(
            {
                "architecture": ECHO_2_ARCHITECTURE,
                "owner_id": request.owner_id,
                "session_id": request.session_id,
                "run_id": request.run_id,
                "provider_id": request.provider_id,
                "model_id": request.model_id,
                "messages_hash": messages_hash,
                "tools_schema_hash": tools_schema_hash,
                "attachments_hash": attachments_hash,
                "requested_scopes": request.requested_scopes,
            }
        )
        permit = ScopePermit(
            architecture=ECHO_2_ARCHITECTURE,
            owner_id=request.owner_id,
            session_id=request.session_id,
            run_id=request.run_id,
            provider_id=request.provider_id,
            model_id=request.model_id,
            granted_scopes=tuple(request.requested_scopes),
            messages_hash=messages_hash,
            tools_schema_hash=tools_schema_hash,
            attachments_hash=attachments_hash,
            request_hash=request_hash,
            mac=b"",
        )
        return replace(permit, mac=_stable_mac(self._signing_key, permit._mac_payload()))


@dataclass(frozen=True)
class BudgetLimits:
    max_prompt_tokens: int
    max_completion_tokens: int
    max_tool_calls: int
    max_journal_appends: int
    max_elapsed_ms: int


@dataclass(frozen=True)
class BudgetSnapshot:
    prompt_tokens: int = 0
    completion_tokens: int = 0
    tool_calls: int = 0
    journal_appends: int = 0
    elapsed_ms: int = 0


@dataclass(frozen=True)
class BudgetReservation:
    ok: bool
    reason: str | None
    snapshot: BudgetSnapshot


class BudgetClock:
    def __init__(self, limits: BudgetLimits) -> None:
        self._limits = limits
        self._snapshot = BudgetSnapshot()

    def snapshot(self) -> BudgetSnapshot:
        return self._snapshot

    def reserve(
        self,
        *,
        prompt_tokens: int = 0,
        completion_tokens: int = 0,
        tool_calls: int = 0,
        journal_appends: int = 0,
        elapsed_ms: int = 0,
    ) -> BudgetReservation:
        candidate = BudgetSnapshot(
            prompt_tokens=self._snapshot.prompt_tokens + prompt_tokens,
            completion_tokens=self._snapshot.completion_tokens + completion_tokens,
            tool_calls=self._snapshot.tool_calls + tool_calls,
            journal_appends=self._snapshot.journal_appends + journal_appends,
            elapsed_ms=self._snapshot.elapsed_ms + elapsed_ms,
        )
        reason = _budget_failure(candidate, self._limits)
        if reason is not None:
            return BudgetReservation(ok=False, reason=reason, snapshot=self._snapshot)
        self._snapshot = candidate
        return BudgetReservation(ok=True, reason=None, snapshot=self._snapshot)


@dataclass(frozen=True)
class ContextSelection:
    selected_texts: tuple[str, ...]
    estimated_prompt_tokens: int
    saved_tokens: int


@dataclass(frozen=True)
class _VaultItem:
    owner_id: str
    session_id: str
    layer: str
    text: str
    token_count: int


class ContextVault:
    def __init__(self) -> None:
        self._items: list[_VaultItem] = []

    def remember(self, *, owner_id: str, session_id: str, layer: str, text: str) -> None:
        self._items.append(
            _VaultItem(
                owner_id=owner_id,
                session_id=session_id,
                layer=layer,
                text=text,
                token_count=_estimate_tokens(text),
            )
        )

    def select(
        self,
        *,
        owner_id: str,
        session_id: str,
        query: str,
        max_tokens: int,
    ) -> ContextSelection:
        query_terms = set(_terms(query))
        candidates = [
            item
            for item in self._items
            if item.owner_id == owner_id and item.session_id == session_id
        ]
        ranked = sorted(
            candidates,
            key=lambda item: (
                len(query_terms.intersection(_terms(item.text))),
                _layer_weight(item.layer),
            ),
            reverse=True,
        )
        selected: list[str] = []
        used_tokens = 0
        for item in ranked:
            if used_tokens + item.token_count > max_tokens:
                continue
            selected.append(item.text)
            used_tokens += item.token_count
        total_tokens = sum(item.token_count for item in candidates)
        return ContextSelection(
            selected_texts=tuple(selected),
            estimated_prompt_tokens=used_tokens,
            saved_tokens=max(0, total_tokens - used_tokens),
        )


def _contains_secret(text: str) -> bool:
    return any(pattern.search(text) for pattern in _SECRET_PATTERNS)


def _prompt_appears_to_grant_scope(text: str) -> bool:
    lowered = text.casefold()
    return (
        "ignore prior rules" in lowered
        or "user approved" in lowered
        or "grant" in lowered
        or "授权" in lowered
    )


def _strings_from_value(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value, *_decoded_data_url_strings(value)]
    if isinstance(value, bytes):
        return [value.decode("utf-8", errors="ignore")]
    if isinstance(value, dict):
        parts: list[str] = []
        for item in value.values():
            parts.extend(_strings_from_value(item))
        return parts
    if isinstance(value, (list, tuple, set)):
        parts = []
        for item in value:
            parts.extend(_strings_from_value(item))
        return parts
    if hasattr(value, "__dict__"):
        return _strings_from_value(value.__dict__)
    return [str(value)]


def _decoded_data_url_strings(value: str) -> list[str]:
    decoded: list[str] = []
    for match in _DATA_URL_BASE64_RE.finditer(value):
        try:
            payload = base64.b64decode(match.group("data"), validate=False)
        except (binascii.Error, ValueError):
            continue
        text = payload.decode("utf-8", errors="ignore")
        if text:
            decoded.append(text)
    return decoded


def _budget_failure(snapshot: BudgetSnapshot, limits: BudgetLimits) -> str | None:
    if snapshot.prompt_tokens > limits.max_prompt_tokens:
        return "prompt_tokens_exceeded"
    if snapshot.completion_tokens > limits.max_completion_tokens:
        return "completion_tokens_exceeded"
    if snapshot.tool_calls > limits.max_tool_calls:
        return "tool_calls_exceeded"
    if snapshot.journal_appends > limits.max_journal_appends:
        return "journal_appends_exceeded"
    if snapshot.elapsed_ms > limits.max_elapsed_ms:
        return "elapsed_ms_exceeded"
    return None


def _estimate_tokens(text: str) -> int:
    return max(1, len(text.split()))


def _terms(text: str) -> tuple[str, ...]:
    return tuple(re.findall(r"[A-Za-z0-9_]+", text.casefold()))


def _layer_weight(layer: str) -> int:
    return {
        "short_term": 4,
        "project_fact": 3,
        "failure_lesson": 2,
        "user_preference": 1,
    }.get(layer, 0)
