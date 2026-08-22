"""Friend and Agent collaboration protocol contracts.

Pure data contracts. No network, no real credentials.
E2E encrypted text only. No attachments, no tool invocation by friends.
"""

from __future__ import annotations

import re
import secrets
import time
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

_FRIEND_ID_RE = re.compile(r"^[a-f0-9]{64}$")
_MAX_TEXT_LENGTH = 5_000
_MAX_JSON_BYTES = 50_000
_MIN_DEADLINE_SECONDS = 1
_MAX_DEADLINE_SECONDS = 3600
_MAX_TOKEN_BUDGET = 100_000
_MAX_COST_BUDGET = 1_000
_MAX_BYTE_BUDGET = 1_000_000
_MAX_COUNT_BUDGET = 50


class FriendStatus(StrEnum):
    PENDING = "pending"
    CONFIRMED = "confirmed"
    BLOCKED = "blocked"
    REVOKED = "revoked"


class FriendMessageStatus(StrEnum):
    SENT = "sent"
    DELIVERED = "delivered"
    READ = "read"
    REVOKED = "revoked"
    REJECTED = "rejected"


@dataclass(frozen=True)
class FriendRequest:
    """A friend invitation: QR code based, mutual confirmation required."""

    request_id: str
    inviter_id: str
    invitee_id: str
    invite_code: str
    created_at: float
    status: FriendStatus = FriendStatus.PENDING

    def as_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "inviter_id": self.inviter_id,
            "invitee_id": self.invitee_id,
            "invite_code": self.invite_code,
            "created_at": self.created_at,
            "status": str(self.status),
        }


@dataclass(frozen=True)
class FriendMessage:
    """E2E encrypted text message between friends.

    No attachments, no tool calls. Text only, max 5000 chars.
    Anti-replay: message_id is unique, key_rotation_epoch tracks key version.
    """

    message_id: str
    sender_id: str
    recipient_id: str
    encrypted_payload: str
    key_rotation_epoch: int
    timestamp: float
    status: FriendMessageStatus = FriendMessageStatus.SENT

    def __init__(
        self,
        *,
        message_id: str,
        sender_id: str,
        recipient_id: str,
        encrypted_payload: str,
        key_rotation_epoch: int = 1,
        timestamp: float = 0.0,
        status: FriendMessageStatus = FriendMessageStatus.SENT,
    ) -> None:
        if type(sender_id) is not str or not _FRIEND_ID_RE.fullmatch(sender_id):
            raise ValueError("sender_id must be 64-hex")
        if type(recipient_id) is not str or not _FRIEND_ID_RE.fullmatch(recipient_id):
            raise ValueError("recipient_id must be 64-hex")
        if sender_id == recipient_id:
            raise ValueError("sender and recipient must differ")
        if type(encrypted_payload) is not str or not encrypted_payload:
            raise ValueError("encrypted_payload must be non-empty")
        if type(key_rotation_epoch) is not int or key_rotation_epoch < 1:
            raise ValueError("key_rotation_epoch must be >= 1")
        object.__setattr__(self, "message_id", message_id)
        object.__setattr__(self, "sender_id", sender_id)
        object.__setattr__(self, "recipient_id", recipient_id)
        object.__setattr__(self, "encrypted_payload", encrypted_payload)
        object.__setattr__(self, "key_rotation_epoch", key_rotation_epoch)
        object.__setattr__(self, "timestamp", timestamp if timestamp > 0 else time.time())
        object.__setattr__(self, "status", status)

    def as_dict(self) -> dict[str, Any]:
        return {
            "message_id": self.message_id,
            "sender_id": self.sender_id,
            "recipient_id": self.recipient_id,
            "encrypted_payload": "[redacted]",
            "key_rotation_epoch": self.key_rotation_epoch,
            "timestamp": self.timestamp,
            "status": str(self.status),
        }


@dataclass(frozen=True)
class RemoteTaskEnvelope:
    """Agent L2 remote task envelope.

    Text and bounded JSON only. Default tools empty.
    Forced deadline, token, cost, byte, count limits.
    No recursive delegation.
    """

    envelope_id: str
    sender_id: str
    recipient_id: str
    task_text: str
    task_json: dict[str, Any] | None
    deadline_seconds: int
    token_budget: int
    cost_budget: int
    byte_budget: int
    count_budget: int
    allowed_tools: tuple[str, ...] = ()
    created_at: float = 0.0
    parent_envelope_id: str | None = None

    def __init__(
        self,
        *,
        envelope_id: str,
        sender_id: str,
        recipient_id: str,
        task_text: str,
        task_json: dict[str, Any] | None = None,
        deadline_seconds: int = 60,
        token_budget: int = 10000,
        cost_budget: int = 100,
        byte_budget: int = 100000,
        count_budget: int = 10,
        allowed_tools: tuple[str, ...] = (),
        created_at: float = 0.0,
        parent_envelope_id: str | None = None,
    ) -> None:
        if type(sender_id) is not str or not _FRIEND_ID_RE.fullmatch(sender_id):
            raise ValueError("sender_id must be 64-hex")
        if type(recipient_id) is not str or not _FRIEND_ID_RE.fullmatch(recipient_id):
            raise ValueError("recipient_id must be 64-hex")
        if sender_id == recipient_id:
            raise ValueError("sender and recipient must differ")
        if type(task_text) is not str or not task_text or len(task_text) > _MAX_TEXT_LENGTH:
            raise ValueError(f"task_text must be 1-{_MAX_TEXT_LENGTH} chars")
        if task_json is not None:
            import json
            raw = json.dumps(task_json, sort_keys=True)
            if len(raw.encode("utf-8")) > _MAX_JSON_BYTES:
                raise ValueError(f"task_json must be <= {_MAX_JSON_BYTES} bytes")
        if not (_MIN_DEADLINE_SECONDS <= deadline_seconds <= _MAX_DEADLINE_SECONDS):
            raise ValueError(f"deadline_seconds must be {_MIN_DEADLINE_SECONDS}-{_MAX_DEADLINE_SECONDS}")
        if token_budget > _MAX_TOKEN_BUDGET:
            raise ValueError(f"token_budget must be <= {_MAX_TOKEN_BUDGET}")
        if cost_budget > _MAX_COST_BUDGET:
            raise ValueError(f"cost_budget must be <= {_MAX_COST_BUDGET}")
        if byte_budget > _MAX_BYTE_BUDGET:
            raise ValueError(f"byte_budget must be <= {_MAX_BYTE_BUDGET}")
        if count_budget > _MAX_COUNT_BUDGET:
            raise ValueError(f"count_budget must be <= {_MAX_COUNT_BUDGET}")
        if parent_envelope_id is not None:
            raise ValueError("recursive delegation is forbidden (parent_envelope_id must be None)")
        object.__setattr__(self, "envelope_id", envelope_id)
        object.__setattr__(self, "sender_id", sender_id)
        object.__setattr__(self, "recipient_id", recipient_id)
        object.__setattr__(self, "task_text", task_text)
        object.__setattr__(self, "task_json", task_json)
        object.__setattr__(self, "deadline_seconds", deadline_seconds)
        object.__setattr__(self, "token_budget", token_budget)
        object.__setattr__(self, "cost_budget", cost_budget)
        object.__setattr__(self, "byte_budget", byte_budget)
        object.__setattr__(self, "count_budget", count_budget)
        object.__setattr__(self, "allowed_tools", tuple(allowed_tools))
        object.__setattr__(self, "created_at", created_at if created_at > 0 else time.time())
        object.__setattr__(self, "parent_envelope_id", parent_envelope_id)

    def as_dict(self) -> dict[str, Any]:
        return {
            "envelope_id": self.envelope_id,
            "sender_id": self.sender_id,
            "recipient_id": self.recipient_id,
            "task_text": self.task_text,
            "task_json": self.task_json,
            "deadline_seconds": self.deadline_seconds,
            "token_budget": self.token_budget,
            "cost_budget": self.cost_budget,
            "byte_budget": self.byte_budget,
            "count_budget": self.count_budget,
            "allowed_tools": list(self.allowed_tools),
            "created_at": self.created_at,
        }


@dataclass(frozen=True)
class CollaborationGrant:
    """Grant for Agent L2 collaboration.

    Only text and bounded JSON. Default tools empty.
    All remote content re-enters local Echo.
    """

    grant_id: str
    granter_id: str
    grantee_id: str
    max_deadline_seconds: int
    max_token_budget: int
    max_cost_budget: int
    max_byte_budget: int
    max_count_budget: int
    allowed_tools: tuple[str, ...] = ()
    created_at: float = 0.0
    revoked_at: float | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "grant_id": self.grant_id,
            "granter_id": self.granter_id,
            "grantee_id": self.grantee_id,
            "max_deadline_seconds": self.max_deadline_seconds,
            "max_token_budget": self.max_token_budget,
            "max_cost_budget": self.max_cost_budget,
            "max_byte_budget": self.max_byte_budget,
            "max_count_budget": self.max_count_budget,
            "allowed_tools": list(self.allowed_tools),
            "created_at": self.created_at,
            "revoked_at": self.revoked_at,
        }


@dataclass(frozen=True)
class CollaborationResult:
    """Result of a remote task execution."""

    envelope_id: str
    success: bool
    output_text: str = ""
    output_json: dict[str, Any] | None = None
    tokens_used: int = 0
    cost_incurred: int = 0
    bytes_transferred: int = 0
    tool_calls: int = 0
    error: str | None = None
    terminal_state: str = "completed"

    def as_dict(self) -> dict[str, Any]:
        return {
            "envelope_id": self.envelope_id,
            "success": self.success,
            "output_text": self.output_text,
            "output_json": self.output_json,
            "tokens_used": self.tokens_used,
            "cost_incurred": self.cost_incurred,
            "bytes_transferred": self.bytes_transferred,
            "tool_calls": self.tool_calls,
            "error": self.error,
            "terminal_state": self.terminal_state,
        }


def generate_friend_id() -> str:
    """Generate a 64-hex friend ID."""
    return secrets.token_hex(32)


def generate_invite_code() -> str:
    """Generate a QR invite code."""
    return secrets.token_urlsafe(32)
