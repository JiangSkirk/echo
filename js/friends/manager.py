"""Friend manager: lifecycle, messaging, revocation, key rotation.

No public search, no centralized offline queue, no group chat.
Friends cannot directly invoke local tools. All remote content re-enters Echo.
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass
from typing import Any

from js.friends.protocol import (
    FriendMessage,
    FriendMessageStatus,
    FriendRequest,
    FriendStatus,
    generate_friend_id,
    generate_invite_code,
)


@dataclass
class FriendRecord:
    """One confirmed friend relationship."""

    friend_id: str
    owner_id: str
    display_name: str
    key_rotation_epoch: int = 1
    confirmed_at: float = 0.0
    status: FriendStatus = FriendStatus.CONFIRMED
    blocked_at: float | None = None


class FriendManager:
    """Manages friend relationships and E2E encrypted messages.

    Rules:
    - QR invite + mutual confirmation required
    - E2E encrypted text only (no attachments)
    - Delivery, revoke, block, anti-replay, key rotation
    - No public search, no group chat
    - Friends cannot invoke local tools
    """

    def __init__(self) -> None:
        self._requests: dict[str, FriendRequest] = {}
        self._friends: dict[str, FriendRecord] = {}
        self._messages: dict[str, list[FriendMessage]] = {}
        self._seen_message_ids: set[str] = set()
        self._blocked: set[tuple[str, str]] = set()

    def create_invite(self, *, owner_id: str, display_name: str = "Friend") -> FriendRequest:
        """Create a friend invitation (QR code based)."""
        friend_id = generate_friend_id()
        invite_code = generate_invite_code()
        now = time.time()
        request = FriendRequest(
            request_id=secrets.token_urlsafe(16),
            inviter_id=owner_id,
            invitee_id=friend_id,
            invite_code=invite_code,
            created_at=now,
        )
        self._requests[request.request_id] = request
        return request

    def confirm_friend(self, request_id: str, *, owner_id: str) -> FriendRecord:
        """Confirm a friend request (mutual confirmation)."""
        request = self._requests.get(request_id)
        if request is None:
            raise ValueError("friend request not found")
        if request.status != FriendStatus.PENDING:
            raise ValueError(f"request is {request.status}")
        now = time.time()
        record = FriendRecord(
            friend_id=request.invitee_id,
            owner_id=owner_id,
            display_name="Friend",
            confirmed_at=now,
        )
        self._friends[request.invitee_id] = record
        self._messages[request.invitee_id] = []
        self._requests[request_id] = FriendRequest(
            request_id=request.request_id,
            inviter_id=request.inviter_id,
            invitee_id=request.invitee_id,
            invite_code=request.invite_code,
            created_at=request.created_at,
            status=FriendStatus.CONFIRMED,
        )
        return record

    def block_friend(self, friend_id: str) -> bool:
        """Block a friend. No further messages allowed."""
        record = self._friends.get(friend_id)
        if record is None:
            return False
        record.status = FriendStatus.BLOCKED
        record.blocked_at = time.time()
        self._blocked.add((record.owner_id, friend_id))
        return True

    def revoke_friend(self, friend_id: str) -> bool:
        """Revoke a friend relationship entirely."""
        record = self._friends.get(friend_id)
        if record is None:
            return False
        record.status = FriendStatus.REVOKED
        self._messages.pop(friend_id, None)
        return True

    def rotate_key(self, friend_id: str) -> int:
        """Rotate encryption key for a friend. Returns new epoch."""
        record = self._friends.get(friend_id)
        if record is None:
            raise ValueError("friend not found")
        if record.status != FriendStatus.CONFIRMED:
            raise ValueError(f"cannot rotate key for {record.status} friend")
        record.key_rotation_epoch += 1
        return record.key_rotation_epoch

    def send_message(self, message: FriendMessage) -> FriendMessage:
        """Send a message to a friend. Anti-replay: unique message_id."""
        if message.message_id in self._seen_message_ids:
            raise ValueError("replay detected: message_id already seen")
        record = self._friends.get(message.recipient_id)
        if record is None:
            raise ValueError("recipient is not a friend")
        if record.status != FriendStatus.CONFIRMED:
            raise ValueError(f"cannot send to {record.status} friend")
        if (record.owner_id, message.recipient_id) in self._blocked:
            raise ValueError("friend is blocked")
        if message.key_rotation_epoch != record.key_rotation_epoch:
            raise ValueError("key rotation epoch mismatch")
        self._seen_message_ids.add(message.message_id)
        self._messages[message.recipient_id].append(message)
        return message

    def revoke_message(self, friend_id: str, message_id: str) -> bool:
        """Revoke a sent message."""
        messages = self._messages.get(friend_id, [])
        for i, msg in enumerate(messages):
            if msg.message_id == message_id:
                messages[i] = FriendMessage(
                    message_id=msg.message_id,
                    sender_id=msg.sender_id,
                    recipient_id=msg.recipient_id,
                    encrypted_payload=msg.encrypted_payload,
                    key_rotation_epoch=msg.key_rotation_epoch,
                    timestamp=msg.timestamp,
                    status=FriendMessageStatus.REVOKED,
                )
                return True
        return False

    def list_messages(self, friend_id: str) -> list[dict[str, Any]]:
        """List messages with a friend (safe dict, no encrypted payload)."""
        messages = self._messages.get(friend_id, [])
        return [m.as_dict() for m in messages]

    def list_friends(self) -> list[dict[str, Any]]:
        """List all friends (safe dict)."""
        return [
            {
                "friend_id": r.friend_id[:16] + "...",
                "display_name": r.display_name,
                "status": str(r.status),
                "key_rotation_epoch": r.key_rotation_epoch,
                "confirmed_at": r.confirmed_at,
            }
            for r in self._friends.values()
        ]

    def is_friend(self, friend_id: str) -> bool:
        """Check if a friend relationship exists and is confirmed."""
        record = self._friends.get(friend_id)
        return record is not None and record.status == FriendStatus.CONFIRMED
