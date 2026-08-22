"""R7 friends and Agent collaboration tests."""

from __future__ import annotations

import pytest

from js.friends import (
    CollaborationGrant,
    CollaborationResult,
    FriendManager,
    FriendMessage,
    FriendMessageStatus,
    FriendStatus,
    RemoteTaskEnvelope,
)
from js.friends.protocol import generate_friend_id

_OWNER = "a" * 64
_FRIEND = "b" * 64
_OTHER = "c" * 64


class TestFriendProtocol:
    """Friend request and message protocol validation."""

    def test_friend_id_is_64_hex(self) -> None:
        fid = generate_friend_id()
        assert len(fid) == 64
        int(fid, 16)

    def test_friend_message_valid(self) -> None:
        msg = FriendMessage(
            message_id="msg-1",
            sender_id=_OWNER,
            recipient_id=_FRIEND,
            encrypted_payload="encrypted-data",
        )
        assert msg.key_rotation_epoch == 1
        assert msg.status == FriendMessageStatus.SENT

    def test_friend_message_rejects_same_sender_recipient(self) -> None:
        with pytest.raises(ValueError, match="must differ"):
            FriendMessage(
                message_id="msg-1",
                sender_id=_OWNER,
                recipient_id=_OWNER,
                encrypted_payload="data",
            )

    def test_friend_message_rejects_invalid_id(self) -> None:
        with pytest.raises(ValueError, match="sender_id"):
            FriendMessage(
                message_id="msg-1",
                sender_id="short",
                recipient_id=_FRIEND,
                encrypted_payload="data",
            )

    def test_friend_message_as_dict_redacts_payload(self) -> None:
        msg = FriendMessage(
            message_id="msg-1",
            sender_id=_OWNER,
            recipient_id=_FRIEND,
            encrypted_payload="secret-data",
        )
        d = msg.as_dict()
        assert d["encrypted_payload"] == "[redacted]"


class TestFriendManager:
    """Friend lifecycle: invite, confirm, message, block, revoke, key rotation."""

    def test_create_invite(self) -> None:
        mgr = FriendManager()
        req = mgr.create_invite(owner_id=_OWNER)
        assert req.status == FriendStatus.PENDING
        assert req.invite_code

    def test_confirm_friend(self) -> None:
        mgr = FriendManager()
        req = mgr.create_invite(owner_id=_OWNER)
        record = mgr.confirm_friend(req.request_id, owner_id=_OWNER)
        assert record.status == FriendStatus.CONFIRMED
        assert mgr.is_friend(record.friend_id)

    def test_block_friend(self) -> None:
        mgr = FriendManager()
        req = mgr.create_invite(owner_id=_OWNER)
        record = mgr.confirm_friend(req.request_id, owner_id=_OWNER)
        assert mgr.block_friend(record.friend_id) is True
        assert not mgr.is_friend(record.friend_id)

    def test_revoke_friend(self) -> None:
        mgr = FriendManager()
        req = mgr.create_invite(owner_id=_OWNER)
        record = mgr.confirm_friend(req.request_id, owner_id=_OWNER)
        assert mgr.revoke_friend(record.friend_id) is True
        assert not mgr.is_friend(record.friend_id)

    def test_send_message_success(self) -> None:
        mgr = FriendManager()
        req = mgr.create_invite(owner_id=_OWNER)
        record = mgr.confirm_friend(req.request_id, owner_id=_OWNER)
        msg = FriendMessage(
            message_id="msg-1",
            sender_id=_OWNER,
            recipient_id=record.friend_id,
            encrypted_payload="encrypted",
        )
        sent = mgr.send_message(msg)
        assert sent.status == FriendMessageStatus.SENT

    def test_anti_replay_rejects_duplicate(self) -> None:
        mgr = FriendManager()
        req = mgr.create_invite(owner_id=_OWNER)
        record = mgr.confirm_friend(req.request_id, owner_id=_OWNER)
        msg = FriendMessage(
            message_id="msg-1",
            sender_id=_OWNER,
            recipient_id=record.friend_id,
            encrypted_payload="encrypted",
        )
        mgr.send_message(msg)
        with pytest.raises(ValueError, match="replay"):
            mgr.send_message(msg)

    def test_send_to_blocked_friend_rejected(self) -> None:
        mgr = FriendManager()
        req = mgr.create_invite(owner_id=_OWNER)
        record = mgr.confirm_friend(req.request_id, owner_id=_OWNER)
        mgr.block_friend(record.friend_id)
        msg = FriendMessage(
            message_id="msg-1",
            sender_id=_OWNER,
            recipient_id=record.friend_id,
            encrypted_payload="encrypted",
        )
        with pytest.raises(ValueError, match="blocked"):
            mgr.send_message(msg)

    def test_key_rotation(self) -> None:
        mgr = FriendManager()
        req = mgr.create_invite(owner_id=_OWNER)
        record = mgr.confirm_friend(req.request_id, owner_id=_OWNER)
        new_epoch = mgr.rotate_key(record.friend_id)
        assert new_epoch == 2

    def test_send_with_wrong_epoch_rejected(self) -> None:
        mgr = FriendManager()
        req = mgr.create_invite(owner_id=_OWNER)
        record = mgr.confirm_friend(req.request_id, owner_id=_OWNER)
        mgr.rotate_key(record.friend_id)
        msg = FriendMessage(
            message_id="msg-1",
            sender_id=_OWNER,
            recipient_id=record.friend_id,
            encrypted_payload="encrypted",
            key_rotation_epoch=1,
        )
        with pytest.raises(ValueError, match="epoch"):
            mgr.send_message(msg)

    def test_revoke_message(self) -> None:
        mgr = FriendManager()
        req = mgr.create_invite(owner_id=_OWNER)
        record = mgr.confirm_friend(req.request_id, owner_id=_OWNER)
        msg = FriendMessage(
            message_id="msg-1",
            sender_id=_OWNER,
            recipient_id=record.friend_id,
            encrypted_payload="encrypted",
        )
        mgr.send_message(msg)
        assert mgr.revoke_message(record.friend_id, "msg-1") is True
        messages = mgr.list_messages(record.friend_id)
        assert messages[0]["status"] == "revoked"

    def test_list_friends_redacts_id(self) -> None:
        mgr = FriendManager()
        req = mgr.create_invite(owner_id=_OWNER)
        mgr.confirm_friend(req.request_id, owner_id=_OWNER)
        friends = mgr.list_friends()
        assert len(friends) == 1
        assert "..." in friends[0]["friend_id"]

    def test_send_to_non_friend_rejected(self) -> None:
        mgr = FriendManager()
        msg = FriendMessage(
            message_id="msg-1",
            sender_id=_OWNER,
            recipient_id=_FRIEND,
            encrypted_payload="encrypted",
        )
        with pytest.raises(ValueError, match="not a friend"):
            mgr.send_message(msg)


class TestRemoteTaskEnvelope:
    """Agent L2 RemoteTaskEnvelope with forced limits."""

    def test_valid_envelope(self) -> None:
        env = RemoteTaskEnvelope(
            envelope_id="env-1",
            sender_id=_OWNER,
            recipient_id=_FRIEND,
            task_text="help me summarize this",
        )
        assert env.allowed_tools == ()
        assert env.parent_envelope_id is None

    def test_recursive_delegation_forbidden(self) -> None:
        with pytest.raises(ValueError, match="recursive"):
            RemoteTaskEnvelope(
                envelope_id="env-1",
                sender_id=_OWNER,
                recipient_id=_FRIEND,
                task_text="task",
                parent_envelope_id="parent-env",
            )

    def test_deadline_limits(self) -> None:
        with pytest.raises(ValueError, match="deadline"):
            RemoteTaskEnvelope(
                envelope_id="env-1",
                sender_id=_OWNER,
                recipient_id=_FRIEND,
                task_text="task",
                deadline_seconds=0,
            )
        with pytest.raises(ValueError, match="deadline"):
            RemoteTaskEnvelope(
                envelope_id="env-1",
                sender_id=_OWNER,
                recipient_id=_FRIEND,
                task_text="task",
                deadline_seconds=3601,
            )

    def test_token_budget_limit(self) -> None:
        with pytest.raises(ValueError, match="token_budget"):
            RemoteTaskEnvelope(
                envelope_id="env-1",
                sender_id=_OWNER,
                recipient_id=_FRIEND,
                task_text="task",
                token_budget=100_001,
            )

    def test_default_tools_empty(self) -> None:
        env = RemoteTaskEnvelope(
            envelope_id="env-1",
            sender_id=_OWNER,
            recipient_id=_FRIEND,
            task_text="task",
        )
        assert env.allowed_tools == ()

    def test_task_text_max_length(self) -> None:
        with pytest.raises(ValueError, match="task_text"):
            RemoteTaskEnvelope(
                envelope_id="env-1",
                sender_id=_OWNER,
                recipient_id=_FRIEND,
                task_text="x" * 5001,
            )

    def test_json_payload_size_limit(self) -> None:
        with pytest.raises(ValueError, match="task_json"):
            RemoteTaskEnvelope(
                envelope_id="env-1",
                sender_id=_OWNER,
                recipient_id=_FRIEND,
                task_text="task",
                task_json={"data": "x" * 50000},
            )


class TestCollaborationGrant:
    """CollaborationGrant for Agent L2."""

    def test_valid_grant(self) -> None:
        grant = CollaborationGrant(
            grant_id="grant-1",
            granter_id=_OWNER,
            grantee_id=_FRIEND,
            max_deadline_seconds=60,
            max_token_budget=10000,
            max_cost_budget=100,
            max_byte_budget=100000,
            max_count_budget=10,
        )
        assert grant.allowed_tools == ()
        assert grant.revoked_at is None

    def test_grant_as_dict(self) -> None:
        grant = CollaborationGrant(
            grant_id="grant-1",
            granter_id=_OWNER,
            grantee_id=_FRIEND,
            max_deadline_seconds=60,
            max_token_budget=10000,
            max_cost_budget=100,
            max_byte_budget=100000,
            max_count_budget=10,
        )
        d = grant.as_dict()
        assert d["grant_id"] == "grant-1"
        assert d["allowed_tools"] == []


class TestCollaborationResult:
    """Result of remote task execution."""

    def test_success_result(self) -> None:
        result = CollaborationResult(
            envelope_id="env-1",
            success=True,
            output_text="summary of the task",
        )
        d = result.as_dict()
        assert d["success"] is True
        assert d["terminal_state"] == "completed"

    def test_unknown_terminal_state(self) -> None:
        result = CollaborationResult(
            envelope_id="env-1",
            success=False,
            error="timeout",
            terminal_state="unknown",
        )
        assert result.terminal_state == "unknown"

    def test_manual_review_terminal_state(self) -> None:
        result = CollaborationResult(
            envelope_id="env-1",
            success=False,
            error="uncertain",
            terminal_state="manual_review",
        )
        assert result.terminal_state == "manual_review"
