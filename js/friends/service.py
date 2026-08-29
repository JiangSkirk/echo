"""Friends v1 service: identity, pairing, encrypted delivery, Echo ingest."""

from __future__ import annotations

import json
import secrets
import time
from pathlib import Path
from typing import Any

from js.friends.crypto import (
    decode_invite,
    decrypt_text,
    derive_shared_key,
    encode_invite,
    encrypt_text,
    fingerprint,
    generate_keypair,
    sign_body,
    verify_signature,
)
from js.friends.protocol import FriendStatus, generate_friend_id
from js.friends.store import FriendStore, StoredFriend, StoredInvite
from js.friends.transport import FriendsTransport, LoopbackTransport
from js.security.secrets import SecretManager

TIMESTAMP_HEADER = "x-js-friends-timestamp"
SIGNATURE_HEADER = "x-js-friends-signature"
SENDER_HEADER = "x-js-friends-sender"
RECIPIENT_HEADER = "x-js-friends-recipient"
EPOCH_HEADER = "x-js-friends-epoch"


class FriendsError(ValueError):
    """Caller-facing friends failure."""


class FriendService:
    def __init__(
        self,
        state_dir: Path,
        *,
        secrets: SecretManager,
        transport: FriendsTransport | None = None,
        local_endpoint: str = "",
        agent: Any | None = None,
    ) -> None:
        self.state_dir = Path(state_dir)
        self.store = FriendStore(self.state_dir)
        self.secrets = secrets
        self.transport = transport or LoopbackTransport()
        self.local_endpoint = local_endpoint
        self.agent = agent

    def _secret_name(self, owner: str) -> str:
        return f"friends.x25519.{owner}"

    def ensure_identity(self, owner: str) -> tuple[str, str]:
        existing_id = self.store.local_friend_id(owner)
        raw = self.secrets.retrieve(self._secret_name(owner))
        if raw and existing_id:
            payload = json.loads(raw)
            return existing_id, str(payload["public_hex"])
        private_hex, public_hex = generate_keypair()
        friend_id = existing_id or generate_friend_id()
        self.store.get_or_create_identity(owner, friend_id)
        self.secrets.store(
            self._secret_name(owner),
            json.dumps({"private_hex": private_hex, "public_hex": public_hex}),
            category="friends",
        )
        return friend_id, public_hex

    def _private_hex(self, owner: str) -> str:
        raw = self.secrets.retrieve(self._secret_name(owner))
        if not raw:
            self.ensure_identity(owner)
            raw = self.secrets.retrieve(self._secret_name(owner))
        if not raw:
            raise FriendsError("identity secret missing")
        payload = json.loads(raw)
        return str(payload["private_hex"])

    def create_invite(self, owner: str, *, display_name: str = "Friend") -> dict[str, Any]:
        del display_name
        local_id, public_hex = self.ensure_identity(owner)
        request_id = secrets.token_urlsafe(16)
        invite_code = secrets.token_urlsafe(24)
        now = time.time()
        self.store.put_invite(
            StoredInvite(
                owner=owner,
                request_id=request_id,
                invite_code=invite_code,
                invitee_id="",
                status=FriendStatus.PENDING,
                created_at=now,
            )
        )
        card = encode_invite(
            {
                "v": 1,
                "request_id": request_id,
                "invite_code": invite_code,
                "inviter_id": local_id,
                "public_key": public_hex,
                "fingerprint": fingerprint(public_hex),
                "endpoint": self.local_endpoint,
            }
        )
        return {"request_id": request_id, "invite_card": card, "inviter_id": local_id}

    def accept_invite(
        self,
        owner: str,
        invite_card: str,
        *,
        display_name: str = "Friend",
        endpoint: str = "",
    ) -> dict[str, Any]:
        card = decode_invite(invite_card)
        inviter_id = str(card.get("inviter_id") or "")
        public_key = str(card.get("public_key") or "")
        inviter_endpoint = str(card.get("endpoint") or "")
        invite_code = str(card.get("invite_code") or "")
        if fingerprint(public_key) != str(card.get("fingerprint") or ""):
            raise FriendsError("invite fingerprint mismatch")
        local_id, local_pub = self.ensure_identity(owner)
        now = time.time()
        self.store.upsert_friend(
            StoredFriend(
                owner=owner,
                friend_id=inviter_id,
                display_name=display_name,
                public_key=public_key,
                endpoint=inviter_endpoint,
                status=FriendStatus.CONFIRMED,
                key_rotation_epoch=1,
                confirmed_at=now,
            )
        )
        return {
            "friend_id": inviter_id,
            "accept": {
                "invite_code": invite_code,
                "invitee_id": local_id,
                "public_key": local_pub,
                "fingerprint": fingerprint(local_pub),
                "endpoint": endpoint or self.local_endpoint,
            },
        }

    def complete_invite(self, owner: str, accept: dict[str, Any]) -> StoredFriend:
        invite_code = str(accept.get("invite_code") or "")
        invite = self.store.get_invite_by_code(owner, invite_code)
        if invite is None or invite.status != FriendStatus.PENDING:
            raise FriendsError("invite is not open")
        invitee_id = str(accept.get("invitee_id") or "")
        public_key = str(accept.get("public_key") or "")
        if fingerprint(public_key) != str(accept.get("fingerprint") or ""):
            raise FriendsError("accept fingerprint mismatch")
        now = time.time()
        friend = StoredFriend(
            owner=owner,
            friend_id=invitee_id,
            display_name="Friend",
            public_key=public_key,
            endpoint=str(accept.get("endpoint") or ""),
            status=FriendStatus.CONFIRMED,
            key_rotation_epoch=1,
            confirmed_at=now,
        )
        self.store.upsert_friend(friend)
        self.store.mark_invite(owner, invite.request_id, FriendStatus.CONFIRMED)
        return friend

    def list_friends(self, owner: str) -> list[dict[str, Any]]:
        return [
            {
                "friend_id": item.friend_id[:16] + "...",
                "friend_id_full": item.friend_id,
                "display_name": item.display_name,
                "status": item.status,
                "key_rotation_epoch": item.key_rotation_epoch,
                "endpoint": item.endpoint,
            }
            for item in self.store.list_friends(owner)
        ]

    def block_friend(self, owner: str, friend_id: str) -> bool:
        return self.store.set_status(owner, friend_id, FriendStatus.BLOCKED)

    def revoke_friend(self, owner: str, friend_id: str) -> bool:
        return self.store.set_status(owner, friend_id, FriendStatus.REVOKED)

    def rotate_key(self, owner: str, friend_id: str) -> int:
        return self.store.bump_epoch(owner, friend_id)

    async def send_text(self, owner: str, friend_id: str, text: str) -> dict[str, Any]:
        if not text.strip() or len(text) > 5000:
            raise FriendsError("text must be 1..5000 chars")
        friend = self._require_confirmed(owner, friend_id)
        local_id, _pub = self.ensure_identity(owner)
        key = derive_shared_key(
            self._private_hex(owner), friend.public_key, friend.key_rotation_epoch
        )
        message_id = secrets.token_hex(16)
        aad = f"{local_id}:{friend_id}:{friend.key_rotation_epoch}".encode()
        ciphertext = encrypt_text(key, text, aad=aad)
        body = json.dumps(
            {
                "type": "message",
                "message_id": message_id,
                "sender_id": local_id,
                "text_cipher": ciphertext,
            },
            separators=(",", ":"),
        ).encode()
        timestamp = str(int(time.time()))
        headers = {
            TIMESTAMP_HEADER: timestamp,
            SIGNATURE_HEADER: sign_body(key, timestamp, body),
            SENDER_HEADER: local_id,
            RECIPIENT_HEADER: friend_id,
            EPOCH_HEADER: str(friend.key_rotation_epoch),
            "content-type": "application/json",
        }
        status = await self.transport.deliver(friend.endpoint, headers, body)
        self.store.mark_seen(owner, message_id)
        self.store.add_message(
            owner,
            message_id=message_id,
            friend_id=friend_id,
            direction="out",
            ciphertext=ciphertext,
            epoch=friend.key_rotation_epoch,
        )
        return {"message_id": message_id, "delivered_status": status}

    async def send_task(self, owner: str, friend_id: str, task_text: str) -> dict[str, Any]:
        if not task_text.strip() or len(task_text) > 5000:
            raise FriendsError("task_text must be 1..5000 chars")
        friend = self._require_confirmed(owner, friend_id)
        local_id, _pub = self.ensure_identity(owner)
        key = derive_shared_key(
            self._private_hex(owner), friend.public_key, friend.key_rotation_epoch
        )
        envelope_id = secrets.token_hex(16)
        aad = f"{local_id}:{friend_id}:{friend.key_rotation_epoch}".encode()
        ciphertext = encrypt_text(key, task_text, aad=aad)
        body = json.dumps(
            {
                "type": "task",
                "message_id": envelope_id,
                "sender_id": local_id,
                "task_cipher": ciphertext,
                "allowed_tools": [],
            },
            separators=(",", ":"),
        ).encode()
        timestamp = str(int(time.time()))
        headers = {
            TIMESTAMP_HEADER: timestamp,
            SIGNATURE_HEADER: sign_body(key, timestamp, body),
            SENDER_HEADER: local_id,
            RECIPIENT_HEADER: friend_id,
            EPOCH_HEADER: str(friend.key_rotation_epoch),
            "content-type": "application/json",
        }
        status = await self.transport.deliver(friend.endpoint, headers, body)
        return {"envelope_id": envelope_id, "delivered_status": status}

    async def receive(
        self,
        owner: str,
        *,
        headers: dict[str, str],
        body: bytes,
        turn_runner: Any | None = None,
    ) -> dict[str, Any]:
        sender_id = headers.get(SENDER_HEADER, "")
        epoch_raw = headers.get(EPOCH_HEADER, "1")
        timestamp = headers.get(TIMESTAMP_HEADER, "")
        signature = headers.get(SIGNATURE_HEADER, "")
        friend = self.store.get_friend(owner, sender_id)
        if friend is None or friend.status != FriendStatus.CONFIRMED:
            raise FriendsError("sender is not a confirmed friend")
        if str(friend.key_rotation_epoch) != epoch_raw:
            raise FriendsError("key rotation epoch mismatch")
        key = derive_shared_key(
            self._private_hex(owner), friend.public_key, friend.key_rotation_epoch
        )
        if not verify_signature(key, timestamp, body, signature):
            raise FriendsError("signature rejected")
        payload = json.loads(body.decode("utf-8"))
        message_id = str(payload.get("message_id") or "")
        if not message_id:
            raise FriendsError("message_id required")
        if self.store.seen(owner, message_id):
            raise FriendsError("replay detected")
        self.store.mark_seen(owner, message_id)
        local_id, _pub = self.ensure_identity(owner)
        aad = f"{sender_id}:{local_id}:{friend.key_rotation_epoch}".encode()
        kind = str(payload.get("type") or "message")
        if kind == "task":
            text = decrypt_text(key, str(payload.get("task_cipher") or ""), aad=aad)
            payload["allowed_tools"] = []
            result = await self._ingest_task(owner, sender_id, text, turn_runner=turn_runner)
            return {"ok": True, "type": "task", "message_id": message_id, "result": result}
        text = decrypt_text(key, str(payload.get("text_cipher") or ""), aad=aad)
        self.store.add_message(
            owner,
            message_id=message_id,
            friend_id=sender_id,
            direction="in",
            ciphertext="[held]",
            epoch=friend.key_rotation_epoch,
        )
        await self._ingest_message(owner, sender_id, text, turn_runner=turn_runner)
        return {"ok": True, "type": "message", "message_id": message_id}

    def _require_confirmed(self, owner: str, friend_id: str) -> StoredFriend:
        friend = self.store.get_friend(owner, friend_id)
        if friend is None or friend.status != FriendStatus.CONFIRMED:
            raise FriendsError("friend is not confirmed")
        return friend

    async def _ingest_message(
        self,
        owner: str,
        sender_id: str,
        text: str,
        *,
        turn_runner: Any | None,
    ) -> None:
        runner = turn_runner or _default_turn_runner
        if self.agent is None and turn_runner is None:
            return
        await runner(
            self.agent,
            f"[friend {sender_id[:8]}] {text}",
            channel="friends",
            owner_key_hash=owner,
            disable_tools=True,
        )

    async def _ingest_task(
        self,
        owner: str,
        sender_id: str,
        text: str,
        *,
        turn_runner: Any | None,
    ) -> dict[str, Any]:
        from js.bots.models import GoalBudget, GoalContract
        from js.bots.service import BotService, bot_store_for

        bots = BotService(bot_store_for(self.state_dir))
        draft = bots.create_draft(f"Friend {sender_id[:8]}", owner_key_hash=owner)
        bots.store.update_soul(
            draft.id,
            soul_text="Remote friend task inbox. No local tools.",
            owner_key_hash=owner,
            activate=True,
        )
        room = bots.store.create_room(
            title=f"Friend task {sender_id[:8]}",
            member_bot_ids=[draft.id],
            owner_key_hash=owner,
        )
        goal = bots.store.create_goal_run(
            room.id,
            owner_key_hash=owner,
            questions=[],
            contract=GoalContract(
                objective=text,
                constraints=("allowed_tools:",),
            ),
            budget=GoalBudget(max_echo_turns=4, max_tool_calls=0),
        )
        runner = turn_runner or _default_turn_runner
        output = ""
        if self.agent is not None or turn_runner is not None:
            state = await runner(
                self.agent,
                text,
                channel="friends",
                owner_key_hash=owner,
                disable_tools=True,
            )
            output = str(getattr(state, "final_text", "") or getattr(state, "output", "") or "")
        return {"goal_id": goal.id, "room_id": room.id, "output": output, "allowed_tools": []}


async def _default_turn_runner(agent: Any, message: str, **kwargs: Any) -> Any:
    from js.echo.turn_runtime import run_echo_turn

    return await run_echo_turn(agent, message, **kwargs)
