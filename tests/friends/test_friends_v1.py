"""Friends v1: crypto, owner isolation, pairing, replay, Echo taint, dual HOME."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from js.friends.crypto import (
    decrypt_text,
    derive_shared_key,
    encrypt_text,
    fingerprint,
    generate_keypair,
)
from js.friends.service import RECIPIENT_HEADER, FriendsError, FriendService
from js.friends.store import FriendStore
from js.friends.transport import LoopbackTransport
from js.orin.taint import INBOX_CONTENT, WEB_CONTENT, current_entry_source_taint, set_entry_source
from js.security.secrets import SecretManager


def _service(root: Path, *, endpoint: str, transport: LoopbackTransport) -> FriendService:
    return FriendService(
        root,
        secrets=SecretManager(root),
        transport=transport,
        local_endpoint=endpoint,
    )


def test_crypto_roundtrip() -> None:
    priv_a, pub_a = generate_keypair()
    priv_b, pub_b = generate_keypair()
    key_ab = derive_shared_key(priv_a, pub_b, 1)
    key_ba = derive_shared_key(priv_b, pub_a, 1)
    assert key_ab == key_ba
    aad = b"a:b:1"
    token = encrypt_text(key_ab, "hello", aad=aad)
    assert decrypt_text(key_ba, token, aad=aad) == "hello"
    assert fingerprint(pub_a) != fingerprint(pub_b)


def test_store_owner_isolation(tmp_path: Path) -> None:
    store = FriendStore(tmp_path)
    from js.friends.store import StoredFriend

    store.upsert_friend(
        StoredFriend(
            owner="alice",
            friend_id="b" * 64,
            display_name="Bob",
            public_key="aa",
            endpoint="loop://b",
            status="confirmed",
            key_rotation_epoch=1,
            confirmed_at=1.0,
        )
    )
    assert store.list_friends("alice")
    assert store.list_friends("bob") == []
    assert store.get_friend("bob", "b" * 64) is None


@pytest.mark.asyncio
async def test_dual_home_message_and_task(tmp_path: Path) -> None:
    hub = LoopbackTransport()
    home_a = tmp_path / "a"
    home_b = tmp_path / "b"
    svc_a = _service(home_a, endpoint="loop://a", transport=hub)
    svc_b = _service(home_b, endpoint="loop://b", transport=hub)
    seen: list[str] = []

    async def runner(_agent: object, message: str, **kwargs: object) -> SimpleNamespace:
        seen.append(str(kwargs.get("channel")))
        assert kwargs.get("disable_tools") is True
        return SimpleNamespace(final_text=f"echo:{message}")

    async def handle_a(headers: dict[str, str], body: bytes) -> int:
        await svc_a.receive("owner-a", headers=headers, body=body, turn_runner=runner)
        return 200

    async def handle_b(headers: dict[str, str], body: bytes) -> int:
        await svc_b.receive("owner-b", headers=headers, body=body, turn_runner=runner)
        return 200

    hub.bind("loop://a", handle_a)
    hub.bind("loop://b", handle_b)

    invite = svc_a.create_invite("owner-a")
    accepted = svc_b.accept_invite("owner-b", invite["invite_card"], endpoint="loop://b")
    svc_a.complete_invite("owner-a", accepted["accept"])
    bob_id = svc_b.store.local_friend_id("owner-b")
    assert bob_id
    sent = await svc_a.send_text("owner-a", bob_id, "hello friend")
    assert sent["delivered_status"] == 200
    assert "friends" in seen

    task = await svc_a.send_task("owner-a", bob_id, "summarize this")
    assert task["delivered_status"] == 200
    from js.bots.store import BotStore

    goals = BotStore(home_b).list_goal_runs(owner_key_hash="owner-b")
    assert goals
    assert goals[0].budget.max_tool_calls == 0
    assert goals[0].contract.constraints == ("allowed_tools:",)


@pytest.mark.asyncio
async def test_replay_and_unconfirmed_rejected(tmp_path: Path) -> None:
    hub = LoopbackTransport()
    svc_a = _service(tmp_path / "a", endpoint="loop://a", transport=hub)
    svc_b = _service(tmp_path / "b", endpoint="loop://b", transport=hub)
    captured: list[tuple[dict[str, str], bytes]] = []

    async def handle_b(headers: dict[str, str], body: bytes) -> int:
        captured.append((headers, body))
        await svc_b.receive("owner-b", headers=headers, body=body, turn_runner=None)
        return 200

    hub.bind("loop://b", handle_b)
    invite = svc_a.create_invite("owner-a")
    accepted = svc_b.accept_invite("owner-b", invite["invite_card"], endpoint="loop://b")
    svc_a.complete_invite("owner-a", accepted["accept"])
    bob_id = svc_b.store.local_friend_id("owner-b")
    assert bob_id
    await svc_a.send_text("owner-a", bob_id, "once")
    headers, body = captured[0]
    with pytest.raises(FriendsError, match="replay"):
        await svc_b.receive("owner-b", headers=headers, body=body)
    svc_b.block_friend("owner-b", svc_a.store.local_friend_id("owner-a") or "")
    with pytest.raises(FriendsError, match="not a confirmed"):
        await svc_b.receive("owner-b", headers=headers, body=body)


def test_friends_channel_is_untrusted() -> None:
    token = set_entry_source("friends")
    try:
        assert current_entry_source_taint() == INBOX_CONTENT | WEB_CONTENT
    finally:
        from js.orin.taint import reset_entry_source

        reset_entry_source(token)


def test_disabled_host_does_not_mount_friends(tmp_path: Path) -> None:
    from fastapi.testclient import TestClient

    from js.config import JSSettings
    from js.web.auth import AuthManager
    from js.web.server import create_app

    settings = JSSettings(
        workspace=tmp_path / "w",
        state_dir=tmp_path / "s",
        first_run_completed=True,
        providers=[],
        models=[],
        friends_enabled=False,
    )
    key = AuthManager(settings.state_dir).create_key("u", role="user")
    with TestClient(
        create_app(runtime_settings=settings),
        headers={"Host": "localhost", "Origin": "http://localhost", "X-API-Key": key},
    ) as client:
        assert client.get("/api/friends/status").status_code == 404


def test_recipient_header_constant() -> None:
    assert RECIPIENT_HEADER.startswith("x-js-friends-")
