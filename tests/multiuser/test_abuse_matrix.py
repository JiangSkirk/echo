"""Concurrent multi-owner leak / fixation / guest / rate-limit matrix."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from js.bots.store import BotStore
from js.config import JSSettings, MemoryConfig, SecurityConfig
from js.cron.engine import ScheduledJob
from js.cron.store import JobStore
from js.echo.turn_context import reset_current_owner_key_hash, set_current_owner_key_hash
from js.evolution.cycle import EvolutionCycle
from js.friends.protocol import FriendStatus
from js.friends.store import FriendStore, StoredFriend
from js.gateway.adapter import ChannelPeer
from js.gateway.pairing import PairingStore
from js.memory.enhanced_store import EnhancedMemoryStore
from js.tools.fleet_tools import FleetCollaborateTool
from js.web import server as web_server
from js.web.auth import AuthManager, authenticate_credentials
from js.web.server import create_app

A = "owner-a"
B = "owner-b"


def _bot_store(tmp_path: Path) -> BotStore:
    return BotStore(tmp_path / "bots-state")


def test_concurrent_bot_creates_do_not_cross_owners(tmp_path: Path) -> None:
    store = _bot_store(tmp_path)

    def _make(owner: str, n: int) -> str:
        return store.create_bot(display_name=f"{owner}-{n}", owner_key_hash=owner).id

    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit(_make, owner, i) for owner in (A, B) for i in range(8)]
        ids = [item.result() for item in futures]
    assert len(ids) == 16
    alice = {bot.id for bot in store.list_bots(owner_key_hash=A)}
    bob = {bot.id for bot in store.list_bots(owner_key_hash=B)}
    assert alice.isdisjoint(bob)
    assert len(alice) == 8
    assert len(bob) == 8
    assert store.get_bot(next(iter(alice)), owner_key_hash=B) is None


def test_concurrent_memory_writes_on_shared_session_stay_partitioned(tmp_path: Path) -> None:
    store = EnhancedMemoryStore(tmp_path, MemoryConfig())
    try:

        def _write(owner: str, n: int) -> None:
            store.store_messages(
                "shared-session",
                [{"role": "user", "content": f"{owner}-secret-{n}"}],
                owner_key_hash=owner,
            )

        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = [pool.submit(_write, owner, i) for owner in (A, B) for i in range(6)]
            for item in futures:
                item.result()
        alice = [
            row["content"] for row in store.get_session_messages("shared-session", owner_key_hash=A)
        ]
        bob = [
            row["content"] for row in store.get_session_messages("shared-session", owner_key_hash=B)
        ]
        assert alice and all(item.startswith("owner-a-") for item in alice)
        assert bob and all(item.startswith("owner-b-") for item in bob)
        assert not any("owner-b-" in item for item in alice)
    finally:
        store.close()


def test_evolution_and_friends_and_cron_stay_owner_scoped(tmp_path: Path) -> None:
    cycle = EvolutionCycle(tmp_path)
    friends = FriendStore(tmp_path)
    jobs = JobStore(tmp_path / "cron.db")

    def _work(owner: str) -> None:
        cycle.generate(owner, max_proposals=1)
        friends.upsert_friend(
            StoredFriend(
                owner=owner,
                friend_id=f"{owner}-friend",
                display_name=owner,
                public_key="pk",
                endpoint="http://127.0.0.1:9",
                status=FriendStatus.CONFIRMED,
                key_rotation_epoch=1,
                confirmed_at=1.0,
            )
        )
        friends.mark_seen(owner, f"{owner}-msg")
        jobs.save_job(
            ScheduledJob(
                name=f"{owner}-job",
                cron_expr="0 * * * *",
                owner_key_hash=owner,
            )
        )

    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = [pool.submit(_work, owner) for owner in (A, B)]
        for item in futures:
            item.result()

    assert cycle.list_proposals(A) and all(item.owner == A for item in cycle.list_proposals(A))
    assert cycle.get(cycle.list_proposals(A)[0].proposal_id, B) is None
    assert friends.list_friends(B)[0].friend_id == "owner-b-friend"
    assert friends.seen(A, "owner-b-msg") is False
    assert [job.owner_key_hash for job in jobs.list_jobs(A)] == [A]
    assert jobs.get_job(jobs.list_jobs(A)[0].id, owner_key_hash=B) is None


def test_gateway_pairing_codes_do_not_bind_the_other_owner() -> None:
    store = PairingStore(ttl_seconds=60)
    peer_a = ChannelPeer(channel="telegram", peer_id="1")
    peer_b = ChannelPeer(channel="telegram", peer_id="2")
    code_a = store.issue_code(A)
    assert store.redeem(code_a, peer_a) == A
    assert store.redeem(code_a, peer_b) is None
    store.allow(peer_b, B)
    assert store.owner_of(peer_a) == A
    assert store.owner_of(peer_b) == B


@pytest.mark.asyncio
async def test_api_key_header_wins_over_foreign_session_cookie(tmp_path: Path) -> None:
    settings = JSSettings(
        workspace=tmp_path / "workspace",
        state_dir=tmp_path / "state",
        first_run_completed=True,
        security=SecurityConfig(api_key_required=True),
    )
    web_server._settings = settings
    auth = AuthManager(settings.state_dir)
    key_a = auth.create_key("alice", role="admin")
    key_b = auth.create_key("bob", role="user")
    token_a, _expires = auth.create_session(key_a)
    mixed = await authenticate_credentials(key_b, token_a)
    assert mixed["key_hash"] == auth.verify(key_b)["key_hash"]
    assert mixed["key_hash"] != auth.verify(key_a)["key_hash"]
    stolen = await authenticate_credentials(None, token_a)
    assert stolen["key_hash"] == auth.verify(key_a)["key_hash"]


def test_guest_cannot_read_audit_or_promote(tmp_path: Path) -> None:
    settings = JSSettings(
        workspace=tmp_path / "workspace",
        state_dir=tmp_path / "state",
        first_run_completed=True,
        security=SecurityConfig(api_key_required=False),
    )
    agent = MagicMock()
    agent.settings = settings
    agent.registry.get_stats.return_value = {}
    agent.secrets.get_stats.return_value = {}
    agent.memory.get_sessions.return_value = []
    agent.audit.query.return_value = []
    from js.web.deps import set_globals

    web_server._agent = agent
    web_server._settings = settings
    set_globals(agent, settings)
    client = TestClient(create_app())
    assert client.get("/api/audit").status_code == 403
    assert client.post("/api/skills/promotions/x/approve").status_code == 403


@pytest.mark.asyncio
async def test_fleet_rate_limit_is_per_owner_not_global() -> None:
    FleetCollaborateTool._call_timestamps_by_scope.clear()
    tool = FleetCollaborateTool(lambda: (_ for _ in ()).throw(RuntimeError("no fleet")))

    async def _hit(owner: str) -> str:
        token = set_current_owner_key_hash(owner)
        try:
            result = await tool.collaborate(task="compare two approaches")
            return result.error or ""
        finally:
            reset_current_owner_key_hash(token)

    for _ in range(FleetCollaborateTool._MAX_CALLS_PER_WINDOW):
        await _hit(A)
    limited = await _hit(A)
    other = await _hit(B)
    assert "rate limit" in limited.lower()
    assert "rate limit" not in other.lower()
