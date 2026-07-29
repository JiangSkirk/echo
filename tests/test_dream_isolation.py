"""Regression coverage for owner-scoped dreaming outputs and model calls."""

from __future__ import annotations

import os
import sqlite3
import time
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from js.agent import JSAgent
from js.config import JSSettings, MemoryConfig
from js.memory.enhanced_store import EnhancedMemoryStore
from js.memory.profile_scope import scoped_profile_path
from js.models.providers import ChatResponse

ALICE = "owner-alice"
BOB = "owner-bob"


@pytest.mark.asyncio
async def test_dreaming_uses_each_authenticated_owner_as_model_tenant_and_scopes_outputs(
    tmp_path: Path,
) -> None:
    agent = JSAgent(
        JSSettings(workspace=tmp_path / "workspace", state_dir=tmp_path / "state")
    )
    agent.memory.store_working(
        "alice-session", "alice-secret", "Alice confidential fact", importance=9, owner_key_hash=ALICE
    )
    agent.memory.store_working(
        "bob-session", "bob-secret", "Bob confidential fact", importance=9, owner_key_hash=BOB
    )
    runtime = AsyncMock(
        side_effect=[
            ChatResponse(
                content="Alice-only insight",
                tool_calls=[],
                model="mock",
                usage={},
                finish_reason="stop",
            ),
            ChatResponse(
                content="Bob-only insight",
                tool_calls=[],
                model="mock",
                usage={},
                finish_reason="stop",
            ),
        ]
    )
    forbidden_adapter = AsyncMock(side_effect=AssertionError("background entry bypassed EchoRuntime"))
    agent.echo_runtime.execute_model_effect = runtime  # type: ignore[method-assign]
    agent.authorized_model_chat = forbidden_adapter  # type: ignore[method-assign]

    try:
        await agent._run_dreaming()
    finally:
        await agent.close()

    assert runtime.await_count == 2
    assert forbidden_adapter.await_count == 0
    contexts = [call.args[1] for call in runtime.await_args_list]
    assert [context.owner_key_hash for context in contexts] == [ALICE, BOB]
    assert all(context.product_id == "js-agent" for context in contexts)
    assert all(context.channel == "dreaming" for context in contexts)
    assert all(context.session_id == "dreaming" for context in contexts)
    assert all(context.run_id.startswith("dreaming:") for context in contexts)
    assert all(context.role == "local-user" for context in contexts)
    assert all(context.profile == "default" for context in contexts)
    assert all(context.capabilities == () for context in contexts)
    assert all(context.workspace == agent.settings.workspace for context in contexts)
    assert all(context.state_dir == agent.settings.state_dir for context in contexts)
    effects = [call.args[0] for call in runtime.await_args_list]
    assert all(effect.before_model_attempt is not None for effect in effects)
    assert all(effect.completion_budget_callback is not None for effect in effects)
    assert all(effect.max_tokens == agent.settings.echo_budget.max_completion_tokens for effect in effects)

    alice_logs = agent.memory.get_dream_logs(owner_key_hash=ALICE)
    bob_logs = agent.memory.get_dream_logs(owner_key_hash=BOB)
    assert "Alice-only insight" in "\n".join(log["summary"] for log in alice_logs)
    assert "Bob-only insight" not in "\n".join(log["summary"] for log in alice_logs)
    assert "Bob-only insight" in "\n".join(log["summary"] for log in bob_logs)
    assert "Alice-only insight" not in "\n".join(log["summary"] for log in bob_logs)

    alice_diary = agent.memory.read_memory_file("dreams", owner_key_hash=ALICE)
    bob_diary = agent.memory.read_memory_file("dreams", owner_key_hash=BOB)
    local_diary = agent.memory.read_memory_file("dreams")
    assert "Alice-only insight" in alice_diary
    assert "Bob-only insight" not in alice_diary
    assert "Bob-only insight" in bob_diary
    assert "Alice-only insight" not in bob_diary
    assert "Alice-only insight" not in local_diary
    assert "Bob-only insight" not in local_diary


def test_dream_log_query_fails_closed_to_requesting_owner(tmp_path: Path) -> None:
    store = EnhancedMemoryStore(state_dir=tmp_path, config=MemoryConfig())
    try:
        store._log_dream("deep", "Alice secret", owner_key_hash=ALICE)
        store._log_dream("deep", "Bob secret", owner_key_hash=BOB)

        alice_logs = store.get_dream_logs(owner_key_hash=ALICE)
        bob_logs = store.get_dream_logs(owner_key_hash=BOB)
        local_logs = store.get_dream_logs()
    finally:
        store.close()

    assert [log["summary"] for log in alice_logs] == ["Alice secret"]
    assert [log["summary"] for log in bob_logs] == ["Bob secret"]
    assert local_logs == []


def test_dream_log_migration_quarantines_unattributed_legacy_rows(tmp_path: Path) -> None:
    db_path = tmp_path / "memory_enhanced.db"
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE dream_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                phase TEXT,
                summary TEXT,
                changes TEXT,
                created_at REAL NOT NULL
            )
            """
        )
        conn.execute(
            "INSERT INTO dream_logs (phase, summary, changes, created_at) VALUES ('deep', 'legacy', '', 1)"
        )

    store = EnhancedMemoryStore(state_dir=tmp_path, config=MemoryConfig())
    try:
        with sqlite3.connect(store.db_path) as conn:
            columns = {row[1] for row in conn.execute("PRAGMA table_info(dream_logs)")}
            owner = conn.execute("SELECT owner_key_hash FROM dream_logs").fetchone()[0]
        assert "owner_key_hash" in columns
        assert owner == "__legacy_local__"
        assert [log["summary"] for log in store.get_dream_logs()] == ["legacy"]
        assert store.get_dream_logs(owner_key_hash=ALICE) == []
    finally:
        store.close()


def test_dream_log_default_global_cap_is_deterministic_across_many_owners(
    tmp_path: Path,
) -> None:
    store = EnhancedMemoryStore(state_dir=tmp_path, config=MemoryConfig())
    now = time.time()
    try:
        with sqlite3.connect(store.db_path) as conn:
            conn.executemany(
                """
                INSERT INTO dream_logs (
                    owner_key_hash, phase, summary, changes, created_at
                ) VALUES (?, 'deep', ?, '', ?)
                """,
                (
                    (f"owner-{index:05d}", f"summary-{index:05d}", now)
                    for index in range(10_005)
                ),
            )

        deleted = store.maintain_long_term_bounds(
            dream_log_retention_days=3_650,
            max_dream_logs=1,
            proposal_retention_days=3_650,
            max_proposals_per_owner=100,
            max_proposals_global=100,
        )

        with sqlite3.connect(store.db_path) as conn:
            remaining = conn.execute(
                """
                SELECT owner_key_hash, summary
                FROM dream_logs
                ORDER BY created_at ASC, id ASC
                """
            ).fetchall()
    finally:
        store.close()

    assert deleted == 5
    assert len(remaining) == 10_000
    assert remaining[0] == ("owner-00005", "summary-00005")
    assert remaining[-1] == ("owner-10004", "summary-10004")


def test_dream_diary_keeps_complete_recent_utf8_cycles_within_byte_limit(
    tmp_path: Path,
) -> None:
    store = EnhancedMemoryStore(state_dir=tmp_path, config=MemoryConfig())
    try:
        for index in range(12):
            store._append_dream_diary(
                {
                    "phases": [
                        {
                            "phase": "deep",
                            "summary": f"cycle-{index:02d}:" + "秘密" * 60,
                        }
                    ]
                },
                owner_key_hash=ALICE,
                max_bytes=1_024,
            )
        content = store._read_memory_file("dreams", owner_key_hash=ALICE)
    finally:
        store.close()

    retained = [index for index in range(12) if f"cycle-{index:02d}:" in content]
    assert len(content.encode("utf-8")) <= 1_024
    assert retained
    assert retained == list(range(retained[0], 12))
    assert 0 not in retained
    assert 11 in retained
    assert content.count("## Dream Cycle") == content.count("<!-- dreaming:cycle:end -->")


def test_dream_diary_atomic_failure_preserves_previous_complete_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = EnhancedMemoryStore(state_dir=tmp_path, config=MemoryConfig())
    diary_path = scoped_profile_path(store.state_dir, "dreams", ALICE)
    try:
        store._append_dream_diary(
            {"phases": [{"phase": "deep", "summary": "first complete cycle"}]},
            owner_key_hash=ALICE,
        )
        before = diary_path.read_bytes()

        def fail_replace(source: os.PathLike[str] | str, target: os.PathLike[str] | str) -> None:
            raise OSError(f"replace blocked: {source} -> {target}")

        monkeypatch.setattr(os, "replace", fail_replace)
        with pytest.raises(OSError, match="replace blocked"):
            store._append_dream_diary(
                {"phases": [{"phase": "deep", "summary": "second cycle"}]},
                owner_key_hash=ALICE,
            )

        assert diary_path.read_bytes() == before
        assert list(diary_path.parent.glob(f".{diary_path.name}.*.tmp")) == []
    finally:
        store.close()
