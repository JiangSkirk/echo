"""UNKNOWN_COMMIT reconciles. It does not blind-dispatch again."""

from __future__ import annotations

import pytest

from js.bots.authority import refuse_unknown_commit_replay
from js.bots.exceptions import BotsStateError
from js.orind.cells import memory as memory_mod
from js.orind.cells.memory import MemoryCell


def test_unknown_commit_refuses_blind_replay() -> None:
    refuse_unknown_commit_replay("COMMITTED")
    refuse_unknown_commit_replay("PREPARED")
    with pytest.raises(BotsStateError, match="blind replay"):
        refuse_unknown_commit_replay("UNKNOWN_COMMIT")


def test_memory_cell_reconcile_stays_unknown_without_rewrite(tmp_path) -> None:
    cell = MemoryCell(
        socket_path=tmp_path / "unused.sock",
        state_dir=tmp_path / "memory-state",
        mac_key=b"m" * 32,
    )
    cell._session_key = b"s" * 32  # noqa: SLF001
    cell._conn.execute(  # noqa: SLF001
        "INSERT INTO commits(draft_id, effect_hash, record_id, state) VALUES (?, ?, ?, ?)",
        ("draft:bots-replay", "sha256:abc", "memory:pending", "unknown"),
    )
    cell._conn.commit()  # noqa: SLF001
    result = cell._reconcile_effect("draft:bots-replay", {"draft_id": "draft:bots-replay"})
    assert result["state"] == "UNKNOWN_COMMIT"
    with pytest.raises(BotsStateError, match="blind replay"):
        refuse_unknown_commit_replay(result["state"])


def test_cross_bot_private_session_read_is_absent(tmp_path) -> None:
    cell = MemoryCell(
        socket_path=tmp_path / "unused.sock",
        state_dir=tmp_path / "memory-state",
        mac_key=b"m" * 32,
    )
    owner = "sha256:" + "1" * 64
    cell._conn.execute(  # noqa: SLF001
        "INSERT INTO memories("
        "record_id, owner_key_hash, profile, session_id, task_id, key, "
        "value, source, taint, clearance, created_at_ms, updated_at_ms"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            "memory:bot-a",
            owner,
            "personal",
            "bot:baaa:private",
            "task:goal",
            "soul",
            "private-of-a",
            "user",
            0,
            1,
            1,
            1,
        ),
    )
    cell._conn.commit()  # noqa: SLF001
    own = memory_mod._Scope(
        owner_key_hash=owner,
        profile="personal",
        session_id="bot:baaa:private",
        task_id="task:goal",
        key="soul",
    )
    peer = memory_mod._Scope(
        owner_key_hash=owner,
        profile="personal",
        session_id="bot:bbbb:private",
        task_id="task:goal",
        key="soul",
    )
    row = cell._row(own)  # noqa: SLF001
    assert row is not None
    assert row[1] == "private-of-a"
    assert cell._row(peer) is None  # noqa: SLF001
