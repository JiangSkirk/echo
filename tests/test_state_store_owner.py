"""Tests for StateStore owner isolation."""

from __future__ import annotations

from js.persistence.state_store import StateStore


def test_save_load_delete_with_owner(tmp_path):
    store = StateStore(tmp_path / "state.db")
    store.save(
        session_id="s1",
        run_id="r1",
        turn_count=1,
        messages=[{"role": "user", "content": "hi"}],
        tool_results=[],
        total_tokens={"input": 1, "output": 1},
        cost_estimate=0.0,
        status="running",
        error_message="",
        compression_stats={},
        model="m",
        owner_key_hash="owner_a",
    )
    loaded = store.load("s1", "owner_a")
    assert loaded is not None
    assert loaded["run_id"] == "r1"
    assert loaded["messages"][0]["content"] == "hi"

    # Wrong owner returns None
    assert store.load("s1", "owner_b") is None

    # Delete scoped
    assert store.delete("s1", "owner_a") is True
    assert store.load("s1", "owner_a") is None


def test_same_session_id_different_owners(tmp_path):
    store = StateStore(tmp_path / "state.db")
    for owner in ("owner_a", "owner_b"):
        store.save(
            session_id="same",
            run_id="r1",
            turn_count=1,
            messages=[{"role": "user", "content": f"hi {owner}"}],
            tool_results=[],
            total_tokens={"input": 1, "output": 1},
            cost_estimate=0.0,
            status="running",
            error_message="",
            compression_stats={},
            model="m",
            owner_key_hash=owner,
        )
    a = store.load("same", "owner_a")
    b = store.load("same", "owner_b")
    assert a is not None and a["messages"][0]["content"] == "hi owner_a"
    assert b is not None and b["messages"][0]["content"] == "hi owner_b"


def test_list_sessions_filtered_by_owner(tmp_path):
    store = StateStore(tmp_path / "state.db")
    store.save(
        session_id="s_a",
        run_id="r1",
        turn_count=0,
        messages=[],
        tool_results=[],
        total_tokens={},
        cost_estimate=0.0,
        status="running",
        error_message="",
        compression_stats={},
        model="",
        owner_key_hash="owner_a",
    )
    store.save(
        session_id="s_b",
        run_id="r1",
        turn_count=0,
        messages=[],
        tool_results=[],
        total_tokens={},
        cost_estimate=0.0,
        status="running",
        error_message="",
        compression_stats={},
        model="",
        owner_key_hash="owner_b",
    )
    assert store.list_sessions("owner_a") == ["s_a"]
    assert store.list_sessions("owner_b") == ["s_b"]
    # owner=None must NOT leak authenticated owners' rows;
    # it is normalized to the legacy-local sentinel and finds nothing here.
    assert store.list_sessions() == []
    assert store.list_sessions(None) == []


def test_load_returns_owner_key_hash(tmp_path):
    store = StateStore(tmp_path / "state.db")
    store.save(
        session_id="s_meta",
        run_id="r1",
        turn_count=0,
        messages=[],
        tool_results=[],
        total_tokens={},
        cost_estimate=0.0,
        status="running",
        error_message="",
        compression_stats={},
        model="",
        owner_key_hash="owner_a",
    )
    loaded = store.load("s_meta", "owner_a")
    assert loaded is not None
    assert loaded["owner_key_hash"] == "owner_a"


def test_load_with_wrong_owner_returns_none(tmp_path):
    store = StateStore(tmp_path / "state.db")
    store.save(
        session_id="s_wrong",
        run_id="r1",
        turn_count=0,
        messages=[],
        tool_results=[],
        total_tokens={},
        cost_estimate=0.0,
        status="running",
        error_message="",
        compression_stats={},
        model="",
        owner_key_hash="owner_a",
    )
    assert store.load("s_wrong", "owner_b") is None
    # Unauthenticated (None) caller must NOT see authenticated owner's row
    # because None maps to legacy-local sentinel, not a wildcard.
    assert store.load("s_wrong", None) is None


def test_load_legacy_owner_returns_owner_hash(tmp_path):
    store = StateStore(tmp_path / "state.db")
    store.save(
        session_id="legacy_meta",
        run_id="r1",
        turn_count=0,
        messages=[],
        tool_results=[],
        total_tokens={},
        cost_estimate=0.0,
        status="running",
        error_message="",
        compression_stats={},
        model="",
        owner_key_hash=None,
    )
    loaded = store.load("legacy_meta", None)
    assert loaded is not None
    assert loaded["owner_key_hash"] == "__legacy_local__"


def test_legacy_null_owner_backfill_and_load(tmp_path):
    store = StateStore(tmp_path / "state.db")
    store.save(
        session_id="legacy",
        run_id="r1",
        turn_count=0,
        messages=[],
        tool_results=[],
        total_tokens={},
        cost_estimate=0.0,
        status="running",
        error_message="",
        compression_stats={},
        model="",
        owner_key_hash=None,
    )
    loaded = store.load("legacy", None)
    assert loaded is not None
    assert loaded["run_id"] == "r1"
