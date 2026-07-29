"""Echo persistent context CAS adapter tests."""

from __future__ import annotations

import ast
import hashlib
import pathlib
import sqlite3
import threading

import pytest

from js.echo.context_store import PersistentContextCAS

SCOPE_A = "owner-a:session-a"
SCOPE_B = "owner-a:session-b"
TOKEN_A = "heuristic:v1"
TOKEN_B = "tiktoken:o200k_base"


def test_reopened_instance_hits_existing_record(tmp_path: pathlib.Path) -> None:
    db_path = tmp_path / "context-cas.sqlite3"
    first_store = PersistentContextCAS(db_path)

    first, first_created = first_store.put_with_status(
        SCOPE_A,
        TOKEN_A,
        b"stable prompt chunk",
        tokens=5,
        now_ms=1_000,
    )
    first_store.close()

    second_store = PersistentContextCAS(db_path)
    second, second_created = second_store.put_with_status(
        SCOPE_A,
        TOKEN_A,
        b"stable prompt chunk",
        tokens=5,
        now_ms=2_000,
    )

    assert first_created is True
    assert second_created is False
    assert second.digest == first.digest
    assert second.payload == first.payload
    assert second.tokens == first.tokens
    assert second.last_accessed_ms == 2_000


def test_scope_session_and_token_unit_do_not_share_payloads(
    tmp_path: pathlib.Path,
) -> None:
    store = PersistentContextCAS(tmp_path / "context-cas.sqlite3")
    payload = b"same bytes, separate scopes"

    _, first_created = store.put_with_status(SCOPE_A, TOKEN_A, payload, tokens=7, now_ms=1_000)
    _, duplicate_created = store.put_with_status(
        SCOPE_A,
        TOKEN_A,
        payload,
        tokens=7,
        now_ms=1_100,
    )
    _, other_session_created = store.put_with_status(
        SCOPE_B,
        TOKEN_A,
        payload,
        tokens=7,
        now_ms=1_200,
    )
    _, other_token_created = store.put_with_status(
        SCOPE_A,
        TOKEN_B,
        payload,
        tokens=3,
        now_ms=1_300,
    )

    assert first_created is True
    assert duplicate_created is False
    assert other_session_created is True
    assert other_token_created is True


def test_ttl_expiry_allows_payload_to_be_created_again(tmp_path: pathlib.Path) -> None:
    store = PersistentContextCAS(tmp_path / "context-cas.sqlite3", ttl_ms=10)
    payload = b"short lived prompt chunk"

    first, first_created = store.put_with_status(SCOPE_A, TOKEN_A, payload, tokens=4, now_ms=100)
    before_expiry, before_expiry_created = store.put_with_status(
        SCOPE_A,
        TOKEN_A,
        payload,
        tokens=4,
        now_ms=109,
    )
    after_expiry, after_expiry_created = store.put_with_status(
        SCOPE_A,
        TOKEN_A,
        payload,
        tokens=4,
        now_ms=110,
    )

    assert first_created is True
    assert before_expiry_created is False
    assert after_expiry_created is True
    assert first.expires_at_ms == 110
    assert before_expiry.expires_at_ms == 110
    assert after_expiry.expires_at_ms == 120


def test_entry_quota_evicts_least_recently_accessed_record(tmp_path: pathlib.Path) -> None:
    store = PersistentContextCAS(tmp_path / "context-cas.sqlite3", max_entries_per_scope=2)

    _, p1_created = store.put_with_status(SCOPE_A, TOKEN_A, b"payload-1", tokens=1, now_ms=100)
    _, p2_created = store.put_with_status(SCOPE_A, TOKEN_A, b"payload-2", tokens=1, now_ms=200)
    _, p1_hit_created = store.put_with_status(SCOPE_A, TOKEN_A, b"payload-1", tokens=1, now_ms=300)
    _, p3_created = store.put_with_status(SCOPE_A, TOKEN_A, b"payload-3", tokens=1, now_ms=400)
    _, p2_recreated = store.put_with_status(SCOPE_A, TOKEN_A, b"payload-2", tokens=1, now_ms=500)

    assert p1_created is True
    assert p2_created is True
    assert p1_hit_created is False
    assert p3_created is True
    assert p2_recreated is True


def test_byte_quota_evicts_least_recently_accessed_record(tmp_path: pathlib.Path) -> None:
    store = PersistentContextCAS(tmp_path / "context-cas.sqlite3", max_bytes_per_scope=10)

    _, p1_created = store.put_with_status(SCOPE_A, TOKEN_A, b"1111", tokens=1, now_ms=100)
    _, p2_created = store.put_with_status(SCOPE_A, TOKEN_A, b"2222", tokens=1, now_ms=200)
    _, p1_hit_created = store.put_with_status(SCOPE_A, TOKEN_A, b"1111", tokens=1, now_ms=300)
    _, p3_created = store.put_with_status(SCOPE_A, TOKEN_A, b"3333", tokens=1, now_ms=400)
    _, p2_recreated = store.put_with_status(SCOPE_A, TOKEN_A, b"2222", tokens=1, now_ms=500)

    assert p1_created is True
    assert p2_created is True
    assert p1_hit_created is False
    assert p3_created is True
    assert p2_recreated is True


def test_concurrent_same_payload_has_exactly_one_creator(tmp_path: pathlib.Path) -> None:
    store = PersistentContextCAS(tmp_path / "context-cas.sqlite3")
    payload = b"shared concurrent payload"
    expected_digest = hashlib.sha256(payload).digest()
    thread_count = 32
    barrier = threading.Barrier(thread_count)
    created_flags: list[bool] = []
    digests: list[bytes] = []
    errors: list[BaseException] = []
    results_lock = threading.Lock()

    def worker() -> None:
        try:
            barrier.wait()
            record, created = store.put_with_status(
                SCOPE_A,
                TOKEN_A,
                payload,
                tokens=6,
                now_ms=1_000,
            )
            with results_lock:
                created_flags.append(created)
                digests.append(record.digest)
        except BaseException as exc:  # pragma: no cover - surfaced by assertion below
            with results_lock:
                errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(thread_count)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert len(created_flags) == thread_count
    assert sum(1 for flag in created_flags if flag) == 1
    assert set(digests) == {expected_digest}


def test_corrupted_database_errors_are_not_swallowed(tmp_path: pathlib.Path) -> None:
    db_path = tmp_path / "context-cas.sqlite3"
    db_path.write_bytes(b"not a sqlite database")

    with pytest.raises(sqlite3.DatabaseError):
        PersistentContextCAS(db_path)


def test_locked_database_errors_are_not_swallowed(tmp_path: pathlib.Path) -> None:
    db_path = tmp_path / "context-cas.sqlite3"
    PersistentContextCAS(db_path).close()
    store = PersistentContextCAS(db_path, timeout_s=0.01)
    locker = sqlite3.connect(str(db_path), timeout=0.01, isolation_level=None)
    locker.execute("BEGIN IMMEDIATE")

    try:
        with pytest.raises(sqlite3.OperationalError):
            store.put_with_status(SCOPE_A, TOKEN_A, b"locked payload", tokens=2, now_ms=1_000)
    finally:
        locker.rollback()
        locker.close()
        store.close()


def test_adapter_stays_optional_and_avoids_runtime_wiring() -> None:
    source_path = pathlib.Path(__file__).parents[2] / "js" / "echo" / "context_store.py"
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    imported_modules: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            imported_modules.add(node.module)

    assert "os" not in imported_modules
    assert "js.echo.gateway" not in imported_modules
    assert "js.echo.runtime" not in imported_modules
    assert "js.web" not in imported_modules
