"""F-04: ModelPermit spent-nonce store must be bounded and fail-closed."""

from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from js.models.permit import ModelPermitError, ModelPermitIssuer
from js.models.providers import ChatMessage


def _msgs() -> list[ChatMessage]:
    return [ChatMessage(role="user", content="hi")]


def _issue_and_consume(issuer: ModelPermitIssuer) -> None:
    permit = issuer.issue(
        provider_name="p",
        model="m",
        messages=_msgs(),
        tools=None,
        owner_key_hash="owner",
        session_id="sess",
        run_id="run",
    )
    issuer.verify_and_consume(
        permit,
        provider_name="p",
        model="m",
        messages=_msgs(),
        tools=None,
    )


def test_replay_after_consume_is_rejected() -> None:
    issuer = ModelPermitIssuer(ttl_seconds=30.0, max_spent_nonces=100)
    permit = issuer.issue(
        provider_name="p",
        model="m",
        messages=_msgs(),
        tools=None,
        owner_key_hash="owner",
        session_id="sess",
        run_id="run",
    )
    issuer.verify_and_consume(permit, provider_name="p", model="m", messages=_msgs(), tools=None)
    with pytest.raises(ModelPermitError, match="replayed"):
        issuer.verify_and_consume(
            permit, provider_name="p", model="m", messages=_msgs(), tools=None
        )


def test_expired_nonces_are_purged_under_lock() -> None:
    issuer = ModelPermitIssuer(ttl_seconds=0.05, max_spent_nonces=10)
    for _ in range(5):
        _issue_and_consume(issuer)
    assert issuer.spent_nonce_count() == 5
    time.sleep(0.08)
    # Next consume must purge expired entries before inserting.
    _issue_and_consume(issuer)
    assert issuer.spent_nonce_count() == 1


def test_hard_cap_fail_closed_does_not_evict_unexpired() -> None:
    issuer = ModelPermitIssuer(ttl_seconds=60.0, max_spent_nonces=3)
    for _ in range(3):
        _issue_and_consume(issuer)
    assert issuer.spent_nonce_count() == 3
    with pytest.raises(ModelPermitError, match="spent nonce capacity"):
        _issue_and_consume(issuer)
    # Unexpired nonces must still block replay.
    assert issuer.spent_nonce_count() == 3


def test_concurrent_consume_single_winner() -> None:
    issuer = ModelPermitIssuer(ttl_seconds=30.0, max_spent_nonces=100)
    permit = issuer.issue(
        provider_name="p",
        model="m",
        messages=_msgs(),
        tools=None,
        owner_key_hash="owner",
        session_id="sess",
        run_id="run",
    )
    results: list[str] = []
    barrier = threading.Barrier(8)

    def _worker() -> None:
        barrier.wait()
        try:
            issuer.verify_and_consume(
                permit, provider_name="p", model="m", messages=_msgs(), tools=None
            )
            results.append("ok")
        except ModelPermitError:
            results.append("reject")

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(lambda _: _worker(), range(8)))
    assert results.count("ok") == 1
    assert results.count("reject") == 7


def test_spent_store_never_exceeds_hard_cap_under_load() -> None:
    issuer = ModelPermitIssuer(ttl_seconds=60.0, max_spent_nonces=20)
    accepted = 0
    rejected = 0
    for _ in range(40):
        try:
            _issue_and_consume(issuer)
            accepted += 1
        except ModelPermitError as exc:
            assert "spent nonce capacity" in str(exc)
            rejected += 1
    assert accepted == 20
    assert rejected == 20
    assert issuer.spent_nonce_count() <= 20
