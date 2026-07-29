"""Bounded private handoff storage regressions."""

from __future__ import annotations

import threading

from js.echo.private_handoff import PrivateHandoffVault


def test_private_handoff_is_owner_bound_one_shot_and_thread_safe() -> None:
    vault: PrivateHandoffVault[dict[str, int]] = PrivateHandoffVault(
        max_entries=4,
        ttl_seconds=60.0,
    )
    reference = vault.stage("owner-a", {"value": 1})

    assert reference
    assert vault.take(reference, "owner-b") is None

    results: list[dict[str, int] | None] = []
    barrier = threading.Barrier(3)

    def consume() -> None:
        barrier.wait()
        results.append(vault.take(reference, "owner-a"))

    first = threading.Thread(target=consume)
    second = threading.Thread(target=consume)
    first.start()
    second.start()
    barrier.wait()
    first.join()
    second.join()

    assert results.count({"value": 1}) == 1
    assert results.count(None) == 1


def test_private_handoff_reclaims_expired_capacity() -> None:
    now = [10.0]
    vault: PrivateHandoffVault[str] = PrivateHandoffVault(
        max_entries=1,
        ttl_seconds=5.0,
        clock=lambda: now[0],
    )

    first = vault.stage("owner", "first")
    assert first
    assert vault.stage("owner", "blocked") == ""

    now[0] = 16.0
    second = vault.stage("owner", "second")

    assert second
    assert vault.take(first, "owner") is None
    assert vault.take(second, "owner") == "second"


def test_private_handoff_reservation_guarantees_one_result_slot() -> None:
    vault: PrivateHandoffVault[dict[str, bool]] = PrivateHandoffVault(
        max_entries=1,
        ttl_seconds=60.0,
    )

    reference = vault.reserve("owner-a")

    assert reference
    assert vault.stage("owner-b", {"other": True}) == ""
    assert vault.commit(reference, "owner-b", {"ok": True}) is False
    assert vault.take(reference, "owner-a") is None
    assert vault.commit(reference, "owner-a", {"ok": True}) is True
    assert vault.take(reference, "owner-a") == {"ok": True}


def test_private_handoff_discards_expired_resource_with_cleanup() -> None:
    now = [1.0]
    cleaned: list[str] = []
    vault: PrivateHandoffVault[str] = PrivateHandoffVault(
        max_entries=1,
        ttl_seconds=2.0,
        clock=lambda: now[0],
        cleanup=cleaned.append,
    )
    assert vault.stage("owner", "resource")

    now[0] = 4.0
    assert vault.stage("owner", "replacement")

    assert cleaned == ["resource"]


def test_private_handoff_supports_caller_bound_reference_and_non_consuming_peek() -> None:
    vault: PrivateHandoffVault[str] = PrivateHandoffVault(
        max_entries=2,
        ttl_seconds=60.0,
    )

    assert vault.stage("owner-a", "fingerprint", reference="control-run") == "control-run"
    assert vault.stage("owner-a", "replacement", reference="control-run") == ""
    assert vault.peek("control-run", "owner-b") is None
    assert vault.peek("control-run", "owner-a") == "fingerprint"
    assert vault.peek("control-run", "owner-a") == "fingerprint"
    assert vault.take("control-run", "owner-a") == "fingerprint"
    assert vault.peek("control-run", "owner-a") is None
