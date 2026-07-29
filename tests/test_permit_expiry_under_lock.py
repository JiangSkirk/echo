"""F-04: permit expiry must be re-checked under the spent-nonce lock."""

from __future__ import annotations

import threading
import time
from typing import Any

import pytest

from js.models.permit import ModelPermitError, ModelPermitIssuer
from js.models.providers import ChatMessage


class _GateLock:
    """Wraps a Lock and signals when a waiter reaches acquire / ``with``."""

    def __init__(self, real: threading.Lock, entered: threading.Event) -> None:
        self._real = real
        self._entered = entered

    def acquire(self, blocking: bool = True, timeout: float = -1) -> bool:
        self._entered.set()
        if timeout < 0:
            return self._real.acquire(blocking)
        return self._real.acquire(blocking, timeout)

    def release(self) -> None:
        self._real.release()

    def __enter__(self) -> _GateLock:
        self.acquire()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.release()


def test_permit_expired_while_waiting_for_lock_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Hold the issuer lock, advance clock to expires_at, then release.

    Verifier must reject at the equality boundary via the under-lock recheck.
    """
    issuer = ModelPermitIssuer(ttl_seconds=60.0)
    messages = [ChatMessage(role="user", content="hi")]
    permit = issuer.issue(
        provider_name="p",
        model="m",
        messages=messages,
        tools=None,
        owner_key_hash="owner",
        session_id="sess",
        run_id="run",
    )

    clock = {"now": permit.expires_at - 10.0}
    monkeypatch.setattr(time, "time", lambda: clock["now"])

    entered = threading.Event()
    real_lock = issuer._lock
    issuer._lock = _GateLock(real_lock, entered)  # type: ignore[assignment]

    errors: list[BaseException] = []
    real_lock.acquire()
    try:

        def _verify() -> None:
            try:
                issuer.verify_and_consume(
                    permit,
                    provider_name="p",
                    model="m",
                    messages=messages,
                    tools=None,
                )
            except BaseException as exc:  # noqa: BLE001
                errors.append(exc)

        worker = threading.Thread(target=_verify)
        worker.start()
        assert entered.wait(timeout=2.0), "verifier never reached issuer lock"
        # Equality boundary: now == expires_at must reject under the lock.
        clock["now"] = permit.expires_at
    finally:
        real_lock.release()

    worker.join(timeout=2.0)
    assert not worker.is_alive()
    assert len(errors) == 1
    assert isinstance(errors[0], ModelPermitError)
    assert "expired" in str(errors[0])


def test_permit_rejects_at_exact_expires_at_boundary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    issuer = ModelPermitIssuer(ttl_seconds=60.0)
    messages = [ChatMessage(role="user", content="hi")]
    permit = issuer.issue(
        provider_name="p",
        model="m",
        messages=messages,
        tools=None,
        owner_key_hash="owner",
        session_id="sess",
        run_id="run",
    )
    monkeypatch.setattr(time, "time", lambda: permit.expires_at)
    with pytest.raises(ModelPermitError, match="expired"):
        issuer.verify_and_consume(
            permit,
            provider_name="p",
            model="m",
            messages=messages,
            tools=None,
        )
