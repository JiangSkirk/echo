"""Echo T7 — fail-closed LeasedSandbox implementation of `spi.Sandbox` Protocol.

Every execute() exits via handler success or LeaseDenied-subclass — no third path.

T7 sandbox is in-memory only. It NEVER touches subprocess / socket / urllib / fs / env / real LLM.

Real OS sandbox (Wasm / firejail / firecracker / macOS sandbox) deferred to T9+.

Module never reads env vars; never calls gateway / runtime / pulse().
"""

from __future__ import annotations

import hmac
import threading
from collections.abc import Callable

from js.echo.capability import (
    DEFAULT_NETWORK_POLICY,
    LeaseAuthority,
    LeaseDenied,
    LeaseOwnerMismatch,
    LeaseUnknownTool,
)
from js.echo.types import CapabilityLease

# ---------------------------------------------------------------------------
# Type aliases
# ---------------------------------------------------------------------------
type DeterministicHandler = Callable[[CapabilityLease, str], str]
"""Pure-python handler signature.

The handler receives an already-verified :class:`CapabilityLease` and an
``arguments_hash`` (string digest of the caller's argument payload) and
must return a result payload hash as a ``str``. Handlers must be
deterministic and must not touch subprocess / network / fs / env. The
sandbox cannot enforce this statically — it is part of the contract.
"""


# ---------------------------------------------------------------------------
# Sandbox
# ---------------------------------------------------------------------------
class LeasedSandbox:
    """Fail-closed Sandbox Protocol implementation for Echo T7.

    Every call to :meth:`execute` MUST exit via either:
      (a) a successful handler return; or
      (b) a :class:`LeaseDenied`-subclass exception.

    Any unexpected internal exception is wrapped into ``LeaseDenied`` so a
    bug in the handler or the policy layer never accidentally leaks
    side-effects.

    Default state: ``_handlers={}``, every :meth:`execute` raises
    :class:`LeaseUnknownTool`.

    This sandbox is in-memory only. It NEVER touches:
      - subprocess / os.exec*
      - socket / urllib / requests / httpx
      - the filesystem (no open(), no os.* fs operations)
      - environment variables
      - real LLM calls
    """

    __slots__ = ("_authority", "_now", "_handlers", "_bound_owner", "_lock")

    def __init__(
        self,
        *,
        authority: LeaseAuthority,
        now_fn: Callable[[], int],
    ) -> None:
        """Construct a sandbox bound to a :class:`LeaseAuthority` and clock.

        Parameters
        ----------
        authority:
            The :class:`LeaseAuthority` used to issue, verify and consume
            leases. Must be a real ``LeaseAuthority`` instance.
        now_fn:
            Injected clock returning integer milliseconds. The sandbox
            uses this only for :meth:`execute` verify / consume calls; the
            authority owns its own ``now_fn`` for lease expiry math.
        """

        if not isinstance(authority, LeaseAuthority):
            raise TypeError("authority must be a LeaseAuthority instance")
        if not callable(now_fn):
            raise TypeError("now_fn must be callable")

        self._authority: LeaseAuthority = authority
        self._now: Callable[[], int] = now_fn
        self._handlers: dict[str, DeterministicHandler] = {}
        self._bound_owner: str | None = None
        self._lock = threading.RLock()

    # ---- ownership -----------------------------------------------------
    def bind_owner(self, owner_key_hash: str) -> None:
        """Pin which owner this sandbox instance grants & verifies against.

        Must be called before :meth:`grant` / :meth:`execute`. Calling
        twice with the same ``owner_key_hash`` is idempotent; calling
        twice with a different owner raises :class:`ValueError` —
        sandbox instances are single-owner by design at T7.
        """

        with self._lock:
            if not isinstance(owner_key_hash, str) or owner_key_hash == "":
                raise ValueError("owner_key_hash must be a non-empty str")
            if self._bound_owner is not None and (
                len(self._bound_owner) != len(owner_key_hash)
                or not hmac.compare_digest(
                    self._bound_owner.encode("utf-8"),
                    owner_key_hash.encode("utf-8"),
                )
            ):
                raise ValueError("sandbox already bound to a different owner")
            self._bound_owner = owner_key_hash

    @property
    def bound_owner(self) -> str | None:
        """Test helper — current bound owner (or ``None`` if unbound)."""

        with self._lock:
            return self._bound_owner

    # ---- handler registration ------------------------------------------
    def register_handler(
        self,
        tool_name: str,
        handler: DeterministicHandler,
    ) -> None:
        """Wire a deterministic handler for ``tool_name``.

        T7 keeps every handler pure-python: handlers must NOT touch
        subprocess / network / fs / env. The sandbox cannot enforce
        this statically, but the contract is documented and tested.

        Re-registering the same ``tool_name`` overwrites the previous
        handler — useful for tests; production code should register
        once at startup.
        """

        with self._lock:
            if not isinstance(tool_name, str) or tool_name == "":
                raise ValueError("tool_name must be a non-empty str")
            if not callable(handler):
                raise TypeError("handler must be callable")
            self._handlers[tool_name] = handler

    # ---- spi.Sandbox Protocol ------------------------------------------
    def grant(
        self,
        tool_name: str,
        resource_scope: str,
        now: int,
    ) -> CapabilityLease:
        """Issue a fresh lease for ``(tool_name, resource_scope)`` under bound owner.

        Uses sandbox-policy defaults:
          - ``max_bytes = 1 << 20``           (1 MiB)
          - ``max_duration_ms = 1_000``       (1 second)
          - ``max_invocations = 1``           (single-use)
          - ``ttl_ms = 60_000``               (1 minute)
          - ``fs_roots = ()``
          - ``network_policy = "deny"``
          - ``parent_lease_id = None``

        The ``now`` argument is accepted to match the
        :class:`~js.echo.spi.Sandbox` Protocol but is intentionally
        ignored: the underlying :class:`LeaseAuthority` derives
        ``expires_at`` from its own injected clock so the sandbox does
        not expose an additional clock source.

        Raises
        ------
        ValueError
            If :meth:`bind_owner` has not been called, or if
            ``tool_name`` / ``resource_scope`` are not non-empty strings.
        """

        with self._lock:
            if self._bound_owner is None:
                raise ValueError("sandbox owner not bound")
            if not isinstance(tool_name, str) or tool_name == "":
                raise ValueError("tool_name must be a non-empty str")
            if not isinstance(resource_scope, str) or resource_scope == "":
                raise ValueError("resource_scope must be a non-empty str")
            return self._authority.issue(
                owner_key_hash=self._bound_owner,
                run_id="t7-sandbox",
                tool_name=tool_name,
                args_schema="t7-sandbox-default",
                resource_scope=resource_scope,
                max_bytes=1 << 20,
                max_duration_ms=1_000,
                ttl_ms=60_000,
                max_invocations=1,
                fs_roots=(),
                network_policy=DEFAULT_NETWORK_POLICY,
                parent_lease_id=None,
            )

    def execute(self, lease: CapabilityLease, arguments_hash: str) -> str:
        """Fail-closed entry point.

        Order of checks (first failure wins, each raises a
        :class:`LeaseDenied` subclass):

        1. bound owner exists (else :class:`LeaseOwnerMismatch` with msg
           ``"sandbox owner not bound"``);
        2. ``tool_name`` registered in ``self._handlers`` (else
           :class:`LeaseUnknownTool`);
        3. :meth:`LeaseAuthority.verify` with
           ``expected_owner=self._bound_owner``,
           ``expected_tool=lease.tool_name``,
           ``expected_scope=lease.resource_scope``,
           ``now=self._now()`` — folds MAC / expiry / revocation /
           owner / tool / scope into one call. Sandbox uses the lease's
           own values as the canonical expected set; this is belt-and-
           braces for callers that want to inject distinct expectations
           upstream;
        4. :meth:`LeaseAuthority.consume` — atomically burns nonce /
           decrements invocations; raises
           :class:`LeaseNonceReplay` / :class:`LeaseExhausted` /
           :class:`LeaseRevoked` / :class:`LeaseExpired`;
        5. ``handler = self._handlers[lease.tool_name];
           result = handler(lease, arguments_hash)``;
        6. ``isinstance(result, str)`` check (else :class:`LeaseDenied`);
        7. return ``result``.

        Any non-:class:`LeaseDenied` exception raised inside
        ``handler`` / ``consume`` / ``verify`` is wrapped into
        :class:`LeaseDenied` so the wall stays sealed.
        """

        with self._lock:
            try:
                if self._bound_owner is None:
                    raise LeaseOwnerMismatch("sandbox owner not bound")
                if lease.tool_name not in self._handlers:
                    raise LeaseUnknownTool(f"tool not registered: {lease.tool_name!r}")
                now = self._now()
                self._authority.verify(
                    lease,
                    expected_owner=self._bound_owner,
                    expected_tool=lease.tool_name,
                    expected_scope=lease.resource_scope,
                    now=now,
                )
                self._authority.consume(lease, now=now)
                handler = self._handlers[lease.tool_name]
                result = handler(lease, arguments_hash)
                if not isinstance(result, str):
                    raise LeaseDenied(f"handler must return str, got {type(result).__name__}")
                return result
            except LeaseDenied:
                raise
            except Exception as exc:  # noqa: BLE001 fail-closed wall
                raise LeaseDenied(f"sandbox internal error: {type(exc).__name__}") from exc

    # ---- introspection helpers -----------------------------------------
    @property
    def authority(self) -> LeaseAuthority:
        """Read-only handle to the underlying :class:`LeaseAuthority`."""

        return self._authority

    def registered_tools(self) -> frozenset[str]:
        """Test helper — frozenset of currently-registered tool names."""

        with self._lock:
            return frozenset(self._handlers.keys())


__all__ = [
    "DeterministicHandler",
    "LeasedSandbox",
]
