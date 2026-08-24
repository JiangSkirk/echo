"""Outbound URL safety guard — unified SSRF protection.

Every outbound HTTP(S) request initiated on behalf of untrusted input
(``browser_fetch``, WebBridge navigation, model discovery) must pass through
:func:`resolve_and_validate` first.

The guard does NOT trust the URL's literal host.  It resolves the hostname via
``getaddrinfo`` (following CNAME chains and the OS resolver's numeric-host
shortcuts) and then validates *every* resolved address.  This is what closes
the classic bypasses:

* ``127.1`` and ``2130706433`` — not valid ``ipaddress`` literals, but the
  resolver expands them to ``127.0.0.1``.
* ``127.0.0.1.nip.io`` / ``169.254.169.254.nip.io`` — wildcard-DNS domains that
  resolve to the embedded address.
* DNS rebinding — by validating the *resolved* IPs (and letting callers pin to
  them) rather than the hostname.

Cloud metadata endpoints (``169.254.169.254`` and friends) and link-local /
reserved / multicast / unspecified / non-global (e.g. CGNAT ``100.64.0.0/10``)
ranges are ALWAYS rejected, regardless of the ``allow_loopback`` /
``allow_private`` policy flags.
"""

from __future__ import annotations

import ipaddress
import socket
import typing
from collections.abc import Callable
from typing import Protocol
from urllib.parse import urlparse

import httpcore
import httpx

__all__ = [
    "OutboundURLError",
    "resolve_and_validate",
    "is_blocked_ip",
    "PinnedIPBackend",
    "PinnedTransport",
]

# Hostnames that must never be reachable even when loopback/private is allowed.
# These resolve to link-local (169.254.0.0/16) already, but block by name too
# in case a resolver returns something unexpected.
_BLOCKED_HOSTNAMES = frozenset(
    {
        "metadata.google.internal",
        "metadata",
    }
)

# Cloud metadata service addresses (always blocked).  169.254.169.254 is also
# link-local so it is caught by the range check; listed here for clarity and to
# cover the IPv6 form used by some providers.
_METADATA_ADDRESSES = frozenset(
    {
        "169.254.169.254",
        "fd00:ec2::254",
        "100.100.100.200",  # Alibaba Cloud metadata
    }
)


class OutboundURLError(Exception):
    """Raised when an outbound URL fails the safety policy."""


class _Resolver(Protocol):
    def __call__(self, host: str, port: int | None) -> list[str]:
        """Return the list of IP address strings *host* resolves to."""
        ...


def _default_resolver(host: str, port: int | None) -> list[str]:
    """Resolve *host* to all A/AAAA addresses via the OS resolver."""
    infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    addrs: list[str] = []
    for info in infos:
        sockaddr = info[4]
        addr = str(sockaddr[0])
        if addr not in addrs:
            addrs.append(addr)
    return addrs


def is_blocked_ip(
    addr: ipaddress.IPv4Address | ipaddress.IPv6Address,
    *,
    allow_loopback: bool,
    allow_private: bool,
) -> str | None:
    """Return a rejection reason for *addr*, or ``None`` if it is permitted.

    Link-local, reserved, multicast, unspecified and known metadata addresses
    are always rejected, and so is every address that is not globally
    reachable per the IANA special-purpose registries (CGNAT ``100.64.0.0/10``
    and similar shared space are neither private nor reserved, yet must never
    be an outbound target).  Loopback and private (RFC1918 / ULA) ranges are
    rejected unless explicitly allowed by the policy flags.
    """
    # Normalize IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1) to its IPv4 form so
    # the classification below isn't bypassed via the v6 representation.
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped

    if str(addr) in _METADATA_ADDRESSES:
        return "cloud metadata address is blocked"
    if addr.is_link_local:
        return "link-local address is blocked"
    if addr.is_reserved:
        return "reserved address is blocked"
    if addr.is_multicast:
        return "multicast address is blocked"
    if addr.is_unspecified:
        return "unspecified address is blocked"
    # Loopback is checked before the generic private check because ``is_private``
    # is also True for loopback; an allowed loopback must not fall through.
    if addr.is_loopback:
        return None if allow_loopback else "loopback address is blocked"
    if addr.is_private:
        return None if allow_private else "private/internal address is blocked"
    # Fail closed on everything else that is not globally reachable per the
    # IANA special-purpose registries — e.g. the CGNAT shared address space
    # 100.64.0.0/10, which is neither private nor reserved and therefore
    # slipped past the explicit checks above.
    if not addr.is_global:
        return "non-global (shared/special-purpose) address is blocked"
    return None


def resolve_and_validate(
    url: str,
    *,
    allow_loopback: bool = False,
    allow_private: bool = False,
    resolver: Callable[[str, int | None], list[str]] | None = None,
) -> list[str]:
    """Validate *url* and return the list of safe resolved IP addresses.

    Raises :class:`OutboundURLError` if the scheme is unsupported, the host is
    missing/blocked, resolution fails, or *any* resolved address violates the
    policy (fail-closed: if one address is internal, the whole URL is rejected,
    which defeats split-horizon DNS tricks).

    The returned IP list lets callers pin the connection to a validated address
    to defeat DNS-rebinding between this check and the actual request.
    """
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        raise OutboundURLError("URL must start with http:// or https://")

    hostname = parsed.hostname
    if not hostname:
        raise OutboundURLError("URL has no host")

    from js.orin.hooks import inspect_canary_text

    blocked = inspect_canary_text(url, surface="net")
    if blocked is not None:
        raise OutboundURLError(blocked)

    host_lower = hostname.lower().rstrip(".")
    if host_lower in _BLOCKED_HOSTNAMES:
        raise OutboundURLError("metadata hostname is blocked")

    resolve = resolver or _default_resolver
    try:
        resolved = resolve(hostname, parsed.port)
    except OutboundURLError:
        raise
    except Exception as exc:  # noqa: BLE001 — resolution failure is fail-closed
        raise OutboundURLError(f"could not resolve host: {exc}") from exc

    if not resolved:
        raise OutboundURLError("host did not resolve to any address")

    validated: list[str] = []
    for ip_str in resolved:
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError as exc:
            raise OutboundURLError(f"resolver returned invalid address {ip_str!r}") from exc
        reason = is_blocked_ip(addr, allow_loopback=allow_loopback, allow_private=allow_private)
        if reason is not None:
            raise OutboundURLError(f"blocked destination ({reason})")
        validated.append(ip_str)

    return validated


# ── DNS-rebinding defense: pin connections to validated IPs ──


class PinnedIPBackend(httpcore.AsyncNetworkBackend):
    """Network backend that forces TCP connections to a pre-validated IP.

    When :func:`resolve_and_validate` returns a list of safe IPs, this backend
    ensures the *actual* TCP connection uses one of those IPs instead of
    re-resolving the hostname.  This closes the DNS-rebinding window where an
    attacker domain first resolves to a public IP (passing validation) and
    then rebinds to ``127.0.0.1`` or ``169.254.169.254`` before the HTTP
    request is made.

    The original hostname is preserved in the URL, so TLS SNI and the HTTP
    ``Host`` header remain correct — only the underlying TCP destination is
    pinned.
    """

    def __init__(
        self,
        pinned_ip: str,
        backend: httpcore.AsyncNetworkBackend | None = None,
    ) -> None:
        self.pinned_ip = pinned_ip
        # AsyncNetworkBackend is the abstract interface and raises
        # NotImplementedError on real connects.  AnyIOBackend is httpcore's
        # concrete asyncio/trio implementation; wrapping it preserves the
        # validated-IP substitution below while keeping TLS SNI/Host intact.
        self._backend = backend or httpcore.AnyIOBackend()

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: typing.Iterable[typing.Any] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        # Ignore the hostname and connect directly to the validated IP.
        # The original hostname is still used for TLS SNI and Host header
        # because the URL passed to httpx retains it.
        return await self._backend.connect_tcp(
            self.pinned_ip, port, timeout, local_address, socket_options
        )

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: typing.Iterable[typing.Any] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        return await self._backend.connect_unix_socket(path, timeout, socket_options)

    async def sleep(self, seconds: float) -> None:
        return await self._backend.sleep(seconds)


def create_pinned_transport(
    validated_ips: list[str],
    **pool_kwargs: typing.Any,
) -> httpcore.AsyncConnectionPool:
    """Create an :class:`httpcore.AsyncConnectionPool` pinned to *validated_ips*.

    The first IP in the list is used for the connection.  Callers should pass
    the returned pool as ``transport=`` to :class:`httpx.AsyncClient`.
    """
    if not validated_ips:
        raise OutboundURLError("no validated IPs to pin to")
    backend = PinnedIPBackend(validated_ips[0])
    return httpcore.AsyncConnectionPool(network_backend=backend, **pool_kwargs)


class PinnedTransport(httpx.AsyncHTTPTransport):
    """AsyncHTTPTransport that pins TCP connections to a pre-validated IP.

    Inherits from :class:`httpx.AsyncHTTPTransport` so mypy recognises it as a
    valid ``AsyncBaseTransport``.  The parent ``__init__`` is called first to
    create a default pool, then the pool is replaced with one that uses our
    :class:`PinnedIPBackend` so the TCP destination is pinned while the URL's
    original hostname is preserved for TLS SNI and the HTTP ``Host`` header.
    """

    def __init__(
        self,
        pinned_ip: str,
        **kwargs: typing.Any,
    ) -> None:
        super().__init__(**kwargs)
        # Replace the pool created by the parent with one that pins to the
        # validated IP.  We do not aclose the old pool here (__init__ is sync);
        # it will be garbage-collected and any idle connections reaped.
        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=getattr(self._pool, "_ssl_context", None),
            max_connections=getattr(self._pool, "_max_connections", None),
            max_keepalive_connections=getattr(self._pool, "_max_keepalive_connections", None),
            keepalive_expiry=getattr(self._pool, "_keepalive_expiry", None),
            http1=getattr(self._pool, "_http1", True),
            http2=getattr(self._pool, "_http2", False),
            local_address=getattr(self._pool, "_local_address", None),
            retries=getattr(self._pool, "_retries", 0),
            socket_options=getattr(self._pool, "_socket_options", None),
            network_backend=PinnedIPBackend(pinned_ip),
        )


def create_pinned_client(
    validated_ips: list[str],
    **client_kwargs: typing.Any,
) -> httpx.AsyncClient:
    """Create an :class:`httpx.AsyncClient` whose connections are pinned to
    the first validated IP.

    This is a convenience helper for the common case where a caller needs a
    one-off client with pinned transport.  For long-lived clients, use
    :class:`PinnedTransport` directly.
    """
    if not validated_ips:
        raise OutboundURLError("no validated IPs to pin to")
    return httpx.AsyncClient(transport=PinnedTransport(validated_ips[0]), **client_kwargs)
