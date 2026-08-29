"""Canonical lease MAC encoding (capability-permit domain only)."""

from __future__ import annotations

import hashlib
import hmac
from typing import Any

from js.echo.capability_constants import (
    DEFAULT_CLEARANCE,
    DEFAULT_SANDBOX_PROFILE,
    DEFAULT_TAINT_FLOOR,
    DEFAULT_TAINT_SINK,
    LEASE_MAC_DOMAIN,
    LEASE_MAC_PREFIX,
    LEASE_MAC_PREFIX_V2,
    TOOL_CONTEXT_MAC_DOMAIN,
)
from js.echo.types import CapabilityLease


def _enc_u64_be(value: int) -> bytes:
    """Encode an unsigned 64-bit integer in big-endian byte order."""

    return int(value).to_bytes(8, "big", signed=False)


def _enc_u32_be(value: int) -> bytes:
    """Encode an unsigned 32-bit integer in big-endian byte order."""

    return int(value).to_bytes(4, "big", signed=False)


def _enc_str(text: str) -> bytes:
    """Encode a UTF-8 string as a length-prefixed byte sequence."""

    payload = text.encode("utf-8")
    return _enc_u32_be(len(payload)) + payload


def _enc_tuple_str(items: tuple[str, ...]) -> bytes:
    """Encode a tuple of strings as a length-prefixed sequence of length-prefixed UTF-8 strings."""

    parts = [_enc_u32_be(len(items))]
    parts.extend(_enc_str(item) for item in items)
    return b"".join(parts)


def _enc_opt_str(value: str | None) -> bytes:
    """Encode an optional string as ``\\x00`` (None) or ``\\x01`` + length-prefixed UTF-8."""

    if value is None:
        return b"\x00"
    return b"\x01" + _enc_str(value)


def _canonical_lease_payload(lease: CapabilityLease) -> bytes:
    """Return the canonical, domain-separated MAC pre-image for ``lease``.

    The lease's ``mac`` field is *not* part of the pre-image: only the
    other 14 fields participate, in the order documented in Echo spec §4.
    The returned bytes already include the
    :data:`LEASE_MAC_DOMAIN` prefix; callers should feed them directly
    into HMAC.

    Orin compat red line: these bytes are frozen. The v2 extension fields
    (``taint_floor`` / ``taint_sink`` / ``sandbox_profile`` / ``clearance``)
    are NEVER part of this pre-image; they ride in
    :func:`_canonical_lease_payload_v2` appended after the legacy block.
    """

    return b"".join(
        (
            LEASE_MAC_DOMAIN,
            _enc_str(lease.lease_id),
            _enc_str(lease.product_id),
            _enc_str(lease.owner_key_hash),
            _enc_str(lease.session_id),
            _enc_str(lease.run_id),
            _enc_str(lease.tool_name),
            _enc_str(lease.args_schema),
            _enc_str(lease.resource_scope),
            _enc_tuple_str(lease.fs_roots),
            _enc_str(lease.network_policy),
            _enc_tuple_str(lease.network_hosts),
            _enc_u64_be(lease.max_bytes),
            _enc_u64_be(lease.max_duration_ms),
            _enc_u32_be(lease.max_invocations),
            _enc_str(lease.nonce),
            _enc_u64_be(lease.expires_at),
            _enc_opt_str(lease.parent_lease_id),
        )
    )


def _lease_v2_fields_nondefault(lease: CapabilityLease) -> bool:
    """True when any Orin v2 extension field deviates from its default."""

    return (
        lease.taint_floor != DEFAULT_TAINT_FLOOR
        or lease.taint_sink != DEFAULT_TAINT_SINK
        or lease.sandbox_profile != DEFAULT_SANDBOX_PROFILE
        or lease.clearance != DEFAULT_CLEARANCE
    )


def _canonical_lease_payload_v2(lease: CapabilityLease) -> bytes:
    """v2 MAC pre-image: the frozen legacy block plus four appended fields.

    Only used when :func:`_lease_v2_fields_nondefault` is true; the legacy
    pre-image is byte-identical for default-valued leases either way.
    """

    return b"".join(
        (
            _canonical_lease_payload(lease),
            _enc_u64_be(lease.taint_floor),
            _enc_u64_be(lease.taint_sink),
            _enc_u64_be(lease.sandbox_profile),
            _enc_u64_be(lease.clearance),
        )
    )


def lease_mac_tag(lease: CapabilityLease) -> str:
    """Prefixed string form of a lease MAC (``authority-hmac-sha256[:v2:]…``)."""

    prefix = LEASE_MAC_PREFIX_V2 if _lease_v2_fields_nondefault(lease) else LEASE_MAC_PREFIX
    return prefix + lease.mac.hex()


def _tool_context_payload(context: Any) -> bytes:
    """Canonical payload for an Echo tool execution context."""

    fs_roots = tuple(str(item) for item in getattr(context, "fs_roots", ()))
    return b"".join(
        (
            TOOL_CONTEXT_MAC_DOMAIN,
            _enc_str(str(getattr(context, "product_id", ""))),
            _enc_str(str(getattr(context, "owner_key_hash", ""))),
            _enc_str(str(getattr(context, "session_id", ""))),
            _enc_str(str(getattr(context, "run_id", ""))),
            _enc_str(str(getattr(context, "profile", ""))),
            _enc_str(str(getattr(context, "tool_name", ""))),
            _enc_str(str(getattr(context, "args_hash", ""))),
            _enc_str(str(getattr(context, "resource_scope", ""))),
            _enc_tuple_str(fs_roots),
            _enc_str(str(getattr(context, "network_policy", ""))),
            _enc_tuple_str(tuple(str(item) for item in getattr(context, "network_hosts", ()))),
            _enc_u64_be(int(getattr(context, "max_bytes", 0))),
            _enc_u64_be(int(getattr(context, "max_duration_ms", 0))),
            _enc_str(str(getattr(context, "lease_id", ""))),
            _enc_str(str(getattr(context, "lease_mac", ""))),
        )
    )


def compute_lease_mac(mac_key: bytes, lease: CapabilityLease) -> bytes:
    """Compute the HMAC-SHA-256 MAC tag for ``lease`` under ``mac_key``.

    The lease's own ``mac`` field is ignored; only the non-MAC fields
    contribute to the pre-image. Pre-image dispatch (Orin v2): leases
    whose four extension fields are all default use the frozen legacy
    pre-image byte-for-byte; any non-default extension field switches to
    the v2 pre-image (legacy block + appended fields), matching the
    ``authority-hmac-sha256-v2:`` string prefix in :func:`lease_mac_tag`.
    Returns 32 raw bytes.
    """

    payload = (
        _canonical_lease_payload_v2(lease)
        if _lease_v2_fields_nondefault(lease)
        else _canonical_lease_payload(lease)
    )
    digest = hmac.new(mac_key, digestmod=hashlib.sha256)
    digest.update(payload)
    return digest.digest()
