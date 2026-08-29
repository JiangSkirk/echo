"""Public capability-lease constants."""

from __future__ import annotations

from typing import Final

DEFAULT_NETWORK_POLICY: Final[str] = "deny"
"""Default network policy attached to a lease when the caller omits one."""

LEASE_MAC_DOMAIN: Final[bytes] = b"echo-capability-lease-v1:"
"""Domain separator prefixed to every lease MAC pre-image."""

LEASE_MAC_PREFIX: Final[str] = "authority-hmac-sha256:"
"""String form of a legacy lease MAC (default v2 fields)."""

LEASE_MAC_PREFIX_V2: Final[str] = "authority-hmac-sha256-v2:"
"""String form of a lease MAC covering the Orin v2 extension fields."""

DEFAULT_TAINT_FLOOR: Final[int] = 0xFFFFFFFFFFFFFFFF
DEFAULT_TAINT_SINK: Final[int] = 0
DEFAULT_SANDBOX_PROFILE: Final[int] = 0
DEFAULT_CLEARANCE: Final[int] = 1
"""Orin v2 extension defaults (D appendix D.2); all-default = legacy MAC."""

TOOL_CONTEXT_MAC_DOMAIN: Final[bytes] = b"echo-tool-execution-context-v1:"
"""Domain separator for signed registry execution contexts."""
