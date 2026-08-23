"""Orin client package (main-process side of the orin/v1 protocol).

Orin is the Stage A gatekeeper: Echo keeps doing the work, Orin stamps the
passes. This package never holds lease MAC keys; all authoritative decisions
happen inside the ``orind`` daemon over a Unix domain socket.
"""

from __future__ import annotations

__all__ = ["protocol", "client", "receipts", "testing"]
