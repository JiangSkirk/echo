"""orind — the Orin gatekeeper daemon (Stage A).

Runs as a separate process holding the lease MAC key. Echo keeps executing
tools in-process; orind stamps (issues / consumes / revokes) every lease.
Stage A claims model-layer hardening only — never process-RCE containment.
"""

from __future__ import annotations

__all__ = ["canary", "daemon", "gatekeeper", "keybox", "patrol", "responder", "store"]
