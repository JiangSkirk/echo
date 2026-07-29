"""Echo 2.0 primary runtime package.

The canonical shared primitives live in :mod:`js.echo.primitives`. Pure kernel
modules stay independent from web, model, tool, memory, and legacy agent
packages; integration happens at explicit adapters such as the Echo turn
runtime and the safety ledger service.

The Echo package is the public architecture surface. ``FrameLedger`` remains a
public contract name, but it is an alias of the sole durable implementation,
``FileEchoLedger``. There is no compatibility ledger or alternate recovery path.
"""

from __future__ import annotations

from js.echo.ledger.journal import (
    CommitRecord as FrameRecord,
)
from js.echo.ledger.journal import (
    FileEchoLedger as FrameLedger,
)
from js.echo.ledger.journal import (
    VerificationReport as FrameLedgerHealth,
)
from js.echo.primitives import (
    ECHO_2_ARCHITECTURE,
    BudgetClock,
    BudgetLimits,
    BudgetReservation,
    BudgetSnapshot,
    ContextSelection,
    ContextVault,
    ScopeGate,
    ScopePermit,
    ScopeRequest,
    stable_payload_hash,
)

__all__ = [
    "ECHO_2_ARCHITECTURE",
    "BudgetClock",
    "BudgetLimits",
    "BudgetReservation",
    "BudgetSnapshot",
    "ContextSelection",
    "ContextVault",
    "FrameLedger",
    "FrameLedgerHealth",
    "FrameRecord",
    "ScopeGate",
    "ScopePermit",
    "ScopeRequest",
    "amber",
    "core",
    "spi",
    "stable_payload_hash",
    "tide",
    "types",
    "wheel",
]
