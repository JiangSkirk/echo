"""Tiered approval system: manual, auto-approve, auto-deny, cron-deny.

Inspired by Hermes:
- Manual: interactive prompt for dangerous operations
- Gateway: async queue for WebSocket sessions
- Cron mode: deny all dangerous ops in scheduled jobs
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from js.utils.log import get_logger
from js.utils.metrics import get_metrics

logger = get_logger("js.approvals")


class ApprovalMode(StrEnum):
    MANUAL = "manual"
    AUTO_APPROVE = "auto_approve"
    AUTO_DENY = "auto_deny"
    CRON_DENY = "cron_deny"


@dataclass
class ApprovalRequest:
    id: str
    tool_name: str
    arguments: dict[str, Any]
    timestamp: float
    context: str  # "cli", "web", "cron", "subagent"
    resolved: bool = False
    approved: bool = False


class ApprovalQueue:
    """Async approval queue with session-scoped callbacks."""

    def __init__(
        self,
        default_mode: ApprovalMode = ApprovalMode.MANUAL,
        input_stream: Callable[[str], str] | None = None,
    ) -> None:
        self.default_mode = default_mode
        self._input_stream = input_stream or input
        self._pending: dict[str, ApprovalRequest] = {}
        self._callbacks: dict[str, Callable[[ApprovalRequest], bool]] = {}
        self._lock = threading.RLock()
        self._counter = 0
        self._history: dict[str, int] = {"total": 0, "approved": 0, "denied": 0}

    def _next_id(self) -> str:
        with self._lock:
            self._counter += 1
            return f"approval_{self._counter}_{int(time.time())}"

    def _record_outcome(self, approved: bool) -> None:
        with self._lock:
            self._history["total"] += 1
            if approved:
                self._history["approved"] += 1
            else:
                self._history["denied"] += 1

    def set_callback(self, session_id: str, callback: Callable[[ApprovalRequest], bool]) -> None:
        """Set an approval callback for a session (e.g., WebSocket UI)."""
        with self._lock:
            self._callbacks[session_id] = callback

    def remove_callback(self, session_id: str) -> None:
        with self._lock:
            self._callbacks.pop(session_id, None)

    def request(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        context: str = "cli",
        mode: ApprovalMode | None = None,
        session_id: str | None = None,
    ) -> bool:
        """Request approval for a dangerous operation. Returns True if approved."""
        resolved_mode = mode or self.default_mode

        if resolved_mode == ApprovalMode.AUTO_APPROVE:
            logger.info(f"Auto-approved {tool_name} (auto_approve mode)")
            self._record_outcome(True)
            try:
                get_metrics().approval_requests_total.labels(
                    tool_name=tool_name,
                    mode=resolved_mode.value,
                    outcome="approved",
                ).inc()
            except Exception:
                pass
            return True

        if resolved_mode == ApprovalMode.AUTO_DENY:
            logger.warning(f"Auto-denied {tool_name} (auto_deny mode)")
            self._record_outcome(False)
            try:
                get_metrics().approval_requests_total.labels(
                    tool_name=tool_name,
                    mode=resolved_mode.value,
                    outcome="denied",
                ).inc()
            except Exception:
                pass
            return False

        if resolved_mode == ApprovalMode.CRON_DENY and context == "cron":
            logger.warning(f"Auto-denied {tool_name} (cron_deny mode)")
            self._record_outcome(False)
            try:
                get_metrics().approval_requests_total.labels(
                    tool_name=tool_name,
                    mode=resolved_mode.value,
                    outcome="denied",
                ).inc()
            except Exception:
                pass
            return False

        # MANUAL mode: check for callback or block
        req = ApprovalRequest(
            id=self._next_id(),
            tool_name=tool_name,
            arguments=arguments,
            timestamp=time.time(),
            context=context,
        )

        with self._lock:
            self._pending[req.id] = req

        # Try session callback first
        if session_id and session_id in self._callbacks:
            try:
                approved = self._callbacks[session_id](req)
                req.resolved = True
                req.approved = approved
                self._record_outcome(approved)
                with self._lock:
                    self._pending.pop(req.id, None)
                try:
                    get_metrics().approval_requests_total.labels(
                        tool_name=tool_name,
                        mode=resolved_mode.value,
                        outcome="approved" if approved else "denied",
                    ).inc()
                except Exception:
                    pass
                return approved
            except Exception as e:
                logger.error(f"Approval callback failed: {e}")

        # CLI fallback: synchronous prompt
        if context == "cli":
            approved = self._cli_prompt(req)
            self._record_outcome(approved)
            with self._lock:
                self._pending.pop(req.id, None)
            try:
                get_metrics().approval_requests_total.labels(
                    tool_name=tool_name,
                    mode=resolved_mode.value,
                    outcome="approved" if approved else "denied",
                ).inc()
            except Exception:
                pass
            return approved

        # No callback and not CLI: deny for safety
        logger.warning(f"No approval handler for {tool_name}, defaulting to deny")
        req.resolved = True
        req.approved = False
        self._record_outcome(False)
        with self._lock:
            self._pending.pop(req.id, None)
        try:
            get_metrics().approval_requests_total.labels(
                tool_name=tool_name,
                mode=resolved_mode.value,
                outcome="denied",
            ).inc()
        except Exception:
            pass
        return False

    def _cli_prompt(self, req: ApprovalRequest) -> bool:
        """Synchronous CLI prompt for approval."""
        try:
            args_str = ", ".join(f"{k}={v!r}" for k, v in req.arguments.items())
            prompt_text = f"\n[Approval] {req.tool_name}({args_str})\nApprove? [y/N]: "
            response = self._input_stream(prompt_text).strip().lower()
            approved = response in ("y", "yes")
            req.resolved = True
            req.approved = approved
            return approved
        except (EOFError, KeyboardInterrupt):
            req.resolved = True
            req.approved = False
            return False

    def resolve(self, request_id: str, approved: bool) -> bool:
        """Resolve a pending approval request (e.g., from Web UI)."""
        with self._lock:
            req = self._pending.get(request_id)
            if req and not req.resolved:
                req.resolved = True
                req.approved = approved
                self._record_outcome(approved)
                self._pending.pop(request_id, None)
                return True
        return False

    def get_pending(self) -> list[ApprovalRequest]:
        """Get all unresolved approval requests."""
        with self._lock:
            return [r for r in self._pending.values() if not r.resolved]

    def get_stats(self) -> dict[str, Any]:
        with self._lock:
            pending_count = sum(1 for r in self._pending.values() if not r.resolved)
            return {
                "total_requests": self._history["total"],
                "resolved": self._history["approved"] + self._history["denied"],
                "approved": self._history["approved"],
                "denied": self._history["denied"],
                "pending": pending_count,
            }
