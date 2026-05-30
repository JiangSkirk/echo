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
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from js.utils.log import get_logger
from js.utils.metrics import get_metrics

logger = get_logger("js.approvals")

DEFAULT_APPROVAL_TIMEOUT = 300.0  # 5 minutes


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
    timeout_seconds: float = field(default=DEFAULT_APPROVAL_TIMEOUT)
    resolved: bool = False
    approved: bool = False

    def is_expired(self) -> bool:
        return time.time() - self.timestamp > self.timeout_seconds


class ApprovalQueue:
    """Async approval queue with session-scoped callbacks."""

    def __init__(
        self,
        default_mode: ApprovalMode = ApprovalMode.MANUAL,
        input_stream: Callable[[str], str] | None = None,
        default_timeout: float = DEFAULT_APPROVAL_TIMEOUT,
    ) -> None:
        self.default_mode = default_mode
        self._input_stream = input_stream or input
        self._default_timeout = default_timeout
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

    def _emit_metrics(
        self,
        tool_name: str,
        mode: ApprovalMode,
        approved: bool,
    ) -> None:
        try:
            get_metrics().approval_requests_total.labels(
                tool_name=tool_name,
                mode=mode.value,
                outcome="approved" if approved else "denied",
            ).inc()
        except Exception:
            logger.warning("Failed to emit approval metrics", exc_info=True)

    def _audit_log(
        self,
        req: ApprovalRequest,
        outcome: str,
        reason: str = "",
    ) -> None:
        elapsed = time.time() - req.timestamp
        logger.info(
            "AUDIT approval_id=%s tool=%s context=%s mode=%s outcome=%s elapsed=%.2fs %s",
            req.id,
            req.tool_name,
            req.context,
            self.default_mode.value,
            outcome,
            elapsed,
            f"reason={reason}" if reason else "",
        )

    def _cleanup_stale(self) -> int:
        """Remove expired pending requests. Returns count removed."""
        removed = 0
        with self._lock:
            stale_ids = [
                req_id for req_id, req in self._pending.items()
                if not req.resolved and req.is_expired()
            ]
            for req_id in stale_ids:
                req = self._pending.pop(req_id)
                req.resolved = True
                self._record_outcome(False)
                self._audit_log(req, "expired", "timeout")
                self._emit_metrics(req.tool_name, self.default_mode, False)
                removed += 1
        if removed:
            logger.warning("Cleaned up %d stale approval requests", removed)
        return removed

    def set_callback(self, session_id: str, callback: Callable[[ApprovalRequest], bool]) -> None:
        """Set an approval callback for a session (e.g., WebSocket UI)."""
        with self._lock:
            self._callbacks[session_id] = callback

    def remove_callback(self, session_id: str) -> None:
        """Remove a session callback."""
        with self._lock:
            self._callbacks.pop(session_id, None)

    def request(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        context: str = "cli",
        mode: ApprovalMode | None = None,
        session_id: str | None = None,
        timeout_seconds: float | None = None,
    ) -> bool:
        """Request approval for a dangerous operation. Returns True if approved."""
        # Periodic cleanup of stale requests
        self._cleanup_stale()

        resolved_mode = mode or self.default_mode

        if resolved_mode == ApprovalMode.AUTO_APPROVE:
            logger.info("Auto-approved %s (auto_approve mode)", tool_name)
            self._record_outcome(True)
            self._emit_metrics(tool_name, resolved_mode, True)
            return True

        if resolved_mode == ApprovalMode.AUTO_DENY:
            logger.warning("Auto-denied %s (auto_deny mode)", tool_name)
            self._record_outcome(False)
            self._emit_metrics(tool_name, resolved_mode, False)
            return False

        if resolved_mode == ApprovalMode.CRON_DENY and context == "cron":
            logger.warning("Auto-denied %s (cron_deny mode)", tool_name)
            self._record_outcome(False)
            self._emit_metrics(tool_name, resolved_mode, False)
            return False

        # MANUAL mode: check for callback or block
        req = ApprovalRequest(
            id=self._next_id(),
            tool_name=tool_name,
            arguments=arguments,
            timestamp=time.time(),
            context=context,
            timeout_seconds=timeout_seconds or self._default_timeout,
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
                self._emit_metrics(tool_name, resolved_mode, approved)
                self._audit_log(req, "approved" if approved else "denied", "callback")
                return approved
            except Exception as e:
                logger.error("Approval callback failed: %s", e)

        # CLI fallback: synchronous prompt
        if context == "cli":
            approved = self._cli_prompt(req)
            self._record_outcome(approved)
            with self._lock:
                self._pending.pop(req.id, None)
            self._emit_metrics(tool_name, resolved_mode, approved)
            self._audit_log(req, "approved" if approved else "denied", "cli_prompt")
            return approved

        # No callback and not CLI: deny for safety
        logger.warning("No approval handler for %s, defaulting to deny", tool_name)
        req.resolved = True
        req.approved = False
        self._record_outcome(False)
        with self._lock:
            self._pending.pop(req.id, None)
        self._emit_metrics(tool_name, resolved_mode, False)
        self._audit_log(req, "denied", "no_handler")
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
                # Reject resolution of expired requests
                if req.is_expired():
                    logger.warning(
                        "Attempted to resolve expired approval request %s", request_id
                    )
                    req.resolved = True
                    req.approved = False
                    self._record_outcome(False)
                    self._pending.pop(request_id, None)
                    self._audit_log(req, "expired", "late_resolution")
                    self._emit_metrics(req.tool_name, self.default_mode, False)
                    return False
                req.resolved = True
                req.approved = approved
                self._record_outcome(approved)
                self._pending.pop(request_id, None)
                self._emit_metrics(req.tool_name, self.default_mode, approved)
                self._audit_log(req, "approved" if approved else "denied", "resolved")
                return True
        return False

    def get_pending(self) -> list[ApprovalRequest]:
        """Get all unresolved approval requests."""
        self._cleanup_stale()
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
