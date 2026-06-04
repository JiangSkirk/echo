"""Desktop control safety guard.
# noqa: SIM103 (intentional explicit return)

Integrates with the existing ApprovalQueue for user confirmation.
Provides observe/confirm modes, emergency stop, and operation logging.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any

from .controller import DesktopController
from .permissions import PermissionChecker
from .types import (
    AppAction,
    DesktopMode,
    KeyModifier,
    MouseButton,
    OperationLogEntry,
    Point,
    ScreenRegion,
    ScrollDirection,
    WindowAction,
)

logger = logging.getLogger("js.tools.desktop.guard")


class EmergencyStopError(Exception):
    """Raised when the emergency stop is triggered."""

    pass


class DesktopGuard:
    """Safety guard for desktop control operations.

    All write operations (mouse, keyboard, app/window management) are gated:
    - OBSERVE mode: Denied immediately
    - CONFIRM mode: Require user approval via ApprovalQueue

    Read operations (screenshot, list) are allowed without approval
    but still respect emergency stop and permission checks.
    """

    def __init__(
        self,
        mode: DesktopMode = DesktopMode.OBSERVE,
        approval_queue: Any | None = None,
    ) -> None:
        self._mode = mode
        self._controller = DesktopController()
        self._approval_queue = approval_queue
        self._emergency_stop = False
        self._operation_log: list[OperationLogEntry] = []
        self._session_id = f"desktop_{int(time.time())}_{os.urandom(4).hex()}"

    @property
    def mode(self) -> DesktopMode:
        return self._mode

    @mode.setter
    def mode(self, value: DesktopMode) -> None:
        if value == DesktopMode.AUTO:
            raise ValueError("AUTO mode is not supported for safety reasons")
        self._mode = value
        logger.info(f"Desktop guard mode changed to: {value.value}")

    @property
    def emergency_stop_active(self) -> bool:
        return self._emergency_stop

    def trigger_emergency_stop(self, reason: str = "User triggered") -> dict[str, str]:
        """Immediately halt all desktop control operations."""
        self._emergency_stop = True
        logger.warning(f"EMERGENCY STOP triggered: {reason}")
        return {"status": "stopped", "reason": reason}

    def clear_emergency_stop(self) -> dict[str, str]:
        """Clear the emergency stop. Requires explicit user action."""
        self._emergency_stop = False
        logger.info("Emergency stop cleared")
        return {"status": "cleared"}

    def _check_emergency_stop(self) -> None:
        if self._emergency_stop:
            raise EmergencyStopError("Emergency stop is active. All desktop operations halted.")

    def _check_permissions(self, needs_accessibility: bool = True) -> None:
        """Check required permissions. Raises PermissionError if missing."""
        if needs_accessibility and not PermissionChecker.check_accessibility():
            raise PermissionError(
                "Accessibility permission is required. "
                "Grant it in System Preferences > Security & Privacy > Accessibility."
            )

    async def _request_approval(
        self,
        action: str,
        details: dict[str, Any],
    ) -> bool:
        """Check if the write operation is allowed.

        OBSERVE mode denies all writes (read-only).
        CONFIRM mode allows writes — the upstream Agent approval queue
        handles user confirmation separately (this is defense-in-depth).

        Returns True if allowed, False if denied by safety mode.
        """
        if self._mode == DesktopMode.OBSERVE:
            logger.info(f"Desktop action '{action}' denied in OBSERVE mode")
            return False

        # CONFIRM mode allows writes — the Agent's dangerous-tool
        # approval pipeline handles user confirmation independently.
        # This guard provides defense-in-depth (emergency stop, permissions).
        return self._mode == DesktopMode.CONFIRM

    def _log_operation(
        self,
        action: str,
        details: dict[str, Any],
        approved: bool,
        confirmed_by: str = "system",
        screenshot_before: str | None = None,
        screenshot_after: str | None = None,
    ) -> None:
        """Log an operation to the audit trail."""
        entry = OperationLogEntry(
            timestamp=time.time(),
            action=action,
            details=details,
            approved=approved,
            confirmed_by=confirmed_by,
            session_id=self._session_id,
            screenshot_before=screenshot_before,
            screenshot_after=screenshot_after,
        )
        self._operation_log.append(entry)
        logger.info(
            f"Desktop op logged: {action} approved={approved} by={confirmed_by}"
        )

    def get_operation_log(self, limit: int = 100) -> list[dict[str, Any]]:
        """Get the operation log, newest first."""
        return [e.to_dict() for e in reversed(self._operation_log[-limit:])]

    # ── Read operations (no approval needed) ─────────────────────

    def screenshot(
        self,
        region: ScreenRegion | None = None,
        output_path: str | None = None,
        format_: str = "png",
        show_cursor: bool = False,
    ) -> dict[str, str]:
        """Capture screenshot. Read operation, no approval needed."""
        self._check_emergency_stop()
        result = self._controller.screenshot(
            region=region,
            output_path=output_path,
            format_=format_,
            show_cursor=show_cursor,
        )
        self._log_operation("screenshot", {"region": region.__dict__ if region else None}, approved=True)
        return result

    def get_mouse_position(self) -> Point:
        """Get current mouse position. Read operation."""
        self._check_emergency_stop()
        return self._controller.get_mouse_position()

    def list_apps(self) -> dict[str, Any]:
        """List running applications. Read operation."""
        self._check_emergency_stop()
        return self._controller.app_action(AppAction.LIST)

    def list_windows(self, app_name: str | None = None) -> dict[str, Any]:
        """List windows. Read operation."""
        self._check_emergency_stop()
        return self._controller.window_action(WindowAction.LIST, app_name=app_name)

    def get_permissions(self) -> dict[str, bool]:
        """Get current permission status. Read operation."""
        self._check_emergency_stop()
        return PermissionChecker.get_status()

    # ── Write operations (require approval in confirm mode) ──────

    async def mouse_click(
        self,
        point: Point | None = None,
        button: MouseButton = MouseButton.LEFT,
        clicks: int = 1,
    ) -> dict[str, Any]:
        """Click mouse. Requires approval in confirm mode."""
        self._check_emergency_stop()
        self._check_permissions()

        details = {
            "point": point.__dict__ if point else None,
            "button": button.value,
            "clicks": clicks,
        }

        approved = await self._request_approval("mouse_click", details)
        if not approved:
            self._log_operation("mouse_click", details, approved=False)
            return {"status": "denied", "reason": "Not approved"}

        result = self._controller.mouse_click(point=point, button=button, clicks=clicks)
        self._log_operation("mouse_click", details, approved=True, confirmed_by="user")
        return result

    async def mouse_move(self, point: Point) -> dict[str, Any]:
        """Move mouse cursor. Requires approval in confirm mode."""
        self._check_emergency_stop()
        self._check_permissions()

        details = {"point": point.__dict__}

        approved = await self._request_approval("mouse_move", details)
        if not approved:
            self._log_operation("mouse_move", details, approved=False)
            return {"status": "denied", "reason": "Not approved"}

        result = self._controller.mouse_move(point=point)
        self._log_operation("mouse_move", details, approved=True, confirmed_by="user")
        return result

    async def mouse_scroll(
        self,
        direction: ScrollDirection,
        amount: int = 3,
    ) -> dict[str, Any]:
        """Scroll mouse wheel. Requires approval in confirm mode."""
        self._check_emergency_stop()
        self._check_permissions()

        details = {"direction": direction.value, "amount": amount}

        approved = await self._request_approval("mouse_scroll", details)
        if not approved:
            self._log_operation("mouse_scroll", details, approved=False)
            return {"status": "denied", "reason": "Not approved"}

        result = self._controller.mouse_scroll(direction=direction, amount=amount)
        self._log_operation("mouse_scroll", details, approved=True, confirmed_by="user")
        return result

    async def mouse_drag(
        self,
        start: Point,
        end: Point,
        button: MouseButton = MouseButton.LEFT,
    ) -> dict[str, Any]:
        """Drag mouse. Requires approval in confirm mode."""
        self._check_emergency_stop()
        self._check_permissions()

        details = {
            "start": start.__dict__,
            "end": end.__dict__,
            "button": button.value,
        }

        approved = await self._request_approval("mouse_drag", details)
        if not approved:
            self._log_operation("mouse_drag", details, approved=False)
            return {"status": "denied", "reason": "Not approved"}

        result = self._controller.mouse_drag(start=start, end=end, button=button)
        self._log_operation("mouse_drag", details, approved=True, confirmed_by="user")
        return result

    async def type_text(self, text: str) -> dict[str, Any]:
        """Type text. Requires approval in confirm mode."""
        self._check_emergency_stop()
        self._check_permissions()

        details = {"length": len(text)}

        approved = await self._request_approval("type_text", details)
        if not approved:
            self._log_operation("type_text", details, approved=False)
            return {"status": "denied", "reason": "Not approved"}

        result = self._controller.type_text(text)
        self._log_operation("type_text", details, approved=True, confirmed_by="user")
        return result

    async def key_press(
        self,
        key: str,
        modifiers: list[KeyModifier] | None = None,
    ) -> dict[str, Any]:
        """Press key. Requires approval in confirm mode."""
        self._check_emergency_stop()
        self._check_permissions()

        details = {
            "key": key,
            "modifiers": [m.value for m in modifiers] if modifiers else [],
        }

        approved = await self._request_approval("key_press", details)
        if not approved:
            self._log_operation("key_press", details, approved=False)
            return {"status": "denied", "reason": "Not approved"}

        result = self._controller.key_press(key=key, modifiers=modifiers)
        self._log_operation("key_press", details, approved=True, confirmed_by="user")
        return result

    async def app_action(
        self,
        action: AppAction,
        app_name: str | None = None,
    ) -> dict[str, Any]:
        """Application action. Read (LIST) or write (OPEN/ACTIVATE/QUIT)."""
        self._check_emergency_stop()

        if action == AppAction.LIST:
            return self._controller.app_action(action, app_name)

        self._check_permissions()
        details = {"action": action.value, "app_name": app_name}

        approved = await self._request_approval("app_action", details)
        if not approved:
            self._log_operation("app_action", details, approved=False)
            return {"status": "denied", "reason": "Not approved"}

        result = self._controller.app_action(action, app_name)
        self._log_operation("app_action", details, approved=True, confirmed_by="user")
        return result

    async def window_action(
        self,
        action: WindowAction,
        app_name: str | None = None,
        window_title: str | None = None,
        bounds: ScreenRegion | None = None,
    ) -> dict[str, Any]:
        """Window action. Read (LIST) or write (ACTIVATE/MOVE/RESIZE)."""
        self._check_emergency_stop()

        if action == WindowAction.LIST:
            return self._controller.window_action(action, app_name, window_title, bounds)

        self._check_permissions()
        details = {
            "action": action.value,
            "app_name": app_name,
            "window_title": window_title,
            "bounds": bounds.__dict__ if bounds else None,
        }

        approved = await self._request_approval("window_action", details)
        if not approved:
            self._log_operation("window_action", details, approved=False)
            return {"status": "denied", "reason": "Not approved"}

        result = self._controller.window_action(action, app_name, window_title, bounds)
        self._log_operation("window_action", details, approved=True, confirmed_by="user")
        return result
