"""macOS Desktop Control Module.
# noqa: F401 (public API re-export)

Provides screenshot, mouse/keyboard, and application/window management
with safety-first design:
  - Default OBSERVE mode (read-only)
  - CONFIRM mode with user approval for all writes
  - Emergency stop
  - Operation logging

Requires macOS with Accessibility and Screen Recording permissions.
Requires `cliclick` (brew install cliclick).

Example:
    from js.tools.desktop import DesktopGuard, DesktopMode
    guard = DesktopGuard(mode=DesktopMode.CONFIRM, approval_queue=queue)
    result = await guard.screenshot()
    result = await guard.mouse_click(point=Point(x=100, y=200))
"""

from __future__ import annotations

from .controller import DesktopController
from .controller_native import NativeDesktopBackend
from .guard import DesktopGuard, EmergencyStopError
from .permissions import PermissionChecker
from .types import (
    AppAction,
    AppInfo,
    DesktopMode,
    KeyModifier,
    MouseButton,
    OperationLogEntry,
    Point,
    ScreenRegion,
    ScrollDirection,
    WindowAction,
    WindowInfo,
)

__all__ = [
    "DesktopController",
    "DesktopGuard",
    "DesktopMode",
    "EmergencyStopError",
    "NativeDesktopBackend",
    "PermissionChecker",
    "AppAction",
    "AppInfo",
    "KeyModifier",
    "MouseButton",
    "OperationLogEntry",
    "Point",
    "ScreenRegion",
    "ScrollDirection",
    "WindowAction",
    "WindowInfo",
]
