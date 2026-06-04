"""Type definitions for desktop control module."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class DesktopMode(StrEnum):
    """Desktop control safety mode."""

    OBSERVE = "observe"  # Read-only, all write actions are denied
    CONFIRM = "confirm"  # Each write action requires user confirmation
    AUTO = "auto"  # Not implemented (intentionally disabled)


class MouseButton(StrEnum):
    LEFT = "left"
    RIGHT = "right"
    MIDDLE = "middle"


class KeyModifier(StrEnum):
    CMD = "cmd"
    OPTION = "option"
    CTRL = "ctrl"
    SHIFT = "shift"
    FN = "fn"


class AppAction(StrEnum):
    OPEN = "open"
    ACTIVATE = "activate"
    QUIT = "quit"
    LIST = "list"


class WindowAction(StrEnum):
    LIST = "list"
    ACTIVATE = "activate"
    MOVE = "move"
    RESIZE = "resize"


class ScrollDirection(StrEnum):
    UP = "up"
    DOWN = "down"
    LEFT = "left"
    RIGHT = "right"


@dataclass
class ScreenRegion:
    x: int
    y: int
    width: int
    height: int

    def to_args(self) -> str:
        return f"-R{self.x},{self.y},{self.width},{self.height}"


@dataclass
class Point:
    x: int
    y: int


@dataclass
class WindowInfo:
    title: str
    app_name: str
    bounds: ScreenRegion
    index: int


@dataclass
class AppInfo:
    name: str
    pid: int | None
    active: bool


@dataclass
class OperationLogEntry:
    timestamp: float
    action: str
    details: dict[str, Any]
    approved: bool
    confirmed_by: str
    session_id: str
    screenshot_before: str | None = None
    screenshot_after: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "action": self.action,
            "details": self.details,
            "approved": self.approved,
            "confirmed_by": self.confirmed_by,
            "session_id": self.session_id,
            "screenshot_before": self.screenshot_before,
            "screenshot_after": self.screenshot_after,
        }
