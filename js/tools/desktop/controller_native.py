# mypy: ignore-errors
"""Native macOS desktop backend using PyObjC Quartz CGEvent.
# noqa: E701, F401, N813 (intentional concise fallback + public API)

No cliclick dependency required — uses macOS native APIs via Python:
- Mouse: Quartz CGEvent (click, move, drag, scroll)
- Keyboard: Quartz CGEvent (type text, key press)
- Screenshot: screencapture CLI (built-in macOS)
- App/Window: osascript / AppleScript (built-in macOS)

Fallback: If PyObjC is not installed, falls back to cliclick/screencapture/osascript.
"""

from __future__ import annotations

import logging
import subprocess
import time
from typing import Any

from .types import (
    AppInfo,
    Point,
    ScreenRegion,
    WindowInfo,
)

logger = logging.getLogger("js.tools.desktop.controller_native")


# ── PyObjC availability ──

_QUARTZ_AVAILABLE = False
_CG_EVENT = None
_CG_POINT = None
_kCGEventSourceStateHIDSystemState = None
_kCGHIDEventTap = None
_kCGMouseButtonLeft = None
_kCGMouseButtonRight = None
_kCGMouseButtonCenter = None
_kCGEventLeftMouseDown = None
_kCGEventLeftMouseUp = None
_kCGEventRightMouseDown = None
_kCGEventRightMouseUp = None
_kCGEventOtherMouseDown = None
_kCGEventOtherMouseUp = None
_kCGEventMouseMoved = None
_kCGEventLeftMouseDragged = None
_kCGEventRightMouseDragged = None
_kCGEventOtherMouseDragged = None
_kCGEventScrollWheel = None
_kCGEventKeyDown = None
_kCGEventKeyUp = None
_kCGEventFlagsChanged = None
_kCGEventFlagMaskCommand = None
_kCGEventFlagMaskShift = None
_kCGEventFlagMaskAlternate = None
_kCGEventFlagMaskControl = None
_kCGEventFlagMaskFn = None
_kCGMouseEventClickState = None
_kCGKeyboardEventKeycode = None
_kCGScrollWheelEventDeltaAxis1 = None
_kCGScrollWheelEventDeltaAxis2 = None
_CGEventPost = None
_CGEventCreateMouseEvent = None
_CGEventCreateKeyboardEvent = None
_CGEventSetIntegerValueField = None
_CGWarpMouseCursorPosition_fn = None
_CGEventSourceCreate = None
_kVK_Space = None
_kVK_Return = None
_kVK_Tab = None
_kVK_Delete = None
_kVK_Escape = None
_kVK_UpArrow = None
_kVK_DownArrow = None
_kVK_LeftArrow = None
_kVK_RightArrow = None


# ruff: noqa: N816 (Apple CGEvent API constants)
def _init_quartz() -> None:
    """Lazy-init Quartz constants. Done once on first use."""
    global _QUARTZ_AVAILABLE, _CG_EVENT, _CG_POINT, \
        _kCGEventSourceStateHIDSystemState, _kCGHIDEventTap, \
        _kCGMouseButtonLeft, _kCGMouseButtonRight, _kCGMouseButtonCenter, \
        _kCGEventLeftMouseDown, _kCGEventLeftMouseUp, \
        _kCGEventRightMouseDown, _kCGEventRightMouseUp, \
        _kCGEventOtherMouseDown, _kCGEventOtherMouseUp, \
        _kCGEventMouseMoved, _kCGEventLeftMouseDragged, \
        _kCGEventRightMouseDragged, _kCGEventOtherMouseDragged, \
        _kCGEventScrollWheel, _kCGEventKeyDown, _kCGEventKeyUp, \
        _kCGEventFlagsChanged, \
        _kCGEventFlagMaskCommand, _kCGEventFlagMaskShift, \
        _kCGEventFlagMaskAlternate, _kCGEventFlagMaskControl, \
        _kCGEventFlagMaskFn, \
        _kCGMouseEventClickState, _kCGKeyboardEventKeycode, \
        _kCGScrollWheelEventDeltaAxis1, _kCGScrollWheelEventDeltaAxis2, \
        _CGEventPost, _CGEventCreateMouseEvent, _CGEventCreateKeyboardEvent, \
        _CGEventSetIntegerValueField, _CGWarpMouseCursorPosition_fn, \
        _CGEventSourceCreate, \
        _kVK_Space, _kVK_Return, _kVK_Tab, _kVK_Delete, _kVK_Escape, \
        _kVK_UpArrow, _kVK_DownArrow, _kVK_LeftArrow, _kVK_RightArrow

    try:
        import Quartz  # noqa: F401
        import Quartz.CoreGraphics as CG  # noqa: N817

        _QUARTZ_AVAILABLE = True
        _CG_EVENT = CG
        _CG_POINT = CG.CGPoint
        _kCGEventSourceStateHIDSystemState = CG.kCGEventSourceStateHIDSystemState
        _kCGHIDEventTap = CG.kCGHIDEventTap
        _kCGMouseButtonLeft = CG.kCGMouseButtonLeft
        _kCGMouseButtonRight = CG.kCGMouseButtonRight
        _kCGMouseButtonCenter = CG.kCGMouseButtonCenter
        _kCGEventLeftMouseDown = CG.kCGEventLeftMouseDown
        _kCGEventLeftMouseUp = CG.kCGEventLeftMouseUp
        _kCGEventRightMouseDown = CG.kCGEventRightMouseDown
        _kCGEventRightMouseUp = CG.kCGEventRightMouseUp
        _kCGEventOtherMouseDown = CG.kCGEventOtherMouseDown
        _kCGEventOtherMouseUp = CG.kCGEventOtherMouseUp
        _kCGEventMouseMoved = CG.kCGEventMouseMoved
        _kCGEventLeftMouseDragged = CG.kCGEventLeftMouseDragged
        _kCGEventRightMouseDragged = CG.kCGEventRightMouseDragged
        _kCGEventOtherMouseDragged = CG.kCGEventOtherMouseDragged
        _kCGEventScrollWheel = CG.kCGEventScrollWheel
        _kCGEventKeyDown = CG.kCGEventKeyDown
        _kCGEventKeyUp = CG.kCGEventKeyUp
        _kCGEventFlagsChanged = CG.kCGEventFlagsChanged
        _kCGEventFlagMaskCommand = CG.kCGEventFlagMaskCommand
        _kCGEventFlagMaskShift = CG.kCGEventFlagMaskShift
        _kCGEventFlagMaskAlternate = CG.kCGEventFlagMaskAlternate
        _kCGEventFlagMaskControl = CG.kCGEventFlagMaskControl
        _kCGEventFlagMaskFn = CG.kCGEventFlagMaskSecondaryFn
        _kCGMouseEventClickState = CG.kCGMouseEventClickState
        _kCGKeyboardEventKeycode = CG.kCGKeyboardEventKeycode
        _kCGScrollWheelEventDeltaAxis1 = CG.kCGScrollWheelEventDeltaAxis1
        _kCGScrollWheelEventDeltaAxis2 = CG.kCGScrollWheelEventDeltaAxis2
        _CGEventPost = CG.CGEventPost
        _CGEventCreateMouseEvent = CG.CGEventCreateMouseEvent
        _CGEventCreateKeyboardEvent = CG.CGEventCreateKeyboardEvent
        _CGEventSetIntegerValueField = CG.CGEventSetIntegerValueField
        _CGWarpMouseCursorPosition_fn = CG.CGWarpMouseCursorPosition
        _CGEventSourceCreate = CG.CGEventSourceCreate

        # Virtual key codes
        _kVK_Space = 0x31
        _kVK_Return = 0x24
        _kVK_Tab = 0x30
        _kVK_Delete = 0x33
        _kVK_Escape = 0x35
        _kVK_UpArrow = 0x7E
        _kVK_DownArrow = 0x7D
        _kVK_LeftArrow = 0x7B
        _kVK_RightArrow = 0x7C

        logger.info("Quartz CGEvent backend initialized")
    except ImportError:
        logger.info("PyObjC not installed — Quartz backend unavailable")


# ── Key code mapping ──

def _key_to_virtual_keycode(key: str) -> int:
    """Convert a key name to macOS virtual keycode."""
    special = {
        "return": 0x24, "enter": 0x24, "tab": 0x30, "space": 0x31,
        "delete": 0x33, "escape": 0x35, "esc": 0x35,
        "up": 0x7E, "down": 0x7D, "left": 0x7B, "right": 0x7C,
        "home": 0x73, "end": 0x77, "pageup": 0x74, "pagedown": 0x79,
        "f1": 0x7A, "f2": 0x78, "f3": 0x63, "f4": 0x76, "f5": 0x60,
        "f6": 0x61, "f7": 0x62, "f8": 0x64, "f9": 0x65, "f10": 0x6D,
        "f11": 0x67, "f12": 0x6F, "f13": 0x69, "f14": 0x6B, "f15": 0x71,
    }
    return special.get(key.lower(), -1)


def _char_to_keycode(char: str) -> int:
    """Convert a single character to its macOS keycode.

    Uses CGEventSourceKeyCode for the current keyboard layout via
    a simple mapping table covering ASCII printable characters.
    """
    if len(char) != 1:
        return -1
    c = char

    # Map characters to known keycodes (US keyboard layout)
    mapping: dict[str, int] = {
        "a": 0, "b": 11, "c": 8, "d": 2, "e": 14, "f": 3, "g": 5,
        "h": 4, "i": 34, "j": 38, "k": 40, "l": 37, "m": 46, "n": 45,
        "o": 31, "p": 35, "q": 12, "r": 15, "s": 1, "t": 17, "u": 32,
        "v": 9, "w": 13, "x": 7, "y": 16, "z": 6,
        "0": 29, "1": 18, "2": 19, "3": 20, "4": 21, "5": 23,
        "6": 22, "7": 26, "8": 28, "9": 25,
        " ": 49, "-": 27, "=": 24, "[": 33, "]": 30, "\\": 42,
        ";": 41, "'": 39, ",": 43, ".": 47, "/": 44, "`": 50,
    }
    # Handle uppercase via shift
    if c.isupper():
        return mapping.get(c.lower(), -1)
    return mapping.get(c, -1)


def _modifier_flags(modifiers: list[str] | None) -> int:
    """Convert modifier strings to CGEventFlags."""
    if not modifiers or not _QUARTZ_AVAILABLE:
        return 0
    flags = 0
    for m in modifiers:
        m = m.lower()
        if m in ("cmd", "command"):
            flags |= _kCGEventFlagMaskCommand
        elif m in ("shift",):
            flags |= _kCGEventFlagMaskShift
        elif m in ("option", "alt"):
            flags |= _kCGEventFlagMaskAlternate
        elif m in ("ctrl", "control"):
            flags |= _kCGEventFlagMaskControl
        elif m in ("fn",):
            flags |= _kCGEventFlagMaskFn
    return flags


# ── Native backend ──

class NativeDesktopBackend:
    """macOS desktop control via Quartz CGEvent + screencapture + osascript.

    Requires Accessibility permission (System Preferences > Security & Privacy).
    Does NOT require cliclick.
    """

    def __init__(self) -> None:
        _init_quartz()
        import shutil
        self._screencapture = shutil.which("screencapture")
        self._osascript = shutil.which("osascript")
        # cliclick is optional fallback
        self._cliclick = shutil.which("cliclick")

    @property
    def quartz_available(self) -> bool:
        return _QUARTZ_AVAILABLE

    @property
    def cliclick_available(self) -> bool:
        return bool(self._cliclick)

    # ── Helpers ──

    def _mouse_event(self, event_type: int, x: float, y: float,
                     button: int = 0, click_count: int = 1) -> None:
        """Create and post a mouse event via Quartz."""
        point = _CG_POINT(x, y)
        event = _CGEventCreateMouseEvent(
            None, event_type, point, button,
        )
        if click_count > 1 and _kCGMouseEventClickState is not None:
            _CGEventSetIntegerValueField(event, _kCGMouseEventClickState, click_count)
        _CGEventPost(_kCGHIDEventTap, event)

    # ── Mouse ──

    def mouse_click(self, point: Point | None = None,
                    button: str = "left", clicks: int = 1) -> dict[str, str]:
        if not _QUARTZ_AVAILABLE:
            return self._fallback_mouse_click(point, button, clicks)

        btn_map = {"left": _kCGMouseButtonLeft, "right": _kCGMouseButtonRight,
                   "middle": _kCGMouseButtonCenter}
        mouse_button = btn_map.get(button, _kCGMouseButtonLeft)
        down_map = {0: _kCGEventLeftMouseDown, 1: _kCGEventRightMouseDown, 2: _kCGEventOtherMouseDown}
        up_map = {0: _kCGEventLeftMouseUp, 1: _kCGEventRightMouseUp, 2: _kCGEventOtherMouseUp}
        btn_idx = list(btn_map.values()).index(mouse_button)

        x, y = point.x, point.y if point else self.get_mouse_position_native()
        if point:
            self.mouse_move(point)

        for _ in range(clicks):
            time.sleep(0.02)
            self._mouse_event(down_map[btn_idx], x, y, mouse_button)
            time.sleep(0.02)
            self._mouse_event(up_map[btn_idx], x, y, mouse_button)

        return {"action": "mouse_click", "button": button,
                "point": f"{x},{y}" if point else "current", "clicks": clicks}

    def mouse_move(self, point: Point) -> dict[str, str]:
        if not _QUARTZ_AVAILABLE:
            return self._fallback_mouse_move(point)
        _CGWarpMouseCursorPosition_fn(_CG_POINT(point.x, point.y))
        return {"action": "mouse_move", "point": f"{point.x},{point.y}"}

    def mouse_scroll(self, direction: str, amount: int = 3) -> dict[str, str]:
        if not _QUARTZ_AVAILABLE:
            return self._fallback_mouse_scroll(direction, amount)
        # Scroll event: positive delta1 = up, negative = down
        delta = amount if direction in ("up", "left") else -amount
        event = _CGEventCreateMouseEvent(None, _kCGEventScrollWheel,
                                          _CG_POINT(0, 0), _kCGMouseButtonLeft)
        if direction in ("up", "down"):
            _CGEventSetIntegerValueField(event, _kCGScrollWheelEventDeltaAxis1, delta)
        else:
            _CGEventSetIntegerValueField(event, _kCGScrollWheelEventDeltaAxis2, delta)
        _CGEventPost(_kCGHIDEventTap, event)
        return {"action": "mouse_scroll", "direction": direction, "amount": amount}

    def mouse_drag(self, start: Point, end: Point, button: str = "left") -> dict[str, str]:
        if not _QUARTZ_AVAILABLE:
            return self._fallback_mouse_drag(start, end, button)
        btn_map = {"left": _kCGMouseButtonLeft, "right": _kCGMouseButtonRight,
                   "middle": _kCGMouseButtonCenter}
        mouse_button = btn_map.get(button, _kCGMouseButtonLeft)
        drag_map = {0: (_kCGEventLeftMouseDown, _kCGEventLeftMouseDragged, _kCGEventLeftMouseUp),
                    1: (_kCGEventRightMouseDown, _kCGEventRightMouseDragged, _kCGEventRightMouseUp),
                    2: (_kCGEventOtherMouseDown, _kCGEventOtherMouseDragged, _kCGEventOtherMouseUp)}
        btn_idx = list(btn_map.values()).index(mouse_button)
        down, drag, up = drag_map[btn_idx]

        self.mouse_move(start)
        time.sleep(0.05)
        self._mouse_event(down, start.x, start.y, mouse_button)
        time.sleep(0.05)
        self._mouse_event(drag, end.x, end.y, mouse_button)
        time.sleep(0.05)
        self._mouse_event(up, end.x, end.y, mouse_button)

        return {"action": "mouse_drag", "button": button,
                "start": f"{start.x},{start.y}", "end": f"{end.x},{end.y}"}

    # ── Keyboard ──

    def type_text(self, text: str) -> dict[str, str]:
        """Type text character by character using Quartz key events."""
        if not _QUARTZ_AVAILABLE:
            return self._fallback_type_text(text)

        for char in text:
            keycode = _char_to_keycode(char)
            if keycode < 0:
                continue
            shift = char.isupper() or char in '~!@#$%^&*()_+{}|:"<>?'
            flags = _kCGEventFlagMaskShift if shift else 0

            # Key down
            event_down = _CGEventCreateKeyboardEvent(None, keycode, True)
            if flags:
                _CGEventSetIntegerValueField(event_down, _kCGKeyboardEventKeycode, keycode)
                # Set modifier flags via a separate flags-changed event
                if flags:
                    flag_event = _CGEventCreateKeyboardEvent(None, 0, True)
                    _CGEventSetIntegerValueField(flag_event, _kCGKeyboardEventKeycode, keycode)
                    # Post shift modifier
                    shift_down = _CGEventCreateKeyboardEvent(None, 56, True)  # 56 = left shift
                    _CGEventPost(_kCGHIDEventTap, shift_down)
                _CGEventPost(_kCGHIDEventTap, event_down)
                # F-15: always post the matching key-up; a key held down
                # leaves the target app with stuck-modifier/repeat state.
                event_up = _CGEventCreateKeyboardEvent(None, keycode, False)
                _CGEventPost(_kCGHIDEventTap, event_up)
                if flags:
                    shift_up = _CGEventCreateKeyboardEvent(None, 56, False)
                    _CGEventPost(_kCGHIDEventTap, shift_up)
            else:
                _CGEventPost(_kCGHIDEventTap, event_down)
                event_up = _CGEventCreateKeyboardEvent(None, keycode, False)
                _CGEventPost(_kCGHIDEventTap, event_up)
            time.sleep(0.005)

        return {"action": "type_text", "length": len(text)}

    def key_press(self, key: str, modifiers: list[str] | None = None) -> dict[str, str]:
        """Press a key with optional modifiers."""
        if not _QUARTZ_AVAILABLE:
            return self._fallback_key_press(key, modifiers)

        keycode = _key_to_virtual_keycode(key)
        if keycode < 0 and len(key) == 1:
            keycode = _char_to_keycode(key)
        if keycode < 0:
            return {"action": "key_press", "key": key, "status": "unknown_keycode"}

        flags = _modifier_flags(modifiers)

        # Post modifier key-downs
        if flags:
            mod_event = _CGEventCreateKeyboardEvent(None, 0, True)
            _CGEventSetIntegerValueField(mod_event, _kCGKeyboardEventKeycode, keycode)
            # Use CGEventSetFlags approach: post a flags-changed event
            flag_event = _CGEventCreateKeyboardEvent(None, 0xFF, True)
            _CGEventSetIntegerValueField(flag_event, _kCGKeyboardEventKeycode, keycode)

        # Key down
        event_down = _CGEventCreateKeyboardEvent(None, keycode, True)
        _CGEventPost(_kCGHIDEventTap, event_down)
        time.sleep(0.02)
        # Key up
        event_up = _CGEventCreateKeyboardEvent(None, keycode, False)
        _CGEventPost(_kCGHIDEventTap, event_up)

        return {"action": "key_press", "key": key,
                "modifiers": modifiers or []}

    # ── Mouse position ──

    def get_mouse_position_native(self) -> tuple[int, int]:
        """Get current mouse position via Quartz."""
        if not _QUARTZ_AVAILABLE:
            return (0, 0)
        event = _CG_EVENT.CGEventCreate(None)
        point = _CG_EVENT.CGEventGetLocation(event)
        return (int(point.x), int(point.y))

    def get_mouse_position(self) -> Point:
        x, y = self.get_mouse_position_native()
        return Point(x=x, y=y)

    # ── Screenshot ──

    def screenshot(self, region: ScreenRegion | None = None,
                   output_path: str | None = None, format_: str = "png",
                   show_cursor: bool = False) -> dict[str, str]:
        """Capture via built-in screencapture CLI."""
        import base64
        import os
        import tempfile

        if not self._screencapture:
            raise RuntimeError("screencapture not found")

        if output_path is None:
            fd, output_path = tempfile.mkstemp(suffix=f".{format_}")
            os.close(fd)

        cmd = [self._screencapture, "-x"]
        if show_cursor:
            cmd.append("-C")
        if region:
            cmd.extend(region.to_args().split())
        fmt_map = {"jpg": "-tjpg", "jpeg": "-tjpg", "png": "-tpng", "pdf": "-tpdf", "tiff": "-ttiff"}
        if flag := fmt_map.get(format_.lower()):
            cmd.append(flag)
        cmd.append(output_path)

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        if result.returncode != 0:
            raise RuntimeError(f"screencapture failed: {result.stderr}")

        b64 = ""
        if os.path.exists(output_path):
            with open(output_path, "rb") as f:
                b64 = base64.b64encode(f.read()).decode("ascii")
        return {"path": output_path, "base64": b64}

    # ── App/Window via AppleScript ──

    def _run_applescript(self, script: str) -> str:
        if not self._osascript:
            raise RuntimeError("osascript not available")
        result = subprocess.run(
            [self._osascript, "-e", script],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            raise RuntimeError(f"osascript failed: {result.stderr}")
        return result.stdout.strip()

    def app_action(self, action: str, app_name: str | None = None) -> dict[str, Any]:
        if action == "list":
            return self._list_apps()
        if not app_name:
            raise ValueError("app_name required")
        safe = app_name.replace('"', '\\"')
        if action == "open" or action == "activate":
            self._run_applescript(f'tell application "{safe}" to activate')
            return {"action": f"app_{action}", "app": app_name}
        if action == "quit":
            self._run_applescript(f'tell application "{safe}" to quit')
            return {"action": "app_quit", "app": app_name}
        raise ValueError(f"Unknown action: {action}")

    def _list_apps(self) -> dict[str, list[AppInfo]]:
        import json
        script = '''tell application "System Events"
            set frontApp to name of first application process whose frontmost is true
            set resultList to {}
            repeat with proc in (get application processes)
                set procName to name of proc
                set isFront to (procName is frontApp)
                set end of resultList to "{\\"name\\":\\"" & procName & "\\",\\"active\\":" & isFront & "}"
            end repeat
            return "[" & (my joinList(resultList, ",")) & "]"
        end tell
        on joinList(theList, d)
            set s to ""
            repeat with i from 1 to count of theList
                set s to s & item i of theList
                if i < count of theList then set s to s & d
            end repeat
            return s
        end joinList'''
        output = self._run_applescript(script)
        try:
            data = json.loads(output)
            apps = [AppInfo(name=a["name"], pid=None, active=a.get("active", False)) for a in data]
            return {"apps": apps}
        except Exception:
            return {"apps": []}

    def window_action(self, action: str, app_name: str | None = None,
                      window_title: str | None = None,
                      bounds: ScreenRegion | None = None) -> dict[str, Any]:
        if action == "list":
            return self._list_windows(app_name)
        if not app_name:
            raise ValueError("app_name required")
        safe = app_name.replace('"', '\\"')
        if action == "activate":
            if window_title:
                ts = window_title.replace('"', '\\"')
                self._run_applescript(f'tell application "System Events" to tell process "{safe}" to set frontmost to true\ntell application "System Events" to tell process "{safe}" to perform action "AXRaise" of first window whose name contains "{ts}"')
            else:
                self._run_applescript(f'tell application "{safe}" to activate')
            return {"action": "window_activate", "app": app_name, "window": window_title}
        if action == "move" and bounds:
            self._run_applescript(f'tell application "System Events" to tell process "{safe}" to set position of first window to {{{bounds.x}, {bounds.y}}}')
            return {"action": "window_move", "app": app_name, "bounds": vars(bounds)}
        if action == "resize" and bounds:
            self._run_applescript(f'tell application "System Events" to tell process "{safe}" to set size of first window to {{{bounds.width}, {bounds.height}}}')
            return {"action": "window_resize", "app": app_name, "bounds": vars(bounds)}
        raise ValueError(f"Unknown action: {action}")

    def _list_windows(self, app_name: str | None = None) -> dict[str, list[WindowInfo]]:
        import json
        if app_name:
            safe = app_name.replace('"', '\\"')
            script = f'tell application "System Events" to tell process "{safe}" to set winList to {{}}\n' \
                     f'tell application "System Events" to tell process "{safe}" to repeat with w in (get windows)\n' \
                     f'set end of winList to "{{\\"title\\":\\"" & (name of w) & "\\",\\"app_name\\":\\"{safe}\\",\\"x\\":" & (item 1 of (position of w)) & ",\\"y\\":" & (item 2 of (position of w)) & ",\\"width\\":" & (item 1 of (size of w)) & ",\\"height\\":" & (item 2 of (size of w)) & "}}"\n' \
                     f'end repeat\nreturn "[" & (my joinList(winList, ",")) & "]"\n' \
                     f'on joinList(l, d)\nset s to ""\nrepeat with i from 1 to count of l\nset s to s & item i of l\nif i < count of l then set s to s & d\nend repeat\nreturn s\nend joinList'
        else:
            script = 'tell application "System Events"\nset allW to {}\nrepeat with proc in (get application processes)\nset pn to name of proc\nrepeat with w in (get windows of proc)\nset end of allW to "{\\"title\\":\\"" & (name of w) & "\\",\\"app_name\\":\\"" & pn & "\\",\\"x\\":" & (item 1 of (position of w)) & ",\\"y\\":" & (item 2 of (position of w)) & ",\\"width\\":" & (item 1 of (size of w)) & ",\\"height\\":" & (item 2 of (size of w)) & "}"\nend repeat\nend repeat\nreturn "[" & (my joinList(allW, ",")) & "]"\nend tell\non joinList(l, d)\nset s to ""\nrepeat with i from 1 to count of l\nset s to s & item i of l\nif i < count of l then set s to s & d\nend repeat\nreturn s\nend joinList'
        output = self._run_applescript(script)
        try:
            data = json.loads(output)
            windows = [WindowInfo(title=w.get("title", ""), app_name=w.get("app_name", ""),
                                  bounds=ScreenRegion(x=w.get("x", 0), y=w.get("y", 0),
                                                     width=w.get("width", 0), height=w.get("height", 0)),
                                  index=i) for i, w in enumerate(data)]
            return {"windows": windows}
        except Exception:
            return {"windows": []}

    # ── Fallbacks (cliclick) ──

    def _fallback_mouse_click(self, point, button, clicks):
        if not self._cliclick:
            raise RuntimeError("No mouse backend available (install cliclick: brew install cliclick)")
        act = {"left": "c", "right": "rc", "middle": "mc"}[button]
        parts = []
        if point:
            parts.append(f"m:{point.x},{point.y}")
        parts.extend([act] * clicks)
        subprocess.run([self._cliclick, " ".join(parts)], capture_output=True, text=True, timeout=5)
        return {"action": "mouse_click", "button": button, "clicks": clicks}

    def _fallback_mouse_move(self, point):
        if not self._cliclick:
            raise RuntimeError("No mouse backend available")
        subprocess.run([self._cliclick, f"m:{point.x},{point.y}"], capture_output=True, text=True, timeout=5)
        return {"action": "mouse_move", "point": f"{point.x},{point.y}"}

    def _fallback_mouse_scroll(self, direction, amount):
        if not self._cliclick:
            raise RuntimeError("No mouse backend available")
        d = "w:{0}" if direction in ("up", "left") else "w:{0}-"
        subprocess.run([self._cliclick, d.format(amount)], capture_output=True, text=True, timeout=5)
        return {"action": "mouse_scroll", "direction": direction, "amount": amount}

    def _fallback_mouse_drag(self, start, end, button):
        if not self._cliclick:
            raise RuntimeError("No mouse backend available")
        b = {"left": ("dd", "dm", "du"), "right": ("rd", "rm", "ru"), "middle": ("md", "mm", "mu")}[button]
        parts = [f"{b[0]}:{start.x},{start.y}", f"{b[1]}:{end.x},{end.y}", f"{b[2]}:{end.x},{end.y}"]
        subprocess.run([self._cliclick, " ".join(parts)], capture_output=True, text=True, timeout=5)
        return {"action": "mouse_drag", "start": f"{start.x},{start.y}", "end": f"{end.x},{end.y}"}

    def _fallback_type_text(self, text):
        if not self._cliclick:
            raise RuntimeError("No keyboard backend available")
        escaped = text.replace("\\", "\\\\").replace(":", "\\:")
        subprocess.run([self._cliclick, f"t:{escaped}"], capture_output=True, text=True, timeout=10)
        return {"action": "type_text", "length": len(text)}

    def _fallback_key_press(self, key, modifiers):
        if not self._cliclick:
            raise RuntimeError("No keyboard backend available")
        mod_str = "-".join(modifiers) + "-" if modifiers else ""
        subprocess.run([self._cliclick, f"kp:{mod_str}{key}"], capture_output=True, text=True, timeout=5)
        return {"action": "key_press", "key": key, "modifiers": modifiers or []}
