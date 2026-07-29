# ruff: noqa: E701, B904 (intentional concise fallback error handling)
"""Desktop controller for macOS.

Uses screencapture, cliclick, and osascript.
Requires Accessibility permission for mouse/keyboard.
Requires Screen Recording permission for screenshots.
"""

from __future__ import annotations

import base64
import logging
import os
import platform
import shutil
import subprocess
import tempfile
from typing import Any

from .permissions import PermissionChecker
from .types import (
    AppAction,
    AppInfo,
    KeyModifier,
    MouseButton,
    Point,
    ScreenRegion,
    ScrollDirection,
    WindowAction,
    WindowInfo,
)

logger = logging.getLogger("js.tools.desktop.controller")


def _escape_applescript_string(value: str) -> str:
    """Escape a value for safe interpolation into an AppleScript string literal.

    Order matters: backslashes first, then double quotes, so an attacker
    cannot use ``\\"`` to smuggle a literal quote past the quote escaping.
    Control characters (newlines, carriage returns, etc.) can terminate the
    AppleScript statement regardless of escaping, so they are rejected
    outright (fail-closed).
    """
    for ch in value:
        codepoint = ord(ch)
        if codepoint < 0x20 or codepoint == 0x7F:
            raise ValueError(
                "app_name/window_title contains control characters "
                "(newline/CR/control) — rejected"
            )
    return value.replace("\\", "\\\\").replace('"', '\\"')


# cliclick `kp:` key names (documented set) plus single ASCII letters/digits.
_CLICLICK_ALLOWED_KEYS = frozenset(
    {
        "return", "tab", "space", "delete", "fwd-delete", "esc", "escape",
        "home", "end", "page-up", "page-down",
        "arrow-up", "arrow-down", "arrow-left", "arrow-right",
        "up", "down", "left", "right",
    }
    | {f"f{i}" for i in range(1, 17)}
    | set("abcdefghijklmnopqrstuvwxyz0123456789")
)


def _validate_cliclick_key(key: str) -> str:
    """Allow only known cliclick key names (fail-closed for anything else)."""
    normalized = key.strip().lower()
    if normalized not in _CLICLICK_ALLOWED_KEYS:
        raise ValueError(f"key not in cliclick whitelist: {key!r}")
    return normalized


def _validate_cliclick_type_text(text: str) -> str:
    """Reject control characters before handing text to the cliclick fallback."""
    for ch in text:
        codepoint = ord(ch)
        if codepoint < 0x20 or codepoint == 0x7F:
            raise ValueError(
                "type_text contains control characters — rejected for cliclick fallback"
            )
    return text


class DesktopController:
    """Low-level desktop control via macOS system utilities.

    Uses native Quartz CGEvent for mouse/keyboard (via PyObjC).
    Falls back to cliclick if PyObjC is not installed.
    Uses screencapture + osascript (built-in macOS) for screenshot/app/window.

    All write methods are designed to be called ONLY after guard checks pass.
    Read methods (screenshot, list_windows, list_apps) do not require guards
    but still require the corresponding permissions.
    """

    def __init__(self) -> None:
        if not PermissionChecker.is_macos():
            raise RuntimeError(
                "DesktopController is only supported on macOS. "
                f"Current platform: {platform.system()}"
            )

        # Native Quartz backend (PyObjC) — preferred
        from .controller_native import NativeDesktopBackend
        self._native = NativeDesktopBackend()

        # Legacy cliclick backend — optional fallback
        self._cliclick_path = shutil.which("cliclick")
        self._screencapture_path = shutil.which("screencapture")
        self._osascript_path = shutil.which("osascript")

        if not self._native.quartz_available and not self._cliclick_path:
            logger.warning(
                "No mouse/keyboard backend available. "
                "Install PyObjC (pip install pyobjc-framework-Quartz) "
                "or cliclick (brew install cliclick)."
            )
        if not self._screencapture_path:
            logger.warning("screencapture not found. Screenshots unavailable.")
        if not self._osascript_path:
            logger.warning("osascript not found. App/window management unavailable.")

    # ── Screenshots ───────────────────────────────────────────────

    def screenshot(
        self,
        region: ScreenRegion | None = None,
        output_path: str | None = None,
        format_: str = "png",
        show_cursor: bool = False,
    ) -> dict[str, Any]:
        """Capture a screenshot.

        Args:
            region: Optional capture region. If None, captures full screen.
            output_path: Optional path to save. If None, returns base64 data.
            format_: Image format: png, jpg, pdf, tiff.
            show_cursor: Whether to include cursor in screenshot.

        Returns:
            {"path": str, "base64": str | None} dict.
        """
        PermissionChecker.assert_screen_recording()

        if not self._screencapture_path:
            raise RuntimeError("screencapture not available")

        if output_path is None:
            suffix = f".{format_}"
            fd, output_path = tempfile.mkstemp(suffix=suffix)
            os.close(fd)

        cmd = [self._screencapture_path, "-x"]
        if show_cursor:
            cmd.append("-C")
        if region:
            cmd.extend(region.to_args().split())

        # Format flag
        fmt_map = {"jpg": "-tjpg", "jpeg": "-tjpg", "png": "-tpng", "pdf": "-tpdf", "tiff": "-ttiff"}
        if fmt_flag := fmt_map.get(format_.lower()):
            cmd.append(fmt_flag)

        cmd.append(output_path)

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        if result.returncode != 0:
            raise RuntimeError(f"screencapture failed: {result.stderr}")

        b64: str | None = None
        if os.path.exists(output_path):
            with open(output_path, "rb") as f:
                b64 = base64.b64encode(f.read()).decode("ascii")

        return {"path": output_path, "base64": b64}

    # ── Mouse ────────────────────────────────────────────────────

    def mouse_click(
        self,
        point: Point | None = None,
        button: MouseButton = MouseButton.LEFT,
        clicks: int = 1,
    ) -> dict[str, Any]:
        """Click mouse — native Quartz CGEvent (preferred) or cliclick fallback."""
        try:
            return self._native.mouse_click(point=point, button=button.value, clicks=clicks)
        except Exception:
            if not self._cliclick_path:
                raise
            # cliclick fallback
            action = {"left": "c", "right": "rc", "middle": "mc"}[button.value]
            parts = []
            if point: parts.append(f"m:{point.x},{point.y}")
            parts.extend([action] * clicks)
            subprocess.run([self._cliclick_path, " ".join(parts)], capture_output=True, text=True, timeout=5)
            return {"action": "mouse_click", "button": button.value,
                    "point": f"{point.x},{point.y}" if point else "current", "clicks": clicks}

    def mouse_move(self, point: Point) -> dict[str, str]:
        """Move mouse cursor — native or fallback."""
        try:
            return self._native.mouse_move(point)
        except Exception:
            if not self._cliclick_path: raise
            subprocess.run([self._cliclick_path, f"m:{point.x},{point.y}"], capture_output=True, text=True, timeout=5)
            return {"action": "mouse_move", "point": f"{point.x},{point.y}"}

    def mouse_scroll(self, direction: ScrollDirection, amount: int = 3) -> dict[str, Any]:
        """Scroll mouse — native or fallback."""
        try:
            return self._native.mouse_scroll(direction.value, amount)
        except Exception:
            if not self._cliclick_path: raise
            d = "w:{0}" if direction in (ScrollDirection.UP, ScrollDirection.LEFT) else "w:{0}-"
            subprocess.run([self._cliclick_path, d.format(amount)], capture_output=True, text=True, timeout=5)
            return {"action": "mouse_scroll", "direction": direction.value, "amount": amount}

    def mouse_drag(self, start: Point, end: Point, button: MouseButton = MouseButton.LEFT) -> dict[str, str]:
        """Drag mouse — native or fallback."""
        try:
            return self._native.mouse_drag(start, end, button.value)
        except Exception:
            if not self._cliclick_path: raise
            b = {"left": ("dd", "dm", "du"), "right": ("rd", "rm", "ru"), "middle": ("md", "mm", "mu")}[button.value]
            parts = [f"{b[0]}:{start.x},{start.y}", f"{b[1]}:{end.x},{end.y}", f"{b[2]}:{end.x},{end.y}"]
            subprocess.run([self._cliclick_path, " ".join(parts)], capture_output=True, text=True, timeout=5)
            return {"action": "mouse_drag", "button": button.value,
                    "start": f"{start.x},{start.y}", "end": f"{end.x},{end.y}"}

    def get_mouse_position(self) -> Point:
        """Get current mouse position — native Quartz or cliclick fallback."""
        try:
            return self._native.get_mouse_position()
        except Exception:
            if not self._cliclick_path: raise RuntimeError("No mouse backend available")
            result = subprocess.run([self._cliclick_path, "p:"], capture_output=True, text=True, timeout=5)
            if result.returncode != 0: raise RuntimeError(f"cliclick failed: {result.stderr}")
            coords = result.stdout.strip().split(",")
            return Point(x=int(coords[0]), y=int(coords[1]))

    # ── Keyboard ─────────────────────────────────────────────────

    def type_text(self, text: str) -> dict[str, Any]:
        """Type text — native Quartz or cliclick fallback."""
        try:
            return self._native.type_text(text)
        except Exception:
            if not self._cliclick_path: raise
            # F-15: whitelist-validate before handing text to cliclick —
            # control characters could inject additional cliclick commands.
            text = _validate_cliclick_type_text(text)
            escaped = text.replace("\\", "\\\\").replace(":", "\\:")
            subprocess.run([self._cliclick_path, f"t:{escaped}"], capture_output=True, text=True, timeout=10)
            return {"action": "type_text", "length": len(text)}

    def key_press(self, key: str, modifiers: list[KeyModifier] | None = None) -> dict[str, Any]:
        """Press key — native Quartz or cliclick fallback."""
        try:
            mods = [m.value for m in modifiers] if modifiers else None
            return self._native.key_press(key, mods)
        except Exception:
            if not self._cliclick_path: raise
            # F-15: whitelist-validate the key before handing it to cliclick —
            # an unvalidated key string could inject extra cliclick actions
            # (e.g. "kp:return;m:0,0" style command chaining).
            key = _validate_cliclick_key(key)
            mod_str = "-".join(m.value for m in modifiers) + "-" if modifiers else ""
            subprocess.run([self._cliclick_path, f"kp:{mod_str}{key}"], capture_output=True, text=True, timeout=5)
            return {"action": "key_press", "key": key,
                    "modifiers": [m.value for m in modifiers] if modifiers else []}

    # ── Application Management ───────────────────────────────────

    def _run_applescript(self, script: str) -> str:
        """Run an AppleScript and return stdout."""
        if not self._osascript_path:
            raise RuntimeError("osascript not available")

        result = subprocess.run(
            [self._osascript_path, "-e", script],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            raise RuntimeError(f"osascript failed: {result.stderr}")
        return result.stdout.strip()

    def app_action(
        self,
        action: AppAction,
        app_name: str | None = None,
    ) -> dict[str, Any]:
        """Perform an action on an application.

        Args:
            action: The action to perform.
            app_name: Target application name. Required for open/activate/quit.

        Returns:
            Status or list dict.
        """
        if action == AppAction.LIST:
            return self._list_apps()

        if not app_name:
            raise ValueError("app_name is required for this action")

        app_name_safe = _escape_applescript_string(app_name)

        if action == AppAction.OPEN:
            script = f'tell application "{app_name_safe}" to activate'
            self._run_applescript(script)
            return {"action": "app_open", "app": app_name}

        if action == AppAction.ACTIVATE:
            script = f'tell application "{app_name_safe}" to activate'
            self._run_applescript(script)
            return {"action": "app_activate", "app": app_name}

        if action == AppAction.QUIT:
            script = f'tell application "{app_name_safe}" to quit'
            self._run_applescript(script)
            return {"action": "app_quit", "app": app_name}

        raise ValueError(f"Unknown action: {action}")

    def _list_apps(self) -> dict[str, list[AppInfo]]:
        """List running applications."""
        # Use JSON-based listing (more reliable)
        return self._list_apps_json()

    def _list_apps_json(self) -> dict[str, list[AppInfo]]:
        """List running applications using JSON output."""
        script = '''
            tell application "System Events"
                set frontApp to name of first application process whose frontmost is true
                set resultList to {}
                repeat with proc in (get application processes)
                    set procName to name of proc
                    set isFront to (procName is frontApp)
                    set end of resultList to "{\\"name\\":\\"" & procName & "\\",\\"active\\":" & isFront & "}"
                end repeat
                return "[" & (my joinList(resultList, ",")) & "]"
            end tell

            on joinList(theList, theDelimiter)
                set theString to ""
                set theCount to count of theList
                repeat with i from 1 to theCount
                    set theString to theString & item i of theList
                    if i < theCount then set theString to theString & theDelimiter
                end repeat
                return theString
            end joinList
        '''
        import json

        output = self._run_applescript(script)
        try:
            data = json.loads(output)
            apps = [AppInfo(name=a["name"], pid=None, active=a["active"]) for a in data]
            return {"apps": apps}
        except json.JSONDecodeError:
            # Fallback: return empty list
            return {"apps": []}

    # ── Window Management ────────────────────────────────────────

    def window_action(
        self,
        action: WindowAction,
        app_name: str | None = None,
        window_title: str | None = None,
        bounds: ScreenRegion | None = None,
    ) -> dict[str, Any]:
        """Perform a window action.

        Args:
            action: The action to perform.
            app_name: Target application.
            window_title: Target window title (for activate/move/resize).
            bounds: New bounds (for move/resize).

        Returns:
            Status or list dict.
        """
        if action == WindowAction.LIST:
            return self._list_windows(app_name)

        if not app_name:
            raise ValueError("app_name is required for this action")

        app_safe = _escape_applescript_string(app_name)

        if action == WindowAction.ACTIVATE:
            if window_title:
                title_safe = _escape_applescript_string(window_title)
                script = f'''
                    tell application "System Events"
                        tell process "{app_safe}"
                            set frontmost to true
                            set win to first window whose name contains "{title_safe}"
                            perform action "AXRaise" of win
                        end tell
                    end tell
                '''
            else:
                script = f'''
                    tell application "{app_safe}"
                        activate
                    end tell
                '''
            self._run_applescript(script)
            return {"action": "window_activate", "app": app_name, "window": window_title}

        if action == WindowAction.MOVE:
            if not bounds:
                raise ValueError("bounds is required for move")
            script = f'''
                tell application "System Events"
                    tell process "{app_safe}"
                        set position of first window to {{{bounds.x}, {bounds.y}}}
                    end tell
                end tell
            '''
            self._run_applescript(script)
            return {"action": "window_move", "app": app_name, "bounds": bounds.__dict__}

        if action == WindowAction.RESIZE:
            if not bounds:
                raise ValueError("bounds is required for resize")
            script = f'''
                tell application "System Events"
                    tell process "{app_safe}"
                        set size of first window to {{{bounds.width}, {bounds.height}}}
                    end tell
                end tell
            '''
            self._run_applescript(script)
            return {"action": "window_resize", "app": app_name, "bounds": bounds.__dict__}

        raise ValueError(f"Unknown action: {action}")

    def _list_windows(self, app_name: str | None = None) -> dict[str, list[WindowInfo]]:
        """List windows. If app_name is given, list only that app's windows."""
        if app_name:
            app_safe = _escape_applescript_string(app_name)
            script = f'''
                tell application "System Events"
                    tell process "{app_safe}"
                        set winList to {{}}
                        repeat with w in (get windows)
                            set winName to name of w
                            set winPos to position of w
                            set winSize to size of w
                            set end of winList to "{{\\"title\\":\\"" & winName & "\\",\\"app_name\\":\\"{app_safe}\\",\\"x\\":" & (item 1 of winPos) & ",\\"y\\":" & (item 2 of winPos) & ",\\"width\\":" & (item 1 of winSize) & ",\\"height\\":" & (item 2 of winSize) & "}}"
                        end repeat
                        return "[" & (my joinList(winList, ",")) & "]"
                    end tell
                end tell

                on joinList(theList, theDelimiter)
                    set theString to ""
                    set theCount to count of theList
                    repeat with i from 1 to theCount
                        set theString to theString & item i of theList
                        if i < theCount then set theString to theString & theDelimiter
                    end repeat
                    return theString
                end joinList
            '''
        else:
            script = '''
                tell application "System Events"
                    set allWindows to {}
                    repeat with proc in (get application processes)
                        set procName to name of proc
                        repeat with w in (get windows of proc)
                            set winName to name of w
                            set winPos to position of w
                            set winSize to size of w
                            set end of allWindows to "{\"title\":\"" & winName & "\",\"app_name\":\"" & procName & "\",\"x\":" & (item 1 of winPos) & ",\"y\":" & (item 2 of winPos) & ",\"width\":" & (item 1 of winSize) & ",\"height\":" & (item 2 of winSize) & "}"
                        end repeat
                    end repeat
                    return "[" & (my joinList(allWindows, ",")) & "]"
                end tell

                on joinList(theList, theDelimiter)
                    set theString to ""
                    set theCount to count of theList
                    repeat with i from 1 to theCount
                        set theString to theString & item i of theList
                        if i < theCount then set theString to theString & theDelimiter
                    end repeat
                    return theString
                end joinList
            '''

        import json

        output = self._run_applescript(script)
        try:
            data = json.loads(output)
            windows = [
                WindowInfo(
                    title=w.get("title", ""),
                    app_name=w.get("app_name", ""),
                    bounds=ScreenRegion(
                        x=w.get("x", 0),
                        y=w.get("y", 0),
                        width=w.get("width", 0),
                        height=w.get("height", 0),
                    ),
                    index=i,
                )
                for i, w in enumerate(data)
            ]
            return {"windows": windows}
        except json.JSONDecodeError:
            return {"windows": []}
# noqa: E701,B904 (intentional concise fallback error handling)
