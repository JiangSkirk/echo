"""Desktop control tools for the agent tool registry.

Integrates js.tools.desktop with the ToolRegistry pattern.
All write operations go through DesktopGuard with safety modes.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Callable
from typing import Any

from js.orin.desktop import normalize_desktop_safe_projection
from js.orin.protocol import ProtocolError
from js.tools.desktop import (
    AppAction,
    DesktopGuard,
    DesktopMode,
    KeyModifier,
    MouseButton,
    PermissionChecker,
    Point,
    ScreenRegion,
    ScrollDirection,
    WindowAction,
)
from js.tools.registry import ToolParam, ToolResult, ToolSpec

logger = logging.getLogger("js.tools.desktop_tools")

_CELL_OBSERVE_TOOLS = frozenset(
    {
        "desktop_get_permissions",
        "desktop_get_state",
        "desktop_screenshot",
        "desktop_list",
        "desktop_operation_log",
    }
)
_CELL_PROJECTION_KEYS = frozenset(
    {
        "accessibility",
        "action",
        "after_digest",
        "apps",
        "available",
        "before_digest",
        "dependencies",
        "desktop_target_handle_id",
        "display_id",
        "height",
        "image_base64",
        "image_mime_type",
        "mode",
        "mouse",
        "observed_at_ms",
        "operation_count",
        "owner_pid",
        "pixel_hash",
        "platform",
        "receipt_id",
        "scale",
        "screen_recording",
        "target_kind",
        "target_label",
        "width",
        "window_number",
        "windows",
    }
)
_CELL_SENSITIVE_KEY_PARTS = frozenset(
    {
        "canonical_effect_hash",
        "credential",
        "draft_id",
        "mac",
        "nonce",
        "package",
        "permit",
        "root",
        "seal",
        "secret",
        "session_key",
        "stage_path",
        "task_id",
        "token",
        "witness",
    }
)


def _cell_projection_is_safe(value: Any, *, depth: int = 0) -> bool:
    """Accept a small JSON-only projection, never an authority-bearing object."""
    if depth > 4:
        return False
    if value is None or type(value) in {bool, int, float, str}:
        return not isinstance(value, str) or len(value) <= 48 * 1024
    if isinstance(value, list):
        return len(value) <= 256 and all(
            _cell_projection_is_safe(item, depth=depth + 1) for item in value
        )
    if isinstance(value, dict):
        if len(value) > 64:
            return False
        for key, item in value.items():
            if type(key) is not str or not key or len(key) > 64:
                return False
            lowered = key.casefold()
            if any(part in lowered for part in _CELL_SENSITIVE_KEY_PARTS):
                return False
            if not _cell_projection_is_safe(item, depth=depth + 1):
                return False
        return True
    return False


class DesktopTools:
    """Register desktop control tools with the agent registry.

    Safety modes:
    - OBSERVE (default): Read-only. All write ops return "denied".
    - CONFIRM: Each write op requests user approval via ApprovalQueue.

    Emergency stop can be triggered via desktop_emergency_stop tool.
    """

    def __init__(
        self,
        approval_queue: Any | None = None,
        mode: DesktopMode = DesktopMode.OBSERVE,
        *,
        cell_backend: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
    ) -> None:
        self._guard: DesktopGuard | None = None
        self._approval_queue = approval_queue
        self._mode = mode
        self._cell_backend = cell_backend
        self._available = False
        self._init_error: str = ""

        # The explicit C2 harness backend is the only desktop authority in this
        # branch.  Do not even probe host permissions or construct a raw
        # controller: a Cell failure must remain a hard failure with no local
        # fallback.
        if cell_backend is not None:
            self._available = True
            return

        if not PermissionChecker.is_macos():
            self._init_error = "Desktop tools require macOS"
            return

        # Check system utilities. cliclick is optional — PyObjC Quartz is primary.
        import shutil
        missing = []
        if not shutil.which("screencapture"):
            missing.append("screencapture (built-in macOS, check system)")

        # Detect native Quartz backend (no brew needed)
        _has_native = False
        try:
            from . import controller_native  # type: ignore[attr-defined]
            controller_native._init_quartz()
            _has_native = controller_native._QUARTZ_AVAILABLE
        except Exception:
            _has_native = False

        if not _has_native and not shutil.which("cliclick"):
            missing.append("mouse backend (pip install pyobjc-framework-Quartz or brew install cliclick)")

        if "screencapture" in " ".join(missing):
            self._init_error = f"Missing: {'; '.join(missing)}"
            logger.warning(self._init_error)
            return

        try:
            self._guard = DesktopGuard(mode=mode, approval_queue=approval_queue)
            self._available = True
            self._init_error = "; ".join(missing) if missing else ""
        except Exception as e:
            self._init_error = f"Desktop initialization failed: {e}"
            logger.warning(self._init_error)

    @property
    def available(self) -> bool:
        return self._available

    @property
    def init_error(self) -> str:
        return self._init_error

    def set_mode(self, mode: DesktopMode) -> ToolResult:
        if self._cell_backend is not None:
            return ToolResult(
                success=False,
                error="Desktop Cell mode changes require authenticated tool dispatch",
            )
        if self._guard is None:
            return ToolResult(
                success=False,
                error=f"Desktop control not available. {self._init_error}. "
                      "Install missing dependencies and restart."
            )
        try:
            self._guard.mode = mode
            self._mode = mode
            return ToolResult(success=True, output=f"Desktop mode set to {mode.value}")
        except Exception as e:
            return ToolResult(success=False, error=str(e))

    # ── Staged registration ──

    _write_tools_registered: bool = False

    @property
    def write_tools_registered(self) -> bool:
        return self._write_tools_registered

    def get_read_only_specs(self) -> list[ToolSpec]:
        """Read-only and diagnostic tools — safe to register on first enable."""
        # ToolRegistry caches every ``read_only`` result.  A Cell observation
        # creates a fresh StateWitness/target binding, so the explicit C2 path
        # must execute every observation while the default local path keeps its
        # existing retry/cache classification.
        cacheable_observation = self._cell_backend is None
        return [
            ToolSpec(name="desktop_get_permissions",
                     description="Check macOS desktop control readiness: platform, permissions, dependency status. Use this FIRST.",
                     parameters=[], read_only=cacheable_observation),
            ToolSpec(name="desktop_get_state",
                     description="Get desktop state: availability, init errors, mouse position.",
                     parameters=[], read_only=cacheable_observation),
            ToolSpec(name="desktop_screenshot",
                     description="Capture a screenshot of the macOS desktop or a region. Requires Screen Recording permission.",
                     parameters=[
                         ToolParam("x", "integer", "X of top-left", required=False),
                         ToolParam("y", "integer", "Y of top-left", required=False),
                         ToolParam("width", "integer", "Region width", required=False),
                         ToolParam("height", "integer", "Region height", required=False),
                         ToolParam("show_cursor", "boolean", "Include cursor", required=False),
                     ], read_only=cacheable_observation),
            ToolSpec(name="desktop_list",
                     description="List running applications or windows on macOS.",
                     parameters=[
                         ToolParam("target", "string", "'apps' or 'windows'", enum=["apps", "windows"]),
                         ToolParam("app_name", "string", "Filter windows by app name", required=False),
                     ], read_only=cacheable_observation),
            ToolSpec(name="desktop_operation_log",
                     description="Get the audit log of recent desktop operations.",
                     parameters=[ToolParam("limit", "integer", "Max entries", required=False)],
                     read_only=cacheable_observation),
            ToolSpec(name="desktop_emergency_stop",
                     description="Trigger emergency stop to immediately halt ALL desktop operations.",
                     parameters=[ToolParam("reason", "string", "Reason for stop", required=False)],
                     dangerous=True),
            ToolSpec(name="desktop_clear_stop",
                     description="Clear emergency stop to resume operations.",
                     parameters=[], dangerous=True),
        ]

    def get_write_specs(self) -> list[ToolSpec]:
        """Write tools — require explicit user confirmation to register."""
        return [
            ToolSpec(name="desktop_click",
                     description="Click mouse at coordinates. DANGEROUS: requires approval.",
                     parameters=[
                         ToolParam("x", "integer", "X coordinate", required=False),
                         ToolParam("y", "integer", "Y coordinate", required=False),
                         ToolParam("button", "string", "left/right/middle", enum=["left", "right", "middle"], required=False),
                         ToolParam("clicks", "integer", "1 or 2", required=False),
                     ], dangerous=True),
            ToolSpec(name="desktop_move",
                     description="Move mouse cursor to coordinates. DANGEROUS.",
                     parameters=[ToolParam("x", "integer", "X"), ToolParam("y", "integer", "Y")],
                     dangerous=True),
            ToolSpec(name="desktop_scroll",
                     description="Scroll mouse wheel. DANGEROUS.",
                     parameters=[
                         ToolParam("direction", "string", "up/down/left/right", enum=["up", "down", "left", "right"]),
                         ToolParam("amount", "integer", "Scroll units", required=False),
                     ], dangerous=True),
            ToolSpec(name="desktop_drag",
                     description="Drag mouse from start to end. DANGEROUS.",
                     parameters=[
                         ToolParam("start_x", "integer", "Start X"), ToolParam("start_y", "integer", "Start Y"),
                         ToolParam("end_x", "integer", "End X"), ToolParam("end_y", "integer", "End Y"),
                         ToolParam("button", "string", "left/right/middle", enum=["left", "right", "middle"], required=False),
                     ], dangerous=True),
            ToolSpec(name="desktop_type",
                     description="Type text at cursor. DANGEROUS.",
                     parameters=[ToolParam("text", "string", "Text to type")],
                     dangerous=True),
            ToolSpec(name="desktop_key",
                     description="Press a key with optional modifiers. DANGEROUS.",
                     parameters=[
                         ToolParam("key", "string", "Key name (e.g. 'return', 'esc', 'a')"),
                         ToolParam("modifiers", "array", "e.g. ['cmd', 'shift']", required=False),
                     ], dangerous=True),
            ToolSpec(name="desktop_app",
                     description="Open/activate/quit an application. DANGEROUS for write actions.",
                     parameters=[
                         ToolParam("action", "string", "open/activate/quit/list", enum=["open", "activate", "quit", "list"]),
                         ToolParam("app_name", "string", "App name", required=False),
                     ], dangerous=True),
            ToolSpec(name="desktop_window",
                     description="Manage windows: list/activate/move/resize. DANGEROUS for write actions.",
                     parameters=[
                         ToolParam("action", "string", "list/activate/move/resize", enum=["list", "activate", "move", "resize"]),
                         ToolParam("app_name", "string", "App name", required=False),
                         ToolParam("window_title", "string", "Window title", required=False),
                         ToolParam("x", "integer", "X for move/resize", required=False),
                         ToolParam("y", "integer", "Y for move/resize", required=False),
                         ToolParam("width", "integer", "Width for resize", required=False),
                         ToolParam("height", "integer", "Height for resize", required=False),
                     ], dangerous=True),
            ToolSpec(name="desktop_set_mode",
                     description="Set desktop safety mode: 'observe' (read-only) or 'confirm' (approval needed).",
                     parameters=[ToolParam("mode", "string", "observe/confirm", enum=["observe", "confirm"])],
                     dangerous=True),
        ]

    def get_specs(self) -> list[ToolSpec]:
        """Return all currently-registered tool specs (diagnostic + read-only + optional write)."""
        return self.get_read_only_specs() + (self.get_write_specs() if self._write_tools_registered else [])


    # ── Handlers ──

    async def _call_cell_backend(
        self,
        tool: str,
        arguments: dict[str, Any],
        *,
        observed: bool | None = None,
    ) -> ToolResult:
        """Dispatch one existing desktop tool through the authenticated Cell path."""
        backend = self._cell_backend
        if backend is None:
            return ToolResult(success=False, error="Desktop Cell safety boundary unavailable")
        try:
            result = await asyncio.to_thread(
                backend,
                {"tool": tool, "arguments": arguments},
            )
        except Exception:  # noqa: BLE001 - Cell failure must never fall back locally
            return ToolResult(success=False, error="Desktop Cell safety boundary unavailable")

        if not isinstance(result, dict) or not set(result).issubset(
            {"status", "output", "projection"}
        ):
            return ToolResult(success=False, error="Desktop Cell denied request")
        expected_observation = tool in _CELL_OBSERVE_TOOLS if observed is None else observed
        expected_status = "OBSERVED" if expected_observation else "COMMITTED"
        if result.get("status") != expected_status:
            return ToolResult(success=False, error="Desktop Cell denied request")
        output = result.get("output", "")
        projection = result.get("projection", {})
        if type(output) is not str or len(output.encode("utf-8")) > 64 * 1024:
            return ToolResult(success=False, error="Desktop Cell denied request")
        if not isinstance(projection, dict) or not set(projection).issubset(
            _CELL_PROJECTION_KEYS
        ):
            return ToolResult(success=False, error="Desktop Cell denied request")
        try:
            projection = normalize_desktop_safe_projection(
                projection,
                effect_type=(
                    "desktop.observe" if expected_observation else "desktop.action"
                ),
            )
        except ProtocolError:
            return ToolResult(success=False, error="Desktop Cell denied request")
        observe_base = {
            "desktop_target_handle_id",
            "display_id",
            "height",
            "observed_at_ms",
            "owner_pid",
            "pixel_hash",
            "scale",
            "target_kind",
            "target_label",
            "width",
            "window_number",
        }
        observe_extras = {
            "desktop_app": {"apps"},
            "desktop_get_permissions": {
                "accessibility",
                "dependencies",
                "platform",
                "screen_recording",
            },
            "desktop_get_state": {"available", "mode", "mouse", "operation_count"},
            "desktop_list": {"apps", "windows"},
            "desktop_operation_log": {"operation_count"},
            "desktop_screenshot": {"image_base64", "image_mime_type"},
            "desktop_window": {"windows"},
        }
        permitted_projection = (
            observe_base | observe_extras.get(tool, set())
            if expected_observation
            else {"action", "after_digest", "before_digest", "receipt_id"}
        )
        if not set(projection).issubset(permitted_projection):
            return ToolResult(success=False, error="Desktop Cell denied request")
        if not _cell_projection_is_safe(projection):
            return ToolResult(success=False, error="Desktop Cell denied request")

        if not output:
            output = (
                "Desktop observation completed through Desktop Cell"
                if expected_observation
                else "Desktop action committed through Desktop Cell"
            )
        return ToolResult(
            success=True,
            output=output,
            metadata={"cell": "desktop", **projection},
        )

    async def _screenshot(
        self,
        x: int = 0,
        y: int = 0,
        width: int = 0,
        height: int = 0,
        show_cursor: bool = False,
    ) -> ToolResult:
        if self._cell_backend is not None:
            return await self._call_cell_backend(
                "desktop_screenshot",
                {
                    "x": x,
                    "y": y,
                    "width": width,
                    "height": height,
                    "show_cursor": show_cursor,
                },
            )
        if self._guard is None:
            return ToolResult(success=False, error=f"Desktop write ops unavailable: {self._init_error}")
        try:
            region = None
            if width > 0 and height > 0:
                region = ScreenRegion(x=x, y=y, width=width, height=height)
            result = self._guard.screenshot(
                region=region,
                format_="png",
                show_cursor=show_cursor,
            )
            return ToolResult(
                success=True,
                output=f"Screenshot captured. Path: {result.get('path', 'unknown')}",
                metadata={"base64": result.get("base64"), "path": result.get("path")},
            )
        except PermissionError as e:
            return ToolResult(success=False, error=f"Permission denied: {e}")
        except Exception as e:
            return ToolResult(success=False, error=f"Screenshot failed: {e}")

    async def _list(
        self,
        target: str = "apps",
        app_name: str | None = None,
    ) -> ToolResult:
        if self._cell_backend is not None:
            return await self._call_cell_backend(
                "desktop_list",
                {"target": target, "app_name": app_name},
            )
        if self._guard is None:
            return ToolResult(success=False, error=f"Desktop write ops unavailable: {self._init_error}")
        try:
            if target == "apps":
                result = self._guard.list_apps()
                apps = result.get("apps", [])
                lines = [f"Running applications ({len(apps)}):"]
                for a in apps:
                    active = " [ACTIVE]" if a.active else ""
                    lines.append(f"  - {a.name}{active}")
                return ToolResult(success=True, output="\n".join(lines))
            elif target == "windows":
                result = self._guard.list_windows(app_name=app_name)
                windows = result.get("windows", [])
                lines = [f"Windows ({len(windows)}):"]
                for w in windows:
                    lines.append(
                        f"  - [{w.app_name}] {w.title} "
                        f"({w.bounds.x},{w.bounds.y} {w.bounds.width}x{w.bounds.height})"
                    )
                return ToolResult(success=True, output="\n".join(lines))
            else:
                return ToolResult(success=False, error=f"Unknown target: {target}")
        except Exception as e:
            return ToolResult(success=False, error=f"List failed: {e}")

    async def _get_state(self) -> ToolResult:
        if self._cell_backend is not None:
            return await self._call_cell_backend("desktop_get_state", {})
        try:
            perms = PermissionChecker.get_status()
            pos_info = ""
            if self._guard is not None:
                try:
                    pos = self._guard.get_mouse_position()
                    pos_info = f"\nMouse: ({pos.x}, {pos.y})"
                except Exception:
                    pos_info = "\nMouse: (unavailable)"
            return ToolResult(
                success=True,
                output=(
                    f"Available: {self._available}\n"
                    f"Init error: {self._init_error or 'none'}\n"
                    f"Mode: {self._mode.value}\n"
                    f"Platform: macOS={perms.get('platform')}\n"
                    f"Accessibility: {perms.get('accessibility')}\n"
                    f"Screen Recording: {perms.get('screen_recording')}"
                    f"{pos_info}"
                ),
            )
        except Exception as e:
            return ToolResult(success=False, error=f"Get state failed: {e}")

    async def _get_permissions(self) -> ToolResult:
        if self._cell_backend is not None:
            return await self._call_cell_backend("desktop_get_permissions", {})
        try:
            perms = PermissionChecker.get_status()
            deps = []
            import shutil
            for dep in ["cliclick", "screencapture", "osascript"]:
                deps.append(f"{dep}: {'found' if shutil.which(dep) else 'MISSING'}")
            return ToolResult(
                success=True,
                output=(
                    f"Platform: macOS={perms.get('platform')}\n"
                    f"Accessibility: {perms.get('accessibility')}\n"
                    f"Screen Recording: {perms.get('screen_recording')}\n"
                    f"Dependencies: {'; '.join(deps)}\n"
                    f"Desktop control: {'ENABLED' if self._available else 'UNAVAILABLE'}"
                ),
            )
        except Exception as e:
            return ToolResult(success=False, error=f"Permission check failed: {e}")

    async def _click(
        self,
        x: int | None = None,
        y: int | None = None,
        button: str = "left",
        clicks: int = 1,
    ) -> ToolResult:
        if self._cell_backend is not None:
            return await self._call_cell_backend(
                "desktop_click",
                {"x": x, "y": y, "button": button, "clicks": clicks},
            )
        if self._guard is None:
            return ToolResult(success=False, error=f"Desktop write ops unavailable: {self._init_error}")
        try:
            point = Point(x=x, y=y) if x is not None and y is not None else None
            result = await self._guard.mouse_click(
                point=point,
                button=MouseButton(button),
                clicks=clicks,
            )
            if result.get("status") == "denied":
                return ToolResult(success=False, error=result.get("reason", "Operation denied"))
            return ToolResult(success=True, output=json.dumps(result))
        except PermissionError as e:
            return ToolResult(success=False, error=f"Permission denied: {e}")
        except Exception as e:
            return ToolResult(success=False, error=f"Click failed: {e}")

    async def _move(self, x: int, y: int) -> ToolResult:
        if self._cell_backend is not None:
            return await self._call_cell_backend(
                "desktop_move",
                {"x": x, "y": y},
            )
        if self._guard is None:
            return ToolResult(success=False, error=f"Desktop write ops unavailable: {self._init_error}")
        try:
            result = await self._guard.mouse_move(Point(x=x, y=y))
            if result.get("status") == "denied":
                return ToolResult(success=False, error=result.get("reason", "Operation denied"))
            return ToolResult(success=True, output=json.dumps(result))
        except PermissionError as e:
            return ToolResult(success=False, error=f"Permission denied: {e}")
        except Exception as e:
            return ToolResult(success=False, error=f"Move failed: {e}")

    async def _scroll(
        self,
        direction: str = "down",
        amount: int = 3,
    ) -> ToolResult:
        if self._cell_backend is not None:
            return await self._call_cell_backend(
                "desktop_scroll",
                {"direction": direction, "amount": amount},
            )
        if self._guard is None:
            return ToolResult(success=False, error=f"Desktop write ops unavailable: {self._init_error}")
        try:
            result = await self._guard.mouse_scroll(
                direction=ScrollDirection(direction),
                amount=amount,
            )
            if result.get("status") == "denied":
                return ToolResult(success=False, error=result.get("reason", "Operation denied"))
            return ToolResult(success=True, output=json.dumps(result))
        except PermissionError as e:
            return ToolResult(success=False, error=f"Permission denied: {e}")
        except Exception as e:
            return ToolResult(success=False, error=f"Scroll failed: {e}")

    async def _drag(
        self,
        start_x: int,
        start_y: int,
        end_x: int,
        end_y: int,
        button: str = "left",
    ) -> ToolResult:
        if self._cell_backend is not None:
            return await self._call_cell_backend(
                "desktop_drag",
                {
                    "start_x": start_x,
                    "start_y": start_y,
                    "end_x": end_x,
                    "end_y": end_y,
                    "button": button,
                },
            )
        if self._guard is None:
            return ToolResult(success=False, error=f"Desktop write ops unavailable: {self._init_error}")
        try:
            result = await self._guard.mouse_drag(
                start=Point(x=start_x, y=start_y),
                end=Point(x=end_x, y=end_y),
                button=MouseButton(button),
            )
            if result.get("status") == "denied":
                return ToolResult(success=False, error=result.get("reason", "Operation denied"))
            return ToolResult(success=True, output=json.dumps(result))
        except PermissionError as e:
            return ToolResult(success=False, error=f"Permission denied: {e}")
        except Exception as e:
            return ToolResult(success=False, error=f"Drag failed: {e}")

    async def _type(self, text: str) -> ToolResult:
        if self._cell_backend is not None:
            return await self._call_cell_backend("desktop_type", {"text": text})
        if self._guard is None:
            return ToolResult(success=False, error=f"Desktop write ops unavailable: {self._init_error}")
        try:
            result = await self._guard.type_text(text)
            if result.get("status") == "denied":
                return ToolResult(success=False, error=result.get("reason", "Operation denied"))
            return ToolResult(success=True, output=json.dumps(result))
        except PermissionError as e:
            return ToolResult(success=False, error=f"Permission denied: {e}")
        except Exception as e:
            return ToolResult(success=False, error=f"Type failed: {e}")

    async def _key(
        self,
        key: str,
        modifiers: list[str] | None = None,
    ) -> ToolResult:
        if self._cell_backend is not None:
            return await self._call_cell_backend(
                "desktop_key",
                {"key": key, "modifiers": modifiers},
            )
        if self._guard is None:
            return ToolResult(success=False, error=f"Desktop write ops unavailable: {self._init_error}")
        try:
            mods = [KeyModifier(m) for m in modifiers] if modifiers else None
            result = await self._guard.key_press(key=key, modifiers=mods)
            if result.get("status") == "denied":
                return ToolResult(success=False, error=result.get("reason", "Operation denied"))
            return ToolResult(success=True, output=json.dumps(result))
        except PermissionError as e:
            return ToolResult(success=False, error=f"Permission denied: {e}")
        except Exception as e:
            return ToolResult(success=False, error=f"Key press failed: {e}")

    async def _app(
        self,
        action: str = "list",
        app_name: str | None = None,
    ) -> ToolResult:
        if self._cell_backend is not None:
            return await self._call_cell_backend(
                "desktop_app",
                {"action": action, "app_name": app_name},
                observed=action == "list",
            )
        if self._guard is None:
            return ToolResult(success=False, error=f"Desktop write ops unavailable: {self._init_error}")
        try:
            result = await self._guard.app_action(
                action=AppAction(action),
                app_name=app_name,
            )
            if isinstance(result, dict) and result.get("status") == "denied":
                return ToolResult(success=False, error=result.get("reason", "Operation denied"))
            if action == "list":
                apps = result.get("apps", [])
                lines = [f"Applications ({len(apps)}):"]
                for a in apps:
                    active = " [ACTIVE]" if a.active else ""
                    lines.append(f"  - {a.name}{active}")
                return ToolResult(success=True, output="\n".join(lines))
            return ToolResult(success=True, output=json.dumps(result))
        except PermissionError as e:
            return ToolResult(success=False, error=f"Permission denied: {e}")
        except Exception as e:
            return ToolResult(success=False, error=f"App action failed: {e}")

    async def _window(
        self,
        action: str = "list",
        app_name: str | None = None,
        window_title: str | None = None,
        x: int = 0,
        y: int = 0,
        width: int = 0,
        height: int = 0,
    ) -> ToolResult:
        if self._cell_backend is not None:
            return await self._call_cell_backend(
                "desktop_window",
                {
                    "action": action,
                    "app_name": app_name,
                    "window_title": window_title,
                    "x": x,
                    "y": y,
                    "width": width,
                    "height": height,
                },
                observed=action == "list",
            )
        if self._guard is None:
            return ToolResult(success=False, error=f"Desktop write ops unavailable: {self._init_error}")
        try:
            bounds = None
            if width > 0 and height > 0:
                bounds = ScreenRegion(x=x, y=y, width=width, height=height)
            result = await self._guard.window_action(
                action=WindowAction(action),
                app_name=app_name,
                window_title=window_title,
                bounds=bounds,
            )
            if isinstance(result, dict) and result.get("status") == "denied":
                return ToolResult(success=False, error=result.get("reason", "Operation denied"))
            if action == "list":
                windows = result.get("windows", [])
                lines = [f"Windows ({len(windows)}):"]
                for w in windows:
                    lines.append(
                        f"  - [{w.app_name}] {w.title} "
                        f"({w.bounds.x},{w.bounds.y} {w.bounds.width}x{w.bounds.height})"
                    )
                return ToolResult(success=True, output="\n".join(lines))
            return ToolResult(success=True, output=json.dumps(result))
        except PermissionError as e:
            return ToolResult(success=False, error=f"Permission denied: {e}")
        except Exception as e:
            return ToolResult(success=False, error=f"Window action failed: {e}")

    async def _set_mode(self, mode: str) -> ToolResult:
        if self._cell_backend is not None:
            return await self._call_cell_backend("desktop_set_mode", {"mode": mode})
        return self.set_mode(DesktopMode(mode))

    async def _emergency_stop(self, reason: str = "User triggered") -> ToolResult:
        if self._cell_backend is not None:
            return await self._call_cell_backend(
                "desktop_emergency_stop",
                {"reason": reason},
            )
        if self._guard is None:
            return ToolResult(success=False, error=f"Desktop write ops unavailable: {self._init_error}")
        result = self._guard.trigger_emergency_stop(reason=reason)
        return ToolResult(success=True, output=f"Emergency stop triggered: {result['reason']}")

    async def _clear_stop(self) -> ToolResult:
        if self._cell_backend is not None:
            return await self._call_cell_backend("desktop_clear_stop", {})
        if self._guard is None:
            return ToolResult(success=False, error=f"Desktop write ops unavailable: {self._init_error}")
        self._guard.clear_emergency_stop()
        return ToolResult(success=True, output="Emergency stop cleared. Desktop operations can resume.")

    async def _operation_log(self, limit: int = 100) -> ToolResult:
        if self._cell_backend is not None:
            return await self._call_cell_backend(
                "desktop_operation_log",
                {"limit": limit},
            )
        if self._guard is None:
            return ToolResult(success=False, error=f"Desktop write ops unavailable: {self._init_error}")
        try:
            entries = self._guard.get_operation_log(limit=limit)
            return ToolResult(success=True, output=json.dumps(entries, indent=2))
        except Exception as e:
            return ToolResult(success=False, error=f"Failed to get log: {e}")

    def register_read_only(self, registry: Any) -> int:
        """Register diagnostic + read-only tools only. Returns count registered."""
        specs = self.get_read_only_specs()
        return self._register_specs(specs, registry)

    def register_write_tools(self, registry: Any) -> int:
        """Register write tools (click, type, key, app, window, etc.).

        Must be called AFTER explicit user confirmation.  Returns count.
        """
        if self._write_tools_registered:
            return 0
        specs = self.get_write_specs()
        count = self._register_specs(specs, registry)
        if count > 0:
            self._write_tools_registered = True
            logger.info(f"Registered {count} desktop write tools (user-confirmed)")
        return count

    def unregister_write_tools(self, registry: Any) -> int:
        """Unregister write tools. Returns count removed."""
        if not self._write_tools_registered:
            return 0
        count = 0
        for spec in self.get_write_specs():
            try:
                registry.unregister(spec.name)
                count += 1
            except Exception:
                pass
        self._write_tools_registered = False
        return count

    def _register_specs(self, specs: list[ToolSpec], registry: Any) -> int:
        handlers = {
            "desktop_screenshot": self._screenshot,
            "desktop_list": self._list,
            "desktop_get_state": self._get_state,
            "desktop_get_permissions": self._get_permissions,
            "desktop_click": self._click,
            "desktop_move": self._move,
            "desktop_scroll": self._scroll,
            "desktop_drag": self._drag,
            "desktop_type": self._type,
            "desktop_key": self._key,
            "desktop_app": self._app,
            "desktop_window": self._window,
            "desktop_set_mode": self._set_mode,
            "desktop_emergency_stop": self._emergency_stop,
            "desktop_clear_stop": self._clear_stop,
            "desktop_operation_log": self._operation_log,
        }
        count = 0
        for spec in specs:
            handler = handlers.get(spec.name)
            if handler:
                registry.register(spec, handler)
                count += 1
                logger.info(f"Registered desktop tool: {spec.name}")
            else:
                logger.warning(f"No handler for desktop tool: {spec.name}")
        return count

    def register_all(self, registry: Any) -> None:
        """Register diagnostic + read-only tools only. Write tools require confirmation."""
        self.register_read_only(registry)
