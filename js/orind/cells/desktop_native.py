"""Exact macOS desktop authority for the explicit WP-C2 harness.

This module deliberately does not import the legacy ``DesktopController``.
It resolves an Echo-safe selector to a concrete Accessibility/window identity
and is the sole action sink on the native C2 path.  Resolution and mutation
use only macOS AX, CoreGraphics and AppKit APIs; an unavailable API or an
ambiguous target is a hard failure and never selects another backend.

The production DesktopTools path does not import or instantiate this class.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import hashlib
import math
import os
import platform
import subprocess
import tempfile
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Protocol

from js.orin.desktop import (
    desktop_target_selector_for_action,
    normalize_desktop_action,
    normalize_desktop_target,
)
from js.orin.protocol import ProtocolError, canonical_json

_MAX_AX_DEPTH: Final[int] = 32
_MAX_AX_CHILDREN: Final[int] = 4_096
_MAX_PINNED_IDENTITIES: Final[int] = 2_048
_SCREENCAPTURE_PATHS: Final[tuple[str, ...]] = (
    "/usr/sbin/screencapture",
    "/usr/bin/screencapture",
)
_AX_OK: Final[int] = 0
_AX_VALUE_CGPOINT: Final[int] = 1
_AX_VALUE_CGSIZE: Final[int] = 2
_CF_STRING_ENCODING_UTF8: Final[int] = 0x08000100
_CF_NUMBER_DOUBLE: Final[int] = 13


class DesktopActionSink(Protocol):
    """The only native observe/mutate seam accepted by ``MacOSDesktopBackend``."""

    def resolve(
        self,
        selector: dict[str, Any],
        *,
        identity_scope: str | None = None,
    ) -> dict[str, Any]: ...

    def perform(
        self,
        action: dict[str, Any],
        *,
        expected_target: dict[str, Any],
        selector: dict[str, Any],
        identity_scope: str | None = None,
    ) -> None: ...

    def capture_pixels(
        self,
        *,
        region: Any | None,
        show_cursor: bool,
    ) -> dict[str, str]: ...

    def permission_status(self) -> dict[str, bool]: ...

    def pointer_position(self) -> tuple[int, int]: ...

    def display_bounds(self, display_id: int) -> tuple[int, list[int]]: ...

    def list_apps(self) -> list[dict[str, Any]]: ...

    def list_windows(self, app_name: str | None) -> list[dict[str, Any]]: ...


class _CGPoint(ctypes.Structure):
    _fields_ = [("x", ctypes.c_double), ("y", ctypes.c_double)]


class _CGSize(ctypes.Structure):
    _fields_ = [("width", ctypes.c_double), ("height", ctypes.c_double)]


@dataclass(frozen=True, slots=True)
class _WindowRow:
    window_id: int
    owner_pid: int
    owner_name: str
    title: str
    bounds: tuple[int, int, int, int]
    layer: int
    alpha: float


@dataclass(frozen=True, slots=True)
class _ResolvedElement:
    element: int
    target: dict[str, Any]


def _bounded_native_text(value: Any, *, fallback: str, maximum: int) -> str:
    text = str(value or fallback)
    if not text or len(text) > maximum:
        raise ProtocolError("native desktop identity text is invalid")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in text):
        raise ProtocolError("native desktop identity contains control text")
    return text


def _rounded_bounds(x: float, y: float, width: float, height: float) -> list[int]:
    values = (x, y, width, height)
    if any(not math.isfinite(value) for value in values) or width <= 0 or height <= 0:
        raise ProtocolError("native desktop target has invalid bounds")
    result = [round(x), round(y), round(width), round(height)]
    if result[2] <= 0 or result[3] <= 0:
        raise ProtocolError("native desktop target has empty bounds")
    if any(value < -32_768 or value > 32_768 for value in result[:2]) or any(
        value < 1 or value > 32_768 for value in result[2:]
    ):
        raise ProtocolError("native desktop target bounds exceed protocol limits")
    return result


def _point_inside(bounds: tuple[int, int, int, int] | list[int], x: int, y: int) -> bool:
    left, top, width, height = bounds
    return left <= x < left + width and top <= y < top + height


def _strict_native_target(target: Any) -> dict[str, Any]:
    """Validate the authority's JSON-only result before it reaches a package."""

    if not isinstance(target, dict):
        raise ProtocolError("native desktop target must be an object")
    required = {
        "kind",
        "display_id",
        "window_id",
        "owner_pid",
        "control_id",
        "bounds",
        "app_name",
        "bundle_id",
        "window_title",
        "control_role",
        "control_subrole",
        "control_identifier",
        "topmost_window_id",
    }
    optional = {
        "focused_control_id",
        "focused_owner_pid",
        "focused_window_id",
        "pointer_x",
        "pointer_y",
        "secondary_bounds",
        "secondary_control_id",
        "secondary_window_id",
        "secondary_owner_pid",
    }
    if not required.issubset(target) or not set(target).issubset(required | optional):
        raise ProtocolError("native desktop target fields are invalid")
    if target["kind"] not in {"application", "window", "control"}:
        raise ProtocolError("native desktop target kind is invalid")
    for field in ("display_id", "window_id", "owner_pid", "topmost_window_id"):
        value = target[field]
        if type(value) is not int or value <= 0:
            raise ProtocolError(f"native desktop {field} is invalid")
    if target["window_id"] != target["topmost_window_id"]:
        raise ProtocolError("native desktop target is not the topmost window")
    bounds = target["bounds"]
    if (
        not isinstance(bounds, list)
        or len(bounds) != 4
        or any(type(value) is not int for value in bounds)
        or bounds[2] <= 0
        or bounds[3] <= 0
    ):
        raise ProtocolError("native desktop target bounds are invalid")
    result = dict(target)
    result["bounds"] = list(bounds)
    for field, maximum in (
        ("control_id", 256),
        ("app_name", 256),
        ("bundle_id", 512),
        ("window_title", 512),
        ("control_role", 128),
        ("control_subrole", 128),
        ("control_identifier", 256),
        ("focused_control_id", 256),
        ("secondary_control_id", 256),
    ):
        if field in result:
            result[field] = _bounded_native_text(result[field], fallback="unknown", maximum=maximum)
    for field in (
        "focused_owner_pid",
        "focused_window_id",
        "secondary_window_id",
        "secondary_owner_pid",
    ):
        if field in result and (type(result[field]) is not int or result[field] <= 0):
            raise ProtocolError(f"native desktop {field} is invalid")
    for field in ("pointer_x", "pointer_y"):
        if field in result and (
            type(result[field]) is not int or not -32_768 <= result[field] <= 32_768
        ):
            raise ProtocolError(f"native desktop {field} is invalid")
    if "secondary_bounds" in result:
        secondary_bounds = result["secondary_bounds"]
        if (
            not isinstance(secondary_bounds, list)
            or len(secondary_bounds) != 4
            or any(type(value) is not int for value in secondary_bounds)
            or secondary_bounds[2] <= 0
            or secondary_bounds[3] <= 0
        ):
            raise ProtocolError("native desktop secondary bounds are invalid")
        result["secondary_bounds"] = list(secondary_bounds)
    return result


class _AXBridge:
    """Small ctypes bridge for AX symbols absent from PyObjC's Quartz module."""

    def __init__(self) -> None:
        app_services_path = ctypes.util.find_library("ApplicationServices")
        core_foundation_path = ctypes.util.find_library("CoreFoundation")
        if not app_services_path or not core_foundation_path:
            raise ProtocolError("macOS Accessibility frameworks are unavailable")
        try:
            self._ax = ctypes.CDLL(app_services_path)
            self._cf = ctypes.CDLL(core_foundation_path)
        except OSError as exc:
            raise ProtocolError("macOS Accessibility frameworks cannot be loaded") from exc

        pointer = ctypes.c_void_p
        pointer_out = ctypes.POINTER(pointer)
        self._ax.AXIsProcessTrusted.argtypes = []
        self._ax.AXIsProcessTrusted.restype = ctypes.c_bool
        self._ax.AXUIElementCreateSystemWide.argtypes = []
        self._ax.AXUIElementCreateSystemWide.restype = pointer
        self._ax.AXUIElementCreateApplication.argtypes = [ctypes.c_int32]
        self._ax.AXUIElementCreateApplication.restype = pointer
        self._ax.AXUIElementCopyElementAtPosition.argtypes = [
            pointer,
            ctypes.c_float,
            ctypes.c_float,
            pointer_out,
        ]
        self._ax.AXUIElementCopyElementAtPosition.restype = ctypes.c_int32
        self._ax.AXUIElementCopyAttributeValue.argtypes = [
            pointer,
            pointer,
            pointer_out,
        ]
        self._ax.AXUIElementCopyAttributeValue.restype = ctypes.c_int32
        self._ax.AXUIElementGetPid.argtypes = [pointer, ctypes.POINTER(ctypes.c_int32)]
        self._ax.AXUIElementGetPid.restype = ctypes.c_int32
        self._ax.AXUIElementPerformAction.argtypes = [pointer, pointer]
        self._ax.AXUIElementPerformAction.restype = ctypes.c_int32
        self._ax.AXUIElementSetAttributeValue.argtypes = [pointer, pointer, pointer]
        self._ax.AXUIElementSetAttributeValue.restype = ctypes.c_int32
        self._ax.AXValueGetType.argtypes = [pointer]
        self._ax.AXValueGetType.restype = ctypes.c_int32
        self._ax.AXValueGetValue.argtypes = [pointer, ctypes.c_int32, pointer]
        self._ax.AXValueGetValue.restype = ctypes.c_bool
        self._ax.AXValueCreate.argtypes = [ctypes.c_int32, pointer]
        self._ax.AXValueCreate.restype = pointer
        try:
            get_window = self._ax._AXUIElementGetWindow
        except AttributeError as exc:
            raise ProtocolError("exact AX window identity is unavailable") from exc
        get_window.argtypes = [pointer, ctypes.POINTER(ctypes.c_uint32)]
        get_window.restype = ctypes.c_int32
        self._get_window = get_window

        self._cf.CFStringCreateWithCString.argtypes = [
            pointer,
            ctypes.c_char_p,
            ctypes.c_uint32,
        ]
        self._cf.CFStringCreateWithCString.restype = pointer
        self._cf.CFStringGetLength.argtypes = [pointer]
        self._cf.CFStringGetLength.restype = ctypes.c_long
        self._cf.CFStringGetMaximumSizeForEncoding.argtypes = [
            ctypes.c_long,
            ctypes.c_uint32,
        ]
        self._cf.CFStringGetMaximumSizeForEncoding.restype = ctypes.c_long
        self._cf.CFStringGetCString.argtypes = [
            pointer,
            ctypes.c_char_p,
            ctypes.c_long,
            ctypes.c_uint32,
        ]
        self._cf.CFStringGetCString.restype = ctypes.c_bool
        self._cf.CFStringGetTypeID.argtypes = []
        self._cf.CFStringGetTypeID.restype = ctypes.c_ulong
        self._cf.CFNumberGetTypeID.argtypes = []
        self._cf.CFNumberGetTypeID.restype = ctypes.c_ulong
        self._cf.CFNumberGetValue.argtypes = [pointer, ctypes.c_int32, pointer]
        self._cf.CFNumberGetValue.restype = ctypes.c_bool
        self._cf.CFArrayGetTypeID.argtypes = []
        self._cf.CFArrayGetTypeID.restype = ctypes.c_ulong
        self._cf.CFArrayGetCount.argtypes = [pointer]
        self._cf.CFArrayGetCount.restype = ctypes.c_long
        self._cf.CFArrayGetValueAtIndex.argtypes = [pointer, ctypes.c_long]
        self._cf.CFArrayGetValueAtIndex.restype = pointer
        self._cf.CFGetTypeID.argtypes = [pointer]
        self._cf.CFGetTypeID.restype = ctypes.c_ulong
        self._cf.CFEqual.argtypes = [pointer, pointer]
        self._cf.CFEqual.restype = ctypes.c_bool
        self._cf.CFRetain.argtypes = [pointer]
        self._cf.CFRetain.restype = pointer
        self._cf.CFRelease.argtypes = [pointer]
        self._cf.CFRelease.restype = None

    def ensure_trusted(self) -> None:
        if not self._ax.AXIsProcessTrusted():
            raise ProtocolError("macOS Accessibility authority is unavailable")

    def release(self, value: int | None) -> None:
        if value:
            self._cf.CFRelease(ctypes.c_void_p(value))

    def retain(self, value: int) -> int:
        retained = self._cf.CFRetain(ctypes.c_void_p(value))
        if not retained:
            raise ProtocolError("macOS AX value could not be retained")
        return int(retained)

    def _cf_string(self, value: str) -> int:
        result = self._cf.CFStringCreateWithCString(
            None,
            value.encode("utf-8"),
            _CF_STRING_ENCODING_UTF8,
        )
        if not result:
            raise ProtocolError("macOS AX attribute name is unavailable")
        return int(result)

    def system_wide(self) -> int:
        self.ensure_trusted()
        element = self._ax.AXUIElementCreateSystemWide()
        if not element:
            raise ProtocolError("macOS system-wide AX object is unavailable")
        return int(element)

    def application(self, pid: int) -> int:
        self.ensure_trusted()
        element = self._ax.AXUIElementCreateApplication(pid)
        if not element:
            raise ProtocolError("macOS application AX object is unavailable")
        return int(element)

    def element_at(self, x: int, y: int) -> int:
        system = self.system_wide()
        try:
            output = ctypes.c_void_p()
            error = self._ax.AXUIElementCopyElementAtPosition(
                ctypes.c_void_p(system),
                float(x),
                float(y),
                ctypes.byref(output),
            )
            if error != _AX_OK or not output.value:
                raise ProtocolError("macOS AX hit-test did not resolve exactly one element")
            return int(output.value)
        finally:
            self.release(system)

    def _copy_attribute(self, element: int, name: str) -> int | None:
        attribute = self._cf_string(name)
        try:
            output = ctypes.c_void_p()
            error = self._ax.AXUIElementCopyAttributeValue(
                ctypes.c_void_p(element),
                ctypes.c_void_p(attribute),
                ctypes.byref(output),
            )
            if error != _AX_OK or not output.value:
                return None
            return int(output.value)
        finally:
            self.release(attribute)

    def text(self, element: int, name: str) -> str | None:
        value = self._copy_attribute(element, name)
        if value is None:
            return None
        try:
            if self._cf.CFGetTypeID(ctypes.c_void_p(value)) != self._cf.CFStringGetTypeID():
                return None
            length = self._cf.CFStringGetLength(ctypes.c_void_p(value))
            size = self._cf.CFStringGetMaximumSizeForEncoding(length, _CF_STRING_ENCODING_UTF8) + 1
            if size <= 0 or size > 16_385:
                raise ProtocolError("macOS AX string exceeds its bound")
            buffer = ctypes.create_string_buffer(size)
            if not self._cf.CFStringGetCString(
                ctypes.c_void_p(value),
                buffer,
                size,
                _CF_STRING_ENCODING_UTF8,
            ):
                raise ProtocolError("macOS AX string could not be decoded")
            return buffer.value.decode("utf-8")
        finally:
            self.release(value)

    def number(self, element: int, name: str) -> int | None:
        value = self._copy_attribute(element, name)
        if value is None:
            return None
        try:
            if self._cf.CFGetTypeID(ctypes.c_void_p(value)) != self._cf.CFNumberGetTypeID():
                return None
            output = ctypes.c_double()
            if not self._cf.CFNumberGetValue(
                ctypes.c_void_p(value),
                _CF_NUMBER_DOUBLE,
                ctypes.byref(output),
            ) or not math.isfinite(output.value):
                return None
            return round(output.value)
        finally:
            self.release(value)

    def element(self, element: int, name: str) -> int | None:
        return self._copy_attribute(element, name)

    def elements(self, element: int, name: str) -> list[int]:
        value = self._copy_attribute(element, name)
        if value is None:
            return []
        retained: list[int] = []
        try:
            if self._cf.CFGetTypeID(ctypes.c_void_p(value)) != self._cf.CFArrayGetTypeID():
                return []
            count = self._cf.CFArrayGetCount(ctypes.c_void_p(value))
            if count < 0 or count > _MAX_AX_CHILDREN:
                raise ProtocolError("macOS AX child list exceeds its bound")
            for index in range(count):
                child = self._cf.CFArrayGetValueAtIndex(ctypes.c_void_p(value), index)
                if not child:
                    raise ProtocolError("macOS AX child list contains an invalid element")
                retained.append(self.retain(int(child)))
            return retained
        except Exception:
            for child in retained:
                self.release(child)
            raise
        finally:
            self.release(value)

    def equal(self, left: int, right: int) -> bool:
        return bool(self._cf.CFEqual(ctypes.c_void_p(left), ctypes.c_void_p(right)))

    def pid(self, element: int) -> int:
        output = ctypes.c_int32()
        error = self._ax.AXUIElementGetPid(ctypes.c_void_p(element), ctypes.byref(output))
        if error != _AX_OK or output.value <= 0:
            raise ProtocolError("macOS AX owner PID is unavailable")
        return int(output.value)

    def window_id(self, element: int) -> int:
        output = ctypes.c_uint32()
        error = self._get_window(ctypes.c_void_p(element), ctypes.byref(output))
        if error != _AX_OK or output.value <= 0:
            raise ProtocolError("macOS AX window identity is unavailable")
        return int(output.value)

    def _point_value(self, element: int, name: str, value_type: int) -> tuple[float, float]:
        value = self._copy_attribute(element, name)
        if value is None:
            raise ProtocolError(f"macOS AX {name} is unavailable")
        try:
            if self._ax.AXValueGetType(ctypes.c_void_p(value)) != value_type:
                raise ProtocolError(f"macOS AX {name} has the wrong type")
            if value_type == _AX_VALUE_CGPOINT:
                output: _CGPoint | _CGSize = _CGPoint()
            else:
                output = _CGSize()
            if not self._ax.AXValueGetValue(
                ctypes.c_void_p(value), value_type, ctypes.byref(output)
            ):
                raise ProtocolError(f"macOS AX {name} could not be decoded")
            if isinstance(output, _CGPoint):
                return float(output.x), float(output.y)
            return float(output.width), float(output.height)
        finally:
            self.release(value)

    def bounds(self, element: int) -> list[int]:
        x, y = self._point_value(element, "AXPosition", _AX_VALUE_CGPOINT)
        width, height = self._point_value(element, "AXSize", _AX_VALUE_CGSIZE)
        return _rounded_bounds(x, y, width, height)

    def parent(self, element: int) -> int | None:
        return self.element(element, "AXParent")

    def child_index(self, parent: int, child: int) -> int:
        children = self.elements(parent, "AXChildren")
        try:
            matches = [
                index for index, candidate in enumerate(children) if self.equal(candidate, child)
            ]
            if len(matches) != 1:
                raise ProtocolError("macOS AX structural path is ambiguous")
            return matches[0]
        finally:
            for candidate in children:
                self.release(candidate)

    def set_point(self, element: int, name: str, x: float, y: float) -> None:
        structure: _CGPoint | _CGSize
        value_type: int
        if name == "AXPosition":
            structure = _CGPoint(x, y)
            value_type = _AX_VALUE_CGPOINT
        elif name == "AXSize":
            structure = _CGSize(x, y)
            value_type = _AX_VALUE_CGSIZE
        else:
            raise ProtocolError("unsupported macOS AX geometry attribute")
        value = self._ax.AXValueCreate(value_type, ctypes.byref(structure))
        if not value:
            raise ProtocolError("macOS AX geometry value is unavailable")
        attribute = self._cf_string(name)
        try:
            error = self._ax.AXUIElementSetAttributeValue(
                ctypes.c_void_p(element),
                ctypes.c_void_p(attribute),
                value,
            )
            if error != _AX_OK:
                raise ProtocolError("macOS AX geometry mutation was rejected")
        finally:
            self.release(attribute)
            self.release(int(value))

    def perform_action(self, element: int, action: str) -> None:
        action_name = self._cf_string(action)
        try:
            error = self._ax.AXUIElementPerformAction(
                ctypes.c_void_p(element), ctypes.c_void_p(action_name)
            )
            if error != _AX_OK:
                raise ProtocolError("macOS AX action was rejected")
        finally:
            self.release(action_name)


class MacOSAXActionSink:
    """Resolve exact AX identities and execute through one no-fallback sink."""

    def __init__(self) -> None:
        if platform.system() != "Darwin":
            raise ProtocolError("native desktop actions require macOS")
        try:
            import AppKit  # type: ignore[import-not-found,import-untyped]
            import Quartz  # type: ignore[import-not-found,import-untyped]
        except ImportError as exc:
            raise ProtocolError("native macOS desktop frameworks are unavailable") from exc
        self._appkit: Any = AppKit
        self._quartz: Any = Quartz
        self._ax = _AXBridge()
        self._lock = threading.RLock()
        self._pinned_elements: dict[str, int] = {}
        self._scope_keys: dict[str, set[str]] = {}

    def close(self) -> None:
        with self._lock:
            pinned = tuple(self._pinned_elements.values())
            self._pinned_elements.clear()
            self._scope_keys.clear()
        for element in pinned:
            self._ax.release(element)

    def __del__(self) -> None:  # pragma: no cover - interpreter shutdown best effort
        try:
            self.close()
        except Exception:
            pass

    def release_scope(self, identity_scope: str) -> None:
        with self._lock:
            keys = self._scope_keys.pop(identity_scope, set())
            pinned = [self._pinned_elements.pop(key) for key in keys]
        for element in pinned:
            self._ax.release(element)

    def _pin_element(self, key: str, element: int, *, identity_scope: str) -> None:
        pinned = self._pinned_elements.get(key)
        if pinned is None:
            if len(self._pinned_elements) >= _MAX_PINNED_IDENTITIES:
                raise ProtocolError("native desktop identity capacity is exhausted")
            self._pinned_elements[key] = self._ax.retain(element)
            self._scope_keys.setdefault(identity_scope, set()).add(key)
            return
        if not self._ax.equal(pinned, element):
            raise ProtocolError("native desktop AX object instance changed")

    @staticmethod
    def _pin_key(identity_scope: str, selector: dict[str, Any], role: str) -> str:
        return canonical_json(["orin:macos-ax-pin:v1", identity_scope, selector, role])

    @staticmethod
    def _ensure_screen_capture() -> None:
        core_graphics_path = ctypes.util.find_library("CoreGraphics")
        if not core_graphics_path:
            raise ProtocolError("macOS Screen Capture framework is unavailable")
        try:
            core_graphics = ctypes.CDLL(core_graphics_path)
            preflight = core_graphics.CGPreflightScreenCaptureAccess
        except (AttributeError, OSError) as exc:
            raise ProtocolError("macOS Screen Capture preflight is unavailable") from exc
        preflight.argtypes = []
        preflight.restype = ctypes.c_bool
        if not preflight():
            raise ProtocolError("macOS Screen Recording authority is unavailable")

    def capture_pixels(
        self,
        *,
        region: Any | None,
        show_cursor: bool,
    ) -> dict[str, str]:
        """Capture pixels without permission probes that mutate the clipboard."""

        self._ensure_screen_capture()
        executable = next(
            (
                candidate
                for candidate in _SCREENCAPTURE_PATHS
                if Path(candidate).is_file()
                and not Path(candidate).is_symlink()
                and os.access(candidate, os.X_OK)
            ),
            None,
        )
        if executable is None:
            raise ProtocolError("trusted macOS screencapture is unavailable")
        descriptor, raw_path = tempfile.mkstemp(prefix="orin-c2-", suffix=".png")
        os.close(descriptor)
        path = Path(raw_path)
        command = [executable, "-x"]
        if show_cursor:
            command.append("-C")
        if region is not None:
            coordinates = (region.x, region.y, region.width, region.height)
            if any(type(value) is not int for value in coordinates):
                path.unlink(missing_ok=True)
                raise ProtocolError("native desktop capture region is invalid")
            command.append("-R" + ",".join(str(value) for value in coordinates))
        command.extend(("-tpng", os.fspath(path)))
        try:
            completed = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=15,
                check=False,
                env={
                    "LANG": "C",
                    "LC_ALL": "C",
                    "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                },
            )
        except (OSError, subprocess.SubprocessError) as exc:
            path.unlink(missing_ok=True)
            raise ProtocolError("trusted macOS pixel capture failed") from exc
        if completed.returncode != 0 or not path.is_file():
            path.unlink(missing_ok=True)
            raise ProtocolError("trusted macOS pixel capture was rejected")
        return {"path": os.fspath(path), "base64": ""}

    def permission_status(self) -> dict[str, bool]:
        """Return direct OS preflight status without clipboard-based probes."""

        accessibility = True
        screen_recording = True
        try:
            self._ax.ensure_trusted()
        except ProtocolError:
            accessibility = False
        try:
            self._ensure_screen_capture()
        except ProtocolError:
            screen_recording = False
        return {
            "platform": platform.system() == "Darwin",
            "accessibility": accessibility,
            "screen_recording": screen_recording,
        }

    @staticmethod
    def _row_value(row: Mapping[Any, Any], module: Any, name: str, fallback: Any) -> Any:
        return row.get(getattr(module, name, name), row.get(name, fallback))

    def _window_rows(self) -> list[_WindowRow]:
        q = self._quartz
        try:
            rows = q.CGWindowListCopyWindowInfo(
                q.kCGWindowListOptionOnScreenOnly | q.kCGWindowListExcludeDesktopElements,
                q.kCGNullWindowID,
            )
        except Exception as exc:  # noqa: BLE001 - native observation fails closed
            raise ProtocolError("macOS window ordering is unavailable") from exc
        result: list[_WindowRow] = []
        for raw in rows or []:
            if not isinstance(raw, Mapping):
                raise ProtocolError("macOS window ordering returned an invalid row")
            bounds = self._row_value(raw, q, "kCGWindowBounds", {})
            if not isinstance(bounds, Mapping):
                continue
            window_id = int(self._row_value(raw, q, "kCGWindowNumber", 0))
            owner_pid = int(self._row_value(raw, q, "kCGWindowOwnerPID", 0))
            layer = int(self._row_value(raw, q, "kCGWindowLayer", 0))
            alpha = float(self._row_value(raw, q, "kCGWindowAlpha", 1.0))
            try:
                row_bounds = _rounded_bounds(
                    float(bounds.get("X", 0)),
                    float(bounds.get("Y", 0)),
                    float(bounds.get("Width", 0)),
                    float(bounds.get("Height", 0)),
                )
            except (ProtocolError, TypeError, ValueError):
                continue
            if window_id <= 0 or owner_pid <= 0 or alpha <= 0 or layer < 0:
                continue
            result.append(
                _WindowRow(
                    window_id=window_id,
                    owner_pid=owner_pid,
                    owner_name=_bounded_native_text(
                        self._row_value(raw, q, "kCGWindowOwnerName", "unknown"),
                        fallback="unknown",
                        maximum=256,
                    ),
                    title=_bounded_native_text(
                        self._row_value(raw, q, "kCGWindowName", "untitled"),
                        fallback="untitled",
                        maximum=512,
                    ),
                    bounds=(
                        row_bounds[0],
                        row_bounds[1],
                        row_bounds[2],
                        row_bounds[3],
                    ),
                    layer=layer,
                    alpha=alpha,
                )
            )
        return result

    def _row_by_id(self, window_id: int) -> _WindowRow:
        matches = [row for row in self._window_rows() if row.window_id == window_id]
        if len(matches) != 1:
            raise ProtocolError("macOS window identity is not uniquely observable")
        return matches[0]

    def _topmost_at(self, x: int, y: int) -> _WindowRow:
        # CGWindowListCopyWindowInfo is front-to-back.  Do not sort it.
        for row in self._window_rows():
            if _point_inside(row.bounds, x, y):
                return row
        raise ProtocolError("macOS point has no uniquely observable topmost window")

    def _display_id(self, x: int, y: int) -> int:
        try:
            error, displays, count = self._quartz.CGGetDisplaysWithPoint(
                (float(x), float(y)), 16, None, None
            )
        except Exception as exc:  # noqa: BLE001 - display ambiguity fails closed
            raise ProtocolError("macOS display identity is unavailable") from exc
        if error != 0 or count != 1 or len(displays) != 1:
            raise ProtocolError("macOS point does not resolve to exactly one display")
        display_id = int(displays[0])
        if display_id <= 0:
            raise ProtocolError("macOS display identity is invalid")
        return display_id

    def _application_metadata(self, pid: int) -> tuple[str, str]:
        try:
            application = (
                self._appkit.NSRunningApplication.runningApplicationWithProcessIdentifier_(pid)
            )
            if application is None:
                raise ValueError("application not running")
            name = _bounded_native_text(
                application.localizedName(), fallback="unknown", maximum=256
            )
            bundle_id = _bounded_native_text(
                application.bundleIdentifier(), fallback="pid-only", maximum=512
            )
            if int(application.processIdentifier()) != pid:
                raise ValueError("application PID changed")
            return name, bundle_id
        except ProtocolError:
            raise
        except Exception as exc:  # noqa: BLE001 - native identity fails closed
            raise ProtocolError("macOS application identity is unavailable") from exc

    def _path_material(self, element: int) -> tuple[list[dict[str, Any]], str, str, str]:
        path: list[dict[str, Any]] = []
        leaf_identity: tuple[str, str, str] | None = None
        current = self._ax.retain(element)
        try:
            for depth in range(_MAX_AX_DEPTH):
                role = _bounded_native_text(
                    self._ax.text(current, "AXRole"), fallback="AXUnknown", maximum=128
                )
                subrole = _bounded_native_text(
                    self._ax.text(current, "AXSubrole"),
                    fallback="AXUnknown",
                    maximum=128,
                )
                identifier = _bounded_native_text(
                    self._ax.text(current, "AXIdentifier"),
                    fallback="unidentified",
                    maximum=256,
                )
                if depth == 0:
                    leaf_identity = (role, subrole, identifier)
                item: dict[str, Any] = {
                    "role": role,
                    "subrole": subrole,
                    "identifier": identifier,
                    "bounds": self._ax.bounds(current),
                }
                parent = self._ax.parent(current)
                if parent is None:
                    if role != "AXWindow":
                        raise ProtocolError("macOS AX target has no complete window path")
                    if leaf_identity is None:
                        raise ProtocolError("macOS AX target has no leaf identity")
                    item["index"] = 0
                    path.append(item)
                    return path, *leaf_identity
                try:
                    try:
                        item["index"] = self._ax.child_index(parent, current)
                    except ProtocolError:
                        # AX windows are application children but some apps do not expose
                        # AXChildren.  The exact CG window id remains authoritative here.
                        if role != "AXWindow":
                            raise
                        item["index"] = 0
                    path.append(item)
                    if role == "AXWindow":
                        if leaf_identity is None:
                            raise ProtocolError("macOS AX target has no leaf identity")
                        return path, *leaf_identity
                    self._ax.release(current)
                    current = parent
                    parent = None
                finally:
                    self._ax.release(parent)
            raise ProtocolError("macOS AX structural path exceeds its depth bound")
        finally:
            self._ax.release(current)

    def _target_for_element(
        self,
        element: int,
        *,
        topmost: _WindowRow,
        display_id: int,
    ) -> dict[str, Any]:
        pid = self._ax.pid(element)
        window_id = self._ax.window_id(element)
        row = self._row_by_id(window_id)
        if (
            pid != row.owner_pid
            or row.window_id != topmost.window_id
            or row.owner_pid != topmost.owner_pid
        ):
            raise ProtocolError("macOS AX target is not in the exact topmost window")
        app_name, bundle_id = self._application_metadata(pid)
        path, role, subrole, identifier = self._path_material(element)
        bounds = self._ax.bounds(element)
        digest = hashlib.sha256(
            canonical_json(
                [
                    "orin:macos-ax-control:v1",
                    pid,
                    bundle_id,
                    window_id,
                    path,
                ]
            ).encode("utf-8")
        ).hexdigest()
        return _strict_native_target(
            {
                "kind": "window" if role == "AXWindow" else "control",
                "display_id": display_id,
                "window_id": window_id,
                "owner_pid": pid,
                "control_id": f"ax:{digest}",
                "bounds": bounds,
                "app_name": app_name,
                "bundle_id": bundle_id,
                "window_title": row.title,
                "control_role": role,
                "control_subrole": subrole,
                "control_identifier": identifier,
                "topmost_window_id": topmost.window_id,
            }
        )

    def _resolve_point_element(self, x: int, y: int) -> _ResolvedElement:
        topmost = self._topmost_at(x, y)
        element = self._ax.element_at(x, y)
        try:
            target = self._target_for_element(
                element,
                topmost=topmost,
                display_id=self._display_id(x, y),
            )
            if not _point_inside(target["bounds"], x, y):
                raise ProtocolError("macOS AX hit-test returned an element outside the point")
            if target["kind"] != "control":
                raise ProtocolError("macOS point did not resolve to an exact AX control")
            return _ResolvedElement(element=element, target=target)
        except Exception:
            self._ax.release(element)
            raise

    def _pointer(self) -> tuple[int, int]:
        try:
            event = self._quartz.CGEventCreate(None)
            if event is None:
                raise ValueError("CGEventCreate failed")
            point = self._quartz.CGEventGetLocation(event)
            return round(float(point.x)), round(float(point.y))
        except Exception as exc:  # noqa: BLE001 - native pointer read fails closed
            raise ProtocolError("macOS pointer position is unavailable") from exc

    def pointer_position(self) -> tuple[int, int]:
        return self._pointer()

    def display_bounds(self, display_id: int) -> tuple[int, list[int]]:
        try:
            resolved_id = display_id or int(self._quartz.CGMainDisplayID())
            raw = self._quartz.CGDisplayBounds(resolved_id)
            bounds = [
                int(raw.origin.x),
                int(raw.origin.y),
                int(raw.size.width),
                int(raw.size.height),
            ]
        except Exception as exc:  # noqa: BLE001 - display ambiguity fails closed
            raise ProtocolError("trusted macOS display bounds are unavailable") from exc
        if bounds[2] <= 0 or bounds[3] <= 0 or resolved_id <= 0:
            raise ProtocolError("trusted macOS display bounds are invalid")
        return int(resolved_id), bounds

    def list_apps(self) -> list[dict[str, Any]]:
        try:
            applications = self._appkit.NSWorkspace.sharedWorkspace().runningApplications()
        except Exception as exc:  # noqa: BLE001 - inventory fails closed
            raise ProtocolError("macOS application inventory is unavailable") from exc
        front = self._appkit.NSWorkspace.sharedWorkspace().frontmostApplication()
        front_pid = int(front.processIdentifier()) if front is not None else 0
        result: list[dict[str, Any]] = []
        seen: set[str] = set()
        for application in applications or []:
            try:
                bundle_id = _bounded_native_text(
                    application.bundleIdentifier(), fallback="", maximum=512
                )
                name = _bounded_native_text(
                    application.localizedName(), fallback="unknown", maximum=256
                )
                pid = int(application.processIdentifier())
            except ProtocolError:
                continue
            except Exception:
                continue
            if not bundle_id or pid <= 0 or bundle_id in seen:
                continue
            seen.add(bundle_id)
            result.append(
                {
                    "name": name,
                    "bundle_id": bundle_id,
                    "active": pid == front_pid,
                }
            )
            if len(result) >= 128:
                break
        return result

    def list_windows(self, app_name: str | None) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for row in self._window_rows():
            if row.layer != 0:
                continue
            if app_name and row.owner_name != app_name:
                continue
            result.append(
                {
                    "app_name": row.owner_name,
                    "title": row.title,
                    "bounds": list(row.bounds),
                }
            )
            if len(result) >= 128:
                break
        return result

    def window_facts(self, window_id: int) -> dict[str, Any]:
        row = self._row_by_id(window_id)
        left, top, width, height = row.bounds
        app_name, bundle_id = self._application_metadata(row.owner_pid)
        if not bundle_id or bundle_id == "pid-only":
            raise ProtocolError("macOS window application bundle is unavailable")
        return {
            "kind": "window",
            "display_id": self._display_id(left + width // 2, top + height // 2),
            "window_id": row.window_id,
            "owner_pid": row.owner_pid,
            "control_id": "window",
            "bounds": list(row.bounds),
            "app_name": app_name or row.owner_name,
            "bundle_id": bundle_id,
            "window_title": row.title,
        }

    def _focused_element(self) -> _ResolvedElement:
        system = self._ax.system_wide()
        try:
            element = self._ax.element(system, "AXFocusedUIElement")
        finally:
            self._ax.release(system)
        if element is None:
            raise ProtocolError("macOS focused AX element is unavailable")
        try:
            pid = self._ax.pid(element)
            application = self._appkit.NSWorkspace.sharedWorkspace().frontmostApplication()
            if application is None or int(application.processIdentifier()) != pid:
                raise ProtocolError("macOS AX focus does not match the frontmost application")
            window_id = self._ax.window_id(element)
            row = self._row_by_id(window_id)
            normal_rows = [candidate for candidate in self._window_rows() if candidate.layer == 0]
            if not normal_rows or normal_rows[0].window_id != window_id:
                raise ProtocolError("macOS focused window is not topmost")
            left, top, width, height = row.bounds
            target = self._target_for_element(
                element,
                topmost=row,
                display_id=self._display_id(left + width // 2, top + height // 2),
            )
            if target["kind"] != "control":
                raise ProtocolError("macOS focus did not resolve to an exact AX control")
            target.update(
                {
                    "focused_owner_pid": target["owner_pid"],
                    "focused_window_id": target["window_id"],
                    "focused_control_id": target["control_id"],
                }
            )
            return _ResolvedElement(element=element, target=target)
        except Exception:
            self._ax.release(element)
            raise

    def _running_application(self, name: str) -> Any:
        try:
            applications = self._appkit.NSWorkspace.sharedWorkspace().runningApplications()
            matches = [
                app
                for app in applications
                if str(app.localizedName() or "") == name
                and int(app.processIdentifier()) > 0
                and str(app.bundleIdentifier() or "")
            ]
        except Exception as exc:  # noqa: BLE001 - native lookup fails closed
            raise ProtocolError("macOS running application inventory is unavailable") from exc
        if len(matches) != 1:
            raise ProtocolError("macOS application name is not uniquely running")
        return matches[0]

    def _window_element(self, pid: int, window_id: int) -> int:
        application = self._ax.application(pid)
        try:
            windows = self._ax.elements(application, "AXWindows")
        finally:
            self._ax.release(application)
        matches: list[int] = []
        try:
            for window in windows:
                try:
                    if self._ax.window_id(window) == window_id:
                        matches.append(window)
                except ProtocolError:
                    continue
            if len(matches) != 1:
                raise ProtocolError("macOS AX window is not uniquely addressable")
            result = self._ax.retain(matches[0])
            return result
        finally:
            for window in windows:
                self._ax.release(window)

    def _resolve_window_row(self, row: _WindowRow) -> _ResolvedElement:
        element = self._window_element(row.owner_pid, row.window_id)
        try:
            left, top, width, height = row.bounds
            target = self._target_for_element(
                element,
                topmost=row,
                display_id=self._display_id(left + width // 2, top + height // 2),
            )
            return _ResolvedElement(element=element, target=target)
        except Exception:
            self._ax.release(element)
            raise

    def _resolve_window_query(self, app_name: str, title: str) -> _ResolvedElement:
        matches = [
            row
            for row in self._window_rows()
            if row.owner_name == app_name and row.title == title and row.layer == 0
        ]
        if len(matches) != 1:
            raise ProtocolError("macOS window query is not unique")
        # A title match behind another normal window is not an actionable
        # topmost target.  This also rejects a same-title replacement.
        normal_rows = [row for row in self._window_rows() if row.layer == 0]
        if not normal_rows or normal_rows[0].window_id != matches[0].window_id:
            raise ProtocolError("macOS queried window is not globally topmost")
        return self._resolve_window_row(matches[0])

    def _resolve_application(self, app_name: str) -> _ResolvedElement:
        application = self._running_application(app_name)
        pid = int(application.processIdentifier())
        rows = [row for row in self._window_rows() if row.owner_pid == pid and row.layer == 0]
        if not rows:
            raise ProtocolError("macOS application has no exact visible target window")
        normal_rows = [row for row in self._window_rows() if row.layer == 0]
        if not normal_rows or normal_rows[0].window_id != rows[0].window_id:
            raise ProtocolError("macOS application target is not globally topmost")
        resolved = self._resolve_window_row(rows[0])
        target = dict(resolved.target)
        target["kind"] = "application"
        return _ResolvedElement(element=resolved.element, target=_strict_native_target(target))

    def _resolve_owned(self, selector: dict[str, Any]) -> _ResolvedElement:
        kind = selector["kind"]
        if kind == "point":
            return self._resolve_point_element(selector["x"], selector["y"])
        if kind == "pointer":
            x, y = self._pointer()
            resolved = self._resolve_point_element(x, y)
            target = dict(resolved.target)
            target.update({"pointer_x": x, "pointer_y": y})
            return _ResolvedElement(
                element=resolved.element,
                target=_strict_native_target(target),
            )
        if kind == "focused":
            return self._focused_element()
        if kind == "window_query":
            return self._resolve_window_query(selector["app_name"], selector["window_title"])
        if kind == "application":
            return self._resolve_application(selector["app_name"])
        raise ProtocolError("native desktop selector is unsupported")

    def resolve(
        self,
        selector: dict[str, Any],
        *,
        identity_scope: str | None = None,
    ) -> dict[str, Any]:
        normalized = normalize_desktop_target(selector)
        with self._lock:
            self._ax.ensure_trusted()
            if normalized["kind"] == "screen":
                raise ProtocolError("screen observation is not an action target")
            if normalized["kind"] == "drag":
                primary = self._resolve_point_element(normalized["start_x"], normalized["start_y"])
                try:
                    secondary = self._resolve_point_element(
                        normalized["end_x"], normalized["end_y"]
                    )
                    try:
                        target = dict(primary.target)
                        target.update(
                            {
                                "secondary_control_id": secondary.target["control_id"],
                                "secondary_window_id": secondary.target["window_id"],
                                "secondary_owner_pid": secondary.target["owner_pid"],
                                "secondary_bounds": list(secondary.target["bounds"]),
                            }
                        )
                        strict_target = _strict_native_target(target)
                        if identity_scope is not None:
                            self._pin_element(
                                self._pin_key(identity_scope, normalized, "primary"),
                                primary.element,
                                identity_scope=identity_scope,
                            )
                            self._pin_element(
                                self._pin_key(identity_scope, normalized, "secondary"),
                                secondary.element,
                                identity_scope=identity_scope,
                            )
                        return strict_target
                    finally:
                        self._ax.release(secondary.element)
                finally:
                    self._ax.release(primary.element)
            resolved = self._resolve_owned(normalized)
            try:
                strict_target = _strict_native_target(resolved.target)
                if identity_scope is not None:
                    self._pin_element(
                        self._pin_key(identity_scope, normalized, "primary"),
                        resolved.element,
                        identity_scope=identity_scope,
                    )
                return strict_target
            finally:
                self._ax.release(resolved.element)

    def _post_mouse(self, event_type: int, x: int, y: int, button: int) -> None:
        event = self._quartz.CGEventCreateMouseEvent(None, event_type, (float(x), float(y)), button)
        if event is None:
            raise ProtocolError("macOS native mouse event could not be created")
        self._quartz.CGEventPost(self._quartz.kCGHIDEventTap, event)

    def _perform_mouse(self, action: dict[str, Any]) -> None:
        q = self._quartz
        kind = action["kind"]
        if kind == "move":
            self._post_mouse(q.kCGEventMouseMoved, action["x"], action["y"], q.kCGMouseButtonLeft)
            return
        button = {
            "left": q.kCGMouseButtonLeft,
            "right": q.kCGMouseButtonRight,
            "middle": q.kCGMouseButtonCenter,
        }[action["button"]]
        down, moved, up = {
            "left": (q.kCGEventLeftMouseDown, q.kCGEventLeftMouseDragged, q.kCGEventLeftMouseUp),
            "right": (
                q.kCGEventRightMouseDown,
                q.kCGEventRightMouseDragged,
                q.kCGEventRightMouseUp,
            ),
            "middle": (
                q.kCGEventOtherMouseDown,
                q.kCGEventOtherMouseDragged,
                q.kCGEventOtherMouseUp,
            ),
        }[action["button"]]
        if kind == "drag":
            self._post_mouse(q.kCGEventMouseMoved, action["start_x"], action["start_y"], button)
            self._post_mouse(down, action["start_x"], action["start_y"], button)
            self._post_mouse(moved, action["end_x"], action["end_y"], button)
            self._post_mouse(up, action["end_x"], action["end_y"], button)
            return
        for click_count in range(1, action["clicks"] + 1):
            down_event = q.CGEventCreateMouseEvent(
                None,
                down,
                (float(action["x"]), float(action["y"])),
                button,
            )
            up_event = q.CGEventCreateMouseEvent(
                None,
                up,
                (float(action["x"]), float(action["y"])),
                button,
            )
            if down_event is None or up_event is None:
                raise ProtocolError("macOS native click event could not be created")
            q.CGEventSetIntegerValueField(down_event, q.kCGMouseEventClickState, click_count)
            q.CGEventSetIntegerValueField(up_event, q.kCGMouseEventClickState, click_count)
            q.CGEventPost(q.kCGHIDEventTap, down_event)
            q.CGEventPost(q.kCGHIDEventTap, up_event)

    def _perform_scroll(self, action: dict[str, Any]) -> None:
        q = self._quartz
        vertical = action["direction"] in {"up", "down"}
        delta = action["amount"] if action["direction"] in {"up", "left"} else -action["amount"]
        event = q.CGEventCreateScrollWheelEvent(
            None,
            q.kCGScrollEventUnitLine,
            2,
            delta if vertical else 0,
            0 if vertical else delta,
        )
        if event is None:
            raise ProtocolError("macOS native scroll event could not be created")
        q.CGEventPost(q.kCGHIDEventTap, event)

    def _perform_type(self, text: str) -> None:
        q = self._quartz
        units_raw = text.encode("utf-16-le")
        units = [
            int.from_bytes(units_raw[index : index + 2], "little")
            for index in range(0, len(units_raw), 2)
        ]
        down = q.CGEventCreateKeyboardEvent(None, 0, True)
        up = q.CGEventCreateKeyboardEvent(None, 0, False)
        if down is None or up is None:
            raise ProtocolError("macOS native text event could not be created")
        q.CGEventKeyboardSetUnicodeString(down, len(units), units)
        q.CGEventKeyboardSetUnicodeString(up, len(units), units)
        q.CGEventPost(q.kCGHIDEventTap, down)
        q.CGEventPost(q.kCGHIDEventTap, up)

    @staticmethod
    def _keycode(key: str) -> int:
        codes = {
            "return": 0x24,
            "enter": 0x4C,
            "tab": 0x30,
            "space": 0x31,
            "delete": 0x33,
            "backspace": 0x33,
            "escape": 0x35,
            "left": 0x7B,
            "right": 0x7C,
            "down": 0x7D,
            "up": 0x7E,
            "home": 0x73,
            "end": 0x77,
            "pageup": 0x74,
            "pagedown": 0x79,
        }
        letters = {
            "a": 0x00,
            "s": 0x01,
            "d": 0x02,
            "f": 0x03,
            "h": 0x04,
            "g": 0x05,
            "z": 0x06,
            "x": 0x07,
            "c": 0x08,
            "v": 0x09,
            "b": 0x0B,
            "q": 0x0C,
            "w": 0x0D,
            "e": 0x0E,
            "r": 0x0F,
            "y": 0x10,
            "t": 0x11,
            "o": 0x1F,
            "u": 0x20,
            "i": 0x22,
            "p": 0x23,
            "l": 0x25,
            "j": 0x26,
            "k": 0x28,
            "n": 0x2D,
            "m": 0x2E,
        }
        result = codes.get(key.lower(), letters.get(key.lower()))
        if result is None:
            raise ProtocolError("macOS native key has no exact keycode")
        return result

    def _perform_key(self, action: dict[str, Any]) -> None:
        q = self._quartz
        flags = 0
        flag_by_name = {
            "cmd": q.kCGEventFlagMaskCommand,
            "option": q.kCGEventFlagMaskAlternate,
            "ctrl": q.kCGEventFlagMaskControl,
            "shift": q.kCGEventFlagMaskShift,
            "fn": q.kCGEventFlagMaskSecondaryFn,
        }
        for modifier in action["modifiers"]:
            flags |= int(flag_by_name[modifier])
        keycode = self._keycode(action["key"])
        down = q.CGEventCreateKeyboardEvent(None, keycode, True)
        up = q.CGEventCreateKeyboardEvent(None, keycode, False)
        if down is None or up is None:
            raise ProtocolError("macOS native key event could not be created")
        q.CGEventSetFlags(down, flags)
        q.CGEventSetFlags(up, flags)
        q.CGEventPost(q.kCGHIDEventTap, down)
        q.CGEventPost(q.kCGHIDEventTap, up)

    def _perform_app(self, action: dict[str, Any], expected_target: dict[str, Any]) -> None:
        application = self._appkit.NSRunningApplication.runningApplicationWithProcessIdentifier_(
            expected_target["owner_pid"]
        )
        if (
            application is None
            or str(application.bundleIdentifier() or "") != expected_target["bundle_id"]
            or str(application.localizedName() or "") != action["app_name"]
        ):
            raise ProtocolError("macOS application identity changed before action")
        if action["action"] in {"open", "activate"}:
            if not application.activateWithOptions_(
                self._appkit.NSApplicationActivateIgnoringOtherApps
            ):
                raise ProtocolError("macOS application activation was rejected")
            return
        if not application.terminate():
            raise ProtocolError("macOS application termination was rejected")

    def _perform_window(self, action: dict[str, Any], expected_target: dict[str, Any]) -> None:
        window = self._window_element(expected_target["owner_pid"], expected_target["window_id"])
        try:
            if action["action"] == "activate":
                self._ax.perform_action(window, "AXRaise")
            elif action["action"] == "move":
                self._ax.set_point(window, "AXPosition", action["x"], action["y"])
            else:
                self._ax.set_point(window, "AXSize", action["width"], action["height"])
        finally:
            self._ax.release(window)

    def perform(
        self,
        action: dict[str, Any],
        *,
        expected_target: dict[str, Any],
        selector: dict[str, Any],
        identity_scope: str | None = None,
    ) -> None:
        normalized_action = normalize_desktop_action(action)
        normalized_selector = normalize_desktop_target(selector)
        required_selector = desktop_target_selector_for_action(normalized_action)
        if normalized_selector != required_selector:
            raise ProtocolError("native desktop action selector does not match the action")
        if not isinstance(expected_target, dict):
            raise ProtocolError("native desktop expected target must be an object")
        expected_identity = dict(expected_target)
        # The backend adds the capture's point-to-pixel scale after this sink
        # resolves AX identity.  Pixel hash/dimensions are checked by the
        # backend before entering this method; scale is therefore observation
        # evidence, not part of the authority identity re-resolution.
        scale = expected_identity.pop("scale", None)
        if scale is not None and (
            type(scale) not in {int, float} or not 0.25 <= float(scale) <= 8.0
        ):
            raise ProtocolError("native desktop expected scale is invalid")
        trusted_expected = _strict_native_target(expected_identity)
        with self._lock:
            current = self.resolve(
                normalized_selector,
                identity_scope=identity_scope,
            )
            if canonical_json(current) != canonical_json(trusted_expected):
                raise ProtocolError("native desktop target changed before action")
            kind = normalized_action["kind"]
            if kind == "app" and normalized_action["action"] == "quit":
                raise ProtocolError("native application quit lacks a reconcilable post-observation")
            try:
                if kind in {"click", "move", "drag"}:
                    self._perform_mouse(normalized_action)
                elif kind == "scroll":
                    self._perform_scroll(normalized_action)
                elif kind == "type":
                    self._perform_type(normalized_action["text"])
                elif kind == "key":
                    self._perform_key(normalized_action)
                elif kind == "app":
                    self._perform_app(normalized_action, trusted_expected)
                elif kind == "window":
                    self._perform_window(normalized_action, trusted_expected)
                else:
                    raise ProtocolError("native desktop action is unsupported")
            except ProtocolError:
                raise
            except Exception as exc:  # noqa: BLE001 - no alternate backend is allowed
                raise ProtocolError("single native desktop action sink failed") from exc


__all__ = ["DesktopActionSink", "MacOSAXActionSink"]
