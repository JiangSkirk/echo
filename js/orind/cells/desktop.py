"""Strict Desktop Cell for WP-C2 observe -> act -> observe execution.

The Cell owns every macOS Screen Recording/Accessibility object on the C2
construction path.  Echo proposes only a small target selector and an exact
action.  A trusted observation creates a private report and a Cell-sealed
``DesktopTargetHandle``; the handle can subsequently authorize one action
only while the complete observed state remains unchanged.

The deterministic :class:`ScriptedDesktopBackend` is protocol evidence for
the explicit C2 test harness.  It is not native-pixel or real-model evidence.
The default product desktop path is deliberately not wired to this module.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import io
import json
import os
import secrets
import stat
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Protocol

from js.orin.desktop import (
    DesktopTargetBindingV1,
    derive_desktop_target_handle_id,
    desktop_target_binding_from_dict,
    normalize_desktop_action,
    normalize_desktop_observe_arguments,
    normalize_desktop_target,
)
from js.orin.draft import CellPackage, CommitPermit, Impact, StateWitness
from js.orin.handles import OriginHandle
from js.orin.protocol import ProtocolError, canonical_json
from js.orind.cells.base import CellBase

_SCRIPT_SCHEMA: Final[str] = "DesktopScriptV1"
_OBSERVATION_SCHEMA: Final[str] = "DesktopObservationV1"
_OBSERVATION_REPORT_SCHEMA: Final[str] = "DesktopObservationReportV1"
_ACTION_REPORT_SCHEMA: Final[str] = "DesktopActionReportV1"
_WITNESS_TTL_MS: Final[int] = 60_000
_MAX_SCRIPT_BYTES: Final[int] = 512 * 1024
_MAX_ACTIONS: Final[int] = 1_024
_MAX_PRIVATE_REPORTS: Final[int] = 1_024
_MAX_IMAGE_PROJECTION_BYTES: Final[int] = 32 * 1024


def _now_ms() -> int:
    return time.time_ns() // 1_000_000


def _sha256(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _strict_sha256(value: Any, field: str) -> str:
    if (
        type(value) is not str
        or len(value) != 71
        or not value.startswith("sha256:")
        or any(char not in "0123456789abcdef" for char in value[7:])
    ):
        raise ProtocolError(f"{field} must be sha256:<64 hex>")
    return value


def _strict_int(value: Any, field: str, *, lo: int, hi: int) -> int:
    if type(value) is not int or not lo <= value <= hi:
        raise ProtocolError(f"{field} must be an integer in {lo}..{hi}")
    return value


def _strict_text(value: Any, field: str, *, max_len: int) -> str:
    if type(value) is not str or not value or len(value) > max_len:
        raise ProtocolError(f"{field} must be a bounded string")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        raise ProtocolError(f"{field} contains control text")
    return value


def _target_facts(data: Any) -> dict[str, Any]:
    """Parse Cell-observed target facts, never an Echo selector."""

    if not isinstance(data, dict):
        raise ProtocolError("desktop observation target must be an object")
    required = {
        "kind",
        "display_id",
        "window_id",
        "owner_pid",
        "control_id",
        "bounds",
    }
    optional = {
        "app_name",
        "focused_app_name",
        "focused_control_id",
        "focused_owner_pid",
        "focused_window_id",
        "focused_window_title",
        "pointer_x",
        "pointer_y",
        "scale",
        "window_title",
    }
    if not required.issubset(data) or not set(data).issubset(required | optional):
        raise ProtocolError("desktop observation target fields are invalid")
    kind = data.get("kind")
    if kind not in {"screen", "window", "control"}:
        raise ProtocolError("desktop observation target kind is invalid")
    bounds = data.get("bounds")
    if (
        not isinstance(bounds, list)
        or len(bounds) != 4
        or any(type(value) is not int for value in bounds)
    ):
        raise ProtocolError("desktop observation target bounds are invalid")
    x, y, width, height = bounds
    _strict_int(x, "target x", lo=-32_768, hi=32_768)
    _strict_int(y, "target y", lo=-32_768, hi=32_768)
    _strict_int(width, "target width", lo=1, hi=32_768)
    _strict_int(height, "target height", lo=1, hi=32_768)
    result: dict[str, Any] = {
        "kind": kind,
        "display_id": _strict_int(
            data["display_id"], "target display_id", lo=0, hi=2**63 - 1
        ),
        "window_id": _strict_int(
            data["window_id"], "target window_id", lo=0, hi=2**63 - 1
        ),
        "owner_pid": _strict_int(
            data["owner_pid"], "target owner_pid", lo=0, hi=2**31 - 1
        ),
        "control_id": _strict_text(
            data["control_id"], "target control_id", max_len=256
        ),
        "bounds": [x, y, width, height],
    }
    if "app_name" in data:
        result["app_name"] = _strict_text(
            data["app_name"], "target app_name", max_len=256
        )
    if "window_title" in data:
        result["window_title"] = _strict_text(
            data["window_title"], "target window_title", max_len=512
        )
    if "scale" in data:
        scale = data["scale"]
        if type(scale) not in {int, float} or not 0.25 <= scale <= 8.0:
            raise ProtocolError("desktop target scale is invalid")
        result["scale"] = float(scale)
    for field in ("focused_owner_pid", "focused_window_id"):
        if field in data:
            result[field] = _strict_int(data[field], field, lo=0, hi=2**63 - 1)
    for field in ("pointer_x", "pointer_y"):
        if field in data:
            result[field] = _strict_int(data[field], field, lo=-32_768, hi=32_768)
    for field, maximum in (
        ("focused_app_name", 256),
        ("focused_control_id", 256),
        ("focused_window_title", 512),
    ):
        if field in data:
            result[field] = _strict_text(data[field], field, max_len=maximum)
    if kind == "screen" and (result["window_id"] or result["owner_pid"]):
        raise ProtocolError("screen target must not claim a window identity")
    if kind in {"window", "control"} and (
        result["window_id"] <= 0 or result["owner_pid"] <= 0
    ):
        raise ProtocolError("window/control target requires trusted window identity")
    return result


def _normalize_observe_request(request: dict[str, Any]) -> dict[str, Any]:
    """Close the shared request envelope over existing DesktopTools inputs."""

    tool = request["tool"]
    args = request["arguments"]
    if tool in {"desktop_get_permissions", "desktop_get_state"}:
        if args:
            raise ProtocolError(f"{tool} takes no arguments")
        return {"tool": tool, "arguments": {}}
    if tool == "desktop_screenshot":
        fields = {"x", "y", "width", "height", "show_cursor"}
        if set(args) != fields:
            raise ProtocolError("desktop_screenshot arguments are invalid")
        width = _strict_int(args["width"], "screenshot width", lo=0, hi=32_768)
        height = _strict_int(args["height"], "screenshot height", lo=0, hi=32_768)
        if (width == 0) != (height == 0):
            raise ProtocolError("screenshot width and height must both be zero or positive")
        if type(args["show_cursor"]) is not bool:
            raise ProtocolError("screenshot show_cursor must be boolean")
        return {
            "tool": tool,
            "arguments": {
                "x": _strict_int(args["x"], "screenshot x", lo=-32_768, hi=32_768),
                "y": _strict_int(args["y"], "screenshot y", lo=-32_768, hi=32_768),
                "width": width,
                "height": height,
                "show_cursor": args["show_cursor"],
            },
        }
    if tool == "desktop_list":
        if set(args) != {"target", "app_name"}:
            raise ProtocolError("desktop_list arguments are invalid")
        if args["target"] not in {"apps", "windows"}:
            raise ProtocolError("desktop_list target is invalid")
        app_name = args["app_name"]
        if app_name is not None:
            app_name = _strict_text(app_name, "desktop_list app_name", max_len=256)
        return {
            "tool": tool,
            "arguments": {"target": args["target"], "app_name": app_name},
        }
    if tool == "desktop_operation_log":
        if set(args) != {"limit"}:
            raise ProtocolError("desktop_operation_log arguments are invalid")
        return {
            "tool": tool,
            "arguments": {
                "limit": _strict_int(args["limit"], "operation log limit", lo=1, hi=100)
            },
        }
    raise ProtocolError("desktop observe tool is unsupported")


def _observation(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise ProtocolError("desktop backend observation must be an object")
    fields = {
        "schema",
        "revision",
        "target",
        "pixel_hash",
        "width",
        "height",
        "projection",
    }
    if set(data) != fields or data.get("schema") != _OBSERVATION_SCHEMA:
        raise ProtocolError("desktop backend observation fields are invalid")
    width = _strict_int(data["width"], "desktop width", lo=1, hi=32_768)
    height = _strict_int(data["height"], "desktop height", lo=1, hi=32_768)
    target = _target_facts(data["target"])
    point_width, point_height = target["bounds"][2:]
    scale = float(target.get("scale", 1.0))
    if (
        abs(point_width * scale - width) > 2
        or abs(point_height * scale - height) > 2
    ):
        raise ProtocolError("desktop observation dimensions do not match target bounds")
    projection = data["projection"]
    if not isinstance(projection, dict):
        raise ProtocolError("desktop observation projection must be an object")
    # The base Cell recursively rejects authority-shaped keys.  Keep the
    # backend seam JSON-only and bounded before it reaches that final filter.
    if len(canonical_json(projection).encode("utf-8")) > 56 * 1024:
        raise ProtocolError("desktop observation projection is too large")
    return {
        "schema": _OBSERVATION_SCHEMA,
        "revision": _strict_int(
            data["revision"], "desktop revision", lo=0, hi=2**63 - 1
        ),
        "target": target,
        "pixel_hash": _strict_sha256(data["pixel_hash"], "desktop pixel_hash"),
        "width": width,
        "height": height,
        "projection": dict(projection),
    }


def _state_material(observation: dict[str, Any]) -> dict[str, Any]:
    """Return only stable facts that invalidate a target/action on change."""

    return {
        "revision": observation["revision"],
        "target": observation["target"],
        "pixel_hash": observation["pixel_hash"],
        "width": observation["width"],
        "height": observation["height"],
    }


def _state_digest(observation: dict[str, Any]) -> str:
    return _sha256(canonical_json(_state_material(observation)).encode("utf-8"))


def _selector_matches_target(selector: dict[str, Any], target: dict[str, Any]) -> None:
    if selector["kind"] != target["kind"]:
        raise ProtocolError("desktop selector resolved to the wrong target kind")
    if "display_id" in selector and selector["display_id"] != target["display_id"]:
        raise ProtocolError("desktop selector display changed")
    if "window_id" in selector and selector["window_id"] != target["window_id"]:
        raise ProtocolError("desktop selector window changed")
    if "control_id" in selector and selector["control_id"] != target["control_id"]:
        raise ProtocolError("desktop selector control changed")


def _point_in_target(target: dict[str, Any], x: int, y: int) -> bool:
    left, top, width, height = (int(value) for value in target["bounds"])
    return left <= x < left + width and top <= y < top + height


def _validate_action_target(action: dict[str, Any], target: dict[str, Any]) -> None:
    kind = action["kind"]
    points: list[tuple[int, int]] = []
    if kind in {"click", "move"}:
        points.append((action["x"], action["y"]))
    elif kind == "drag":
        points.extend(
            [
                (action["start_x"], action["start_y"]),
                (action["end_x"], action["end_y"]),
            ]
        )
    if any(not _point_in_target(target, x, y) for x, y in points):
        raise ProtocolError("desktop action coordinate is outside the observed target")
    if kind == "window" and target["kind"] not in {"window", "control"}:
        raise ProtocolError("desktop window action requires a window-bound handle")
    if kind == "window":
        app_name = target.get("app_name")
        window_title = target.get("window_title")
        if app_name is not None and action["app_name"] != app_name:
            raise ProtocolError("desktop action app does not match the observed target")
        if window_title is not None and action["window_title"] != window_title:
            raise ProtocolError("desktop action window does not match the observed target")
    if kind in {"key", "scroll", "type"} and (
        int(target.get("focused_owner_pid", 0)) <= 0
        or int(target.get("focused_window_id", 0)) <= 0
    ):
        raise ProtocolError("desktop focus-dependent action lacks a trusted focused window")
    if kind == "scroll":
        pointer_x = target.get("pointer_x")
        pointer_y = target.get("pointer_y")
        if type(pointer_x) is not int or type(pointer_y) is not int:
            raise ProtocolError("desktop scroll lacks a trusted pointer position")
        if not _point_in_target(target, pointer_x, pointer_y):
            raise ProtocolError("desktop scroll pointer is outside the observed target")


class DesktopBackend(Protocol):
    def observe(
        self,
        target: dict[str, Any],
        request: dict[str, Any],
    ) -> dict[str, Any]: ...

    def act(
        self,
        action: dict[str, Any],
        *,
        expected_observation: dict[str, Any],
        selector: dict[str, Any],
        request: dict[str, Any],
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class DesktopPreflightResult:
    witness: StateWitness
    projection: dict[str, Any]


@dataclass(slots=True)
class _ObservedReport:
    task_id: str
    draft_id: str
    canonical_effect_hash: str
    selector: dict[str, Any]
    request: dict[str, Any]
    observation: dict[str, Any]
    state_digest: str
    target_digest: str
    handle_id: str
    witness: StateWitness
    binding: DesktopTargetBindingV1 | None = None


@dataclass(slots=True)
class _ActionReport:
    task_id: str
    draft_id: str
    canonical_effect_hash: str
    handle_id: str
    action: dict[str, Any]
    state_digest: str
    witness: StateWitness
    attempted: bool = False
    committed: bool = False


class ScriptedDesktopBackend:
    """Atomic deterministic backend used only by the explicit C2 harness."""

    def __init__(self, script_path: Path) -> None:
        self._path = Path(script_path)
        self._lock = threading.RLock()
        self.observe_count = 0
        self.action_count = 0

    def _load(self) -> dict[str, Any]:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(self._path, flags)
        except OSError as exc:
            raise ProtocolError("desktop script is unavailable") from exc
        try:
            metadata = os.fstat(fd)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_nlink != 1
                or metadata.st_size > _MAX_SCRIPT_BYTES
            ):
                raise ProtocolError(
                    "desktop script must be an owned 0600 bounded single-link file"
                )
            chunks: list[bytes] = []
            remaining = _MAX_SCRIPT_BYTES + 1
            while remaining:
                chunk = os.read(fd, min(remaining, 64 * 1024))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            if len(raw) > _MAX_SCRIPT_BYTES:
                raise ProtocolError("desktop script exceeds its persistence bound")
            data = json.loads(raw)
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ProtocolError("desktop script is invalid JSON") from exc
        finally:
            os.close(fd)
        fields = {
            "schema",
            "revision",
            "target",
            "pixel_hash",
            "width",
            "height",
            "actions",
        }
        if not isinstance(data, dict) or set(data) != fields:
            raise ProtocolError("DesktopScriptV1 fields are invalid")
        if data["schema"] != _SCRIPT_SCHEMA:
            raise ProtocolError("desktop script schema is invalid")
        revision = _strict_int(data["revision"], "script revision", lo=0, hi=2**63 - 1)
        target = _target_facts(data["target"])
        width = _strict_int(data["width"], "script width", lo=1, hi=32_768)
        height = _strict_int(data["height"], "script height", lo=1, hi=32_768)
        scale = float(target.get("scale", 1.0))
        if (
            abs(target["bounds"][2] * scale - width) > 2
            or abs(target["bounds"][3] * scale - height) > 2
        ):
            raise ProtocolError("desktop script dimensions do not match target")
        actions = data["actions"]
        if not isinstance(actions, list) or len(actions) > _MAX_ACTIONS:
            raise ProtocolError("desktop script actions are invalid")
        normalized_actions = [normalize_desktop_action(action) for action in actions]
        if normalized_actions != actions:
            raise ProtocolError("desktop script actions are not canonical")
        return {
            "schema": _SCRIPT_SCHEMA,
            "revision": revision,
            "target": target,
            "pixel_hash": _strict_sha256(data["pixel_hash"], "script pixel_hash"),
            "width": width,
            "height": height,
            "actions": normalized_actions,
        }

    def _store(self, data: dict[str, Any]) -> None:
        payload = canonical_json(data).encode("utf-8")
        if len(payload) > _MAX_SCRIPT_BYTES:
            raise ProtocolError("desktop script exceeds its persistence bound")
        parent = self._path.parent
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        temp = parent / f".{self._path.name}.{secrets.token_hex(8)}.tmp"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(temp, flags, 0o600)
            try:
                view = memoryview(payload)
                while view:
                    written = os.write(fd, view)
                    if written <= 0:
                        raise ProtocolError("short write while updating desktop script")
                    view = view[written:]
                os.fsync(fd)
            finally:
                os.close(fd)
            os.replace(temp, self._path)
            directory_fd = os.open(parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            try:
                temp.unlink()
            except OSError:
                pass

    def observe(
        self,
        target: dict[str, Any],
        request: dict[str, Any],
    ) -> dict[str, Any]:
        del request
        selector = normalize_desktop_target(target)
        with self._lock:
            state = self._load()
            _selector_matches_target(selector, state["target"])
            self.observe_count += 1
            return {
                "schema": _OBSERVATION_SCHEMA,
                "revision": state["revision"],
                "target": state["target"],
                "pixel_hash": state["pixel_hash"],
                "width": state["width"],
                "height": state["height"],
                "projection": {},
            }

    def act(
        self,
        action: dict[str, Any],
        *,
        expected_observation: dict[str, Any],
        selector: dict[str, Any],
        request: dict[str, Any],
    ) -> None:
        normalized = normalize_desktop_action(action)
        trusted_selector = normalize_desktop_target(selector)
        del request
        with self._lock:
            state = self._load()
            _selector_matches_target(trusted_selector, state["target"])
            current = {
                "schema": _OBSERVATION_SCHEMA,
                "revision": state["revision"],
                "target": state["target"],
                "pixel_hash": state["pixel_hash"],
                "width": state["width"],
                "height": state["height"],
                "projection": {},
            }
            if _state_digest(current) != _state_digest(expected_observation):
                raise ProtocolError("scripted desktop state changed before action")
            if len(state["actions"]) >= _MAX_ACTIONS:
                raise ProtocolError("desktop script action bound is exhausted")
            revision = state["revision"] + 1
            pixel_hash = _sha256(
                canonical_json(
                    [
                        "orin:scripted-desktop-action:v1",
                        state["pixel_hash"],
                        revision,
                        normalized,
                    ]
                ).encode("utf-8")
            )
            state["revision"] = revision
            state["pixel_hash"] = pixel_hash
            state["actions"] = [*state["actions"], normalized]
            self._store(state)
            self.action_count += 1

    def mutate(self, **changes: Any) -> None:
        """Test-only trusted state mutation used to prove stale rejection."""

        if not changes or not set(changes).issubset({"revision", "pixel_hash", "target"}):
            raise ProtocolError("unsupported scripted desktop mutation")
        with self._lock:
            state = self._load()
            state.update(changes)
            # Re-parse before replacing the authoritative script.
            candidate = {
                "schema": _SCRIPT_SCHEMA,
                "revision": state["revision"],
                "target": state["target"],
                "pixel_hash": state["pixel_hash"],
                "width": state["width"],
                "height": state["height"],
                "actions": state["actions"],
            }
            _strict_int(candidate["revision"], "script revision", lo=0, hi=2**63 - 1)
            _strict_sha256(candidate["pixel_hash"], "script pixel_hash")
            _target_facts(candidate["target"])
            self._store(candidate)


class MacOSDesktopBackend:
    """Native macOS pixels and controller actions, instantiated in the Cell."""

    def __init__(self) -> None:
        from js.tools.desktop.controller import DesktopController

        self._controller = DesktopController()
        self._lock = threading.RLock()
        self._revision = 0
        self._operation_count = 0
        self._emergency_stop = False

    @staticmethod
    def _window_facts(window_id: int) -> dict[str, Any]:
        try:
            import Quartz  # type: ignore[import-not-found,import-untyped]

            options = Quartz.kCGWindowListOptionIncludingWindow
            rows = Quartz.CGWindowListCopyWindowInfo(options, window_id)
        except Exception as exc:  # noqa: BLE001 - missing native facts fail closed
            raise ProtocolError("trusted macOS window observation is unavailable") from exc
        if not isinstance(rows, list) or len(rows) != 1:
            raise ProtocolError("desktop window is not uniquely observable")
        row = rows[0]
        bounds = row.get("kCGWindowBounds") or row.get(Quartz.kCGWindowBounds)
        if not isinstance(bounds, dict):
            raise ProtocolError("desktop window bounds are unavailable")
        return {
            "kind": "window",
            "display_id": 0,
            "window_id": int(row.get("kCGWindowNumber", window_id)),
            "owner_pid": int(row.get("kCGWindowOwnerPID", 0)),
            "control_id": "window",
            "bounds": [
                int(bounds.get("X", 0)),
                int(bounds.get("Y", 0)),
                int(bounds.get("Width", 0)),
                int(bounds.get("Height", 0)),
            ],
            "app_name": str(row.get("kCGWindowOwnerName") or "unknown"),
            "window_title": str(row.get("kCGWindowName") or "untitled"),
        }

    @staticmethod
    def _frontmost_focus() -> dict[str, Any]:
        """Return trusted frontmost app/window facts for focus-bound actions."""

        try:
            import AppKit  # type: ignore[import-not-found,import-untyped]
            import Quartz  # type: ignore[import-not-found,import-untyped]

            application = AppKit.NSWorkspace.sharedWorkspace().frontmostApplication()
            owner_pid = int(application.processIdentifier())
            app_name = str(application.localizedName() or "unknown")
            options = (
                Quartz.kCGWindowListOptionOnScreenOnly
                | Quartz.kCGWindowListExcludeDesktopElements
            )
            rows = Quartz.CGWindowListCopyWindowInfo(options, Quartz.kCGNullWindowID)
        except Exception:  # noqa: BLE001 - actions requiring focus fail closed later
            return {}
        matches = [
            row
            for row in rows or []
            if int(row.get("kCGWindowOwnerPID", 0)) == owner_pid
            and int(row.get("kCGWindowLayer", 0)) == 0
        ]
        if not matches:
            return {
                "focused_owner_pid": owner_pid,
                "focused_app_name": app_name,
            }
        row = matches[0]
        result: dict[str, Any] = {
            "focused_owner_pid": owner_pid,
            "focused_window_id": int(row.get("kCGWindowNumber", 0)),
            "focused_app_name": app_name,
            "focused_control_id": "window",
        }
        title = str(row.get("kCGWindowName") or "")
        if title:
            result["focused_window_title"] = title
        return result

    @staticmethod
    def _project_image(image: Any) -> tuple[str, str]:
        """Return a bounded PNG projection without exposing a private path."""

        projected = image.copy()
        projected.thumbnail((640, 640))
        for width in (640, 480, 320, 240):
            candidate = projected.copy()
            candidate.thumbnail((width, width))
            buffer = io.BytesIO()
            candidate.save(buffer, format="PNG", optimize=True)
            payload = buffer.getvalue()
            if len(payload) <= _MAX_IMAGE_PROJECTION_BYTES:
                return base64.b64encode(payload).decode("ascii"), "image/png"
        raise ProtocolError("desktop image cannot be projected within the frame bound")

    @staticmethod
    def _display_bounds(
        requested_display_id: int,
    ) -> tuple[int, list[int]]:
        """Return Quartz point bounds; pixel dimensions are never coordinates."""

        try:
            import Quartz  # type: ignore[import-not-found,import-untyped]

            display_id = requested_display_id or int(Quartz.CGMainDisplayID())
            raw = Quartz.CGDisplayBounds(display_id)
            bounds = [
                int(raw.origin.x),
                int(raw.origin.y),
                int(raw.size.width),
                int(raw.size.height),
            ]
            if bounds[2] <= 0 or bounds[3] <= 0:
                raise ValueError("empty display bounds")
            return display_id, bounds
        except Exception as exc:  # noqa: BLE001 - coordinate ambiguity fails closed
            raise ProtocolError("trusted macOS display bounds are unavailable") from exc

    def _capture(
        self,
        selector: dict[str, Any],
        request: dict[str, Any],
    ) -> tuple[dict[str, Any], str, int, int, dict[str, Any]]:
        from PIL import Image

        from js.tools.desktop.types import ScreenRegion

        args = request["arguments"] if request["tool"] == "desktop_screenshot" else {}
        region = None
        trusted_target: dict[str, Any] | None = None
        if selector["kind"] == "control":
            # A generic AX selector is not a trusted control observation.  C2
            # refuses to pretend a window screenshot proves one.
            raise ProtocolError("trusted macOS control observation is unavailable")
        if selector["kind"] == "window":
            trusted_target = self._window_facts(int(selector["window_id"]))
            left, top, point_width, point_height = trusted_target["bounds"]
            region = ScreenRegion(left, top, point_width, point_height)
        elif args.get("width", 0) and args.get("height", 0):
            region = ScreenRegion(
                x=args["x"],
                y=args["y"],
                width=args["width"],
                height=args["height"],
            )
        # Capture one full real pixel plane, then crop inside the Cell.  The
        # repository's legacy ``screencapture -R`` path is not reliable on all
        # signed macOS builds, and no full-size artifact may leave this process.
        result = self._controller.screenshot(
            region=None,
            format_="png",
            show_cursor=bool(args.get("show_cursor", False)),
        )
        path_value = result.get("path")
        if not isinstance(path_value, str) or not path_value:
            raise ProtocolError("macOS screenshot did not return a private artifact")
        path = Path(path_value)
        try:
            payload = path.read_bytes()
        except OSError as exc:
            raise ProtocolError("macOS screenshot artifact is unavailable") from exc
        finally:
            try:
                path.unlink()
            except OSError:
                pass
        try:
            with Image.open(io.BytesIO(payload)) as image:
                rgba = image.convert("RGBA")
                full_width, full_height = rgba.size
        except Exception as exc:  # noqa: BLE001 - malformed capture fails closed
            raise ProtocolError("macOS screenshot pixels are invalid") from exc

        display_id, display_bounds = self._display_bounds(
            int(selector.get("display_id", 0))
        )
        display_left, display_top, point_width, point_height = display_bounds
        scale_x = full_width / max(1, point_width)
        scale_y = full_height / max(1, point_height)
        if abs(scale_x - scale_y) > 0.05:
            raise ProtocolError("macOS capture has inconsistent coordinate scale")
        scale = (scale_x + scale_y) / 2
        if region is not None:
            crop = (
                round((region.x - display_left) * scale),
                round((region.y - display_top) * scale),
                round((region.x + region.width - display_left) * scale),
                round((region.y + region.height - display_top) * scale),
            )
            if (
                crop[0] < 0
                or crop[1] < 0
                or crop[2] > full_width
                or crop[3] > full_height
                or crop[2] <= crop[0]
                or crop[3] <= crop[1]
            ):
                raise ProtocolError("desktop target region is outside the captured display")
            rgba = rgba.crop(crop)
        width, height = rgba.size
        pixel_hash = _sha256(rgba.tobytes())

        target: dict[str, Any]
        if selector["kind"] == "screen":
            if region is not None:
                bounds = [region.x, region.y, region.width, region.height]
            else:
                bounds = display_bounds
            target = {
                "kind": "screen",
                "display_id": display_id,
                "window_id": 0,
                "owner_pid": 0,
                "control_id": "screen",
                "bounds": bounds,
                "scale": round(scale, 4),
            }
        else:
            assert trusted_target is not None
            target = trusted_target
            target["display_id"] = display_id
            target["scale"] = round(scale, 4)
        target.update(self._frontmost_focus())
        pointer = self._controller.get_mouse_position()
        target.update({"pointer_x": int(pointer.x), "pointer_y": int(pointer.y)})
        projection = {
            "target_kind": target["kind"],
            "display_id": target["display_id"],
            "owner_pid": target["owner_pid"],
            "window_number": target["window_id"],
            "scale": target.get("scale", 1.0),
        }
        if request["tool"] == "desktop_screenshot":
            image_base64, image_mime_type = self._project_image(rgba)
            projection.update(
                {
                    "image_base64": image_base64,
                    "image_mime_type": image_mime_type,
                }
            )
        return target, pixel_hash, width, height, projection

    def observe(
        self,
        target: dict[str, Any],
        request: dict[str, Any],
    ) -> dict[str, Any]:
        selector = normalize_desktop_target(target)
        with self._lock:
            facts, pixel_hash, width, height, projection = self._capture(
                selector, request
            )
            _selector_matches_target(selector, facts)
            tool = request["tool"]
            args = request["arguments"]
            if tool == "desktop_get_permissions":
                from js.tools.desktop.permissions import PermissionChecker

                status = PermissionChecker.get_status()
                projection.update(
                    {
                        "platform": bool(status.get("platform")),
                        "accessibility": bool(status.get("accessibility")),
                        "screen_recording": bool(status.get("screen_recording")),
                    }
                )
            elif tool == "desktop_get_state":
                position = self._controller.get_mouse_position()
                projection.update(
                    {
                        "available": True,
                        "mouse": {"x": position.x, "y": position.y},
                        "operation_count": self._operation_count,
                    }
                )
            elif tool == "desktop_list":
                if args["target"] == "apps":
                    listed = self._controller.app_action(
                        __import__("js.tools.desktop.types", fromlist=["AppAction"]).AppAction.LIST
                    )
                    projection["apps"] = [
                        {"name": item.name, "active": item.active}
                        for item in listed.get("apps", [])[:128]
                    ]
                else:
                    module = __import__(
                        "js.tools.desktop.types", fromlist=["WindowAction"]
                    )
                    listed = self._controller.window_action(
                        module.WindowAction.LIST, app_name=args["app_name"]
                    )
                    projection["windows"] = [
                        {
                            "app_name": item.app_name,
                            "title": item.title,
                            "bounds": [
                                item.bounds.x,
                                item.bounds.y,
                                item.bounds.width,
                                item.bounds.height,
                            ],
                        }
                        for item in listed.get("windows", [])[:128]
                    ]
            elif tool == "desktop_operation_log":
                projection["operation_count"] = min(
                    self._operation_count, args["limit"]
                )
            if tool != "desktop_screenshot":
                projection.pop("image_base64", None)
                projection.pop("image_mime_type", None)
            return {
                "schema": _OBSERVATION_SCHEMA,
                "revision": self._revision,
                "target": facts,
                "pixel_hash": pixel_hash,
                "width": width,
                "height": height,
                "projection": projection,
            }

    def act(
        self,
        action: dict[str, Any],
        *,
        expected_observation: dict[str, Any],
        selector: dict[str, Any],
        request: dict[str, Any],
    ) -> None:
        normalized = normalize_desktop_action(action)
        trusted_selector = normalize_desktop_target(selector)
        kind = normalized["kind"]
        with self._lock:
            facts, pixel_hash, width, height, _projection = self._capture(
                trusted_selector, request
            )
            current = _observation(
                {
                    "schema": _OBSERVATION_SCHEMA,
                    "revision": self._revision,
                    "target": facts,
                    "pixel_hash": pixel_hash,
                    "width": width,
                    "height": height,
                    "projection": {},
                }
            )
            if _state_digest(current) != _state_digest(expected_observation):
                raise ProtocolError("desktop state changed at the action boundary")
            trusted_target = current["target"]
            _validate_action_target(normalized, trusted_target)
            if self._emergency_stop:
                raise ProtocolError("desktop emergency stop is active")
            if kind == "emergency_stop":
                self._emergency_stop = True
                self._revision += 1
                self._operation_count += 1
                return
            # The legacy controller may select a different topmost/focused
            # target and can fall back to a second backend after an ambiguous
            # native event.  Neither satisfies C2's exact target or at-most-once
            # boundary, so native OS mutations stay disabled until a single
            # AX/CG identity backend and durable reconciliation exist.
            raise ProtocolError("exact native desktop action is unavailable")


class DesktopCell(CellBase):
    """``cell.desktop`` strict package executor for the C2 test harness."""

    def __init__(
        self,
        *,
        socket_path: Path,
        state_dir: Path,
        mac_key: bytes,
        backend: DesktopBackend | None = None,
    ) -> None:
        if not isinstance(mac_key, bytes) or len(mac_key) != 32:
            raise ProtocolError("Desktop Cell mac key must be 32 bytes")
        self._mac_key = mac_key
        self._backend: DesktopBackend = backend or MacOSDesktopBackend()
        self._reports: dict[str, _ObservedReport] = {}
        self._observation_drafts: dict[str, str] = {}
        self._action_reports: dict[str, _ActionReport] = {}
        self._lock = threading.RLock()
        super().__init__(
            cap="cell.desktop",
            socket_path=socket_path,
            state_dir=state_dir,
            handler=self._commit_package,
            preflight_handler=self._preflight_package,
            handle_handler=self._resolve_handle,
            strict_effect_protocol=True,
        )

    def _prune_private_reports(self, *, now_ms: int | None = None) -> None:
        now = _now_ms() if now_ms is None else now_ms
        expired_handles = [
            handle_id
            for handle_id, report in self._reports.items()
            if report.witness.expires_at_ms <= now
        ]
        for handle_id in expired_handles:
            report = self._reports.pop(handle_id)
            self._observation_drafts.pop(report.draft_id, None)
        expired_actions = [
            draft_id
            for draft_id, report in self._action_reports.items()
            if report.witness.expires_at_ms <= now
        ]
        for draft_id in expired_actions:
            self._action_reports.pop(draft_id, None)

    def _observe(
        self,
        selector: dict[str, Any],
        request: dict[str, Any],
    ) -> dict[str, Any]:
        return _observation(self._backend.observe(selector, request))

    def _new_witness(
        self,
        *,
        package: CellPackage,
        target_version: str,
        material: dict[str, Any],
        writes: int,
    ) -> StateWitness:
        now = _now_ms()
        witness_id = "state:" + hmac.new(
            self._mac_key,
            canonical_json(material).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return StateWitness(
            witness_id=witness_id,
            draft_id=package.draft.draft_id,
            executor_id=package.executor_id,
            target_version=target_version,
            canonical_effect_hash=package.canonical_effect_hash,
            impact=Impact(writes=writes),
            reversibility=(
                "reversible_until_stage"
                if writes == 0
                else "irreversible_after_provider_accept"
            ),
            idempotency_support="none" if writes else "query_only",
            created_at_ms=now,
            expires_at_ms=now + _WITNESS_TTL_MS,
        )

    def _preflight_observe(self, package: CellPackage) -> DesktopPreflightResult:
        self._prune_private_reports()
        package.validate_binding()
        if package.resolved_handles:
            raise ProtocolError("desktop.observe must not carry a resolved handle")
        arguments = normalize_desktop_observe_arguments(package.draft.arguments)
        selector = arguments["target"]
        request = _normalize_observe_request(arguments["request"])
        observation = self._observe(selector, request)
        _selector_matches_target(selector, observation["target"])
        state_digest = _state_digest(observation)
        target_digest = _sha256(
            canonical_json(
                ["orin:desktop-observation:v1", _state_material(observation)]
            ).encode("utf-8")
        )
        handle_id = derive_desktop_target_handle_id(
            task_id=package.draft.task_id,
            draft_id=package.draft.draft_id,
            canonical_effect_hash=package.canonical_effect_hash,
            target_digest=target_digest,
        )
        material = {
            "schema": _OBSERVATION_REPORT_SCHEMA,
            "task_id": package.draft.task_id,
            "draft_id": package.draft.draft_id,
            "canonical_effect_hash": package.canonical_effect_hash,
            "selector": selector,
            "request": request,
            "state_digest": state_digest,
            "target_digest": target_digest,
            "handle_id": handle_id,
        }
        witness = self._new_witness(
            package=package,
            target_version=handle_id,
            material=material,
            writes=0,
        )
        prior_handle = self._observation_drafts.get(package.draft.draft_id)
        if prior_handle is not None:
            prior = self._reports.get(prior_handle)
            if (
                prior is None
                or prior.canonical_effect_hash != package.canonical_effect_hash
                or prior.state_digest != state_digest
            ):
                raise ProtocolError("desktop observe draft replay changed state")
            witness = prior.witness
            handle_id = prior.handle_id
        else:
            if len(self._reports) >= _MAX_PRIVATE_REPORTS:
                raise ProtocolError("desktop private observation capacity is exhausted")
            private_observation = {**observation, "projection": {}}
            self._reports[handle_id] = _ObservedReport(
                task_id=package.draft.task_id,
                draft_id=package.draft.draft_id,
                canonical_effect_hash=package.canonical_effect_hash,
                selector=selector,
                request=request,
                observation=private_observation,
                state_digest=state_digest,
                target_digest=target_digest,
                handle_id=handle_id,
                witness=witness,
            )
            self._observation_drafts[package.draft.draft_id] = handle_id
        projection = {
            "desktop_target_handle_id": handle_id,
            "target_kind": observation["target"]["kind"],
            "display_id": observation["target"]["display_id"],
            "window_number": observation["target"]["window_id"],
            "owner_pid": observation["target"]["owner_pid"],
            "scale": observation["target"].get("scale", 1.0),
            "pixel_hash": observation["pixel_hash"],
            "width": observation["width"],
            "height": observation["height"],
            **observation["projection"],
        }
        return DesktopPreflightResult(witness=witness, projection=projection)

    def _authority_for_action(
        self,
        package: CellPackage,
    ) -> tuple[OriginHandle, _ObservedReport, dict[str, Any]]:
        package.validate_binding(require_witness=package.state_witness is not None)
        if set(package.draft.arguments) != {"desktop_target_handle", "action"}:
            raise ProtocolError("desktop.action arguments are invalid")
        raw_handle_id = package.draft.arguments["desktop_target_handle"]
        if type(raw_handle_id) is not str or not raw_handle_id.startswith("desktop:"):
            raise ProtocolError("desktop.action requires a DesktopTargetHandle id")
        if len(package.resolved_handles) != 1:
            raise ProtocolError("desktop.action requires exactly one resolved handle")
        handle = package.resolved_handles[0]
        if (
            handle.handle_id != raw_handle_id
            or handle.kind != "DesktopTargetHandle"
            or handle.issuer != "cell:desktop"
            or set(handle.capabilities) != {"read", "use"}
            or not handle.verify_seal(self._mac_key)
        ):
            raise ProtocolError("DesktopTargetHandle is invalid or not broker sealed")
        now = _now_ms()
        if handle.created_at_ms > now + 5_000 or handle.expires_at_ms <= now:
            raise ProtocolError("DesktopTargetHandle is outside its validity window")
        report = self._reports.get(handle.handle_id)
        if report is None or report.binding is None:
            raise ProtocolError("DesktopTargetHandle has no Cell-private observation")
        binding = report.binding
        if (
            package.draft.task_id != binding.task_id
            or handle.owner_key_hash != binding.owner_key_hash
            or handle.tenant != binding.tenant
            or handle.expires_at_ms != binding.expires_at_ms
            or handle.object_digest != report.target_digest
        ):
            raise ProtocolError("DesktopTargetHandle binding does not match the action")
        action = normalize_desktop_action(package.draft.arguments["action"])
        _validate_action_target(action, report.observation["target"])
        return handle, report, action

    def _preflight_action(self, package: CellPackage) -> DesktopPreflightResult:
        self._prune_private_reports()
        handle, observed, action = self._authority_for_action(package)
        current = self._observe(observed.selector, observed.request)
        if _state_digest(current) != observed.state_digest:
            raise ProtocolError("desktop target state changed after trusted observe")
        material = {
            "schema": _ACTION_REPORT_SCHEMA,
            "task_id": package.draft.task_id,
            "draft_id": package.draft.draft_id,
            "canonical_effect_hash": package.canonical_effect_hash,
            "desktop_target_handle_id": handle.handle_id,
            "action": action,
            "state_digest": observed.state_digest,
        }
        target_version = "desktop-action:" + hashlib.sha256(
            canonical_json(material).encode("utf-8")
        ).hexdigest()
        witness = self._new_witness(
            package=package,
            target_version=target_version,
            material=material,
            writes=1,
        )
        prior = self._action_reports.get(package.draft.draft_id)
        if prior is not None:
            if (
                prior.canonical_effect_hash != package.canonical_effect_hash
                or prior.handle_id != handle.handle_id
                or prior.action != action
                or prior.state_digest != observed.state_digest
                or prior.attempted
            ):
                raise ProtocolError("desktop action preflight replay is stale")
            witness = prior.witness
        else:
            if len(self._action_reports) >= _MAX_PRIVATE_REPORTS:
                raise ProtocolError("desktop private action capacity is exhausted")
            self._action_reports[package.draft.draft_id] = _ActionReport(
                task_id=package.draft.task_id,
                draft_id=package.draft.draft_id,
                canonical_effect_hash=package.canonical_effect_hash,
                handle_id=handle.handle_id,
                action=action,
                state_digest=observed.state_digest,
                witness=witness,
            )
        return DesktopPreflightResult(
            witness=witness,
            projection={"action": action["kind"], "before_digest": observed.state_digest},
        )

    def _preflight_package(self, package: CellPackage) -> DesktopPreflightResult:
        with self._lock:
            if package.executor_id != "cell.desktop":
                raise ProtocolError("Desktop Cell executor mismatch")
            if package.draft.effect_type == "desktop.observe":
                return self._preflight_observe(package)
            if package.draft.effect_type == "desktop.action":
                return self._preflight_action(package)
            raise ProtocolError("Desktop Cell accepts only desktop.observe/action")

    def _resolve_handle(self, handle_id: str, raw_binding: dict[str, Any]) -> OriginHandle:
        with self._lock:
            self._prune_private_reports()
            binding = desktop_target_binding_from_dict(raw_binding)
            report = self._reports.get(handle_id)
            if report is None or report.handle_id != handle_id:
                raise ProtocolError("DesktopTargetHandle was not produced by this Cell")
            if (
                binding.task_id != report.task_id
                or binding.draft_id != report.draft_id
                or binding.witness_id != report.witness.witness_id
                or binding.canonical_effect_hash != report.canonical_effect_hash
            ):
                raise ProtocolError("DesktopTargetBindingV1 does not match trusted observe")
            now = _now_ms()
            if binding.expires_at_ms <= now:
                raise ProtocolError("DesktopTargetBindingV1 is expired")
            if binding.expires_at_ms > report.witness.expires_at_ms + 5_000:
                raise ProtocolError("DesktopTargetBindingV1 outlives its observation")
            if report.binding is not None and report.binding != binding:
                raise ProtocolError("DesktopTargetHandle binding cannot be replaced")
            session_key = self._session_key
            if not isinstance(session_key, bytes) or len(session_key) != 32:
                raise ProtocolError("Desktop Cell session is not authenticated")
            report.binding = binding
            handle = OriginHandle(
                handle_id=handle_id,
                kind="DesktopTargetHandle",
                owner_key_hash=binding.owner_key_hash,
                tenant=binding.tenant,
                source_class="TRUSTED_LOCAL",
                integrity="trusted_local_object",
                confidentiality="CONFIDENTIAL",
                object_digest=report.target_digest,
                capabilities=("read", "use"),
                issuer="cell:desktop",
                created_at_ms=report.witness.created_at_ms,
                expires_at_ms=binding.expires_at_ms,
            )
            return handle.sealed_by(
                session_key, "cell:desktop", report.witness.created_at_ms
            )

    def _commit_package(
        self,
        permit: CommitPermit,
        package: CellPackage,
    ) -> dict[str, Any]:
        with self._lock:
            self._prune_private_reports()
            package.validate_binding(permit, require_witness=True)
            if package.draft.effect_type != "desktop.action":
                raise ProtocolError("Desktop Cell commit accepts only desktop.action")
            _handle, observed, action = self._authority_for_action(package)
            report = self._action_reports.get(package.draft.draft_id)
            witness = package.state_witness
            if witness is None or report is None:
                raise ProtocolError("desktop action was not preflighted")
            if report.attempted:
                raise ProtocolError("desktop action permit replay is already committed")
            if (
                report.task_id != package.draft.task_id
                or report.canonical_effect_hash != package.canonical_effect_hash
                or report.handle_id != package.draft.arguments["desktop_target_handle"]
                or report.action != action
                or report.witness != witness
                or permit.state_witness_id != report.witness.witness_id
            ):
                raise ProtocolError("desktop action commit does not match preflight")
            current = self._observe(observed.selector, observed.request)
            before_digest = _state_digest(current)
            if before_digest != report.state_digest:
                raise ProtocolError("desktop target state changed before commit")
            # Claim before crossing the OS side-effect boundary.  If the act
            # or post-observation becomes ambiguous, this Cell instance
            # refuses a second attempt instead of blindly replaying it.
            report.attempted = True
            self._backend.act(
                action,
                expected_observation=observed.observation,
                selector=observed.selector,
                request=observed.request,
            )
            after = self._observe(observed.selector, observed.request)
            after_digest = _state_digest(after)
            receipt_material = {
                "schema": "DesktopCellReceiptV1",
                "permit_id": permit.permit_id,
                "draft_id": package.draft.draft_id,
                "desktop_target_handle_id": report.handle_id,
                "action": action,
                "before_digest": before_digest,
                "after_digest": after_digest,
            }
            receipt_id = "receipt:" + hmac.new(
                self._mac_key,
                canonical_json(receipt_material).encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
            report.committed = True
            return {
                "status": "COMMITTED",
                "action": action["kind"],
                "before_digest": before_digest,
                "after_digest": after_digest,
                "receipt_id": receipt_id,
            }


def main() -> None:  # pragma: no cover - subprocess entry
    socket_path = os.environ.get("ORIN_CELLS_SOCKET")
    state_dir_env = os.environ.get("ORIN_STATE_DIR")
    if not socket_path or not state_dir_env:
        raise SystemExit("ORIN_CELLS_SOCKET and ORIN_STATE_DIR are required")

    from js.orind.keybox import KeyBox

    state_dir = Path(state_dir_env)
    strict_paths = os.environ.get("ORIN_CELL_IDENTITY_ENFORCE") == "1"
    keybox_tier = os.environ.get("ORIN_KEYBOX_TIER")
    if strict_paths and keybox_tier not in {"dev", "production"}:
        raise SystemExit("ORIN_KEYBOX_TIER must be explicit in Cell identity enforce mode")
    keybox = KeyBox(
        state_dir,
        tier=keybox_tier or "dev",
        strict_paths=strict_paths,
    )
    script_path = os.environ.get("ORIN_DESKTOP_SCRIPT_PATH")
    backend: DesktopBackend = (
        ScriptedDesktopBackend(Path(script_path))
        if script_path
        else MacOSDesktopBackend()
    )
    cell = DesktopCell(
        socket_path=Path(socket_path),
        state_dir=state_dir,
        mac_key=keybox.key,
        backend=backend,
    )
    cell.start()
    try:
        while True:
            time.sleep(1)
            if not cell.healthy():
                raise SystemExit("Desktop Cell became unhealthy")
    except KeyboardInterrupt:
        pass
    finally:
        cell.stop()


if __name__ == "__main__":  # pragma: no cover
    main()


__all__ = [
    "DesktopCell",
    "DesktopPreflightResult",
    "MacOSDesktopBackend",
    "ScriptedDesktopBackend",
]
