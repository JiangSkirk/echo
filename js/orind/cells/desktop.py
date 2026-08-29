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
from js.orin.draft import (
    CellPackage,
    CommitPermit,
    Impact,
    StateWitness,
    seal_signed_effect_receipt,
)
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
        "bundle_id",
        "control_identifier",
        "control_role",
        "control_subrole",
        "focused_app_name",
        "focused_control_id",
        "focused_owner_pid",
        "focused_window_id",
        "focused_window_title",
        "pointer_x",
        "pointer_y",
        "scale",
        "secondary_bounds",
        "secondary_control_id",
        "secondary_owner_pid",
        "secondary_window_id",
        "topmost_window_id",
        "window_title",
    }
    if not required.issubset(data) or not set(data).issubset(required | optional):
        raise ProtocolError("desktop observation target fields are invalid")
    kind = data.get("kind")
    if kind not in {"screen", "window", "control", "application"}:
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
        "display_id": _strict_int(data["display_id"], "target display_id", lo=0, hi=2**63 - 1),
        "window_id": _strict_int(data["window_id"], "target window_id", lo=0, hi=2**63 - 1),
        "owner_pid": _strict_int(data["owner_pid"], "target owner_pid", lo=0, hi=2**31 - 1),
        "control_id": _strict_text(data["control_id"], "target control_id", max_len=256),
        "bounds": [x, y, width, height],
    }
    if "app_name" in data:
        result["app_name"] = _strict_text(data["app_name"], "target app_name", max_len=256)
    if "window_title" in data:
        result["window_title"] = _strict_text(
            data["window_title"], "target window_title", max_len=512
        )
    if "scale" in data:
        scale = data["scale"]
        if type(scale) not in {int, float} or not 0.25 <= scale <= 8.0:
            raise ProtocolError("desktop target scale is invalid")
        result["scale"] = float(scale)
    for field in (
        "focused_owner_pid",
        "focused_window_id",
        "secondary_owner_pid",
        "secondary_window_id",
        "topmost_window_id",
    ):
        if field in data:
            result[field] = _strict_int(data[field], field, lo=0, hi=2**63 - 1)
    for field in ("pointer_x", "pointer_y"):
        if field in data:
            result[field] = _strict_int(data[field], field, lo=-32_768, hi=32_768)
    for field, maximum in (
        ("bundle_id", 512),
        ("control_identifier", 512),
        ("control_role", 128),
        ("control_subrole", 128),
        ("focused_app_name", 256),
        ("focused_control_id", 256),
        ("focused_window_title", 512),
        ("secondary_control_id", 256),
    ):
        if field in data:
            result[field] = _strict_text(data[field], field, max_len=maximum)
    if "secondary_bounds" in data:
        secondary = data["secondary_bounds"]
        if (
            not isinstance(secondary, list)
            or len(secondary) != 4
            or any(type(value) is not int for value in secondary)
        ):
            raise ProtocolError("desktop secondary target bounds are invalid")
        secondary_x, secondary_y, secondary_width, secondary_height = secondary
        _strict_int(secondary_x, "secondary x", lo=-32_768, hi=32_768)
        _strict_int(secondary_y, "secondary y", lo=-32_768, hi=32_768)
        _strict_int(secondary_width, "secondary width", lo=1, hi=32_768)
        _strict_int(secondary_height, "secondary height", lo=1, hi=32_768)
        result["secondary_bounds"] = list(secondary)
    if kind == "screen" and (result["window_id"] or result["owner_pid"]):
        raise ProtocolError("screen target must not claim a window identity")
    if kind in {"window", "control"} and (result["window_id"] <= 0 or result["owner_pid"] <= 0):
        raise ProtocolError("window/control target requires trusted window identity")
    if kind == "control" and (
        not result["control_id"].startswith("ax:")
        or not result.get("bundle_id")
        or result.get("topmost_window_id") != result["window_id"]
    ):
        raise ProtocolError("control target requires exact AX/topmost identity")
    if kind == "application" and (
        result["owner_pid"] <= 0
        or not result.get("bundle_id")
        or not result["control_id"].startswith("ax:")
    ):
        raise ProtocolError("application target requires exact process identity")
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
            "arguments": {"limit": _strict_int(args["limit"], "operation log limit", lo=1, hi=100)},
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
    if abs(point_width * scale - width) > 2 or abs(point_height * scale - height) > 2:
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
        "revision": _strict_int(data["revision"], "desktop revision", lo=0, hi=2**63 - 1),
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
    selector_kind = selector["kind"]
    expected_kind = {
        "point": "control",
        "drag": "control",
        "pointer": "control",
        "focused": "control",
        "window_query": "window",
        "application": "application",
    }.get(selector_kind, selector_kind)
    if expected_kind != target["kind"]:
        raise ProtocolError("desktop selector resolved to the wrong target kind")
    if "display_id" in selector and selector["display_id"] != target["display_id"]:
        raise ProtocolError("desktop selector display changed")
    if "window_id" in selector and selector["window_id"] != target["window_id"]:
        raise ProtocolError("desktop selector window changed")
    if "control_id" in selector and selector["control_id"] != target["control_id"]:
        raise ProtocolError("desktop selector control changed")
    if selector_kind == "window_query" and (
        selector["app_name"] != target.get("app_name")
        or selector["window_title"] != target.get("window_title")
    ):
        raise ProtocolError("desktop window query resolved to a different window")
    if selector_kind == "application" and selector["app_name"] != target.get("app_name"):
        raise ProtocolError("desktop application selector resolved to a different process")


def _script_selector_matches_target(
    selector: dict[str, Any],
    target: dict[str, Any],
) -> None:
    """Keep deterministic protocol fixtures compatible without native claims."""

    kind = selector["kind"]
    if kind == "point":
        if not _point_in_target(target, selector["x"], selector["y"]):
            raise ProtocolError("scripted desktop point is outside the target")
        return
    if kind == "drag":
        for x_field, y_field in (("start_x", "start_y"), ("end_x", "end_y")):
            if not _point_in_target(target, selector[x_field], selector[y_field]):
                raise ProtocolError("scripted desktop drag is outside the target")
        return
    _selector_matches_target(selector, target)


def _point_in_target(target: dict[str, Any], x: int, y: int) -> bool:
    left, top, width, height = (int(value) for value in target["bounds"])
    return left <= x < left + width and top <= y < top + height


def _validate_action_target(
    action: dict[str, Any],
    target: dict[str, Any],
    *,
    require_exact_native: bool = False,
) -> None:
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
    if (
        require_exact_native
        and kind in {"click", "move", "drag"}
        and (target["kind"] != "control" or target.get("topmost_window_id") != target["window_id"])
    ):
        raise ProtocolError("desktop coordinate action lacks exact topmost AX identity")
    if require_exact_native and kind == "drag":
        secondary_bounds = target.get("secondary_bounds")
        if (
            not isinstance(secondary_bounds, list)
            or not target.get("secondary_control_id")
            or int(target.get("secondary_owner_pid", 0)) <= 0
            or int(target.get("secondary_window_id", 0)) <= 0
            or not _point_in_target({"bounds": secondary_bounds}, action["end_x"], action["end_y"])
        ):
            raise ProtocolError("desktop drag lacks an exact secondary AX target")
    if kind == "window" and target["kind"] not in {"window", "control"}:
        raise ProtocolError("desktop window action requires a window-bound handle")
    if kind == "window":
        app_name = target.get("app_name")
        window_title = target.get("window_title")
        if app_name is not None and action["app_name"] != app_name:
            raise ProtocolError("desktop action app does not match the observed target")
        if window_title is not None and action["window_title"] != window_title:
            raise ProtocolError("desktop action window does not match the observed target")
    if require_exact_native and kind in {"key", "scroll", "type"} and target["kind"] != "control":
        raise ProtocolError("desktop focus action requires an AX control target")
    if (
        require_exact_native
        and kind in {"key", "type"}
        and (
            int(target.get("focused_owner_pid", 0)) <= 0
            or int(target.get("focused_window_id", 0)) <= 0
            or target.get("focused_owner_pid") != target["owner_pid"]
            or target.get("focused_window_id") != target["window_id"]
            or target.get("focused_control_id") != target["control_id"]
        )
    ):
        raise ProtocolError("desktop focus-dependent action lacks exact AX focus")
    if kind == "scroll":
        pointer_x = target.get("pointer_x")
        pointer_y = target.get("pointer_y")
        if type(pointer_x) is not int or type(pointer_y) is not int:
            raise ProtocolError("desktop scroll lacks a trusted pointer position")
        if not _point_in_target(target, pointer_x, pointer_y):
            raise ProtocolError("desktop scroll pointer is outside the observed target")
    if (
        require_exact_native
        and kind == "app"
        and (target["kind"] != "application" or action["app_name"] != target.get("app_name"))
    ):
        raise ProtocolError("desktop app action does not match an exact application target")
    if require_exact_native and kind in {"clear_stop", "set_mode"}:
        raise ProtocolError("desktop administrative action is unavailable in C2")


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
                raise ProtocolError("desktop script must be an owned 0600 bounded single-link file")
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
            _script_selector_matches_target(selector, state["target"])
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
            _script_selector_matches_target(trusted_selector, state["target"])
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
    """Native macOS pixels and a single Cell-private action sink."""

    def __init__(self, *, action_sink: Any | None = None) -> None:
        if action_sink is None:
            from js.orind.cells.desktop_native import MacOSAXActionSink

            action_sink = MacOSAXActionSink()
        self._action_sink = action_sink
        self._lock = threading.RLock()
        self._revision = 0
        self._operation_count = 0
        self._emergency_stop = False

    def _require_sink(self, name: str) -> Any:
        method = getattr(self._action_sink, name, None)
        if not callable(method):
            raise ProtocolError(f"single native desktop sink is missing {name}")
        return method

    def _window_facts(self, window_id: int) -> dict[str, Any]:
        facts = self._require_sink("window_facts")(window_id)
        parsed = _target_facts(facts)
        bundle = parsed.get("bundle_id")
        if type(bundle) is not str or not bundle or bundle == "pid-only":
            raise ProtocolError("desktop window requires a trusted application bundle")
        return parsed

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

    def _display_bounds(
        self,
        requested_display_id: int,
    ) -> tuple[int, list[int]]:
        """Return point bounds; pixel dimensions are never coordinates."""

        display_id, bounds = self._require_sink("display_bounds")(requested_display_id)
        if (
            type(display_id) is not int
            or display_id <= 0
            or not isinstance(bounds, list)
            or len(bounds) != 4
            or any(type(value) is not int for value in bounds)
            or bounds[2] <= 0
            or bounds[3] <= 0
        ):
            raise ProtocolError("trusted macOS display bounds are unavailable")
        return display_id, list(bounds)

    def _capture(
        self,
        selector: dict[str, Any],
        request: dict[str, Any],
        *,
        identity_scope: str | None = None,
    ) -> tuple[dict[str, Any], str, int, int, dict[str, Any]]:
        from PIL import Image

        from js.tools.desktop.types import ScreenRegion

        args = request["arguments"] if request["tool"] == "desktop_screenshot" else {}
        region = None
        trusted_target: dict[str, Any] | None = None
        exact_selector_kinds = {
            "application",
            "drag",
            "focused",
            "point",
            "pointer",
            "window_query",
        }
        exact_native_target = selector["kind"] in exact_selector_kinds
        if exact_native_target:
            if identity_scope is None:
                raw_target = self._action_sink.resolve(selector)
            else:
                raw_target = self._action_sink.resolve(
                    selector,
                    identity_scope=identity_scope,
                )
            trusted_target = _target_facts(raw_target)
            left, top, point_width, point_height = trusted_target["bounds"]
            region = ScreenRegion(left, top, point_width, point_height)
        elif selector["kind"] == "control":
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
        # Exact native targets capture only their sealed region.  Broader
        # observe requests still capture one real pixel plane and crop inside
        # the Cell; no full-size artifact may leave this process.
        captured_region = region if trusted_target is not None else None
        result = self._require_sink("capture_pixels")(
            region=captured_region,
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

        requested_display_id = (
            int(trusted_target["display_id"])
            if exact_native_target and trusted_target is not None
            else int(selector.get("display_id", 0))
        )
        display_id, display_bounds = self._display_bounds(requested_display_id)
        display_left, display_top, display_width, display_height = display_bounds
        if captured_region is not None:
            if (
                captured_region.x < display_left
                or captured_region.y < display_top
                or captured_region.x + captured_region.width > display_left + display_width
                or captured_region.y + captured_region.height > display_top + display_height
            ):
                raise ProtocolError("desktop target region is outside its trusted display")
            scale_x = full_width / max(1, captured_region.width)
            scale_y = full_height / max(1, captured_region.height)
        else:
            scale_x = full_width / max(1, display_width)
            scale_y = full_height / max(1, display_height)
        if abs(scale_x - scale_y) > 0.05:
            raise ProtocolError("macOS capture has inconsistent coordinate scale")
        scale = (scale_x + scale_y) / 2
        if region is not None and captured_region is None:
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
        if not exact_native_target:
            pointer_x, pointer_y = self._require_sink("pointer_position")()
            if type(pointer_x) is not int or type(pointer_y) is not int:
                raise ProtocolError("desktop pointer position is invalid")
            target.update({"pointer_x": pointer_x, "pointer_y": pointer_y})
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
        *,
        identity_scope: str | None = None,
    ) -> dict[str, Any]:
        selector = normalize_desktop_target(target)
        with self._lock:
            if identity_scope is None:
                captured = self._capture(selector, request)
            else:
                captured = self._capture(
                    selector,
                    request,
                    identity_scope=identity_scope,
                )
            facts, pixel_hash, width, height, projection = captured
            _selector_matches_target(selector, facts)
            tool = request["tool"]
            args = request["arguments"]
            if tool == "desktop_get_permissions":
                status = self._require_sink("permission_status")()
                if (
                    not isinstance(status, dict)
                    or set(status) != {"platform", "accessibility", "screen_recording"}
                    or any(type(value) is not bool for value in status.values())
                ):
                    raise ProtocolError("desktop permission status is invalid")
                projection.update(status)
            elif tool == "desktop_get_state":
                pointer_x, pointer_y = self._require_sink("pointer_position")()
                if type(pointer_x) is not int or type(pointer_y) is not int:
                    raise ProtocolError("desktop pointer position is invalid")
                projection.update(
                    {
                        "available": True,
                        "mouse": {"x": pointer_x, "y": pointer_y},
                        "operation_count": self._operation_count,
                    }
                )
            elif tool == "desktop_list":
                if args["target"] == "apps":
                    listed = self._require_sink("list_apps")()
                    if not isinstance(listed, list):
                        raise ProtocolError("desktop application inventory is invalid")
                    projection["apps"] = [
                        {"name": item["name"], "active": bool(item["active"])}
                        for item in listed[:128]
                        if isinstance(item, dict) and type(item.get("name")) is str and item["name"]
                    ]
                else:
                    listed = self._require_sink("list_windows")(args["app_name"])
                    if not isinstance(listed, list):
                        raise ProtocolError("desktop window inventory is invalid")
                    projection["windows"] = [
                        {
                            "app_name": item["app_name"],
                            "title": item["title"],
                            "bounds": list(item["bounds"]),
                        }
                        for item in listed[:128]
                        if isinstance(item, dict)
                        and type(item.get("app_name")) is str
                        and type(item.get("title")) is str
                        and isinstance(item.get("bounds"), list)
                    ]
            elif tool == "desktop_operation_log":
                projection["operation_count"] = min(self._operation_count, args["limit"])
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
        identity_scope: str | None = None,
    ) -> None:
        normalized = normalize_desktop_action(action)
        trusted_selector = normalize_desktop_target(selector)
        kind = normalized["kind"]
        with self._lock:
            if identity_scope is None:
                captured = self._capture(trusted_selector, request)
            else:
                captured = self._capture(
                    trusted_selector,
                    request,
                    identity_scope=identity_scope,
                )
            facts, pixel_hash, width, height, _projection = captured
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
            _validate_action_target(
                normalized,
                trusted_target,
                require_exact_native=True,
            )
            if self._emergency_stop:
                raise ProtocolError("desktop emergency stop is active")
            if kind == "emergency_stop":
                self._emergency_stop = True
                self._revision += 1
                self._operation_count += 1
                return
            action_sink = self._action_sink
            if action_sink is None:
                raise ProtocolError("exact native desktop action sink is unavailable")
            if identity_scope is None:
                action_sink.perform(
                    normalized,
                    expected_target=trusted_target,
                    selector=trusted_selector,
                )
            else:
                action_sink.perform(
                    normalized,
                    expected_target=trusted_target,
                    selector=trusted_selector,
                    identity_scope=identity_scope,
                )
            self._revision += 1
            self._operation_count += 1

    def release_identity(self, identity_scope: str) -> None:
        release_scope = getattr(self._action_sink, "release_scope", None)
        if release_scope is None:
            return
        if not callable(release_scope):
            raise ProtocolError("native desktop identity release is unavailable")
        release_scope(identity_scope)


class _DesktopReceiptLog:
    """Private 0600 JSONL of attempted/committed desktop actions."""

    def __init__(self, state_dir: Path) -> None:
        self._path = state_dir / "desktop-action-receipts.jsonl"
        self._lock = threading.RLock()
        state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        if not self._path.exists():
            fd = os.open(self._path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(fd)
        mode = self._path.stat().st_mode
        if stat.S_ISLNK(mode) or (mode & 0o777) != 0o600:
            raise ProtocolError("desktop receipt log is not a private 0600 file")

    def record(self, row: dict[str, Any]) -> None:
        with self._lock, self._path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, separators=(",", ":")) + "\n")
            handle.flush()
            os.fsync(handle.fileno())

    def latest(self, *, permit_id: str = "", draft_id: str = "") -> dict[str, Any] | None:
        with self._lock:
            try:
                lines = self._path.read_text(encoding="utf-8").splitlines()
            except OSError:
                return None
        found: dict[str, Any] | None = None
        for line in lines:
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(row, dict):
                continue
            if (
                permit_id
                and row.get("permit_id") == permit_id
                or not permit_id
                and draft_id
                and row.get("draft_id") == draft_id
            ):
                found = row
        return found


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
        self._receipts = _DesktopReceiptLog(state_dir)
        self._lock = threading.RLock()
        super().__init__(
            cap="cell.desktop",
            socket_path=socket_path,
            state_dir=state_dir,
            handler=self._commit_package,
            preflight_handler=self._preflight_package,
            handle_handler=self._resolve_handle,
            reconcile_handler=self._reconcile_effect,
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
            self._release_identity(report.draft_id)
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
        *,
        identity_scope: str | None = None,
    ) -> dict[str, Any]:
        if isinstance(self._backend, MacOSDesktopBackend):
            observed = self._backend.observe(
                selector,
                request,
                identity_scope=identity_scope,
            )
        else:
            observed = self._backend.observe(selector, request)
        return _observation(observed)

    def _release_identity(self, identity_scope: str) -> None:
        if isinstance(self._backend, MacOSDesktopBackend):
            self._backend.release_identity(identity_scope)

    def _new_witness(
        self,
        *,
        package: CellPackage,
        target_version: str,
        material: dict[str, Any],
        writes: int,
    ) -> StateWitness:
        now = _now_ms()
        witness_id = (
            "state:"
            + hmac.new(
                self._mac_key,
                canonical_json(material).encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
        )
        return StateWitness(
            witness_id=witness_id,
            draft_id=package.draft.draft_id,
            executor_id=package.executor_id,
            target_version=target_version,
            canonical_effect_hash=package.canonical_effect_hash,
            impact=Impact(writes=writes),
            reversibility=(
                "reversible_until_stage" if writes == 0 else "irreversible_after_provider_accept"
            ),
            idempotency_support="none" if writes else "query_only",
            created_at_ms=now,
            expires_at_ms=now + _WITNESS_TTL_MS,
        )

    def _granted_bundle_ids(self, package: CellPackage) -> set[str]:
        bundles: set[str] = set()
        for handle in package.resolved_handles:
            if handle.kind != "ApplicationHandle":
                continue
            if "use" not in handle.capabilities or type(handle.object_digest) is not str:
                raise ProtocolError("ApplicationHandle is not usable")
            if not handle.object_digest or len(handle.object_digest) > 512:
                raise ProtocolError("ApplicationHandle bundle is invalid")
            bundles.add(handle.object_digest)
        return bundles

    def _assert_application_authority(
        self,
        package: CellPackage,
        selector: dict[str, Any],
        target: dict[str, Any],
    ) -> None:
        granted = self._granted_bundle_ids(package)
        bundle = target.get("bundle_id")
        selector_kind = selector["kind"]
        target_kind = target.get("kind")
        # Scripted/native screen observe without a bundle remains the tested exception.
        if selector_kind == "screen" and target_kind == "screen":
            return
        if not granted:
            raise ProtocolError("desktop target requires an owner ApplicationHandle")
        if type(bundle) is not str or not bundle or bundle == "pid-only" or bundle not in granted:
            raise ProtocolError("desktop target is outside the granted application")

    def _preflight_observe(self, package: CellPackage) -> DesktopPreflightResult:
        self._prune_private_reports()
        package.validate_binding()
        if any(handle.kind != "ApplicationHandle" for handle in package.resolved_handles):
            raise ProtocolError("desktop.observe may only carry ApplicationHandles")
        arguments = normalize_desktop_observe_arguments(package.draft.arguments)
        selector = arguments["target"]
        request = _normalize_observe_request(arguments["request"])
        prior_handle = self._observation_drafts.get(package.draft.draft_id)
        if prior_handle is None and len(self._reports) >= _MAX_PRIVATE_REPORTS:
            raise ProtocolError("desktop private observation capacity is exhausted")
        try:
            observation = self._observe(
                selector,
                request,
                identity_scope=package.draft.draft_id,
            )
        except Exception:
            if prior_handle is None:
                self._release_identity(package.draft.draft_id)
            raise
        try:
            if isinstance(self._backend, ScriptedDesktopBackend):
                _script_selector_matches_target(selector, observation["target"])
            else:
                _selector_matches_target(selector, observation["target"])
            self._assert_application_authority(package, selector, observation["target"])
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
        except Exception:
            if prior_handle is None:
                self._release_identity(package.draft.draft_id)
            raise
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
        desktop_handles = [
            item for item in package.resolved_handles if item.kind == "DesktopTargetHandle"
        ]
        other_handles = [
            item
            for item in package.resolved_handles
            if item.kind not in {"DesktopTargetHandle", "ApplicationHandle"}
        ]
        if len(desktop_handles) != 1 or other_handles:
            raise ProtocolError("desktop.action requires exactly one DesktopTargetHandle")
        handle = desktop_handles[0]
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
        self._assert_application_authority(package, report.selector, report.observation["target"])
        return handle, report, action

    def _preflight_action(self, package: CellPackage) -> DesktopPreflightResult:
        self._prune_private_reports()
        handle, observed, action = self._authority_for_action(package)
        current = self._observe(
            observed.selector,
            observed.request,
            identity_scope=observed.draft_id,
        )
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
        target_version = (
            "desktop-action:" + hashlib.sha256(canonical_json(material).encode("utf-8")).hexdigest()
        )
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
            return handle.sealed_by(session_key, "cell:desktop", report.witness.created_at_ms)

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
            current = self._observe(
                observed.selector,
                observed.request,
                identity_scope=observed.draft_id,
            )
            before_digest = _state_digest(current)
            if before_digest != report.state_digest:
                raise ProtocolError("desktop target state changed before commit")
            # Claim before crossing the OS side-effect boundary.  If the act
            # or post-observation becomes ambiguous, this Cell instance
            # refuses a second attempt instead of blindly replaying it.
            report.attempted = True
            self._receipts.record(
                {
                    "permit_id": permit.permit_id,
                    "draft_id": package.draft.draft_id,
                    "before_digest": before_digest,
                    "after_digest": "",
                    "target_digest": observed.target_digest,
                    "state": "unknown",
                    "created_at_ms": _now_ms(),
                }
            )
            try:
                if isinstance(self._backend, MacOSDesktopBackend):
                    self._backend.act(
                        action,
                        expected_observation=observed.observation,
                        selector=observed.selector,
                        request=observed.request,
                        identity_scope=observed.draft_id,
                    )
                else:
                    self._backend.act(
                        action,
                        expected_observation=observed.observation,
                        selector=observed.selector,
                        request=observed.request,
                    )
                after = self._observe(
                    observed.selector,
                    observed.request,
                    identity_scope=observed.draft_id,
                )
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
                receipt_id = (
                    "receipt:"
                    + hmac.new(
                        self._mac_key,
                        canonical_json(receipt_material).encode("utf-8"),
                        hashlib.sha256,
                    ).hexdigest()
                )
                report.committed = True
                self._receipts.record(
                    {
                        "permit_id": permit.permit_id,
                        "draft_id": package.draft.draft_id,
                        "before_digest": before_digest,
                        "after_digest": after_digest,
                        "target_digest": observed.target_digest,
                        "state": "committed",
                        "receipt_id": receipt_id,
                        "created_at_ms": _now_ms(),
                    }
                )
                public = {
                    "status": "COMMITTED",
                    "action": action["kind"],
                    "before_digest": before_digest,
                    "after_digest": after_digest,
                    "receipt_id": receipt_id,
                    "target_digest": observed.target_digest,
                }
                finished_at_ms = _now_ms()
                public["signed_receipt"] = seal_signed_effect_receipt(
                    mac_key=self._mac_key,
                    permit_id=permit.permit_id,
                    executor_id="cell.desktop",
                    status="COMMITTED",
                    canonical_effect_hash=package.canonical_effect_hash,
                    result_digest=_sha256(canonical_json(public).encode("utf-8")),
                    started_at_ms=finished_at_ms,
                    finished_at_ms=finished_at_ms,
                    receipt_id=receipt_id,
                )
                return public
            finally:
                # ``attempted`` makes the observation authority single-use.
                # Release retained AX objects on every post-claim exit; the
                # report remains as the replay/ambiguity tombstone until TTL.
                self._release_identity(observed.draft_id)

    def _reconcile_effect(
        self,
        effect_id: str,
        probe: dict[str, Any],
    ) -> dict[str, str]:
        try:
            if not isinstance(effect_id, str) or not 1 <= len(effect_id) <= 256:
                raise ProtocolError("desktop reconcile effect_id is invalid")
            if not isinstance(probe, dict):
                raise ProtocolError("desktop reconcile probe must be an object")
            permit_id = probe.get("permit_id")
            draft_id = probe.get("draft_id")
            if permit_id is not None and (
                type(permit_id) is not str or not 1 <= len(permit_id) <= 256
            ):
                raise ProtocolError("desktop reconcile permit_id is invalid")
            if draft_id is not None and (
                type(draft_id) is not str or not 1 <= len(draft_id) <= 256
            ):
                raise ProtocolError("desktop reconcile draft_id is invalid")
            row = self._receipts.latest(
                permit_id=str(permit_id or ""),
                draft_id=str(draft_id or effect_id),
            )
            if row is None:
                return {"state": "PREPARED"}
            extra: dict[str, str] = {}
            for key in ("before_digest", "after_digest", "target_digest"):
                value = row.get(key)
                if type(value) is str and value.startswith("sha256:") and len(value) == 71:
                    extra[key] = value
            if row.get("state") == "committed" and row.get("after_digest"):
                return {"state": "COMMITTED", **extra}
            return {"state": "UNKNOWN_COMMIT", **extra}
        except Exception:  # noqa: BLE001 - reconciliation is fail-closed
            return {"state": "unknown"}


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
        ScriptedDesktopBackend(Path(script_path)) if script_path else MacOSDesktopBackend()
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
