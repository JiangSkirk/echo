"""Strict WP-C2 Desktop Cell payload contracts.

These are nested Stage-B payloads, not new orin/v1 message types.  Every
decision is closed-world and deterministic; no model participates in target
or action validation.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import unicodedata
from dataclasses import dataclass
from typing import Any, Final

from js.orin.handles import make_handle_id
from js.orin.protocol import MAX_SEQ, ProtocolError, canonical_json

DESKTOP_TARGET_BINDING_SCHEMA: Final[str] = "DesktopTargetBindingV1"
DESKTOP_TARGET_DOMAIN: Final[str] = "orin:desktop-target:v1"
_SHA256_LEN: Final[int] = 71
_ACTION_KINDS: Final[frozenset[str]] = frozenset(
    {
        "app",
        "clear_stop",
        "click",
        "drag",
        "emergency_stop",
        "key",
        "move",
        "scroll",
        "set_mode",
        "type",
        "window",
    }
)
_SENSITIVE_PROJECTION_TEXT: Final[tuple[str, ...]] = (
    "draft:",
    "package:",
    "permit:",
    "session_key",
    "state:",
    "task:",
    "token:",
)


def _string(value: Any, name: str, *, max_len: int = 512) -> str:
    if type(value) is not str or not value or len(value) > max_len:
        raise ProtocolError(f"{name} must be a bounded string")
    if unicodedata.normalize("NFC", value) != value:
        raise ProtocolError(f"{name} must be NFC normalized")
    if any(unicodedata.category(char).startswith("C") for char in value):
        raise ProtocolError(f"{name} contains control text")
    return value


def _integer(value: Any, name: str, *, lo: int, hi: int) -> int:
    if type(value) is not int or not lo <= value <= hi:
        raise ProtocolError(f"{name} must be an integer in {lo}..{hi}")
    return value


def _sha256(value: Any, name: str) -> str:
    if (
        type(value) is not str
        or len(value) != _SHA256_LEN
        or not value.startswith("sha256:")
        or any(char not in "0123456789abcdef" for char in value[7:])
    ):
        raise ProtocolError(f"{name} must be sha256:<64 hex>")
    return value


def _projection_text(value: Any, name: str, *, max_len: int) -> str:
    text = _string(value, name, max_len=max_len)
    lowered = text.casefold()
    if text.startswith("/") or any(marker in lowered for marker in _SENSITIVE_PROJECTION_TEXT):
        raise ProtocolError(f"{name} contains authority-shaped text")
    return text


def normalize_desktop_safe_projection(
    data: Any,
    *,
    effect_type: str,
) -> dict[str, Any]:
    """Validate the complete Echo-visible Desktop projection by field.

    Cell authentication does not make provider/window text trustworthy.  This
    parser therefore rejects unknown fields, nested authority-shaped values,
    fake booleans and unbounded image/list structures at every hop.
    """

    if not isinstance(data, dict):
        raise ProtocolError("desktop projection must be an object")
    observe_fields = {
        "accessibility",
        "apps",
        "available",
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
        "scale",
        "screen_recording",
        "status",
        "target_kind",
        "target_label",
        "width",
        "window_number",
        "windows",
    }
    action_fields = {
        "action",
        "after_digest",
        "before_digest",
        "commit_guarantee",
        "duplicate",
        "error",
        "receipt_id",
        "status",
    }
    allowed = observe_fields if effect_type == "desktop.observe" else action_fields
    if effect_type not in {"desktop.observe", "desktop.action"} or not set(data).issubset(allowed):
        raise ProtocolError("desktop projection fields are invalid")

    result: dict[str, Any] = {}
    boolean_fields = {"accessibility", "available", "duplicate", "platform", "screen_recording"}
    integer_bounds = {
        "display_id": (0, 2**63 - 1),
        "height": (1, 32_768),
        "observed_at_ms": (0, MAX_SEQ),
        "operation_count": (0, MAX_SEQ),
        "owner_pid": (0, 2**31 - 1),
        "width": (1, 32_768),
        "window_number": (0, 2**63 - 1),
    }
    for key, value in data.items():
        if key in boolean_fields:
            if type(value) is not bool:
                raise ProtocolError(f"desktop projection {key} must be boolean")
            result[key] = value
        elif key in integer_bounds:
            lo, hi = integer_bounds[key]
            parsed = _integer(value, f"desktop projection {key}", lo=lo, hi=hi)
            if key in {"owner_pid", "window_number"}:
                # Cell-internal window/PID identity stays on the Cell/orind hop only.
                continue
            result[key] = parsed
        elif key == "scale":
            if type(value) not in {int, float} or not 0.25 <= value <= 8.0:
                raise ProtocolError("desktop projection scale is invalid")
            result[key] = float(value)
        elif key in {"pixel_hash", "before_digest", "after_digest"}:
            result[key] = _sha256(value, f"desktop projection {key}")
        elif key == "desktop_target_handle_id":
            handle_id = _string(value, key, max_len=256)
            if not handle_id.startswith("desktop:"):
                raise ProtocolError("desktop projection handle id is invalid")
            result[key] = handle_id
        elif key == "receipt_id":
            receipt_id = _string(value, key, max_len=256)
            if not receipt_id.startswith("receipt:"):
                raise ProtocolError("desktop projection receipt id is invalid")
            result[key] = receipt_id
        elif key == "image_base64":
            image = _string(value, key, max_len=48 * 1024)
            try:
                decoded = base64.b64decode(image, validate=True)
            except (ValueError, binascii.Error) as exc:
                raise ProtocolError("desktop projection image is invalid base64") from exc
            if len(decoded) > 32 * 1024:
                raise ProtocolError("desktop projection image is too large")
            result[key] = image
        elif key == "image_mime_type":
            if value != "image/png":
                raise ProtocolError("desktop projection image type is invalid")
            result[key] = value
        elif key == "target_kind":
            if type(value) is not str or value not in {
                "application",
                "control",
                "screen",
                "window",
            }:
                raise ProtocolError("desktop projection target kind is invalid")
            result[key] = value
        elif key == "action":
            if type(value) is not str or value not in _ACTION_KINDS:
                raise ProtocolError("desktop projection action is invalid")
            result[key] = value
        elif key == "status":
            if type(value) is not str or value not in {"COMMITTED", "OBSERVED"}:
                raise ProtocolError("desktop projection status is invalid")
            result[key] = value
        elif key == "commit_guarantee":
            if value != "best_effort":
                raise ProtocolError("desktop projection commit guarantee is invalid")
            result[key] = value
        elif key == "mode":
            if type(value) is not str or value not in {"observe", "confirm"}:
                raise ProtocolError("desktop projection mode is invalid")
            result[key] = value
        elif key in {"error", "target_label"}:
            result[key] = _projection_text(value, key, max_len=512)
        elif key == "mouse":
            if not isinstance(value, dict) or set(value) != {"x", "y"}:
                raise ProtocolError("desktop projection mouse is invalid")
            result[key] = {
                "x": _integer(value["x"], "mouse x", lo=-32_768, hi=32_768),
                "y": _integer(value["y"], "mouse y", lo=-32_768, hi=32_768),
            }
        elif key == "apps":
            if not isinstance(value, list) or len(value) > 128:
                raise ProtocolError("desktop projection apps are invalid")
            apps: list[dict[str, Any]] = []
            for item in value:
                if not isinstance(item, dict) or set(item) != {"name", "active"}:
                    raise ProtocolError("desktop projection app row is invalid")
                if type(item["active"]) is not bool:
                    raise ProtocolError("desktop projection app active must be boolean")
                apps.append(
                    {
                        "name": _projection_text(item["name"], "app name", max_len=256),
                        "active": item["active"],
                    }
                )
            result[key] = apps
        elif key == "windows":
            if not isinstance(value, list) or len(value) > 128:
                raise ProtocolError("desktop projection windows are invalid")
            windows: list[dict[str, Any]] = []
            for item in value:
                if not isinstance(item, dict) or set(item) != {
                    "app_name",
                    "bounds",
                    "title",
                }:
                    raise ProtocolError("desktop projection window row is invalid")
                bounds = item["bounds"]
                if (
                    not isinstance(bounds, list)
                    or len(bounds) != 4
                    or any(type(part) is not int for part in bounds)
                ):
                    raise ProtocolError("desktop projection window bounds are invalid")
                windows.append(
                    {
                        "app_name": _projection_text(
                            item["app_name"], "window app name", max_len=256
                        ),
                        "title": _projection_text(item["title"], "window title", max_len=512),
                        "bounds": [
                            _integer(bounds[0], "window x", lo=-32_768, hi=32_768),
                            _integer(bounds[1], "window y", lo=-32_768, hi=32_768),
                            _integer(bounds[2], "window width", lo=1, hi=32_768),
                            _integer(bounds[3], "window height", lo=1, hi=32_768),
                        ],
                    }
                )
            result[key] = windows
        elif key == "dependencies":
            if not isinstance(value, list) or len(value) > 32:
                raise ProtocolError("desktop projection dependencies are invalid")
            result[key] = [_projection_text(item, "dependency", max_len=128) for item in value]
        else:  # pragma: no cover - closed field sets above are exhaustive
            raise ProtocolError("desktop projection field is unsupported")
    if ("image_base64" in result) != ("image_mime_type" in result):
        raise ProtocolError("desktop projection image fields must be paired")
    return result


def normalize_desktop_target(data: Any) -> dict[str, Any]:
    """Parse the small selector Echo may propose; observed facts stay Cell-side."""

    if not isinstance(data, dict):
        raise ProtocolError("desktop target must be an object")
    kind = data.get("kind")
    if type(kind) is not str:
        raise ProtocolError("desktop target kind is invalid")
    if kind == "screen":
        if set(data) not in ({"kind"}, {"kind", "display_id"}):
            raise ProtocolError("screen target has unknown fields")
        result: dict[str, Any] = {"kind": "screen"}
        if "display_id" in data:
            result["display_id"] = _integer(data["display_id"], "display_id", lo=0, hi=MAX_SEQ)
        return result
    if kind == "window":
        if set(data) != {"kind", "window_id"}:
            raise ProtocolError("window target must contain only window_id")
        return {
            "kind": "window",
            "window_id": _integer(data["window_id"], "window_id", lo=1, hi=MAX_SEQ),
        }
    if kind == "control":
        if set(data) != {"kind", "window_id", "control_id"}:
            raise ProtocolError("control target fields are invalid")
        return {
            "kind": "control",
            "window_id": _integer(data["window_id"], "window_id", lo=1, hi=MAX_SEQ),
            "control_id": _string(data["control_id"], "control_id", max_len=256),
        }
    if kind == "point":
        if set(data) != {"kind", "x", "y"}:
            raise ProtocolError("point target fields are invalid")
        return {
            "kind": "point",
            "x": _integer(data["x"], "point x", lo=-32_768, hi=32_768),
            "y": _integer(data["y"], "point y", lo=-32_768, hi=32_768),
        }
    if kind == "drag":
        if set(data) != {"kind", "start_x", "start_y", "end_x", "end_y"}:
            raise ProtocolError("drag target fields are invalid")
        return {
            "kind": "drag",
            "start_x": _integer(data["start_x"], "drag start_x", lo=-32_768, hi=32_768),
            "start_y": _integer(data["start_y"], "drag start_y", lo=-32_768, hi=32_768),
            "end_x": _integer(data["end_x"], "drag end_x", lo=-32_768, hi=32_768),
            "end_y": _integer(data["end_y"], "drag end_y", lo=-32_768, hi=32_768),
        }
    if kind in {"pointer", "focused"}:
        if set(data) != {"kind"}:
            raise ProtocolError(f"{kind} target has unknown fields")
        return {"kind": kind}
    if kind == "window_query":
        if set(data) != {"kind", "app_name", "window_title"}:
            raise ProtocolError("window query target fields are invalid")
        return {
            "kind": "window_query",
            "app_name": _string(data["app_name"], "app_name", max_len=256),
            "window_title": _string(data["window_title"], "window_title", max_len=512),
        }
    if kind == "application":
        if set(data) != {"kind", "app_name"}:
            raise ProtocolError("application target fields are invalid")
        return {
            "kind": "application",
            "app_name": _string(data["app_name"], "app_name", max_len=256),
        }
    raise ProtocolError("desktop target kind is invalid")


def normalize_desktop_observe_arguments(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict) or set(data) != {"target", "request"}:
        raise ProtocolError("desktop.observe arguments must be target + request")
    target = normalize_desktop_target(data["target"])
    request = normalize_desktop_observe_request(data["request"])
    return {"target": target, "request": request}


def normalize_desktop_observe_request(data: Any) -> dict[str, Any]:
    """Parse one existing DesktopTools observation request exactly."""

    if not isinstance(data, dict) or set(data) != {"tool", "arguments"}:
        raise ProtocolError("desktop observe request fields are invalid")
    tool = data.get("tool")
    args = data.get("arguments")
    if (
        type(tool) is not str
        or not isinstance(args, dict)
        or len(canonical_json(args).encode("utf-8")) > 8_192
    ):
        raise ProtocolError("desktop observe arguments are invalid")
    if tool in {"desktop_get_permissions", "desktop_get_state"}:
        if args:
            raise ProtocolError(f"{tool} takes no arguments")
        return {"tool": tool, "arguments": {}}
    if tool == "desktop_screenshot":
        fields = {"x", "y", "width", "height", "show_cursor"}
        if set(args) != fields:
            raise ProtocolError("desktop_screenshot arguments are invalid")
        width = _integer(args["width"], "screenshot width", lo=0, hi=32_768)
        height = _integer(args["height"], "screenshot height", lo=0, hi=32_768)
        if (width == 0) != (height == 0):
            raise ProtocolError("screenshot width and height must both be zero or positive")
        if type(args["show_cursor"]) is not bool:
            raise ProtocolError("screenshot show_cursor must be boolean")
        return {
            "tool": tool,
            "arguments": {
                "x": _integer(args["x"], "screenshot x", lo=-32_768, hi=32_768),
                "y": _integer(args["y"], "screenshot y", lo=-32_768, hi=32_768),
                "width": width,
                "height": height,
                "show_cursor": args["show_cursor"],
            },
        }
    if tool == "desktop_list":
        if set(args) != {"target", "app_name"}:
            raise ProtocolError("desktop_list arguments are invalid")
        target = args["target"]
        if type(target) is not str or target not in {"apps", "windows"}:
            raise ProtocolError("desktop_list target is invalid")
        app_name = args["app_name"]
        if app_name is not None:
            app_name = _string(app_name, "desktop_list app_name", max_len=256)
        return {
            "tool": tool,
            "arguments": {"target": target, "app_name": app_name},
        }
    if tool == "desktop_operation_log":
        if set(args) != {"limit"}:
            raise ProtocolError("desktop_operation_log arguments are invalid")
        return {
            "tool": tool,
            "arguments": {"limit": _integer(args["limit"], "operation log limit", lo=1, hi=100)},
        }
    raise ProtocolError("desktop observe tool is invalid")


def _exact(data: dict[str, Any], fields: set[str], name: str) -> None:
    if set(data) != fields:
        raise ProtocolError(f"desktop {name} action fields are invalid")


def normalize_desktop_action(data: Any) -> dict[str, Any]:
    """Strict tagged union for every existing DesktopTools mutation."""

    if not isinstance(data, dict):
        raise ProtocolError("desktop action must be an object")
    kind = data.get("kind")

    def coord(value: Any, name: str) -> int:
        return _integer(value, name, lo=-32_768, hi=32_768)

    if kind == "click":
        _exact(data, {"kind", "x", "y", "button", "clicks"}, "click")
        button = data["button"]
        if type(button) is not str or button not in {"left", "right", "middle"}:
            raise ProtocolError("desktop click button is invalid")
        return {
            "kind": kind,
            "x": coord(data["x"], "x"),
            "y": coord(data["y"], "y"),
            "button": button,
            "clicks": _integer(data["clicks"], "clicks", lo=1, hi=2),
        }
    if kind == "move":
        _exact(data, {"kind", "x", "y"}, "move")
        return {"kind": kind, "x": coord(data["x"], "x"), "y": coord(data["y"], "y")}
    if kind == "scroll":
        _exact(data, {"kind", "direction", "amount"}, "scroll")
        direction = data["direction"]
        if type(direction) is not str or direction not in {"up", "down", "left", "right"}:
            raise ProtocolError("desktop scroll direction is invalid")
        return {
            "kind": kind,
            "direction": direction,
            "amount": _integer(data["amount"], "amount", lo=1, hi=100),
        }
    if kind == "drag":
        _exact(
            data,
            {"kind", "start_x", "start_y", "end_x", "end_y", "button"},
            "drag",
        )
        button = data["button"]
        if type(button) is not str or button not in {"left", "right", "middle"}:
            raise ProtocolError("desktop drag button is invalid")
        return {
            "kind": kind,
            "start_x": coord(data["start_x"], "start_x"),
            "start_y": coord(data["start_y"], "start_y"),
            "end_x": coord(data["end_x"], "end_x"),
            "end_y": coord(data["end_y"], "end_y"),
            "button": button,
        }
    if kind == "type":
        _exact(data, {"kind", "text"}, "type")
        return {"kind": kind, "text": _string(data["text"], "text", max_len=4_096)}
    if kind == "key":
        _exact(data, {"kind", "key", "modifiers"}, "key")
        key = _string(data["key"], "key", max_len=64)
        modifiers = data["modifiers"]
        if (
            not isinstance(modifiers, list)
            or len(modifiers) > 4
            or any(
                type(item) is not str or item not in {"cmd", "option", "ctrl", "shift", "fn"}
                for item in modifiers
            )
            or len(set(modifiers)) != len(modifiers)
        ):
            raise ProtocolError("desktop key modifiers are invalid")
        return {"kind": kind, "key": key, "modifiers": list(modifiers)}
    if kind == "app":
        _exact(data, {"kind", "action", "app_name"}, "app")
        action = data["action"]
        if type(action) is not str or action not in {"open", "activate", "quit"}:
            raise ProtocolError("desktop app action is invalid")
        return {
            "kind": kind,
            "action": action,
            "app_name": _string(data["app_name"], "app_name", max_len=256),
        }
    if kind == "window":
        action = data.get("action")
        if type(action) is not str or action not in {"activate", "move", "resize"}:
            raise ProtocolError("desktop window action is invalid")
        common = {"kind", "action", "app_name", "window_title"}
        if action == "activate":
            _exact(data, common, "window")
        elif action == "move":
            _exact(data, common | {"x", "y"}, "window")
        else:
            _exact(data, common | {"width", "height"}, "window")
        result = {
            "kind": kind,
            "action": action,
            "app_name": _string(data["app_name"], "app_name", max_len=256),
            "window_title": _string(data["window_title"], "window_title", max_len=512),
        }
        if action == "move":
            result.update({"x": coord(data["x"], "x"), "y": coord(data["y"], "y")})
        elif action == "resize":
            result.update(
                {
                    "width": _integer(data["width"], "width", lo=1, hi=32_768),
                    "height": _integer(data["height"], "height", lo=1, hi=32_768),
                }
            )
        return result
    if kind == "set_mode":
        _exact(data, {"kind", "mode"}, "set_mode")
        if type(data["mode"]) is not str or data["mode"] not in {"observe", "confirm"}:
            raise ProtocolError("desktop mode is invalid")
        return {"kind": kind, "mode": data["mode"]}
    if kind == "emergency_stop":
        _exact(data, {"kind", "reason"}, "emergency_stop")
        return {"kind": kind, "reason": _string(data["reason"], "reason", max_len=512)}
    if kind == "clear_stop":
        _exact(data, {"kind"}, "clear_stop")
        return {"kind": kind}
    raise ProtocolError("desktop action kind is invalid")


def desktop_target_selector_for_action(data: Any) -> dict[str, Any]:
    """Derive the sole trusted-observe selector for one exact native action.

    Echo never supplies a native PID, window identity, AX path or bundle id.
    It supplies only the existing tool arguments; the Desktop Cell resolves
    those arguments to exact OS facts and seals them into its target handle.
    """

    action = normalize_desktop_action(data)
    kind = action["kind"]
    if kind in {"click", "move"}:
        return {"kind": "point", "x": action["x"], "y": action["y"]}
    if kind == "drag":
        return {
            "kind": "drag",
            "start_x": action["start_x"],
            "start_y": action["start_y"],
            "end_x": action["end_x"],
            "end_y": action["end_y"],
        }
    if kind == "scroll":
        return {"kind": "pointer"}
    if kind in {"type", "key"}:
        return {"kind": "focused"}
    if kind == "app":
        return {"kind": "application", "app_name": action["app_name"]}
    if kind == "window":
        return {
            "kind": "window_query",
            "app_name": action["app_name"],
            "window_title": action["window_title"],
        }
    if kind == "emergency_stop":
        return {"kind": "screen"}
    raise ProtocolError("desktop action has no C2 native target selector")


@dataclass(frozen=True, slots=True)
class DesktopTargetBindingV1:
    task_id: str
    draft_id: str
    witness_id: str
    canonical_effect_hash: str
    owner_key_hash: str
    tenant: str
    expires_at_ms: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": DESKTOP_TARGET_BINDING_SCHEMA,
            "task_id": self.task_id,
            "draft_id": self.draft_id,
            "witness_id": self.witness_id,
            "canonical_effect_hash": self.canonical_effect_hash,
            "owner_key_hash": self.owner_key_hash,
            "tenant": self.tenant,
            "expires_at_ms": self.expires_at_ms,
        }


def desktop_target_binding_from_dict(data: Any) -> DesktopTargetBindingV1:
    fields = {
        "schema",
        "task_id",
        "draft_id",
        "witness_id",
        "canonical_effect_hash",
        "owner_key_hash",
        "tenant",
        "expires_at_ms",
    }
    if not isinstance(data, dict) or set(data) != fields:
        raise ProtocolError("DesktopTargetBindingV1 fields are invalid")
    if data["schema"] != DESKTOP_TARGET_BINDING_SCHEMA:
        raise ProtocolError("DesktopTargetBindingV1 schema is invalid")
    task_id = _string(data["task_id"], "task_id", max_len=256)
    draft_id = _string(data["draft_id"], "draft_id", max_len=256)
    witness_id = _string(data["witness_id"], "witness_id", max_len=256)
    if not task_id.startswith("task:") or not draft_id.startswith("draft:"):
        raise ProtocolError("desktop binding task/draft ids are invalid")
    if not witness_id.startswith("state:"):
        raise ProtocolError("desktop binding witness id is invalid")
    tenant = _string(data["tenant"], "tenant", max_len=32)
    if tenant not in {"personal", "work"}:
        raise ProtocolError("desktop binding tenant is invalid")
    return DesktopTargetBindingV1(
        task_id=task_id,
        draft_id=draft_id,
        witness_id=witness_id,
        canonical_effect_hash=_sha256(data["canonical_effect_hash"], "canonical_effect_hash"),
        owner_key_hash=_sha256(data["owner_key_hash"], "owner_key_hash"),
        tenant=tenant,
        expires_at_ms=_integer(data["expires_at_ms"], "expires_at_ms", lo=1, hi=MAX_SEQ),
    )


def derive_desktop_target_handle_id(
    *,
    task_id: str,
    draft_id: str,
    canonical_effect_hash: str,
    target_digest: str,
) -> str:
    _string(task_id, "task_id", max_len=256)
    _string(draft_id, "draft_id", max_len=256)
    _sha256(canonical_effect_hash, "canonical_effect_hash")
    _sha256(target_digest, "target_digest")
    material = [
        DESKTOP_TARGET_DOMAIN,
        task_id,
        draft_id,
        canonical_effect_hash,
        target_digest,
    ]
    digest = hashlib.sha256(canonical_json(material).encode("utf-8")).hexdigest()
    return make_handle_id("DesktopTargetHandle", digest)


__all__ = [
    "DESKTOP_TARGET_BINDING_SCHEMA",
    "DesktopTargetBindingV1",
    "derive_desktop_target_handle_id",
    "desktop_target_binding_from_dict",
    "desktop_target_selector_for_action",
    "normalize_desktop_action",
    "normalize_desktop_observe_arguments",
    "normalize_desktop_observe_request",
    "normalize_desktop_target",
]
