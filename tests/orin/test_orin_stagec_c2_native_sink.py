"""WP-C2 exact native target and single-sink contracts.

These tests use an injected authority seam so the normal suite never moves the
real pointer or types into the user's desktop.  A local Calculator
``observe → click → observe`` smoke was run by hand on a developer machine;
it is not a CI-gated live test and is not a real-model E2E.
"""

from __future__ import annotations

import tempfile
import threading
from pathlib import Path
from types import MappingProxyType, SimpleNamespace
from typing import Any

import pytest
from PIL import Image

from js.orin.desktop import desktop_target_selector_for_action
from js.orin.protocol import ProtocolError
from js.orind.cells import desktop_native as desktop_native_module
from js.orind.cells.desktop import MacOSDesktopBackend
from js.orind.cells.desktop_native import MacOSAXActionSink, _WindowRow
from js.tools.desktop.types import Point


def _request() -> dict[str, Any]:
    return {
        "tool": "desktop_screenshot",
        "arguments": {
            "x": 0,
            "y": 0,
            "width": 0,
            "height": 0,
            "show_cursor": False,
        },
    }


def _exact_control_target() -> dict[str, Any]:
    return {
        "kind": "control",
        "display_id": 1,
        "window_id": 71,
        "owner_pid": 420,
        "control_id": "ax:" + "1" * 64,
        "bounds": [0, 0, 100, 80],
        "scale": 1.0,
        "app_name": "C2 Fixture",
        "bundle_id": "dev.js-agent.c2-fixture",
        "window_title": "C2 Native Target",
        "control_role": "AXButton",
        "control_subrole": "AXUnknown",
        "control_identifier": "commit-button",
        "topmost_window_id": 71,
        "focused_owner_pid": 420,
        "focused_window_id": 71,
        "focused_control_id": "ax:" + "1" * 64,
        "pointer_x": 20,
        "pointer_y": 24,
    }


class _CaptureOnlyController:
    """Real-pixel-shaped capture seam with every mutation method forbidden."""

    def __init__(self) -> None:
        self.generation = 0
        self.mutation_calls: list[str] = []
        self.screenshot_regions: list[Any] = []

    def screenshot(self, **kwargs: Any) -> dict[str, str]:
        self.screenshot_regions.append(kwargs.get("region"))
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as handle:
            path = Path(handle.name)
        Image.new("RGBA", (100, 80), (self.generation, 0, 0, 255)).save(path)
        return {"path": str(path), "base64": ""}

    def get_mouse_position(self) -> Point:
        return Point(x=20, y=24)

    def __getattr__(self, name: str) -> Any:
        def forbidden(*_args: object, **_kwargs: object) -> None:
            self.mutation_calls.append(name)
            raise AssertionError("capture controller must never become an action sink")

        return forbidden


class _ExactAuthority:
    def __init__(self, controller: _CaptureOnlyController) -> None:
        self.controller = controller
        self.target = _exact_control_target()
        self.resolve_calls: list[dict[str, Any]] = []
        self.identity_scopes: list[str | None] = []
        self.released_scopes: list[str] = []
        self.perform_calls: list[tuple[dict[str, Any], dict[str, Any]]] = []
        self.fail = False

    def resolve(
        self,
        selector: dict[str, Any],
        *,
        identity_scope: str | None = None,
    ) -> dict[str, Any]:
        self.resolve_calls.append(dict(selector))
        self.identity_scopes.append(identity_scope)
        return dict(self.target)

    def perform(
        self,
        action: dict[str, Any],
        *,
        expected_target: dict[str, Any],
        selector: dict[str, Any],
        identity_scope: str | None = None,
    ) -> None:
        assert self.resolve(selector, identity_scope=identity_scope) == expected_target
        self.perform_calls.append((dict(action), dict(expected_target)))
        if self.fail:
            raise ProtocolError("single native desktop sink failed")
        self.controller.generation += 1

    def capture_pixels(self, *, region: Any | None, show_cursor: bool) -> dict[str, str]:
        del show_cursor
        return self.controller.screenshot(region=region)

    def permission_status(self) -> dict[str, bool]:
        return {
            "platform": True,
            "accessibility": True,
            "screen_recording": True,
        }

    def pointer_position(self) -> tuple[int, int]:
        point = self.controller.get_mouse_position()
        return int(point.x), int(point.y)

    def display_bounds(self, display_id: int) -> tuple[int, list[int]]:
        return (display_id or 1, [0, 0, 100, 80])

    def list_apps(self) -> list[dict[str, Any]]:
        return [{"name": "C2 Fixture", "bundle_id": "dev.js-agent.c2-fixture", "active": True}]

    def list_windows(self, app_name: str | None) -> list[dict[str, Any]]:
        del app_name
        return [
            {
                "app_name": "C2 Fixture",
                "title": "C2 Native Target",
                "bounds": [0, 0, 100, 80],
            }
        ]

    def window_facts(self, window_id: int) -> dict[str, Any]:
        return {
            "kind": "window",
            "display_id": 1,
            "window_id": window_id,
            "owner_pid": 420,
            "control_id": "window",
            "bounds": [0, 0, 100, 80],
            "app_name": "C2 Fixture",
            "bundle_id": "dev.js-agent.c2-fixture",
            "window_title": "C2 Native Target",
        }

    def release_scope(self, identity_scope: str) -> None:
        self.released_scopes.append(identity_scope)


def _native_backend(
    controller: _CaptureOnlyController,
    authority: _ExactAuthority,
) -> MacOSDesktopBackend:
    del controller
    backend = MacOSDesktopBackend(action_sink=authority)
    backend._display_bounds = lambda _display_id: (1, [0, 0, 100, 80])  # type: ignore[method-assign]  # noqa: SLF001,E501
    return backend


@pytest.mark.parametrize(
    ("action", "selector"),
    [
        (
            {"kind": "click", "x": 10, "y": 12, "button": "left", "clicks": 1},
            {"kind": "point", "x": 10, "y": 12},
        ),
        (
            {"kind": "move", "x": 10, "y": 12},
            {"kind": "point", "x": 10, "y": 12},
        ),
        (
            {
                "kind": "drag",
                "start_x": 10,
                "start_y": 12,
                "end_x": 30,
                "end_y": 32,
                "button": "left",
            },
            {
                "kind": "drag",
                "start_x": 10,
                "start_y": 12,
                "end_x": 30,
                "end_y": 32,
            },
        ),
        (
            {"kind": "scroll", "direction": "down", "amount": 3},
            {"kind": "pointer"},
        ),
        ({"kind": "type", "text": "exact"}, {"kind": "focused"}),
        (
            {"kind": "key", "key": "return", "modifiers": []},
            {"kind": "focused"},
        ),
        (
            {"kind": "app", "action": "activate", "app_name": "TextEdit"},
            {"kind": "application", "app_name": "TextEdit"},
        ),
        (
            {
                "kind": "window",
                "action": "activate",
                "app_name": "TextEdit",
                "window_title": "C2",
            },
            {
                "kind": "window_query",
                "app_name": "TextEdit",
                "window_title": "C2",
            },
        ),
    ],
)
def test_every_native_action_gets_one_closed_exact_target_selector(
    action: dict[str, Any],
    selector: dict[str, Any],
) -> None:
    assert desktop_target_selector_for_action(action) == selector


@pytest.mark.parametrize(
    ("changed_field", "changed_value"),
    [
        ("window_id", 72),
        ("owner_pid", 421),
        ("control_id", "ax:" + "2" * 64),
        ("topmost_window_id", 72),
        ("bounds", [1, 0, 100, 80]),
    ],
)
def test_exact_target_drift_rejects_before_the_action_sink(
    changed_field: str,
    changed_value: Any,
) -> None:
    controller = _CaptureOnlyController()
    authority = _ExactAuthority(controller)
    backend = _native_backend(controller, authority)
    selector = {"kind": "point", "x": 10, "y": 12}
    observed = backend.observe(selector, _request())
    authority.target[changed_field] = changed_value

    with pytest.raises(ProtocolError):
        backend.act(
            {"kind": "click", "x": 10, "y": 12, "button": "left", "clicks": 1},
            expected_observation=observed,
            selector=selector,
            request=_request(),
        )

    assert authority.perform_calls == []
    assert controller.mutation_calls == []


def test_native_backend_does_not_accept_a_legacy_controller(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden() -> None:
        raise AssertionError("DesktopController must not be constructed by the Cell")

    monkeypatch.setattr("js.tools.desktop.controller.DesktopController", forbidden)
    controller = _CaptureOnlyController()
    authority = _ExactAuthority(controller)
    backend = MacOSDesktopBackend(action_sink=authority)
    backend.observe({"kind": "point", "x": 10, "y": 12}, _request())
    assert controller.mutation_calls == []


def test_native_action_uses_one_sink_and_never_falls_back_after_failure() -> None:
    controller = _CaptureOnlyController()
    authority = _ExactAuthority(controller)
    backend = _native_backend(controller, authority)
    selector = {"kind": "point", "x": 10, "y": 12}
    observed = backend.observe(selector, _request())
    authority.fail = True

    with pytest.raises(ProtocolError, match="single native desktop sink failed"):
        backend.act(
            {"kind": "click", "x": 10, "y": 12, "button": "left", "clicks": 1},
            expected_observation=observed,
            selector=selector,
            request=_request(),
        )

    assert len(authority.perform_calls) == 1
    assert controller.mutation_calls == []
    assert backend._revision == 0  # noqa: SLF001
    assert backend._operation_count == 0  # noqa: SLF001


def test_native_success_requires_fresh_observe_act_observe_pixels() -> None:
    controller = _CaptureOnlyController()
    authority = _ExactAuthority(controller)
    backend = _native_backend(controller, authority)
    selector = {"kind": "point", "x": 10, "y": 12}
    before = backend.observe(selector, _request())

    backend.act(
        {"kind": "click", "x": 10, "y": 12, "button": "left", "clicks": 1},
        expected_observation=before,
        selector=selector,
        request=_request(),
    )
    after = backend.observe(selector, _request())

    assert len(authority.perform_calls) == 1
    assert before["pixel_hash"] != after["pixel_hash"]
    assert before["revision"] == 0
    assert after["revision"] == 1
    assert all(region is not None for region in controller.screenshot_regions)
    assert controller.mutation_calls == []


def test_exact_pixels_use_the_ax_targets_display_instead_of_the_main_display() -> None:
    controller = _CaptureOnlyController()
    authority = _ExactAuthority(controller)
    authority.target["display_id"] = 5
    backend = MacOSDesktopBackend(action_sink=authority)
    requested_displays: list[int] = []

    def display_bounds(display_id: int) -> tuple[int, list[int]]:
        requested_displays.append(display_id)
        return display_id, [0, 0, 100, 80]

    backend._display_bounds = display_bounds  # type: ignore[method-assign]  # noqa: SLF001

    observed = backend.observe({"kind": "point", "x": 10, "y": 12}, _request())

    assert requested_displays == [5]
    assert observed["target"]["display_id"] == 5
    assert controller.screenshot_regions[0] is not None


def test_native_identity_pin_is_scoped_to_one_observation_draft() -> None:
    controller = _CaptureOnlyController()
    authority = _ExactAuthority(controller)
    backend = _native_backend(controller, authority)
    selector = {"kind": "point", "x": 10, "y": 12}
    scope = "draft:" + "1" * 32
    before = backend.observe(selector, _request(), identity_scope=scope)

    backend.act(
        {"kind": "click", "x": 10, "y": 12, "button": "left", "clicks": 1},
        expected_observation=before,
        selector=selector,
        request=_request(),
        identity_scope=scope,
    )
    backend.release_identity(scope)

    assert authority.identity_scopes == [scope, scope, scope]
    assert authority.released_scopes == [scope]


def test_native_ax_path_keeps_the_leaf_control_identity() -> None:
    class _AXPath:
        @staticmethod
        def retain(value: int) -> int:
            return value

        @staticmethod
        def release(_value: int | None) -> None:
            return None

        @staticmethod
        def text(element: int, name: str) -> str | None:
            values = {
                (1, "AXRole"): "AXButton",
                (1, "AXSubrole"): "AXUnknown",
                (1, "AXIdentifier"): "exact-button",
                (2, "AXRole"): "AXWindow",
                (2, "AXSubrole"): "AXStandardWindow",
                (2, "AXIdentifier"): "main-window",
            }
            return values.get((element, name))

        @staticmethod
        def bounds(element: int) -> list[int]:
            return [10, 20, 30, 40] if element == 1 else [0, 0, 100, 80]

        @staticmethod
        def parent(element: int) -> int | None:
            return 2 if element == 1 else None

        @staticmethod
        def child_index(parent: int, child: int) -> int:
            assert (parent, child) == (2, 1)
            return 0

    sink = object.__new__(MacOSAXActionSink)
    sink._ax = _AXPath()  # type: ignore[assignment]  # noqa: SLF001

    path, role, subrole, identifier = sink._path_material(1)  # noqa: SLF001

    assert [item["role"] for item in path] == ["AXButton", "AXWindow"]
    assert (role, subrole, identifier) == (
        "AXButton",
        "AXUnknown",
        "exact-button",
    )


def test_native_window_inventory_accepts_immutable_macos_mappings() -> None:
    quartz_rows = SimpleNamespace(
        kCGWindowListOptionOnScreenOnly=1,
        kCGWindowListExcludeDesktopElements=2,
        kCGNullWindowID=0,
        CGWindowListCopyWindowInfo=lambda _options, _window_id: [
            MappingProxyType(
                {
                    "kCGWindowNumber": 71,
                    "kCGWindowOwnerPID": 420,
                    "kCGWindowOwnerName": "C2 Fixture",
                    "kCGWindowName": "Exact Target",
                    "kCGWindowLayer": 0,
                    "kCGWindowAlpha": 1.0,
                    "kCGWindowBounds": MappingProxyType(
                        {"X": 10, "Y": 20, "Width": 100, "Height": 80}
                    ),
                }
            )
        ],
    )

    sink = object.__new__(MacOSAXActionSink)
    sink._quartz = quartz_rows  # type: ignore[assignment]  # noqa: SLF001

    assert sink._window_rows() == [  # noqa: SLF001
        _WindowRow(
            window_id=71,
            owner_pid=420,
            owner_name="C2 Fixture",
            title="Exact Target",
            bounds=(10, 20, 100, 80),
            layer=0,
            alpha=1.0,
        )
    ]


def test_native_pixel_capture_never_uses_the_clipboard_permission_fallback(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    sink = object.__new__(MacOSAXActionSink)
    commands: list[list[str]] = []
    executable = tmp_path / "screencapture"
    executable.write_text("#!/bin/sh\n", encoding="utf-8")
    executable.chmod(0o700)
    monkeypatch.setattr(sink, "_ensure_screen_capture", lambda: None)
    monkeypatch.setattr(
        desktop_native_module,
        "_SCREENCAPTURE_PATHS",
        (str(executable),),
    )

    def run(command: list[str], **_kwargs: Any) -> SimpleNamespace:
        commands.append(list(command))
        Image.new("RGBA", (20, 20), (0, 0, 0, 255)).save(command[-1])
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(desktop_native_module.subprocess, "run", run)
    result = sink.capture_pixels(
        region=SimpleNamespace(x=10, y=20, width=20, height=20),
        show_cursor=False,
    )
    Path(result["path"]).unlink()

    assert len(commands) == 1
    assert commands[0][0] == str(executable)
    assert "-c" not in commands[0]
    assert "-R10,20,20,20" in commands[0]
    assert commands[0][-2] == "-tpng"


def test_native_permission_projection_never_calls_legacy_clipboard_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    controller = _CaptureOnlyController()
    authority = _ExactAuthority(controller)
    authority.permission_status = lambda: {  # type: ignore[attr-defined]
        "platform": True,
        "accessibility": True,
        "screen_recording": True,
    }
    backend = _native_backend(controller, authority)

    def forbidden() -> dict[str, bool]:
        raise AssertionError("legacy permission probe must not run in Desktop Cell")

    monkeypatch.setattr(
        "js.tools.desktop.permissions.PermissionChecker.get_status",
        forbidden,
    )
    observed = backend.observe(
        {"kind": "screen"},
        {"tool": "desktop_get_permissions", "arguments": {}},
    )

    assert {
        key: observed["projection"][key]
        for key in ("platform", "accessibility", "screen_recording")
    } == {"platform": True, "accessibility": True, "screen_recording": True}


@pytest.mark.parametrize("ambiguous", [False, True])
def test_native_window_query_rejects_occlusion_and_same_name_replacement(
    monkeypatch: pytest.MonkeyPatch,
    ambiguous: bool,
) -> None:
    target = _WindowRow(71, 420, "C2 Fixture", "Exact Target", (0, 0, 100, 80), 0, 1.0)
    blocker = _WindowRow(72, 421, "Cover", "Cover", (0, 0, 100, 80), 0, 1.0)
    rows = [blocker, target]
    if ambiguous:
        rows.append(
            _WindowRow(
                73,
                422,
                "C2 Fixture",
                "Exact Target",
                (0, 0, 100, 80),
                0,
                1.0,
            )
        )
    sink = object.__new__(MacOSAXActionSink)
    monkeypatch.setattr(sink, "_window_rows", lambda: list(rows))

    with pytest.raises(ProtocolError):
        sink._resolve_window_query("C2 Fixture", "Exact Target")  # noqa: SLF001


def test_native_sink_re_resolves_exact_identity_and_dispatches_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sink = object.__new__(MacOSAXActionSink)
    sink._lock = threading.RLock()  # noqa: SLF001
    expected = _exact_control_target()
    expected.pop("scale")
    resolve_calls: list[dict[str, Any]] = []
    dispatches: list[dict[str, Any]] = []

    def resolve(
        selector: dict[str, Any],
        *,
        identity_scope: str | None = None,
    ) -> dict[str, Any]:
        assert identity_scope is None
        resolve_calls.append(dict(selector))
        return dict(expected)

    monkeypatch.setattr(sink, "resolve", resolve)
    monkeypatch.setattr(sink, "_perform_mouse", lambda action: dispatches.append(action))
    action = {"kind": "click", "x": 10, "y": 12, "button": "left", "clicks": 1}
    selector = {"kind": "point", "x": 10, "y": 12}

    sink.perform(action, expected_target=expected, selector=selector)

    assert resolve_calls == [selector]
    assert dispatches == [action]


def test_native_sink_rejects_an_isomorphic_ax_object_replacement() -> None:
    class _AXInstances:
        retained: list[int] = []
        released: list[int] = []

        def retain(self, element: int) -> int:
            self.retained.append(element)
            return element

        def release(self, element: int) -> None:
            self.released.append(element)

        @staticmethod
        def equal(left: int, right: int) -> bool:
            return left == right

    sink = object.__new__(MacOSAXActionSink)
    sink._ax = _AXInstances()  # type: ignore[assignment]  # noqa: SLF001
    sink._lock = threading.RLock()  # noqa: SLF001
    sink._pinned_elements = {}  # noqa: SLF001
    sink._scope_keys = {}  # noqa: SLF001
    selector = {"kind": "point", "x": 10, "y": 12}
    first_key = sink._pin_key("draft:one", selector, "primary")  # noqa: SLF001
    second_key = sink._pin_key("draft:two", selector, "primary")  # noqa: SLF001

    sink._pin_element(  # noqa: SLF001
        first_key, 101, identity_scope="draft:one"
    )
    sink._pin_element(  # noqa: SLF001
        first_key, 101, identity_scope="draft:one"
    )
    with pytest.raises(ProtocolError, match="object instance changed"):
        sink._pin_element(  # noqa: SLF001
            first_key, 202, identity_scope="draft:one"
        )
    sink._pin_element(second_key, 202, identity_scope="draft:two")  # noqa: SLF001
    sink.release_scope("draft:one")

    assert sink._ax.retained == [101, 202]  # type: ignore[attr-defined]  # noqa: SLF001
    assert sink._ax.released == [101]  # type: ignore[attr-defined]  # noqa: SLF001
    assert sink._pinned_elements == {second_key: 202}  # noqa: SLF001


def test_native_application_quit_is_blocked_before_the_unreceiptable_effect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sink = object.__new__(MacOSAXActionSink)
    sink._lock = threading.RLock()  # noqa: SLF001
    expected = _exact_control_target()
    expected.pop("scale")
    expected.update({"kind": "application", "app_name": "TextEdit"})
    dispatches: list[dict[str, Any]] = []
    monkeypatch.setattr(
        sink,
        "resolve",
        lambda _selector, identity_scope=None: dict(expected),
    )
    monkeypatch.setattr(
        sink,
        "_perform_app",
        lambda action, _target: dispatches.append(action),
    )

    with pytest.raises(ProtocolError, match="reconcilable post-observation"):
        sink.perform(
            {"kind": "app", "action": "quit", "app_name": "TextEdit"},
            expected_target=expected,
            selector={"kind": "application", "app_name": "TextEdit"},
        )

    assert dispatches == []
