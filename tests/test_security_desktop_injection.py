"""F-11/F-15 regression tests: desktop controller injection & key validation.

F-11: app_name was only quote-escaped, allowing AppleScript string-literal
breakout via backslashes/newlines (e.g. ``foo" & (do shell script "id") & "``).
F-15: the cliclick fallback accepted arbitrary key names and control
characters.
"""

from __future__ import annotations

import platform
from unittest.mock import patch

import pytest

from js.tools.desktop.types import AppAction, WindowAction

pytestmark = pytest.mark.skipif(
    platform.system() != "Darwin", reason="DesktopController is macOS-only"
)


@pytest.fixture
def controller():
    from js.tools.desktop.controller import DesktopController

    return DesktopController()


class TestAppleScriptInjection:
    ATTACK = 'foo" & (do shell script "id") & "'

    def test_escape_helper_escapes_backslash_before_quote(self) -> None:
        from js.tools.desktop.controller import _escape_applescript_string

        assert _escape_applescript_string('a\\"b') == 'a\\\\\\"b'
        assert _escape_applescript_string('say "hi"') == 'say \\"hi\\"'

    def test_escape_helper_rejects_newline(self) -> None:
        from js.tools.desktop.controller import _escape_applescript_string

        with pytest.raises(ValueError, match="control"):
            _escape_applescript_string("foo\ntell application x")

    def test_escape_helper_rejects_carriage_return(self) -> None:
        from js.tools.desktop.controller import _escape_applescript_string

        with pytest.raises(ValueError, match="control"):
            _escape_applescript_string("foo\ropt")

    def test_escape_helper_rejects_control_characters(self) -> None:
        from js.tools.desktop.controller import _escape_applescript_string

        with pytest.raises(ValueError, match="control"):
            _escape_applescript_string("foo\x07bell")

    def test_app_action_injection_stays_inside_string_literal(
        self, controller
    ) -> None:
        captured: dict[str, str] = {}
        with patch.object(
            controller, "_run_applescript", lambda s: captured.setdefault("s", s)
        ):
            controller.app_action(AppAction.ACTIVATE, self.ATTACK)
        script = captured["s"]
        # The payload must remain inside one quoted literal: no raw breakout.
        assert self.ATTACK not in script
        assert 'do shell script \\"id\\"' in script  # quotes neutralized
        assert 'tell application "foo\\"' in script

    def test_window_action_injection_stays_inside_string_literal(
        self, controller
    ) -> None:
        captured: dict[str, str] = {}
        with patch.object(
            controller, "_run_applescript", lambda s: captured.setdefault("s", s)
        ):
            controller.window_action(WindowAction.ACTIVATE, app_name=self.ATTACK)
        script = captured["s"]
        assert self.ATTACK not in script
        assert 'do shell script \\"id\\"' in script  # quotes neutralized

    def test_app_name_with_newline_rejected(self, controller) -> None:
        with pytest.raises(ValueError, match="control"):
            controller.app_action(AppAction.QUIT, 'Safari"\n do shell script "id')

    def test_window_title_escaped(self, controller) -> None:
        captured: dict[str, str] = {}
        with patch.object(
            controller, "_run_applescript", lambda s: captured.setdefault("s", s)
        ):
            controller.window_action(
                WindowAction.ACTIVATE,
                app_name="Safari",
                window_title='x" & (do shell script "id") & "',
            )
        attack = 'x" & (do shell script "id") & "'
        assert attack not in captured["s"]


class TestCliclickKeyValidation:
    def test_key_press_fallback_rejects_unknown_key(self, controller) -> None:
        controller._native = _AlwaysFailNative()
        controller._cliclick_path = "/usr/bin/true"
        with pytest.raises(ValueError, match="key"):
            controller.key_press("kp:return;m:0,0")

    def test_key_press_fallback_allows_whitelisted_key(self, controller) -> None:
        controller._native = _AlwaysFailNative()
        controller._cliclick_path = "/usr/bin/true"
        result = controller.key_press("return")
        assert result["key"] == "return"

    def test_type_text_fallback_rejects_control_characters(
        self, controller
    ) -> None:
        controller._native = _AlwaysFailNative()
        controller._cliclick_path = "/usr/bin/true"
        with pytest.raises(ValueError, match="control"):
            controller.type_text("line1\nline2")

    def test_type_text_fallback_allows_plain_text(self, controller) -> None:
        controller._native = _AlwaysFailNative()
        controller._cliclick_path = "/usr/bin/true"
        result = controller.type_text("hello world")
        assert result["action"] == "type_text"


class TestNativeTypeTextKeyUp:
    """F-15: native type_text must post a key-up for every key-down."""

    def test_type_text_posts_key_up_for_every_key_down(self) -> None:
        from js.tools.desktop import controller_native as native_mod

        backend = native_mod.NativeDesktopBackend()
        posted: list[bool] = []
        with (
            patch.object(native_mod, "_QUARTZ_AVAILABLE", True),
            patch.object(native_mod, "_char_to_keycode", lambda _ch: 1),
            patch.object(native_mod, "_kCGKeyboardEventKeycode", 0),
            patch.object(native_mod, "_kCGHIDEventTap", 0),
            patch.object(native_mod, "_kCGEventFlagMaskShift", 0),
            patch.object(
                native_mod, "_CGEventCreateKeyboardEvent",
                side_effect=lambda _src, keycode, down: (keycode, down),
            ),
            patch.object(
                native_mod, "_CGEventPost",
                side_effect=lambda _tap, event: posted.append(event[1]),
            ),
            patch.object(native_mod, "_CGEventSetIntegerValueField", lambda *a: None),
            patch.object(native_mod.time, "sleep", lambda _s: None),
        ):
            backend.type_text("ab")

        downs = posted.count(True)
        ups = posted.count(False)
        assert downs >= 2
        assert ups >= 2, "every key-down must be paired with a key-up"


class _AlwaysFailNative:
    """Native backend stand-in that always fails so cliclick fallback runs."""

    quartz_available = False

    def __getattr__(self, name: str):
        raise RuntimeError("native backend unavailable in test")
