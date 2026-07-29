"""F-12 regression tests: WebBridge tool exposure and JS scan bypasses.

web_navigate / web_find_tab must be marked dangerous.  The JS scanner must
defeat comment-splitting, unicode/hex escapes, and string-concat
normalization bypasses, plus Reflect.apply / with-statement primitives.
"""

from __future__ import annotations

import pytest

from js.tools.webbridge import WebBridgeTool


@pytest.fixture
def bridge() -> WebBridgeTool:
    return WebBridgeTool()


class TestDangerousFlags:
    def test_web_navigate_is_dangerous(self, bridge: WebBridgeTool) -> None:
        spec = next(s for s in bridge.get_specs() if s.name == "web_navigate")
        assert spec.dangerous is True

    def test_web_find_tab_is_dangerous(self, bridge: WebBridgeTool) -> None:
        spec = next(s for s in bridge.get_specs() if s.name == "web_find_tab")
        assert spec.dangerous is True


class TestJsScanBypassFamilies:
    def test_reflect_apply_eval_rejected(self, bridge: WebBridgeTool) -> None:
        assert bridge._scan_js_code(
            'Reflect.apply(eval, null, ["alert(1)"])'
        ) is not None

    def test_reflect_construct_function_rejected(self, bridge: WebBridgeTool) -> None:
        assert bridge._scan_js_code(
            'Reflect.construct(Function, ["alert(1)"])()'
        ) is not None

    def test_with_statement_rejected(self, bridge: WebBridgeTool) -> None:
        assert bridge._scan_js_code(
            "with(document) { alert(cookie) }"
        ) is not None

    def test_unicode_escape_eval_rejected(self, bridge: WebBridgeTool) -> None:
        assert bridge._scan_js_code('\\u0065val("alert(1)")') is not None

    def test_hex_escape_eval_rejected(self, bridge: WebBridgeTool) -> None:
        assert bridge._scan_js_code('\\x65val("alert(1)")') is not None

    def test_comment_split_eval_rejected(self, bridge: WebBridgeTool) -> None:
        assert bridge._scan_js_code('ev/*x*/al("alert(1)")') is not None

    def test_line_comment_split_rejected(self, bridge: WebBridgeTool) -> None:
        assert bridge._scan_js_code('eval//\n("alert(1)")') is not None

    def test_string_concat_eval_rejected(self, bridge: WebBridgeTool) -> None:
        assert bridge._scan_js_code('window["ev"+"al"]("alert(1)")') is not None

    def test_comment_split_fetch_rejected(self, bridge: WebBridgeTool) -> None:
        assert bridge._scan_js_code("fet/*x*/ch('https://evil.example')") is not None


class TestJsScanLegitCode:
    @pytest.mark.parametrize(
        "code",
        [
            "document.title",
            "document.querySelectorAll('a').length",
            "document.body.innerText.length",
            "JSON.stringify({a: 1})",
            "// a comment mentioning evaluation\n2 + 2",
        ],
    )
    def test_benign_code_allowed(self, bridge: WebBridgeTool, code: str) -> None:
        assert bridge._scan_js_code(code) is None
