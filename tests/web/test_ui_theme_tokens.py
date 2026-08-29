"""Static contracts for the unified visual shell (B1).

These tests guard the design-token layer, CSP discipline and the absence of
legacy hard-coded dark/blue styling in the production template. They run
without a browser.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
TEMPLATE = REPO / "js" / "web" / "templates" / "index.html"
STATIC = REPO / "js" / "web" / "static"
TOKENS_CSS = STATIC / "css" / "tokens.css"
SHELL_CSS = STATIC / "css" / "shell.css"
THEME_INIT_JS = STATIC / "js" / "theme-init.js"
THEME_JS = STATIC / "js" / "theme.js"
SHELL_JS = STATIC / "js" / "shell.js"
ICONS_JS = STATIC / "js" / "icons.js"
LUCIDE_LICENSE = STATIC / "vendor" / "lucide" / "LICENSE"

# Mandated palette (from the confirmed design spec).
LIGHT_TOKENS = {
    "--color-bg": "#F7F4EC",
    "--color-surface": "#FCFBF7",
    "--color-text": "#23221F",
    "--color-text-secondary": "#77736B",
    "--color-pine": "#355D4C",
    "--color-celadon": "#6E8D7C",
    "--color-cinnabar": "#B84F3B",
}
DARK_TOKENS = {
    "--color-bg": "#181916",
    "--color-nav": "#151613",
    "--color-surface": "#1E201C",
    "--color-text": "#ECE9DF",
    "--color-text-secondary": "#AAA69C",
    "--color-border": "#343630",
    "--color-pine": "#789A87",
    "--color-primary": "#466E59",
    "--color-cinnabar": "#C76048",
}

LEGACY_BRIGHT_BLUE = ("#3b82f6", "#2563eb", "#60a5fa")


def _read(path: Path) -> str:
    assert path.is_file(), f"missing file: {path.relative_to(REPO)}"
    return path.read_text(encoding="utf-8")


class TestTemplateReferences:
    def test_template_links_token_and_shell_css(self) -> None:
        html = _read(TEMPLATE)
        assert "/static/css/tokens.css" in html
        assert "/static/css/shell.css" in html
        assert "/static/css/memory.css" in html

    def test_template_loads_theme_init_before_app(self) -> None:
        html = _read(TEMPLATE)
        init_pos = html.find("/static/js/theme-init.js")
        app_pos = html.find("/static/app.js")
        assert init_pos != -1, "theme-init.js not referenced"
        assert app_pos != -1
        assert init_pos < app_pos, "theme-init.js must load before app.js to avoid flash"

    def test_template_references_shell_js(self) -> None:
        html = _read(TEMPLATE)
        assert "/static/js/shell.js" in html

    def test_csp_stays_self_only(self) -> None:
        html = _read(TEMPLATE)
        m = re.search(r'http-equiv="Content-Security-Policy" content="([^"]+)"', html)
        assert m, "CSP meta missing"
        csp = m.group(1)
        assert "http://" not in csp and "https://" not in csp
        assert "unsafe-eval" not in csp
        assert "script-src 'self'" in csp

    def test_no_legacy_bright_blue_in_template(self) -> None:
        html = _read(TEMPLATE).lower()
        for blue in LEGACY_BRIGHT_BLUE:
            assert blue not in html, f"legacy bright blue {blue} still hardcoded in template"

    def test_no_robot_icon_in_template(self) -> None:
        html = _read(TEMPLATE).lower()
        assert "fa-robot" not in html, "robot brand icon still present"


class TestTokensCss:
    def test_tokens_file_exists(self) -> None:
        _read(TOKENS_CSS)
        _read(SHELL_CSS)

    def test_light_tokens(self) -> None:
        css = _read(TOKENS_CSS)
        for name, value in LIGHT_TOKENS.items():
            assert f"{name}: {value}".lower() in css.lower(), f"missing light token {name}"

    def test_dark_tokens(self) -> None:
        css = _read(TOKENS_CSS)
        dark = re.search(r'data-theme="dark"\s*\]\s*\{(.*?)\}', css, re.S)
        assert dark, "dark theme block missing"
        body = dark.group(1).lower()
        for name, value in DARK_TOKENS.items():
            assert f"{name}: {value}".lower() in body, f"missing dark token {name}={value}"

    def test_reduced_motion_support(self) -> None:
        css = _read(TOKENS_CSS) + _read(SHELL_CSS)
        assert "prefers-reduced-motion" in css

    def test_no_gradient_no_glassmorphism(self) -> None:
        css = (_read(TOKENS_CSS) + _read(SHELL_CSS)).lower()
        assert "linear-gradient" not in css
        assert "backdrop-filter" not in css


class TestThemeInit:
    def test_whitelist_only_values(self) -> None:
        js = _read(THEME_INIT_JS)
        for value in ("light", "dark", "system"):
            assert f"'{value}'" in js or f'"{value}"' in js

    def test_invalid_value_cleared(self) -> None:
        js = _read(THEME_INIT_JS)
        assert "removeItem" in js, "invalid stored theme must be cleared"

    def test_sets_data_theme_before_paint(self) -> None:
        js = _read(THEME_INIT_JS)
        assert "data-theme" in js
        assert "prefers-color-scheme" in js

    def test_no_remote_or_eval(self) -> None:
        js = _read(THEME_INIT_JS)
        assert "eval(" not in js
        assert "http://" not in js and "https://" not in js


class TestIcons:
    def test_lucide_vendored_with_license(self) -> None:
        license_text = _read(LUCIDE_LICENSE)
        assert "ISC License" in license_text

    def test_icons_module_is_line_style(self) -> None:
        js = _read(ICONS_JS)
        assert 'stroke="currentColor"' in js
        assert 'fill="none"' in js

    def test_shell_icon_names_available(self) -> None:
        js = _read(ICONS_JS)
        for name in (
            "message-circle",
            "brain",
            "folder",
            "list-checks",
            "ellipsis",
            "settings",
            "search",
            "sun",
            "moon",
            "monitor",
            "paperclip",
            "send-horizontal",
        ):
            assert f"'{name}'" in js, f"icon {name} missing"
