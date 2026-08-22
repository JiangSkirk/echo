"""B6: visual QA screenshots + responsive checks (Playwright hard gate).

Captures the mandated screenshot set into the round evidence dir and runs
responsive/a11y assertions. Screenshots are evidence artifacts; assertions
are the gate.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

import pytest
from playwright.sync_api import Page, expect

from tests.e2e.test_ui_shell import _goto_shell, _wait_product, _wait_shell_ready
from tests.e2e.test_ui_work_context import _enter_work

pytestmark = pytest.mark.playwright

EVIDENCE_DIR = Path(
    os.environ.get(
        "JS_UI_EVIDENCE_DIR",
        str(
            Path(__file__).resolve().parents[2]
            / ".task-tmp"
            / "evidence"
            / "ui-current"
            / "visual-qa"
        ),
    )
)

THEMES = ("light", "dark")


def _set_theme(page: Page, theme: str) -> None:
    page.evaluate(
        """(theme) => {
            localStorage.setItem('js-theme', theme);
            document.documentElement.setAttribute('data-theme', theme);
            document.documentElement.style.colorScheme = theme;
        }""",
        theme,
    )
    page.wait_for_timeout(150)


def _shot(page: Page, name: str) -> Path:
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    path = EVIDENCE_DIR / f"{name}.png"
    page.screenshot(path=str(path), full_page=False)
    assert path.is_file() and path.stat().st_size > 10_000
    return path


class TestVisualQAScreenshots:
    def test_personal_1440_both_themes(
        self, page: Page, appshell_authed_server: tuple[str, str]
    ) -> None:
        page.set_viewport_size({"width": 1440, "height": 1024})
        _goto_shell(page, appshell_authed_server)
        _wait_shell_ready(page)
        product = _wait_product(page)
        if product == "js-work":
            page.locator("#product-personal-btn").click()
            page.wait_for_load_state("load")
            _wait_shell_ready(page)
            page.wait_for_function(
                "() => document.body.dataset.product === 'js-agent'", timeout=15_000
            )
        for theme in THEMES:
            _set_theme(page, theme)
            self._assert_layout_intact(page, product="personal")
            _shot(page, f"personal-{theme}-1440x1024")

    def test_work_1440_both_themes(
        self, page: Page, appshell_authed_server: tuple[str, str]
    ) -> None:
        page.set_viewport_size({"width": 1440, "height": 1024})
        _enter_work(page, appshell_authed_server)
        for theme in THEMES:
            _set_theme(page, theme)
            self._assert_layout_intact(page, product="work")
            _shot(page, f"work-{theme}-1440x1024")

    def test_personal_and_work_1280(
        self, page: Page, appshell_authed_server: tuple[str, str]
    ) -> None:
        page.set_viewport_size({"width": 1280, "height": 800})
        _goto_shell(page, appshell_authed_server)
        _wait_shell_ready(page)
        product = _wait_product(page)
        if product == "js-work":
            page.locator("#product-personal-btn").click()
            page.wait_for_load_state("load")
            _wait_shell_ready(page)
            page.wait_for_function(
                "() => document.body.dataset.product === 'js-agent'", timeout=15_000
            )
        self._assert_layout_intact(page, product="personal")
        _shot(page, "personal-light-1280x800")
        page.locator("#product-work-btn").click()
        page.wait_for_load_state("load")
        _wait_shell_ready(page)
        page.wait_for_function(
            "() => document.body.dataset.product === 'js-work'", timeout=15_000
        )
        self._assert_layout_intact(page, product="work")
        _shot(page, "work-light-1280x800")

    def test_models_page_and_palette(
        self, page: Page, appshell_authed_server: tuple[str, str]
    ) -> None:
        page.set_viewport_size({"width": 1440, "height": 1024})
        _goto_shell(page, appshell_authed_server)
        _wait_shell_ready(page)
        page.evaluate("window.switchTab('models')")
        expect(page.locator("#tab-models")).to_be_visible()
        page.wait_for_timeout(800)
        _shot(page, "models-page-1440x1024")
        page.keyboard.press("Meta+k")
        expect(page.locator("#command-palette")).to_be_visible()
        page.locator("#command-palette-input").fill("审批")
        page.wait_for_timeout(300)
        _shot(page, "command-palette-open-1440x1024")

    def _assert_layout_intact(self, page: Page, *, product: str) -> None:
        """No clipping, all regions visible, chat input reachable."""
        overflow = page.evaluate(
            "() => document.documentElement.scrollWidth - document.documentElement.clientWidth"
        )
        assert overflow <= 0, f"horizontal overflow: {overflow}px"
        expect(page.locator("#nav-rail")).to_be_visible()
        expect(page.locator("#session-column")).to_be_visible()
        expect(page.locator("#top-bar")).to_be_visible()
        expect(page.locator("#chat-input")).to_be_visible()
        rail_box = page.locator("#nav-rail").bounding_box()
        assert rail_box is not None and rail_box["width"] <= 70, "rail width drift"
        if product == "work":
            expect(page.locator("#work-context-band")).to_be_visible()
            expect(page.locator("#work-context-panel")).to_be_visible()
        else:
            expect(page.locator("#work-context-band")).to_be_hidden()
            expect(page.locator("#work-context-panel")).to_be_hidden()


class TestA11y:
    def test_icon_buttons_have_aria_labels(
        self, page: Page, appshell_authed_server: tuple[str, str]
    ) -> None:
        _goto_shell(page, appshell_authed_server)
        _wait_shell_ready(page)
        unlabeled = page.evaluate(
            """() => Array.from(
                document.querySelectorAll(
                    '#nav-rail button, #top-bar button, .chat-tool-row button, '
                    + '#work-context-panel button'
                )
            ).filter(b => !b.getAttribute('aria-label') && !b.textContent.trim())
            .map(b => b.id || b.className)"""
        )
        assert unlabeled == [], f"icon buttons missing aria-label: {unlabeled}"

    def test_focus_visible_on_interactive(
        self, page: Page, appshell_authed_server: tuple[str, str]
    ) -> None:
        _goto_shell(page, appshell_authed_server)
        _wait_shell_ready(page)
        page.keyboard.press("Tab")
        page.keyboard.press("Tab")
        outline = page.evaluate(
            """() => {
                const el = document.activeElement;
                if (!el) return null;
                const style = getComputedStyle(el);
                return {outline: style.outlineWidth + ' ' + style.outlineStyle,
                        tag: el.tagName};
            }"""
        )
        assert outline is not None
        assert outline["outline"] != "0px none", f"no visible focus: {outline}"

    def test_reduced_motion_honored(
        self, page: Page, appshell_authed_server: tuple[str, str]
    ) -> None:
        page.emulate_media(reduced_motion="reduce")
        page.set_viewport_size({"width": 1024, "height": 768})
        _goto_shell(page, appshell_authed_server)
        _wait_shell_ready(page)
        duration = page.evaluate(
            """() => {
                const el = document.querySelector('#session-column');
                return getComputedStyle(el).transitionDuration;
            }"""
        )
        assert duration in ("0.01ms", "1e-05s", "0s"), f"reduced motion not honored: {duration}"

    def test_status_not_color_only(
        self, page: Page, appshell_authed_server: tuple[str, str]
    ) -> None:
        """Connection status must carry text, not only a colored dot."""
        _goto_shell(page, appshell_authed_server)
        _wait_shell_ready(page)
        page.wait_for_function(
            "() => document.getElementById('conn-status').textContent.trim().length > 0",
            timeout=10_000,
        )
        text = page.locator("#conn-status").inner_text()
        assert re.search(r"已连接|断开|错误|重连", text), f"status lacks text: {text!r}"
