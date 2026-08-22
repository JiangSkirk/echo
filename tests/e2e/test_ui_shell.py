"""Browser hard-gate tests for the unified visual shell (B1/B2).

Covers: nav rail, session column, top bar, command palette (⌘K), theme
switching + persistence + invalid-value fallback, contrast, responsive
layout, Personal/Work mode layout differences, and reachability of all
secondary features via More/⌘K.
"""

from __future__ import annotations

import pytest
from playwright.sync_api import Page, expect

pytestmark = pytest.mark.playwright

RAIL_PRIMARY = ("对话", "记忆", "文件", "任务", "更多")

CONTRAST_JS = """
(selectors) => {
  function lum(c) {
    const m = c.match(/rgba?\\((\\d+),\\s*(\\d+),\\s*(\\d+)(?:,\\s*([\\d.]+))?\\)/);
    if (!m) return null;
    if (m[4] !== undefined && parseFloat(m[4]) === 0) return null;
    const f = (v) => {
      v = v / 255;
      return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4);
    };
    return 0.2126 * f(+m[1]) + 0.7152 * f(+m[2]) + 0.0722 * f(+m[3]);
  }
  function effectiveBg(el) {
    let node = el;
    while (node) {
      const bg = getComputedStyle(node).backgroundColor;
      const l = lum(bg);
      if (l !== null) return l;
      node = node.parentElement;
    }
    return 1.0;
  }
  const out = {};
  for (const sel of selectors) {
    const el = document.querySelector(sel);
    if (!el) { out[sel] = null; continue; }
    const fg = lum(getComputedStyle(el).color);
    const bg = effectiveBg(el);
    if (fg === null || bg === null) { out[sel] = null; continue; }
    const ratio = (Math.max(fg, bg) + 0.05) / (Math.min(fg, bg) + 0.05);
    out[sel] = Math.round(ratio * 100) / 100;
  }
  return out;
}
"""


def _goto_shell(page: Page, server: tuple[str, str]) -> None:
    """Authenticate via the production bootstrap-key fragment handoff."""
    base_url, key = server
    page.goto(f"{base_url}/#bootstrap-api-key={key}")


def _wait_shell_ready(page: Page) -> None:
    page.wait_for_selector("#nav-rail", timeout=10_000)
    page.wait_for_selector("#session-column", timeout=10_000)
    page.wait_for_selector("#top-bar", timeout=10_000)
    # Shell interactivity (⌘K, popovers, mode layout) is ready only after
    # initShell() completes, which itself awaits the capability manifest.
    page.wait_for_function("() => window.__shellReady === true", timeout=15_000)


class TestShellStructure:
    def test_nav_rail_primary_items(self, page: Page, appshell_authed_server: tuple[str, str]) -> None:
        _goto_shell(page, appshell_authed_server)
        _wait_shell_ready(page)
        rail = page.locator("#nav-rail")
        labels = [rail.locator(f"button[data-rail-label='{name}']") for name in RAIL_PRIMARY]
        for locator in labels:
            expect(locator).to_be_visible()
        expect(rail.locator("button[data-rail-label='设置']")).to_be_visible()
        # Icons must be inline SVG (unified line set), not emoji/text glyphs.
        icons = rail.locator("button svg")
        assert icons.count() >= 6, "rail buttons must render SVG icons"

    def test_session_column(self, page: Page, appshell_authed_server: tuple[str, str]) -> None:
        _goto_shell(page, appshell_authed_server)
        _wait_shell_ready(page)
        column = page.locator("#session-column")
        expect(column.locator("#btn-new-chat")).to_be_visible()
        expect(column.locator("#session-search")).to_be_visible()
        expect(column.locator("#session-list")).to_be_attached()
        expect(column.locator("#session-view-all")).to_be_visible()

    def test_top_bar_elements(self, page: Page, appshell_authed_server: tuple[str, str]) -> None:
        _goto_shell(page, appshell_authed_server)
        _wait_shell_ready(page)
        top = page.locator("#top-bar")
        expect(top.locator("#product-switcher")).to_be_visible()
        expect(top.locator("#current-model")).to_be_visible()
        expect(top.locator("#conn-status")).to_be_visible()
        expect(top.locator("#cmdk-button")).to_be_visible()
        expect(top.locator("#user-entry")).to_be_visible()

    def test_no_horizontal_overflow_1440(self, page: Page, appshell_authed_server: tuple[str, str]) -> None:
        page.set_viewport_size({"width": 1440, "height": 1024})
        _goto_shell(page, appshell_authed_server)
        _wait_shell_ready(page)
        overflow = page.evaluate(
            "() => document.documentElement.scrollWidth - document.documentElement.clientWidth"
        )
        assert overflow <= 0, f"horizontal overflow at 1440px: {overflow}px"


class TestCommandPalette:
    def test_cmdk_opens_and_closes(self, page: Page, appshell_authed_server: tuple[str, str]) -> None:
        _goto_shell(page, appshell_authed_server)
        _wait_shell_ready(page)
        page.keyboard.press("Meta+k")
        palette = page.locator("#command-palette")
        expect(palette).to_be_visible()
        expect(page.locator("#command-palette-input")).to_be_focused()
        page.keyboard.press("Escape")
        expect(palette).to_be_hidden()

    def test_cmdk_button_opens(self, page: Page, appshell_authed_server: tuple[str, str]) -> None:
        _goto_shell(page, appshell_authed_server)
        _wait_shell_ready(page)
        page.locator("#cmdk-button").click()
        expect(page.locator("#command-palette")).to_be_visible()

    def test_cmdk_reaches_secondary_tab(self, page: Page, appshell_authed_server: tuple[str, str]) -> None:
        _goto_shell(page, appshell_authed_server)
        _wait_shell_ready(page)
        page.keyboard.press("Meta+k")
        page.locator("#command-palette-input").fill("模型")
        page.keyboard.press("Enter")
        expect(page.locator("#tab-models")).to_be_visible()


class TestMoreMenu:
    def test_more_menu_lists_secondary_tabs(self, page: Page, appshell_authed_server: tuple[str, str]) -> None:
        _goto_shell(page, appshell_authed_server)
        _wait_shell_ready(page)
        page.locator("#nav-rail button[data-rail-label='更多']").click()
        menu = page.locator("#more-menu")
        expect(menu).to_be_visible()
        for tab in ("models", "approvals", "skills", "cron", "status"):
            expect(menu.locator(f"#nav-{tab}")).to_be_attached()

    def test_all_enabled_tabs_reachable(self, page: Page, appshell_authed_server: tuple[str, str]) -> None:
        """Every tab in the capability manifest must be reachable from rail/more menu."""
        _goto_shell(page, appshell_authed_server)
        _wait_shell_ready(page)
        page.wait_for_function(
            "() => window.__shellReady === true || document.querySelector('#nav-rail') !== null"
        )
        tabs = page.evaluate(
            """async () => {
                const res = await fetch('/api/capabilities');
                if (!res.ok) return [];
                const data = await res.json();
                return data.enabled_tabs || [];
            }"""
        )
        for tab in tabs:
            count = page.locator(f"button#nav-{tab}").count()
            assert count == 1, f"tab {tab} must have exactly one nav entry, found {count}"


class TestTheme:
    def test_theme_toggle_and_persistence(self, page: Page, appshell_authed_server: tuple[str, str]) -> None:
        _goto_shell(page, appshell_authed_server)
        _wait_shell_ready(page)
        html = page.locator("html")
        initial = html.get_attribute("data-theme")
        assert initial in ("light", "dark"), f"unexpected initial theme: {initial}"
        page.locator("#theme-toggle").click()
        toggled = html.get_attribute("data-theme")
        assert toggled in ("light", "dark") and toggled != initial
        page.reload()
        _wait_shell_ready(page)
        assert page.locator("html").get_attribute("data-theme") == toggled

    def test_invalid_stored_theme_falls_back(self, page: Page, appshell_authed_server: tuple[str, str]) -> None:
        page.add_init_script("localStorage.setItem('js-theme', 'neon-purple')")
        _goto_shell(page, appshell_authed_server)
        _wait_shell_ready(page)
        theme = page.locator("html").get_attribute("data-theme")
        assert theme in ("light", "dark")
        stored = page.evaluate("() => localStorage.getItem('js-theme')")
        assert stored in (None, "system", "light", "dark")

    def test_system_theme_follows_preference(
        self, page: Page, appshell_authed_server: tuple[str, str]
    ) -> None:
        page.emulate_media(color_scheme="dark")
        _goto_shell(page, appshell_authed_server)
        _wait_shell_ready(page)
        assert page.locator("html").get_attribute("data-theme") == "dark"
        page.emulate_media(color_scheme="light")
        _goto_shell(page, appshell_authed_server)
        _wait_shell_ready(page)
        assert page.locator("html").get_attribute("data-theme") == "light"

    def test_contrast_aa_both_themes(self, page: Page, appshell_authed_server: tuple[str, str]) -> None:
        _goto_shell(page, appshell_authed_server)
        _wait_shell_ready(page)
        selectors = ["#nav-rail button", "#session-column", "#top-bar"]
        for theme in ("light", "dark"):
            page.evaluate(f"() => document.documentElement.setAttribute('data-theme', '{theme}')")
            ratios = page.evaluate(CONTRAST_JS, selectors)
            for sel, ratio in ratios.items():
                assert ratio is not None, f"cannot measure contrast for {sel} in {theme}"
                assert ratio >= 4.5, f"{sel} contrast {ratio} < 4.5 in {theme} theme"

    def test_same_dom_both_themes(self, page: Page, appshell_authed_server: tuple[str, str]) -> None:
        _goto_shell(page, appshell_authed_server)
        _wait_shell_ready(page)
        # Tag-structure equality is the real invariant: theme switching must
        # never rebuild the DOM. Attributes/text/async content are ignored.
        snapshot_js = """() => Array.from(
            document.getElementById('app-shell').querySelectorAll('*')
        ).filter(e =>
            !e.closest('#session-list') &&
            !e.closest('#chat-messages') &&
            !e.closest('#setup-wizard') &&
            !e.closest('#conn-status') &&
            !e.closest('#theme-toggle') &&
            !e.closest('#current-model') &&
            !e.closest('#wcp-files,#wcp-artifacts,#wcp-approvals,#wcp-current-task')
        ).map(e => e.tagName).join(',')"""
        # Settle async first-render (sessions, models, ws) before snapshot A;
        # A and B are then back-to-back with no async window between them.
        page.wait_for_timeout(1200)
        signature = page.evaluate(snapshot_js)
        page.evaluate("() => document.documentElement.setAttribute('data-theme', 'dark')")
        signature_dark = page.evaluate(snapshot_js)
        assert signature == signature_dark, "light/dark must share one DOM"


class TestResponsive:
    def test_1280_no_clip(self, page: Page, appshell_authed_server: tuple[str, str]) -> None:
        page.set_viewport_size({"width": 1280, "height": 800})
        _goto_shell(page, appshell_authed_server)
        _wait_shell_ready(page)
        overflow = page.evaluate(
            "() => document.documentElement.scrollWidth - document.documentElement.clientWidth"
        )
        assert overflow <= 0, f"horizontal overflow at 1280px: {overflow}px"
        expect(page.locator("#nav-rail")).to_be_visible()
        expect(page.locator("#session-column")).to_be_visible()

    def test_1024_session_column_collapsible(self, page: Page, appshell_authed_server: tuple[str, str]) -> None:
        page.set_viewport_size({"width": 1024, "height": 768})
        _goto_shell(page, appshell_authed_server)
        _wait_shell_ready(page)
        # At 1024 the session column must not cause overflow; toggle must exist.
        overflow = page.evaluate(
            "() => document.documentElement.scrollWidth - document.documentElement.clientWidth"
        )
        assert overflow <= 0
        expect(page.locator("#btn-toggle-session-column")).to_be_visible()


def _wait_product(page: Page, timeout: float = 15_000) -> str:
    """Wait until the server-driven product mode is applied; dump diagnostics on failure."""
    try:
        page.wait_for_function(
            "() => document.body.dataset.product === 'js-agent'"
            " || document.body.dataset.product === 'js-work'",
            timeout=timeout,
        )
    except Exception:
        diag = page.evaluate(
            """async () => {
                const out = {url: location.href, product: document.body.dataset.product};
                try {
                    const r1 = await fetch('/api/capabilities');
                    out.cap_status = r1.status;
                    const r2 = await fetch('/api/appshell/capabilities');
                    out.appshell_status = r2.status;
                    if (r2.ok) out.mode = (await r2.json()).active_mode;
                    const rb = await fetch('/api/appshell/bootstrap', {method: 'POST'});
                    out.bootstrap_status = rb.status;
                    out.bootstrap_body = (await rb.text()).slice(0, 200);
                } catch (e) { out.err = String(e); }
                return out;
            }"""
        )
        raise AssertionError(f"product mode never applied: {diag}") from None
    return page.evaluate("() => document.body.dataset.product")


class TestModeLayouts:
    def test_personal_hides_work_context(self, page: Page, appshell_authed_server: tuple[str, str]) -> None:
        _goto_shell(page, appshell_authed_server)
        _wait_shell_ready(page)
        product = _wait_product(page)
        if product == "js-work":
            page.locator("#product-personal-btn").click()
            page.wait_for_load_state("load")
            _wait_shell_ready(page)
            page.wait_for_function("() => document.body.dataset.product === 'js-agent'", timeout=15_000)
        expect(page.locator("#work-context-band")).to_be_hidden()
        expect(page.locator("#work-context-panel")).to_be_hidden()
        expect(page.locator("#workspace-label")).to_be_hidden()

    def test_work_shows_context_band(self, page: Page, appshell_authed_server: tuple[str, str]) -> None:
        _goto_shell(page, appshell_authed_server)
        _wait_shell_ready(page)
        product = _wait_product(page)
        if product == "js-agent":
            page.locator("#product-work-btn").click()
            page.wait_for_load_state("load")
            _wait_shell_ready(page)
            page.wait_for_function("() => document.body.dataset.product === 'js-work'", timeout=15_000)
        expect(page.locator("#work-context-band")).to_be_visible()
        expect(page.locator("#work-context-panel")).to_be_visible()
        expect(page.locator("#workspace-label")).to_be_visible()
        # Workspace label is a label, not a fake dropdown selector.
        tag = page.evaluate(
            "() => document.getElementById('workspace-label').tagName.toLowerCase()"
        )
        assert tag != "select", "workspace must be a label, not a selector"
        assert (
            page.locator("#workspace-label select").count() == 0
        ), "workspace label must not contain a dropdown"
