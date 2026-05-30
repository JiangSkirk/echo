"""Playwright end-to-end tests for the web UI."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from playwright.sync_api import Page, expect

# Use system Chrome on macOS if Playwright browsers are not installed
SYSTEM_CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
USE_SYSTEM_CHROME = Path(SYSTEM_CHROME).exists()

pytestmark = pytest.mark.skipif(
    not (Path.home() / "Library" / "Caches" / "ms-playwright").exists()
    and not (Path.home() / ".cache" / "ms-playwright").exists()
    and not USE_SYSTEM_CHROME,
    reason="No Playwright browsers or system Chrome available",
)


@pytest.fixture(scope="session")
def live_server():
    """Use the already-running dev server for browser tests."""
    import urllib.request
    # Verify server is up
    try:
        with urllib.request.urlopen("http://127.0.0.1:8000/", timeout=5) as resp:
            assert resp.status == 200
    except Exception as exc:
        pytest.skip(f"Dev server not running at http://127.0.0.1:8000: {exc}")
    yield "http://127.0.0.1:8000"


class TestPageLoad:
    def test_homepage_loads(self, live_server: str, page: Page) -> None:
        page.goto(live_server)
        expect(page).to_have_title(re.compile("Agent"))

    def test_app_js_module_loads_without_console_errors(self, live_server: str, page: Page) -> None:
        errors: list[str] = []
        page.on("console", lambda msg: errors.append(msg.text) if msg.type == "error" else None)
        page.goto(live_server)
        page.wait_for_load_state("networkidle")
        # Filter out non-JS errors (e.g., favicon, websocket connection refused)
        js_errors = [e for e in errors if "favicon" not in e.lower() and "websocket" not in e.lower()]
        assert not js_errors, f"JS console errors: {js_errors}"


class TestSidebar:
    def test_sidebar_toggle_button_visible_on_mobile(self, live_server: str, page: Page) -> None:
        page.set_viewport_size({"width": 375, "height": 667})  # iPhone SE
        page.goto(live_server)
        toggle = page.locator('button[onclick="toggleSidebar()"]')
        expect(toggle).to_be_visible()

    def test_sidebar_hidden_on_mobile_initially(self, live_server: str, page: Page) -> None:
        page.set_viewport_size({"width": 375, "height": 667})
        page.goto(live_server)
        sidebar = page.locator("#sidebar")
        expect(sidebar).to_have_class(re.compile("-translate-x-full"))

    def test_sidebar_toggles_on_click(self, live_server: str, page: Page) -> None:
        page.set_viewport_size({"width": 375, "height": 667})
        page.goto(live_server)
        toggle = page.locator('button[onclick="toggleSidebar()"]')
        sidebar = page.locator("#sidebar")
        toggle.click()
        expect(sidebar).not_to_have_class(re.compile("-translate-x-full"))
        toggle.click()
        expect(sidebar).to_have_class(re.compile("-translate-x-full"))


class TestTabNavigation:
    def test_switch_tab_to_dashboard(self, live_server: str, page: Page) -> None:
        page.goto(live_server)
        page.locator('#nav-dashboard').click()
        dashboard = page.locator("#tab-dashboard")
        expect(dashboard).to_be_visible()
        expect(dashboard).not_to_have_class("hidden")

    def test_switch_tab_to_memory(self, live_server: str, page: Page) -> None:
        page.goto(live_server)
        page.locator('#nav-memory').click()
        memory = page.locator("#tab-memory")
        expect(memory).to_be_visible()
        expect(memory).not_to_have_class("hidden")

    def test_nav_button_highlighted_after_click(self, live_server: str, page: Page) -> None:
        page.goto(live_server)
        btn = page.locator('#nav-dashboard')
        btn.click()
        expect(btn).to_have_class(re.compile("text-blue-400"))


class TestWindowMounts:
    def test_toggle_sidebar_is_function(self, live_server: str, page: Page) -> None:
        page.goto(live_server)
        result = page.evaluate("typeof window.toggleSidebar === 'function'")
        assert result is True

    def test_switch_tab_is_function(self, live_server: str, page: Page) -> None:
        page.goto(live_server)
        result = page.evaluate("typeof window.switchTab === 'function'")
        assert result is True

    def test_all_window_funcs_are_functions(self, live_server: str, page: Page) -> None:
        page.goto(live_server)
        missing = page.evaluate("""
            const expected = [
                'showToast','escapeHtml','toggleSidebar','renderMarkdown',
                'switchTab','sendMessage','toggleFleetMode','newSession','toggleSessionList',
                'loadDashboard','loadFiles','loadMemory','loadSkills','loadEvolution',
                'loadStats','loadSearch','doSearch','runEvolutionNow','discoverModels',
                'saveProvider','testCloudProvider','toggleAddProvider','addCloudProvider',
                'onCloudPresetChange','switchModel','deleteProvider','addFleetRoleCard',
                'removeFleetRoleCard','renameFleetRole','saveFleetModelConfig','loadAgents',
                'populateFleetRoleSelect','refreshFleetSubtaskRoles','showAddSemanticModal',
                'submitSemanticMemory','searchSemantic','editSemanticMemory',
                'deleteSemanticMemory','saveSemanticMemory','recoverEmbedder',
                'openMemoryFileEditor','closeMemoryFileEditor','saveMemoryFile',
                'showSkillDetail','closeSkillModal','uninstallSkill','updateTrust',
                'showWizard','hideWizard','wizardNext','wizardPrev','wizardComplete',
                'wizardSelectModel','loadWizardModels','checkFirstStart',
                'showCronCreateModal','hideCronCreateModal','submitCronJob',
                'refreshCronJobs','runCronJob','deleteCronJob','toggleCronJob',
                'parseCronNatural','onCronTemplateChange','loadCronTemplates',
                'renderCronJobs','triggerFileSelect','handleFileSelect',
                'loadSessions','switchSession','deleteSession','setCurrentModel',
                'loadCloudPresets','loadAudit','loadStatus','loadModels',
            ];
            expected.filter(name => typeof window[name] !== 'function');
        """)
        assert not missing, f"Missing window functions: {missing}"
