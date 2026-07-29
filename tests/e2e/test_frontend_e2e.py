"""Playwright end-to-end tests for the web UI."""

from __future__ import annotations

import re
from urllib.parse import quote

import pytest
from playwright.sync_api import Page, expect

pytestmark = pytest.mark.playwright

_FAKE_WEBSOCKET = """
class LocalOnlyFakeWebSocket {
  static OPEN = 1;
  constructor(url) {
    this.url = url;
    this.readyState = LocalOnlyFakeWebSocket.OPEN;
    window.__localTestSocket = this;
    setTimeout(() => this.onopen && this.onopen(), 0);
  }
  send(payload) { this.lastSent = payload; }
  close() {
    this.readyState = 3;
    if (this.onclose) this.onclose();
  }
  emit(frame) {
    if (this.onmessage) this.onmessage({data: JSON.stringify(frame)});
  }
}
window.WebSocket = LocalOnlyFakeWebSocket;
"""


def _open_with_fake_websocket(page: Page, live_server: str) -> None:
    page.add_init_script(_FAKE_WEBSOCKET)
    page.goto(live_server, wait_until="domcontentloaded")
    page.wait_for_function("window.__localTestSocket && typeof window.loadStatus === 'function'")


def _emit(page: Page, frame: dict[str, object]) -> None:
    page.evaluate("frame => window.__localTestSocket.emit(frame)", frame)


class TestPageLoad:
    def test_homepage_loads(self, live_server: str, page: Page) -> None:
        page.goto(live_server, wait_until="domcontentloaded")
        expect(page).to_have_title(re.compile("Agent"))

    def test_app_js_module_loads_without_console_errors(self, live_server: str, page: Page) -> None:
        errors: list[str] = []
        page.on("console", lambda msg: errors.append(msg.text) if msg.type == "error" else None)
        page.goto(live_server, wait_until="domcontentloaded")
        page.wait_for_function("typeof window.loadStatus === 'function'")
        # Filter out non-JS errors (e.g., favicon, websocket connection refused)
        js_errors = [
            e for e in errors if "favicon" not in e.lower() and "websocket" not in e.lower()
        ]
        assert not js_errors, f"JS console errors: {js_errors}"

    def test_page_loads_only_local_runtime_assets(self, live_server: str, page: Page) -> None:
        page.goto(live_server, wait_until="domcontentloaded")
        page.wait_for_function("typeof window.loadStatus === 'function'")

        resource_urls = page.evaluate(
            "performance.getEntriesByType('resource').map(entry => entry.name)"
        )
        assert all(url.startswith(live_server) for url in resource_urls), resource_urls


class TestSidebar:
    def test_sidebar_toggle_button_visible_on_mobile(self, live_server: str, page: Page) -> None:
        page.set_viewport_size({"width": 375, "height": 667})  # iPhone SE
        page.goto(live_server, wait_until="domcontentloaded")
        toggle = page.locator('button[onclick="toggleSidebar()"]')
        expect(toggle).to_be_visible()

    def test_sidebar_hidden_on_mobile_initially(self, live_server: str, page: Page) -> None:
        page.set_viewport_size({"width": 375, "height": 667})
        page.goto(live_server, wait_until="domcontentloaded")
        sidebar = page.locator("#sidebar")
        expect(sidebar).to_have_class(re.compile("-translate-x-full"))

    def test_sidebar_toggles_on_click(self, live_server: str, page: Page) -> None:
        page.set_viewport_size({"width": 375, "height": 667})
        page.goto(live_server, wait_until="domcontentloaded")
        toggle = page.locator('button[onclick="toggleSidebar()"]')
        sidebar = page.locator("#sidebar")
        toggle.click()
        expect(sidebar).not_to_have_class(re.compile("-translate-x-full"))
        toggle.click()
        expect(sidebar).to_have_class(re.compile("-translate-x-full"))


class TestTabNavigation:
    def test_switch_tab_to_dashboard(self, live_server: str, page: Page) -> None:
        page.goto(live_server, wait_until="domcontentloaded")
        page.locator("#nav-dashboard").click()
        dashboard = page.locator("#tab-dashboard")
        expect(dashboard).to_be_visible()
        expect(dashboard).not_to_have_class("hidden")

    def test_switch_tab_to_memory(self, live_server: str, page: Page) -> None:
        page.goto(live_server, wait_until="domcontentloaded")
        page.locator("#nav-memory").click()
        memory = page.locator("#tab-memory")
        expect(memory).to_be_visible()
        expect(memory).not_to_have_class("hidden")

    def test_nav_button_highlighted_after_click(self, live_server: str, page: Page) -> None:
        page.goto(live_server, wait_until="domcontentloaded")
        btn = page.locator("#nav-dashboard")
        btn.click()
        expect(btn).to_have_class(re.compile("text-blue-400"))


class TestWindowMounts:
    def test_toggle_sidebar_is_function(self, live_server: str, page: Page) -> None:
        page.goto(live_server, wait_until="domcontentloaded")
        result = page.evaluate("typeof window.toggleSidebar === 'function'")
        assert result is True

    def test_switch_tab_is_function(self, live_server: str, page: Page) -> None:
        page.goto(live_server, wait_until="domcontentloaded")
        result = page.evaluate("typeof window.switchTab === 'function'")
        assert result is True

    def test_all_window_funcs_are_functions(self, live_server: str, page: Page) -> None:
        page.goto(live_server, wait_until="domcontentloaded")
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


class TestStreamingUI:
    def test_thinking_and_token_deltas_finalize_and_cleanup(
        self, live_server: str, page: Page
    ) -> None:
        _open_with_fake_websocket(page, live_server)

        _emit(page, {"type": "status", "content": "thinking..."})
        expect(page.locator("#typing-indicator")).to_be_visible()
        _emit(page, {"type": "thinking", "content": "first "})
        _emit(page, {"type": "thinking", "content": "second"})
        expect(page.locator(".thinking-block")).to_be_visible()
        expect(page.locator(".thinking-content")).to_have_text("first second")
        _emit(page, {"type": "token", "content": "answer"})
        expect(page.locator("#streaming-bubble")).to_contain_text("answer")

        _emit(page, {"type": "done", "session_id": "synthetic-session"})

        expect(page.locator("#typing-indicator")).to_have_count(0)
        expect(page.locator("#streaming-bubble")).to_have_count(0)
        expect(page.locator(".thinking-block")).not_to_have_attribute("open", "")
        expect(page.locator(".thinking-status")).to_have_text("已完成")

    def test_model_without_thinking_never_creates_thinking_panel(
        self, live_server: str, page: Page
    ) -> None:
        _open_with_fake_websocket(page, live_server)

        _emit(page, {"type": "status", "content": "thinking..."})
        _emit(page, {"type": "token", "content": "plain answer"})
        expect(page.locator("#streaming-bubble")).to_contain_text("plain answer")
        _emit(page, {"type": "done"})

        expect(page.locator(".thinking-block")).to_have_count(0)
        expect(page.locator("#typing-indicator")).to_have_count(0)
        expect(page.locator("#streaming-bubble")).to_have_count(0)
        expect(page.locator(".response-content")).to_have_text("plain answer")

    def test_tool_delta_and_terminal_error_clear_transient_ui(
        self, live_server: str, page: Page
    ) -> None:
        _open_with_fake_websocket(page, live_server)

        _emit(
            page,
            {
                "type": "tool_call",
                "tool_call": {
                    "index": 0,
                    "id": "synthetic-tool",
                    "name": "file_read",
                    "arguments_delta": '{"path":"fixture.txt"}',
                },
            },
        )
        expect(page.locator("#typing-indicator")).to_contain_text("正在读取文件")
        _emit(page, {"type": "thinking", "content": "checking"})
        _emit(page, {"type": "token", "content": "partial"})
        _emit(page, {"type": "error", "content": "synthetic failure"})

        expect(page.locator("#typing-indicator")).to_have_count(0)
        expect(page.locator("#streaming-bubble")).to_have_count(0)
        expect(page.locator(".thinking-status")).to_have_text("已完成")
        expect(page.locator("#chat-messages")).to_contain_text("错误: synthetic failure")

    def test_setup_wizard_can_be_opened_and_closed(self, live_server: str, page: Page) -> None:
        page.goto(live_server, wait_until="domcontentloaded")
        page.wait_for_function("typeof window.showWizard === 'function'")

        page.evaluate("window.showWizard()")
        expect(page.locator("#setup-wizard")).to_be_visible()
        page.evaluate("window.hideWizard()")
        expect(page.locator("#setup-wizard")).to_be_hidden()


class TestAttachmentAPI:
    def test_upload_list_preview_session_isolation_and_delete(
        self, live_server: str, live_server_api_key: str, page: Page
    ) -> None:
        session_id = "browser-synthetic-attachment"
        filename = "synthetic-note.txt"
        content = b"synthetic browser attachment"
        auth_headers = {
            "Origin": live_server,
            "X-API-Key": live_server_api_key,
        }
        upload = page.request.post(
            f"{live_server}/api/upload",
            headers=auth_headers,
            multipart={
                "session_id": session_id,
                "file": {
                    "name": filename,
                    "mimeType": "text/plain",
                    "buffer": content,
                },
            },
        )
        assert upload.ok, upload.text()
        upload_path = upload.json()["path"]

        listed = page.request.get(
            f"{live_server}/api/uploads",
            headers={"X-API-Key": live_server_api_key},
            params={"session_id": session_id},
        )
        assert listed.ok
        assert [item["path"] for item in listed.json()["files"]] == [upload_path]

        preview = page.request.get(
            f"{live_server}/api/file-preview",
            headers={"X-API-Key": live_server_api_key},
            params={"session_id": session_id, "path": upload_path},
        )
        assert preview.ok
        assert preview.json()["content"] == content.decode()

        other_session = page.request.get(
            f"{live_server}/api/uploads",
            headers={"X-API-Key": live_server_api_key},
            params={"session_id": "browser-other-session"},
        )
        assert other_session.ok
        assert other_session.json()["files"] == []

        deleted = page.request.delete(
            f"{live_server}/api/uploads/{quote(filename)}",
            headers=auth_headers,
            params={"session_id": session_id},
        )
        assert deleted.ok, deleted.text()
        assert deleted.json()["success"] is True
        after_delete = page.request.get(
            f"{live_server}/api/uploads",
            headers={"X-API-Key": live_server_api_key},
            params={"session_id": session_id},
        )
        assert after_delete.ok
        assert after_delete.json()["files"] == []


class TestWorkWebProduct:
    def test_work_web_has_distinct_identity_profile_and_skill_boundary(
        self, work_live_server: str, page: Page
    ) -> None:
        page.goto(work_live_server, wait_until="domcontentloaded")
        expect(page).to_have_title("JS Agent Work")
        expect(page.locator("h1").first).to_have_text("JS Agent Work")

        status = page.request.get(f"{work_live_server}/api/status")
        assert status.ok, status.text()
        status_payload = status.json()
        assert status_payload["product_id"] == "js-work"
        assert status_payload["profile"] == "office"
        assert status_payload["echo"]["architecture_state"] == "primary_healthy"

        skills = page.request.get(f"{work_live_server}/api/skills")
        assert skills.ok, skills.text()
        skills_payload = skills.json()
        assert skills_payload["skills"] == []
        assert skills_payload["disabled"] is True
        assert skills_payload.get("global_stats", {}).get("skills_loaded", 0) == 0

        resource_urls = page.evaluate(
            "performance.getEntriesByType('resource').map(entry => entry.name)"
        )
        assert all(url.startswith(work_live_server) for url in resource_urls), resource_urls
