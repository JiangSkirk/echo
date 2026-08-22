"""Playwright end-to-end tests for the web UI."""

from __future__ import annotations

import json
import re
from pathlib import Path
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

_FAKE_CONFIGURED_MODELS = {
    "active_model": "browser-fixture/model",
    "providers": [
        {
            "name": "browser-fixture",
            "healthy": False,
            "has_key": True,
            "models": [
                {
                    "id": "model",
                    "name": "Browser Fixture",
                    "provider": "browser-fixture",
                    "context_window": 8192,
                }
            ],
        }
    ],
    "presets": [],
}


def _open_with_fake_websocket(page: Page, live_server: str) -> None:
    page.add_init_script(_FAKE_WEBSOCKET)
    # Streaming tests exercise lifecycle, not the zero-model product guard.
    # Give them one anonymous configured model so sendMessage reaches the fake
    # socket under the same contract as production.
    page.route(
        "**/api/models",
        lambda route: route.fulfill(
            status=200,
            body=json.dumps(_FAKE_CONFIGURED_MODELS),
            content_type="application/json",
        ),
    )
    page.goto(live_server, wait_until="domcontentloaded")
    page.wait_for_function(
        "() => window.__localTestSocket && typeof window.loadStatus === 'function'"
    )
    page.wait_for_function("() => document.body.dataset.modelCatalogSnapshot === 'true'")


def _emit(page: Page, frame: dict[str, object]) -> None:
    identified = page.evaluate(
        """frame => {
          const identifiedTypes = new Set([
            'token', 'thinking', 'tool_call', 'usage', 'stream_diagnostic',
            'response', 'done', 'status', 'progress', 'error'
          ]);
          if (!identifiedTypes.has(frame.type) || frame.request_id) return frame;
          let sent = null;
          try { sent = JSON.parse(window.__localTestSocket.lastSent || 'null'); } catch (_) {}
          if (!sent || sent.type !== 'stream') {
            const input = document.getElementById('chat-input');
            input.value = 'synthetic identified turn';
            window.sendMessage();
            sent = JSON.parse(window.__localTestSocket.lastSent);
          }
          if (!window.__localTestStreamIdentity) {
            window.__localTestStreamIdentity = {
              request_id: sent.request_id,
              turn_id: sent.turn_id,
              run_id: `synthetic-run-${sent.request_id}`,
              session_id: sent.session_id,
            };
          }
          return {...frame, ...window.__localTestStreamIdentity};
        }""",
        frame,
    )
    page.evaluate("frame => window.__localTestSocket.emit(frame)", identified)


def _route_appshell_capabilities(page: Page) -> None:
    page.route(
        "**/api/capabilities",
        lambda route: route.fulfill(
            status=200,
            body='{"product_id":"js-agent","enabled_tabs":["chat"]}',
            content_type="application/json",
        ),
    )
    page.route(
        "**/api/appshell/capabilities",
        lambda route: route.fulfill(
            status=200,
            body=(
                '{"active_mode":"personal","workspace":null,'
                '"available_modes":["personal","work"],'
                '"mode_roles":{"personal":"admin","work":"admin"},'
                '"workspace_handles":{"personal":null,"work":"ws-test"}}'
            ),
            content_type="application/json",
        ),
    )


class TestPageLoad:
    def test_homepage_loads(self, live_server: str, page: Page) -> None:
        page.goto(live_server, wait_until="domcontentloaded")
        expect(page).to_have_title(re.compile("Agent"))

    def test_app_js_module_loads_without_console_errors(self, live_server: str, page: Page) -> None:
        errors: list[str] = []
        page.on("console", lambda msg: errors.append(msg.text) if msg.type == "error" else None)
        page.goto(live_server, wait_until="domcontentloaded")
        page.wait_for_function("() => typeof window.loadStatus === 'function'")
        # Filter out non-JS errors (e.g., favicon, websocket, resource 404)
        js_errors = [
            e for e in errors
            if "favicon" not in e.lower()
            and "websocket" not in e.lower()
            and "Failed to load resource" not in e
        ]
        assert not js_errors, f"JS console errors: {js_errors}"

    def test_page_loads_only_local_runtime_assets(self, live_server: str, page: Page) -> None:
        page.goto(live_server, wait_until="domcontentloaded")
        page.wait_for_function("() => typeof window.loadStatus === 'function'")

        resource_urls = page.evaluate(
            "performance.getEntriesByType('resource').map(entry => entry.name)"
        )
        assert all(url.startswith(live_server) for url in resource_urls), resource_urls


class TestSidebar:
    """Legacy sidebar was replaced by the nav rail + collapsible session column."""

    def test_sidebar_toggle_button_visible_on_mobile(self, live_server: str, page: Page) -> None:
        page.set_viewport_size({"width": 375, "height": 667})  # iPhone SE
        page.goto(live_server, wait_until="domcontentloaded")
        toggle = page.locator("#btn-toggle-session-column")
        expect(toggle).to_be_visible()

    def test_sidebar_hidden_on_mobile_initially(self, live_server: str, page: Page) -> None:
        page.set_viewport_size({"width": 375, "height": 667})
        page.goto(live_server, wait_until="domcontentloaded")
        page.wait_for_function("() => window.__shellReady === true")
        expect(page.locator("#app-shell")).to_have_class(re.compile("session-collapsed"))

    def test_sidebar_toggles_on_click(self, live_server: str, page: Page) -> None:
        page.set_viewport_size({"width": 375, "height": 667})
        page.goto(live_server, wait_until="domcontentloaded")
        page.wait_for_function("() => window.__shellReady === true")
        toggle = page.locator("#btn-toggle-session-column")
        shell = page.locator("#app-shell")
        toggle.click()
        expect(shell).not_to_have_class(re.compile("session-collapsed"))
        toggle.click()
        expect(shell).to_have_class(re.compile("session-collapsed"))


class TestTabNavigation:
    def test_switch_tab_to_dashboard(self, live_server: str, page: Page) -> None:
        page.goto(live_server, wait_until="domcontentloaded")
        page.wait_for_function("() => window.__shellReady === true")
        page.locator("#nav-rail button[data-tab='__more__']").click()
        page.locator("#more-menu #nav-dashboard").click()
        dashboard = page.locator("#tab-dashboard")
        expect(dashboard).to_be_visible()
        expect(dashboard).not_to_have_class("hidden")

    def test_switch_tab_to_memory(self, live_server: str, page: Page) -> None:
        page.goto(live_server, wait_until="domcontentloaded")
        page.wait_for_function("() => window.__shellReady === true")
        page.locator("#nav-memory").click()
        memory = page.locator("#tab-memory")
        expect(memory).to_be_visible()
        expect(memory).not_to_have_class("hidden")

    def test_nav_button_highlighted_after_click(self, live_server: str, page: Page) -> None:
        page.goto(live_server, wait_until="domcontentloaded")
        page.wait_for_function("() => window.__shellReady === true")
        btn = page.locator("#nav-memory")
        btn.click()
        expect(btn).to_have_class(re.compile("shell-active"))


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


class TestAppShellSwitchFailClosed:
    def test_legacy_storage_key_is_purged_before_automatic_bootstrap(
        self,
        appshell_legacy_key_server: tuple[str, Path, str],
        page: Page,
    ) -> None:
        from js.exceptions import AuthRequiredError
        from js.web.auth import AuthManager

        base_url, work_state, legacy_key = appshell_legacy_key_server
        bootstrap_headers: list[dict[str, str]] = []
        page.add_init_script(
            f"localStorage.setItem('js-api-key', {json.dumps(legacy_key)});"
        )

        def record_bootstrap(request: object) -> None:
            bootstrap_headers.append(request.headers)  # type: ignore[attr-defined]

        page.on(
            "request",
            lambda request: (
                record_bootstrap(request)
                if request.url.endswith("/api/appshell/bootstrap")
                else None
            ),
        )

        page.goto(base_url, wait_until="domcontentloaded")
        page.wait_for_function("() => typeof window.saveApiKey === 'function'")
        page.wait_for_timeout(100)

        assert len(bootstrap_headers) == 1
        assert "x-api-key" not in bootstrap_headers[0]
        assert page.evaluate("localStorage.getItem('js-api-key')") is None
        assert page.evaluate(
            "import('/static/state/store.js').then(module => module.state.apiKey)"
        ) == ""
        with pytest.raises(AuthRequiredError):
            AuthManager(work_state).verify(legacy_key)

    def test_clear_key_uses_only_parent_logout(
        self,
        live_server: str,
        page: Page,
    ) -> None:
        called: list[str] = []
        _route_appshell_capabilities(page)
        page.route(
            "**/api/appshell/bootstrap",
            lambda route: route.fulfill(status=401, body='{"detail":"login required"}'),
        )

        def logout(route: object) -> None:
            called.append(route.request.url)  # type: ignore[attr-defined]
            route.fulfill(  # type: ignore[attr-defined]
                status=200,
                body='{"success":true}',
                content_type="application/json",
            )

        page.route("**/api/appshell/logout", logout)
        page.route("**/api/auth/logout", logout)
        _open_with_fake_websocket(page, live_server)

        page.evaluate("window.saveApiKey('')")
        page.wait_for_timeout(100)

        assert len(called) == 1
        assert called[0].endswith("/api/appshell/logout")

    def test_page_attempts_parent_bootstrap_before_first_mode_use(
        self,
        live_server: str,
        page: Page,
    ) -> None:
        bootstrap_requests = 0
        _route_appshell_capabilities(page)

        def bootstrap(route: object) -> None:
            nonlocal bootstrap_requests
            bootstrap_requests += 1
            route.fulfill(  # type: ignore[attr-defined]
                status=200,
                body=(
                    '{"success":true,"principal":{"schema":"AppShellPrincipalV1",'
                    '"active_mode":"personal","mode_roles":{"personal":"admin",'
                    '"work":"admin"},"workspace":null}}'
                ),
                content_type="application/json",
            )

        page.route("**/api/appshell/bootstrap", bootstrap)
        _open_with_fake_websocket(page, live_server)
        page.wait_for_timeout(100)

        assert bootstrap_requests == 1

    def test_manual_parent_login_refreshes_trusted_capabilities(
        self,
        live_server: str,
        page: Page,
    ) -> None:
        logged_in = False
        post_login_capability_requests = 0

        page.route(
            "**/api/appshell/bootstrap",
            lambda route: route.fulfill(status=401, body='{"detail":"login required"}'),
        )

        def session(route: object) -> None:
            nonlocal logged_in
            logged_in = True
            route.fulfill(  # type: ignore[attr-defined]
                status=200,
                body='{"success":true}',
                content_type="application/json",
            )

        def product_caps(route: object) -> None:
            nonlocal post_login_capability_requests
            if logged_in:
                post_login_capability_requests += 1
                route.fulfill(  # type: ignore[attr-defined]
                    status=200,
                    body='{"product_id":"js-agent","enabled_tabs":["chat"]}',
                    content_type="application/json",
                )
            else:
                route.fulfill(status=401, body='{"detail":"login required"}')  # type: ignore[attr-defined]

        page.route("**/api/appshell/session", session)
        page.route("**/api/capabilities", product_caps)
        page.route(
            "**/api/appshell/capabilities",
            lambda route: route.fulfill(
                status=200,
                body=(
                    '{"active_mode":"personal","workspace":null,'
                    '"workspace_handles":{"personal":null,"work":"ws-test"}}'
                ),
                content_type="application/json",
            ),
        )
        _open_with_fake_websocket(page, live_server)

        page.evaluate("window.saveApiKey('js_browser-login-test-key')")
        page.wait_for_timeout(100)

        assert logged_in is True
        assert post_login_capability_requests == 1

    @pytest.mark.parametrize("status", [401, 403, 409])
    def test_http_failure_preserves_current_mode_ui_and_socket(
        self,
        live_server: str,
        page: Page,
        status: int,
    ) -> None:
        _route_appshell_capabilities(page)
        requests_seen = 0

        def reject_switch(route: object) -> None:
            nonlocal requests_seen
            requests_seen += 1
            route.fulfill(  # type: ignore[attr-defined]
                status=status,
                body='{"detail":"synthetic switch denial"}',
                content_type="application/json",
            )

        page.route(
            "**/api/appshell/switch",
            reject_switch,
        )
        _open_with_fake_websocket(page, live_server)
        page.evaluate("""
            document.getElementById('chat-messages').innerHTML =
              '<div id="switch-preserved-marker">keep me</div>';
            window.__socketBeforeSwitch = window.__localTestSocket;
        """)
        before_url = page.url

        page.evaluate("window.switchProductWorkspace('js-work')")
        page.wait_for_timeout(100)

        assert page.url == before_url
        expect(page.locator("#switch-preserved-marker")).to_have_text("keep me")
        assert page.evaluate(
            "window.__localTestSocket === window.__socketBeforeSwitch && "
            "window.__localTestSocket.readyState === 1"
        )
        assert requests_seen == 1

    def test_network_failure_preserves_current_mode_ui_and_socket(
        self,
        live_server: str,
        page: Page,
    ) -> None:
        _route_appshell_capabilities(page)
        requests_seen = 0

        def abort_switch(route: object) -> None:
            nonlocal requests_seen
            requests_seen += 1
            route.abort("failed")  # type: ignore[attr-defined]

        page.route("**/api/appshell/switch", abort_switch)
        _open_with_fake_websocket(page, live_server)
        page.evaluate("""
            document.getElementById('chat-messages').innerHTML =
              '<div id="switch-preserved-marker">keep me</div>';
            window.__socketBeforeSwitch = window.__localTestSocket;
        """)
        before_url = page.url

        page.evaluate("window.switchProductWorkspace('js-work')")

        assert page.url == before_url
        expect(page.locator("#switch-preserved-marker")).to_have_text("keep me")
        assert page.evaluate(
            "window.__localTestSocket === window.__socketBeforeSwitch && "
            "window.__localTestSocket.readyState === 1"
        )
        assert requests_seen == 1

    def test_success_clears_then_navigates_only_to_server_target(
        self,
        live_server: str,
        page: Page,
    ) -> None:
        target_url = live_server + "/synthetic-switch-target"
        seen_request: dict[str, object] = {}
        _route_appshell_capabilities(page)

        def fulfill_switch(route: object) -> None:
            request = route.request  # type: ignore[attr-defined]
            seen_request.update(request.post_data_json)
            route.fulfill(  # type: ignore[attr-defined]
                status=200,
                body=(
                    '{"ok":true,"clear_ui_cache_keys":["messages"],'
                    '"target_path":"/synthetic-switch-target","must_reconnect":true}'
                ),
                content_type="application/json",
            )

        page.route(
            "**/api/appshell/switch",
            fulfill_switch,
        )
        page.route(
            "**/synthetic-switch-target",
            lambda route: route.fulfill(
                status=200,
                body=(
                    "<body><script>document.body.textContent = "
                    "sessionStorage.getItem('switch-mode') + '|' + "
                    "sessionStorage.getItem('switch-ui-cleared');</script></body>"
                ),
                content_type="text/html",
            ),
        )
        _open_with_fake_websocket(page, live_server)
        _emit(page, {"type": "done"})
        stream_session_id = page.evaluate(
            "JSON.parse(window.__localTestSocket.lastSent).session_id"
        )
        assert isinstance(stream_session_id, str)
        assert stream_session_id
        page.evaluate("""
            const messages = document.getElementById('chat-messages');
            messages.innerHTML = '<div>departing data</div>';
            new MutationObserver(() => {
              if (messages.children.length === 0) {
                sessionStorage.setItem('switch-ui-cleared', 'yes');
                sessionStorage.setItem('switch-mode', 'work');
              }
            }).observe(messages, {childList: true});
        """)

        page.evaluate("window.switchProductWorkspace('js-work')")
        page.wait_for_url(target_url)

        expect(page.locator("body")).to_have_text("work|yes")
        assert seen_request == {
            "expected_from_mode": "personal",
            "to_mode": "work",
            "session_id": stream_session_id,
            "workspace_handle": "ws-test",
        }


class TestRealAppShellBrowserRoute:
    def test_one_origin_switches_actual_root_api_from_personal_to_work(
        self,
        appshell_live_server: str,
        page: Page,
    ) -> None:
        requests: list[str] = []
        page.on("request", lambda request: requests.append(request.url))
        page.goto(appshell_live_server, wait_until="domcontentloaded")
        page.wait_for_function(
            "() => typeof window.switchProductWorkspace === 'function'"
        )

        page.wait_for_function(
            """async () => {
              const response = await fetch('/api/status');
              return response.ok && (await response.json()).product_id === 'js-agent';
            }"""
        )
        page.evaluate("window.switchProductWorkspace('js-work')")
        page.wait_for_function(
            """async () => {
              const response = await fetch('/api/status');
              return response.ok && (await response.json()).product_id === 'js-work';
            }"""
        )

        assert page.url.rstrip("/") == appshell_live_server
        assert all(url.startswith(appshell_live_server) for url in requests)
        assert not any("8765" in url for url in requests)


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
        progress = page.locator(".run-progress").last
        expect(progress).to_contain_text("正在读取文件")
        _emit(page, {"type": "thinking", "content": "checking"})
        _emit(page, {"type": "token", "content": "partial"})
        _emit(page, {"type": "error", "content": "synthetic failure"})

        expect(page.locator("#typing-indicator")).to_have_count(0)
        expect(page.locator("#streaming-bubble")).to_have_count(0)
        expect(page.locator(".thinking-status")).to_have_text("已完成")
        expect(progress).to_contain_text("失败")
        expect(page.locator("#chat-messages")).to_contain_text("错误: synthetic failure")

    def test_tool_progress_keeps_real_step_states(
        self, live_server: str, page: Page
    ) -> None:
        _open_with_fake_websocket(page, live_server)

        _emit(
            page,
            {
                "type": "tool_call",
                "tool_call": {
                    "index": 0,
                    "id": "synthetic-read",
                    "name": "file_read",
                    "arguments_delta": '{"path":"fixture.txt"}',
                },
            },
        )
        progress = page.locator(".run-progress").last
        expect(progress).to_be_visible()
        expect(progress).to_contain_text("执行进度")
        read_step = progress.locator('[data-progress-key="tool-0"]')
        expect(read_step).to_contain_text("正在读取文件")
        expect(read_step).to_contain_text("进行中")

        _emit(
            page,
            {
                "type": "progress",
                "tool": "file_read",
                "success": True,
                "preview": "fixture content",
            },
        )
        expect(read_step).to_contain_text("已完成")

        _emit(
            page,
            {
                "type": "tool_call",
                "tool_call": {
                    "index": 1,
                    "id": "synthetic-write",
                    "name": "file_write",
                    "arguments_delta": '{"path":"out.txt"}',
                },
            },
        )
        write_step = progress.locator('[data-progress-key="tool-1"]')
        expect(write_step).to_contain_text("正在写入文件")
        _emit(
            page,
            {
                "type": "progress",
                "tool": "file_write",
                "success": False,
                "preview": "write rejected",
            },
        )
        expect(write_step).to_contain_text("失败")
        _emit(page, {"type": "done", "session_id": "synthetic-session"})
        expect(progress).to_be_visible()

    def test_manual_stop_marks_running_tool_step_cancelled(
        self, live_server: str, page: Page
    ) -> None:
        _open_with_fake_websocket(page, live_server)

        _emit(
            page,
            {
                "type": "tool_call",
                "tool_call": {
                    "index": 0,
                    "id": "synthetic-cancelled",
                    "name": "file_read",
                    "arguments_delta": '{"path":"fixture.txt"}',
                },
            },
        )
        step = page.locator('[data-progress-key="tool-0"]')
        expect(step).to_contain_text("进行中")

        page.evaluate("document.getElementById('chat-stop-button').click()")

        expect(step).to_contain_text("已取消")
        expect(step).to_have_attribute("data-progress-state", "cancelled")

    def test_websocket_disconnect_fails_running_tool_step(
        self, live_server: str, page: Page
    ) -> None:
        _open_with_fake_websocket(page, live_server)
        _emit(
            page,
            {
                "type": "tool_call",
                "tool_call": {
                    "index": 0,
                    "id": "synthetic-disconnect",
                    "name": "file_read",
                    "arguments_delta": "{}",
                },
            },
        )
        step = page.locator('[data-progress-key="tool-0"]')
        expect(step).to_contain_text("进行中")

        page.evaluate("window.__localTestSocket.close()")

        expect(step).to_contain_text("失败")
        expect(step).to_have_attribute("data-progress-state", "failed")

    def test_tool_call_fragments_reuse_index_bound_step(
        self, live_server: str, page: Page
    ) -> None:
        _open_with_fake_websocket(page, live_server)
        _emit(
            page,
            {
                "type": "tool_call",
                "tool_call": {
                    "index": 0,
                    "id": "provider-call-id",
                    "name": "file_read",
                    "arguments_delta": '{"path":',
                },
            },
        )
        _emit(
            page,
            {
                "type": "tool_call",
                "tool_call": {
                    "index": 0,
                    "name": "file_read",
                    "arguments_delta": '"fixture.txt"}',
                },
            },
        )

        expect(page.locator('[data-progress-key="tool-0"]')).to_have_count(1)
        expect(page.locator(".run-progress-step")).to_have_count(1)

    def test_first_turn_stop_uses_client_session_id_for_real_cancel_route(
        self, live_server: str, page: Page
    ) -> None:
        cancelled: list[str] = []

        def capture_cancel(route: object) -> None:
            request = route.request  # type: ignore[attr-defined]
            cancelled.append(request.url.rsplit("/", 1)[-1])
            route.fulfill(  # type: ignore[attr-defined]
                status=200,
                body=json.dumps(
                    {"session_id": cancelled[-1], "cancelled": True}
                ),
                content_type="application/json",
            )

        page.route("**/api/cancel/*", capture_cancel)
        _open_with_fake_websocket(page, live_server)
        page.locator("#chat-input").fill("cancel this first turn")
        page.evaluate("window.sendMessage()")

        payload = page.evaluate("JSON.parse(window.__localTestSocket.lastSent)")
        assert isinstance(payload["session_id"], str)
        assert payload["session_id"]

        page.evaluate("document.getElementById('chat-stop-button').click()")
        page.wait_for_timeout(100)
        assert [item.split("?", 1)[0] for item in cancelled] == [payload["session_id"]]

    def test_setup_wizard_can_be_opened_and_closed(self, live_server: str, page: Page) -> None:
        page.goto(live_server, wait_until="domcontentloaded")
        page.wait_for_function("() => typeof window.showWizard === 'function'")

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
        expect(page.locator("#nav-rail .rail-brand").first).to_have_text("JS")

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
