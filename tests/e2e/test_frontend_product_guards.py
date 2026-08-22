"""Product-level browser guards for model, Work, onboarding and a11y flows."""

from __future__ import annotations

import json

import pytest
from playwright.sync_api import Page, expect

pytestmark = pytest.mark.playwright


_FAKE_WEBSOCKET = """
class ProductGuardFakeWebSocket {
  static OPEN = 1;
  static instances = [];
  constructor(url) {
    this.url = url;
    this.readyState = ProductGuardFakeWebSocket.OPEN;
    this.sent = [];
    ProductGuardFakeWebSocket.instances.push(this);
    if (url.endsWith('/ws')) window.__chatGuardSocket = this;
    if (url.endsWith('/ws/fleet')) window.__fleetGuardSocket = this;
    setTimeout(() => this.onopen && this.onopen(), 0);
  }
  send(payload) { this.sent.push(payload); }
  close() { this.readyState = 3; }
  emit(frame) {
    if (this.onmessage) this.onmessage({data: JSON.stringify(frame)});
  }
}
window.WebSocket = ProductGuardFakeWebSocket;
"""


_CONFIGURED_MODELS = {
    "active_model": "fake/model-1",
    "providers": [
        {
            "name": "fake",
            "healthy": False,
            "has_key": True,
            "models": [
                {
                    "id": "model-1",
                    "name": "Model One",
                    "provider": "fake",
                    "context_window": 8192,
                }
            ],
        }
    ],
    "presets": [],
}


def _route_models(page: Page, payload: dict[str, object]) -> None:
    page.route(
        "**/api/models",
        lambda route: route.fulfill(
            status=200,
            body=json.dumps(payload),
            content_type="application/json",
        ),
    )


def _open(page: Page, live_server: str) -> None:
    page.add_init_script(_FAKE_WEBSOCKET)
    page.goto(live_server, wait_until="domcontentloaded")
    page.wait_for_function("() => window.__shellReady === true")


def _seed_draft_and_attachment(page: Page, text: str = "请保留这段草稿") -> None:
    page.locator("#chat-input").fill(text)
    page.evaluate(
        """() => import('/static/state/store.js').then(({state}) => {
          state.pendingAttachments = [{
            id: 'guard-attachment', path: 'uploads/guard.txt',
            name: 'guard.txt', type: 'document', size: 12,
          }];
          const bar = document.getElementById('attachment-bar');
          bar.classList.remove('hidden');
          bar.innerHTML = '<span id="guard-attachment">guard.txt</span>';
        })"""
    )


def _draft_snapshot(page: Page) -> dict[str, object]:
    return page.evaluate(
        """() => import('/static/state/store.js').then(({state}) => ({
          value: document.getElementById('chat-input').value,
          attachments: state.pendingAttachments.map(item => item.name),
          cardPresent: Boolean(document.getElementById('guard-attachment')),
          chatSent: (window.__chatGuardSocket?.sent || []).length,
          fleetSent: (window.__fleetGuardSocket?.sent || []).length,
        }))"""
    )


class TestModelSubmissionGuards:
    def test_zero_model_single_preserves_draft_and_attachment(
        self, live_server: str, page: Page
    ) -> None:
        _route_models(page, {"active_model": None, "providers": [], "presets": []})
        _open(page, live_server)
        page.wait_for_function("() => document.body.dataset.modelCatalogSnapshot === 'true'")
        _seed_draft_and_attachment(page)

        page.locator("#chat-send-button").click()

        assert _draft_snapshot(page) == {
            "value": "请保留这段草稿",
            "attachments": ["guard.txt"],
            "cardPresent": True,
            "chatSent": 0,
            "fleetSent": 0,
        }
        expect(page.locator("#chat-empty-state")).to_be_visible()
        expect(page.locator("#toast-region")).to_contain_text("配置模型")

    def test_zero_model_fleet_uses_same_guard_without_connecting(
        self, live_server: str, page: Page
    ) -> None:
        _route_models(page, {"active_model": None, "providers": [], "presets": []})
        _open(page, live_server)
        page.wait_for_function("() => document.body.dataset.modelCatalogSnapshot === 'true'")
        page.evaluate("window.toggleFleetMode()")
        _seed_draft_and_attachment(page, "集群也要保留")

        page.evaluate("window.sendMessage()")

        snap = _draft_snapshot(page)
        assert snap["value"] == "集群也要保留"
        assert snap["attachments"] == ["guard.txt"]
        assert snap["cardPresent"] is True
        assert snap["chatSent"] == 0
        assert snap["fleetSent"] == 0
        expect(page.locator("#toast-region")).to_contain_text("配置模型")
        expect(page.locator("#chat-messages")).not_to_contain_text("正在建立协作连接")

    def test_initial_catalog_loading_blocks_before_any_side_effect(
        self, live_server: str, page: Page
    ) -> None:
        page.route("**/api/models", lambda route: None)
        _open(page, live_server)
        page.wait_for_function("() => document.body.dataset.modelCatalogStatus === 'loading'")
        _seed_draft_and_attachment(page, "加载期间不能发送")

        page.evaluate("window.sendMessage()")

        snap = _draft_snapshot(page)
        assert snap["value"] == "加载期间不能发送"
        assert snap["attachments"] == ["guard.txt"]
        assert snap["chatSent"] == 0
        expect(page.locator("#toast-region")).to_contain_text("正在加载")

    def test_failed_refresh_keeps_last_successful_catalog_usable(
        self, live_server: str, page: Page
    ) -> None:
        _route_models(page, _CONFIGURED_MODELS)
        _open(page, live_server)
        page.wait_for_function("() => document.body.dataset.modelCatalogSnapshot === 'true'")
        page.unroute("**/api/models")
        page.route(
            "**/api/models",
            lambda route: route.fulfill(
                status=503,
                body='{"detail":"temporary"}',
                content_type="application/json",
            ),
        )
        page.evaluate("window.loadModels()")
        page.wait_for_function("() => document.body.dataset.modelCatalogStatus === 'error'")
        page.locator("#chat-input").fill("使用上次成功目录")

        page.evaluate("window.sendMessage()")

        sent = page.evaluate("() => JSON.parse(window.__chatGuardSocket.sent.at(-1) || 'null')")
        assert sent["type"] == "stream"
        assert sent["content"] == "使用上次成功目录"

    def test_overlapping_catalog_refresh_commits_only_latest_response(
        self, live_server: str, page: Page
    ) -> None:
        _route_models(page, _CONFIGURED_MODELS)
        _open(page, live_server)
        page.wait_for_function("() => document.body.dataset.modelCatalogSnapshot === 'true'")
        page.evaluate(
            """() => {
              const originalFetch = window.fetch;
              let refreshCall = 0;
              window.fetch = (url, options = {}) => {
                if (url !== '/api/models') return originalFetch(url, options);
                refreshCall += 1;
                if (refreshCall === 1) {
                  return new Promise(resolve => {
                    window.__resolveOldCatalog = () => resolve(new Response(JSON.stringify({
                      active_model: 'old/model',
                      providers: [{name:'old', healthy:false, has_key:true,
                        models:[{id:'model', name:'Old Model', provider:'old', context_window:4096}]}],
                      presets: [],
                    }), {status:200, headers:{'Content-Type':'application/json'}}));
                  });
                }
                return Promise.resolve(new Response(JSON.stringify({
                  active_model: 'new/model',
                  providers: [{name:'new', healthy:false, has_key:true,
                    models:[{id:'model', name:'New Model', provider:'new', context_window:8192}]}],
                  presets: [],
                }), {status:200, headers:{'Content-Type':'application/json'}}));
              };
              window.__oldCatalogLoad = window.loadModels();
              window.__newCatalogLoad = window.loadModels();
            }"""
        )
        page.wait_for_function(
            """() => import('/static/state/store.js').then(({state}) =>
              state.selectedModel === 'new/model' && state.modelCatalogStatus === 'ready')"""
        )
        page.evaluate("window.__resolveOldCatalog()")
        page.wait_for_timeout(100)
        snapshot = page.evaluate(
            """() => import('/static/state/store.js').then(({state}) => ({
              selected: state.selectedModel,
              ids: state.availableModels.map(model => model.id),
            }))"""
        )
        assert snapshot == {"selected": "new/model", "ids": ["new/model"]}

    def test_malformed_200_refresh_preserves_last_successful_catalog(
        self, live_server: str, page: Page
    ) -> None:
        _route_models(page, _CONFIGURED_MODELS)
        _open(page, live_server)
        page.wait_for_function("() => document.body.dataset.modelCatalogSnapshot === 'true'")
        page.evaluate(
            """() => {
              const originalFetch = window.fetch;
              window.fetch = (url, options = {}) => url === '/api/models'
                ? Promise.resolve(new Response(JSON.stringify({
                    active_model: 'broken/model',
                    providers: [{name:'broken', healthy:false, has_key:true, models:null}],
                    presets: [],
                  }), {status:200, headers:{'Content-Type':'application/json'}}))
                : originalFetch(url, options);
            }"""
        )
        page.evaluate("window.loadModels()")
        page.wait_for_function("() => document.body.dataset.modelCatalogStatus === 'error'")
        snapshot = page.evaluate(
            """() => import('/static/state/store.js').then(({state}) => ({
              snapshot: state.modelCatalogHasSnapshot,
              selected: state.selectedModel,
              ids: state.availableModels.map(model => model.id),
            }))"""
        )
        assert snapshot == {
            "snapshot": True,
            "selected": "fake/model-1",
            "ids": ["fake/model-1"],
        }
        expect(page.locator("#models-content")).to_contain_text("fake")

    @pytest.mark.parametrize("failure_surface", ["storage", "dom"])
    def test_commit_failure_rolls_back_every_last_success_surface(
        self,
        live_server: str,
        page: Page,
        failure_surface: str,
    ) -> None:
        """A synchronous commit failure must not expose a mixed model snapshot."""
        _route_models(page, _CONFIGURED_MODELS)
        _open(page, live_server)
        page.wait_for_function("() => document.body.dataset.modelCatalogSnapshot === 'true'")
        page.evaluate("window.switchTab('models')")

        snapshot_script = """() => import('/static/state/store.js').then(({state}) => ({
          selected: state.selectedModel,
          ids: state.availableModels.map(model => model.id),
          hasSnapshot: state.modelCatalogHasSnapshot,
          stored: localStorage.getItem('js-selected-model'),
          selectValue: document.getElementById('current-model').value,
          selectOptions: Array.from(document.getElementById('current-model').options)
            .map(option => [option.value, option.textContent]),
          contentHtml: document.getElementById('models-content').innerHTML,
          activeName: document.getElementById('active-model-name').textContent,
          activeMeta: document.getElementById('active-model-meta').textContent,
          badgeDisplay: document.getElementById('active-model-badge').style.display,
          chatName: document.getElementById('chat-model-name').textContent,
        }))"""
        before = page.evaluate(snapshot_script)

        page.unroute("**/api/models")
        _route_models(
            page,
            {
                "active_model": "new/model-2",
                "providers": [
                    {
                        "name": "new",
                        "healthy": True,
                        "has_key": True,
                        "models": [
                            {
                                "id": "model-2",
                                "name": "Model Two",
                                "provider": "new",
                                "context_window": 16384,
                            }
                        ],
                    }
                ],
                "presets": [],
            },
        )
        if failure_surface == "storage":
            page.evaluate(
                """() => {
                  const original = Storage.prototype.setItem;
                  let failOnce = true;
                  Storage.prototype.setItem = function(key, value) {
                    if (failOnce && key === 'js-selected-model') {
                      failOnce = false;
                      throw new DOMException('injected storage failure', 'QuotaExceededError');
                    }
                    return original.call(this, key, value);
                  };
                  window.__restoreCatalogFailure = () => {
                    Storage.prototype.setItem = original;
                  };
                }"""
            )
        else:
            page.evaluate(
                """() => {
                  const container = document.getElementById('models-content');
                  const original = container.replaceChildren;
                  let failOnce = true;
                  container.replaceChildren = function(...nodes) {
                    if (failOnce) {
                      failOnce = false;
                      original.apply(this, nodes);
                      throw new DOMException('injected DOM failure', 'InvalidStateError');
                    }
                    return original.apply(this, nodes);
                  };
                  window.__restoreCatalogFailure = () => {
                    container.replaceChildren = original;
                  };
                }"""
            )

        page.evaluate("window.loadModels()")
        page.wait_for_function("() => document.body.dataset.modelCatalogStatus === 'error'")

        assert page.evaluate(snapshot_script) == before

        # A retry of the exact same payload must commit. This also proves that
        # the failed transaction did not advance the private fingerprint.
        page.evaluate("window.__restoreCatalogFailure()")
        page.evaluate("window.loadModels()")
        page.wait_for_function(
            """() => import('/static/state/store.js').then(({state}) =>
              state.modelCatalogStatus === 'ready'
              && state.selectedModel === 'new/model-2')"""
        )
        committed = page.evaluate(
            """() => import('/static/state/store.js').then(({state}) => ({
              ids: state.availableModels.map(model => model.id),
              stored: localStorage.getItem('js-selected-model'),
              select: document.getElementById('current-model').value,
              content: document.getElementById('models-content').textContent,
            }))"""
        )
        assert committed["ids"] == ["new/model-2"]
        assert committed["stored"] == "new/model-2"
        assert committed["select"] == "new/model-2"
        assert "Model Two" in committed["content"]

    @pytest.mark.parametrize(
        "malformed",
        [
            {"active_model": 7, "providers": [], "presets": []},
            {"active_model": "bad/<model>", "providers": [], "presets": []},
            {
                "active_model": "bad/model",
                "providers": [
                    {
                        "name": "bad",
                        "healthy": False,
                        "has_key": True,
                        "models": [
                            {
                                "id": "model",
                                "name": "Bad",
                                "provider": "other",
                                "context_window": 8192,
                            }
                        ],
                    }
                ],
                "presets": [],
            },
            {
                "active_model": "bad/model",
                "providers": [
                    {
                        "name": "bad",
                        "healthy": False,
                        "has_key": True,
                        "models": [
                            {
                                "id": "model",
                                "name": "Bad",
                                "provider": "bad",
                                "context_window": True,
                            }
                        ],
                    }
                ],
                "presets": [],
            },
            {
                "active_model": "bad/model",
                "providers": [
                    {
                        "name": "bad",
                        "healthy": False,
                        "has_key": True,
                        "models": [
                            {
                                "id": "model",
                                "name": "Bad",
                                "provider": "bad",
                                "context_window": -1,
                            }
                        ],
                    }
                ],
                "presets": [],
            },
            {
                "active_model": "bad/model",
                "providers": [
                    {
                        "name": "bad",
                        "healthy": False,
                        "has_key": True,
                        "models": [
                            {
                                "id": "model",
                                "name": "Bad",
                                "provider": "bad",
                                "context_window": 8192,
                                "unexpected": "open",
                            }
                        ],
                    }
                ],
                "presets": [],
            },
            {
                "active_model": "bad/model",
                "providers": [
                    {
                        "name": "bad",
                        "healthy": False,
                        "has_key": True,
                        "models": [
                            {"id": "model", "name": "One", "provider": "bad"},
                            {"id": "model", "name": "Two", "provider": "bad"},
                        ],
                    }
                ],
                "presets": [],
            },
            {
                "active_model": "preset/model",
                "providers": [],
                "presets": [
                    {
                        "id": "preset",
                        "name": "Preset",
                        "description": "x",
                        "base_url": "https://example.invalid",
                        "api_key_env": "KEY",
                        "models": [{"id": "model", "name": "Preset", "context_window": 8192}],
                    }
                ],
            },
        ],
    )
    def test_deeply_malformed_catalog_refresh_is_rejected_atomically(
        self,
        live_server: str,
        page: Page,
        malformed: dict[str, object],
    ) -> None:
        _route_models(page, _CONFIGURED_MODELS)
        _open(page, live_server)
        page.wait_for_function("() => document.body.dataset.modelCatalogSnapshot === 'true'")
        page.unroute("**/api/models")
        _route_models(page, malformed)

        page.evaluate("window.loadModels()")
        page.wait_for_function("() => document.body.dataset.modelCatalogStatus === 'error'")

        snapshot = page.evaluate(
            """() => import('/static/state/store.js').then(({state}) => ({
              selected: state.selectedModel,
              ids: state.availableModels.map(model => model.id),
            }))"""
        )
        assert snapshot == {"selected": "fake/model-1", "ids": ["fake/model-1"]}

    def test_send_button_click_is_bound_once(self, live_server: str, page: Page) -> None:
        _route_models(page, {"active_model": None, "providers": [], "presets": []})
        _open(page, live_server)
        page.wait_for_function("() => document.body.dataset.modelCatalogSnapshot === 'true'")
        page.locator("#chat-input").fill("only once")

        page.locator("#chat-send-button").dispatch_event("pointerdown")
        page.locator("#chat-send-button").dispatch_event("click")

        expect(page.locator("#toast-region [data-toast-type]")).to_have_count(1)


class TestWorkEntryAndErrors:
    def test_work_entry_hidden_without_explicit_server_role_and_no_request(
        self, live_server: str, page: Page
    ) -> None:
        switch_requests: list[str] = []
        page.route(
            "**/api/appshell/capabilities",
            lambda route: route.fulfill(
                status=200,
                body=json.dumps(
                    {
                        "active_mode": "personal",
                        "available_modes": ["personal"],
                        "mode_roles": {"personal": "admin"},
                        "workspace_handles": {"personal": None, "work": None},
                    }
                ),
                content_type="application/json",
            ),
        )
        page.on(
            "request",
            lambda request: (
                switch_requests.append(request.url)
                if request.url.endswith("/api/appshell/switch")
                else None
            ),
        )
        _open(page, live_server)

        expect(page.locator("#product-work-btn")).to_be_hidden()
        page.evaluate("window.switchProductWorkspace('js-work')")
        page.wait_for_timeout(100)
        assert switch_requests == []

    def test_work_error_uses_closed_chinese_message_without_raw_payload(
        self, live_server: str, page: Page
    ) -> None:
        page.route(
            "**/api/appshell/capabilities",
            lambda route: route.fulfill(
                status=200,
                body=json.dumps(
                    {
                        "active_mode": "personal",
                        "available_modes": ["personal", "work"],
                        "mode_roles": {"personal": "admin", "work": "user"},
                        "workspace_handles": {"personal": None, "work": "ws-test"},
                    }
                ),
                content_type="application/json",
            ),
        )
        page.route(
            "**/api/appshell/switch",
            lambda route: route.fulfill(
                status=403,
                body=json.dumps(
                    {
                        "detail": {
                            "code": "work_role_required",
                            "debug": "/Users/private/secret",
                        }
                    }
                ),
                content_type="application/json",
            ),
        )
        _open(page, live_server)

        page.locator("#product-work-btn").click()

        toast = page.locator("#toast-region [role='alert']").last
        expect(toast).to_contain_text("没有工作模式权限")
        assert "work_role_required" not in toast.inner_text()
        assert "/Users/" not in toast.inner_text()
        assert "{" not in toast.inner_text()


class TestOnboardingAndLiveRegions:
    def test_wizard_is_modal_traps_focus_inerts_background_and_restores_focus(
        self, live_server: str, page: Page
    ) -> None:
        _open(page, live_server)
        page.locator("#chat-input").focus()
        page.evaluate("window.showWizard()")

        wizard = page.locator("#setup-wizard")
        expect(wizard).to_have_attribute("role", "dialog")
        expect(wizard).to_have_attribute("aria-modal", "true")
        assert page.evaluate("document.activeElement.closest('#setup-wizard') !== null")
        assert page.locator("#app-shell").evaluate("node => node.inert") is True

        page.keyboard.press("Shift+Tab")
        assert page.evaluate("document.activeElement.closest('#setup-wizard') !== null")
        page.evaluate("window.hideWizard()")
        expect(page.locator("#chat-input")).to_be_focused()
        assert page.locator("#app-shell").evaluate("node => node.inert") is False

    def test_wizard_closes_and_blocks_command_palette_until_hidden(
        self, live_server: str, page: Page
    ) -> None:
        _open(page, live_server)
        page.evaluate("window.openCommandPalette()")
        expect(page.locator("#command-palette")).to_be_visible()

        page.evaluate("window.showWizard()")
        expect(page.locator("#command-palette")).to_be_hidden()
        page.keyboard.press("Control+k")
        expect(page.locator("#command-palette")).to_be_hidden()
        assert page.evaluate(
            "document.getElementById('setup-wizard').contains(document.activeElement)"
        )

        page.evaluate("window.hideWizard()")
        page.keyboard.press("Control+k")
        expect(page.locator("#command-palette")).to_be_visible()

    def test_chat_log_sender_and_busy_completion_announcement(
        self, live_server: str, page: Page
    ) -> None:
        _route_models(page, _CONFIGURED_MODELS)
        _open(page, live_server)
        page.wait_for_function("() => document.body.dataset.modelCatalogSnapshot === 'true'")
        log = page.locator("#chat-messages")
        expect(log).to_have_attribute("role", "log")
        page.locator("#chat-input").fill("语义测试")
        page.evaluate("window.sendMessage()")

        expect(log).to_have_attribute("aria-busy", "true")
        expect(log.locator("[data-message-role='user']").last).to_have_attribute("aria-label", "你")
        sent = page.evaluate("() => JSON.parse(window.__chatGuardSocket.sent.at(-1))")
        page.evaluate(
            """identity => window.__chatGuardSocket.emit({
              type: 'done', request_id: identity.request_id, turn_id: identity.turn_id,
              run_id: 'guard-run', session_id: identity.session_id,
            })""",
            sent,
        )
        expect(log).to_have_attribute("aria-busy", "false")
        expect(page.locator("#chat-live-status")).to_have_text("JS Agent 回复完成")

    def test_toasts_stack_and_expose_warning_and_error_roles(
        self, live_server: str, page: Page
    ) -> None:
        _open(page, live_server)
        page.evaluate(
            """() => {
              window.showToast('需要注意', 'warning');
              window.showToast('操作失败', 'error');
            }"""
        )

        region = page.locator("#toast-region")
        expect(region.locator("[data-toast-type='warning']")).to_have_count(1)
        expect(region.locator("[data-toast-type='error'][role='alert']")).to_have_count(1)
        expect(region.locator("[data-toast-type='warning'][role='status']")).to_have_count(1)


class TestDesktopBootstrapFailure:
    def test_failed_exchange_renders_persistent_safe_chinese_recovery(
        self, live_server: str, page: Page
    ) -> None:
        bootstrap_requests: list[str] = []
        page.on(
            "request",
            lambda request: (
                bootstrap_requests.append(request.url)
                if request.url.endswith("/api/appshell/desktop-bootstrap")
                else None
            ),
        )
        page.route(
            "**/api/appshell/desktop-bootstrap",
            lambda route: route.fulfill(
                status=500,
                body=json.dumps({"detail": "token leaked at /Users/private/config.yaml"}),
                content_type="application/json",
            ),
        )

        page.goto(f"{live_server}/#bootstrap=secret-token", wait_until="domcontentloaded")

        failure = page.locator("#bootstrap-failure")
        expect(failure).to_be_visible()
        expect(failure).to_contain_text("无法完成安全连接")
        expect(failure).to_contain_text("退出后重新打开 JS Agent")
        expect(failure.locator("button")).to_have_count(0)
        body_text = failure.inner_text()
        assert "secret-token" not in body_text
        assert "/Users/" not in body_text
        assert "HTTP 500" not in body_text
        assert page.evaluate("location.hash") == ""

        page.reload(wait_until="domcontentloaded")
        expect(page.locator("#bootstrap-failure")).to_be_visible()
        assert len(bootstrap_requests) == 1


_XSS_PAYLOAD = "x');alert(1);//"


class TestInterpolatedOnclickXss:
    def test_dynamic_tab_renders_do_not_execute_id_payloads(
        self, live_server: str, page: Page
    ) -> None:
        dialogs: list[str] = []
        page.on("dialog", lambda dialog: (dialogs.append(dialog.message), dialog.dismiss()))
        page.add_init_script(
            "window.__xssAlertCount = 0;window.alert = function(){ window.__xssAlertCount += 1; };"
        )

        def _json(payload: dict[str, object]):
            return json.dumps(payload)

        page.route(
            "**/api/tasks**",
            lambda route: (
                route.fulfill(
                    status=200,
                    body=_json(
                        {
                            "tasks": [
                                {
                                    "id": _XSS_PAYLOAD,
                                    "name": "xss-task",
                                    "type": "agent",
                                    "status": "running",
                                    "progress": 0.4,
                                    "updated_at": 1,
                                }
                            ]
                        }
                    ),
                    content_type="application/json",
                )
                if route.request.method == "GET"
                else route.fulfill(
                    status=200, body=_json({"ok": True}), content_type="application/json"
                )
            ),
        )
        page.route(
            "**/api/skills**",
            lambda route: route.fulfill(
                status=200,
                body=_json(
                    {
                        "skills": [
                            {
                                "id": _XSS_PAYLOAD,
                                "name": "xss-skill",
                                "description": "payload",
                                "trust_level": "community",
                                "trust_css": "bg-gray-800 text-gray-400",
                                "type": "prompt",
                                "category": "test",
                                "usage_count": 0,
                                "success_rate": 0,
                                "compatible": True,
                                "prerequisites_ok": True,
                                "risk_flags": [],
                                "tags": [],
                            }
                        ],
                        "categories": [],
                    }
                ),
                content_type="application/json",
            ),
        )
        page.route(
            "**/api/memory/enhanced**",
            lambda route: route.fulfill(
                status=200,
                body=_json(
                    {
                        "context": "ctx",
                        "working_memories": [],
                        "semantic_memories": [
                            {
                                "id": 42,
                                "key": _XSS_PAYLOAD,
                                "value": _XSS_PAYLOAD,
                                "category": "fact",
                                "confidence": 0.9,
                                "source": "user",
                                "entity_type": "general",
                                "memory_path": _XSS_PAYLOAD,
                                "entity_name": _XSS_PAYLOAD,
                                "last_verified_at": 0,
                            }
                        ],
                        "episodes": [],
                        "dream_logs": [],
                        "memory_files": ["identity"],
                    }
                ),
                content_type="application/json",
            ),
        )
        page.route(
            "**/api/memory/blocks**",
            lambda route: route.fulfill(
                status=200,
                body=_json(
                    {
                        "blocks": [
                            {
                                "block_path": _XSS_PAYLOAD,
                                "memory_count": 1,
                            }
                        ]
                    }
                ),
                content_type="application/json",
            ),
        )
        page.route(
            "**/api/memory/proposals**",
            lambda route: route.fulfill(
                status=200,
                body=_json(
                    {
                        "proposals": [
                            {
                                "id": 7,
                                "key": _XSS_PAYLOAD,
                                "value": _XSS_PAYLOAD,
                                "confidence": 0.5,
                                "source": "agent",
                                "entity_type": "general",
                                "memory_path": "",
                                "evidence": _XSS_PAYLOAD,
                            }
                        ]
                    }
                ),
                content_type="application/json",
            ),
        )
        page.route(
            "**/api/desktop/wizard**",
            lambda route: route.fulfill(
                status=200,
                body=_json(
                    {
                        "overall_status": "pending",
                        "ready": False,
                        "enabled": False,
                        "write_tools_enabled": False,
                        "install_summary": _XSS_PAYLOAD,
                        "steps": [
                            {
                                "status": "error",
                                "title": _XSS_PAYLOAD,
                                "detail": _XSS_PAYLOAD,
                                "action_type": "open_accessibility",
                                "action_label": _XSS_PAYLOAD,
                            }
                        ],
                    }
                ),
                content_type="application/json",
            ),
        )
        page.route(
            "**/api/diag**",
            lambda route: route.fulfill(
                status=200,
                body=_json({"embedder": {"active": True, "provider": "none"}}),
                content_type="application/json",
            ),
        )
        page.route(
            "**/api/status**",
            lambda route: route.fulfill(
                status=200,
                body=_json({"overall_status": "ok", "overall_status_text": "ok"}),
                content_type="application/json",
            ),
        )

        _open(page, live_server)
        page.wait_for_function("() => typeof window.switchTab === 'function'")

        page.evaluate("() => window.switchTab('tasks')")
        expect(page.locator("#tasks-list [data-task-action]")).to_have_count(1)
        page.evaluate("() => window.switchTab('skills')")
        expect(page.locator("#skills-content [data-skill-id]")).to_have_count(1)
        page.evaluate("() => window.switchTab('memory')")
        expect(page.locator("[data-mem-action]")).not_to_have_count(0)
        page.evaluate("() => window.switchTab('status')")
        expect(page.locator("#desktop-wizard-container [data-wizard-action]")).to_have_count(2)

        snapshot = page.evaluate(
            """() => ({
              tasksOnclick: document.querySelectorAll('#tasks-list [onclick]').length,
              tasksData: document.querySelectorAll('#tasks-list [data-task-action]').length,
              tasksId: document.querySelector('#tasks-list [data-task-id]')?.dataset.taskId || '',
              skillsOnclick: document.querySelectorAll('#skills-content [onclick]').length,
              skillsData: document.querySelectorAll('#skills-content [data-skill-id]').length,
              memoryOnclick: document.querySelectorAll('#memory-semantic [onclick], #memory-block-tree [onclick], #memory-proposals [onclick]').length,
              memoryData: document.querySelectorAll('[data-mem-action]').length,
              wizardOnclick: document.querySelectorAll('#desktop-wizard-container [onclick]').length,
              wizardData: document.querySelectorAll('#desktop-wizard-container [data-wizard-action]').length,
              alertCount: window.__xssAlertCount || 0,
            })"""
        )

        page.evaluate("() => window.switchTab('tasks')")
        expect(page.locator("#tasks-list [data-task-action='pause']")).to_be_visible()
        pause = page.locator("#tasks-list [data-task-action='pause']")
        expect(pause).to_have_count(1)
        pause.click()
        after_click = page.evaluate("() => window.__xssAlertCount || 0")

        assert snapshot["tasksOnclick"] == 0
        assert snapshot["tasksData"] >= 1
        assert snapshot["tasksId"] == _XSS_PAYLOAD
        assert snapshot["skillsOnclick"] == 0
        assert snapshot["skillsData"] >= 1
        assert snapshot["memoryOnclick"] == 0
        assert snapshot["memoryData"] >= 1
        assert snapshot["wizardOnclick"] == 0
        assert snapshot["wizardData"] >= 2
        assert snapshot["alertCount"] == 0
        assert after_click == 0
        assert dialogs == []
