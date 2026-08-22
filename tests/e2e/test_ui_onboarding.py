"""B4 browser checks: onboarding never traps the user; models page structure.

Covers: one-click skip, model-later, cancellable connection test
(AbortController), buttons usable during slow/failing tests, no raw JSON
errors, restart persistence, no chip wall on the models page, and entering
the main UI with zero configured models.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
import urllib.request
from collections.abc import Iterator
from pathlib import Path

import pytest
from playwright.sync_api import Page, expect

from tests.e2e.test_ui_shell import CONTRAST_JS, _goto_shell, _wait_shell_ready

pytestmark = pytest.mark.playwright

_LOCAL_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.fixture()
def pending_server(tmp_path: Path) -> Iterator[tuple[str, str]]:
    """Standalone server with onboarding PENDING (first run, zero providers).

    Function-scoped: skip/skip-once mutates server onboarding state, so each
    test gets a fresh server. Yields (base_url, admin_key).
    """
    base = tmp_path / "onboarding-gate"
    base.mkdir()
    workspace = base / "workspace"
    state_dir = base / "state"
    workspace.mkdir()
    state_dir.mkdir()
    config_path = base / "config.yaml"
    config_path.write_text(
        "\n".join(
            (
                'version: "0.1.5"',
                f'workspace: "{workspace}"',
                f'state_dir: "{state_dir}"',
                "log_level: WARNING",
                "providers: []",
                "models: []",
                "security:",
                "  defense_mode: enforce",
                "  api_key_required: false",
                "",
            )
        ),
        encoding="utf-8",
    )
    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"
    from js.web.auth import AuthManager

    admin_key = AuthManager(state_dir).create_key("onboarding-e2e-admin", role="admin")
    env = os.environ.copy()
    env.update(
        {
            "JS_CONFIG_PATH": str(config_path),
            "JS_STATE_DIR": str(state_dir),
            "JS_API_KEY_REQUIRED": "false",
            "NO_PROXY": "127.0.0.1,localhost",
            "no_proxy": "127.0.0.1,localhost",
            "PYTHONUNBUFFERED": "1",
        }
    )
    for name in ("JS_WARM_START", "JS_ECHO_ENGINE", "JS_ALLOWED_ORIGINS"):
        env.pop(name, None)
    log_path = base / "server.log"
    with log_path.open("w", encoding="utf-8") as log:
        process = subprocess.Popen(
            [sys.executable, "-m", "js", "web", "--host", "127.0.0.1", "--port", str(port)],
            stdout=log,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
        )
        try:
            deadline = time.monotonic() + 45
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    break
                try:
                    with _LOCAL_OPENER.open(f"{base_url}/", timeout=1) as response:
                        if response.status == 200:
                            yield base_url, admin_key
                            return
                except Exception:
                    pass
                time.sleep(0.2)
            pytest.fail("pending onboarding server failed to start", pytrace=False)
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)


_FAKE_MODELS = {
    "active_model": None,
    "providers": [
        {
            "name": "fakep",
            "healthy": False,
            "has_key": True,
            "models": [
                {
                    "id": "m1",
                    "name": "fake-model-1",
                    "provider": "fakep",
                    "context_window": 8192,
                }
            ],
        }
    ],
    "presets": [],
}


def _stub_models(page: Page) -> None:
    page.route(
        "**/api/models",
        lambda route: route.fulfill(
            status=200,
            body=json.dumps(_FAKE_MODELS),
            content_type="application/json",
        ),
    )


_HANGING_TEST_MODEL_STUB = """
(() => {
    const orig = window.fetch;
    window.__testModelCalls = 0;
    window.fetch = (url, opts) => {
        if (String(url).includes('/api/setup/test-model')) {
            window.__testModelCalls += 1;
            return new Promise((resolve, reject) => {
                if (opts && opts.signal) {
                    opts.signal.addEventListener('abort', () =>
                        reject(new DOMException('Aborted', 'AbortError')));
                }
            });
        }
        return orig(url, opts);
    };
})();
"""

_FAILING_TEST_MODEL_STUB = """
(() => {
    const orig = window.fetch;
    window.fetch = (url, opts) => {
        if (String(url).includes('/api/setup/test-model')) {
            return Promise.resolve(new Response(
                '{"detail": {"error": "connection refused"}}',
                {status: 500, headers: {'Content-Type': 'application/json'}},
            ));
        }
        return orig(url, opts);
    };
})();
"""


class TestOnboardingFlow:
    def test_primary_cta_meets_aa_in_both_themes(
        self, pending_server: tuple[str, str], page: Page
    ) -> None:
        _goto_shell(page, pending_server)
        expect(page.locator("#setup-wizard")).to_be_visible()
        selector = '#wizard-step-1 button[onclick="wizardNext()"]'
        for theme in ("light", "dark"):
            page.evaluate(
                "theme => document.documentElement.setAttribute('data-theme', theme)",
                theme,
            )
            ratios = page.evaluate(CONTRAST_JS, [selector])
            ratio = ratios[selector]
            assert ratio is not None
            assert ratio >= 4.5, f"onboarding primary CTA contrast {ratio} < 4.5 in {theme}"

    def test_one_click_skip_enters_main_ui(self, pending_server: tuple[str, str], page: Page) -> None:
        _goto_shell(page, pending_server)
        wizard = page.locator("#setup-wizard")
        expect(wizard).to_be_visible()
        skip = page.locator("#wizard-skip-1")
        expect(skip).to_be_visible()
        skip.click()
        expect(wizard).to_be_hidden()
        expect(page.locator("#chat-input")).to_be_visible()
        # Server-authoritative: reload must not re-block.
        page.reload()
        page.wait_for_timeout(1500)
        expect(page.locator("#setup-wizard")).to_be_hidden()

    def test_model_test_is_cancellable_and_never_locks(
        self, pending_server: tuple[str, str], page: Page
    ) -> None:
        _stub_models(page)
        page.add_init_script(_HANGING_TEST_MODEL_STUB)
        _goto_shell(page, pending_server)
        expect(page.locator("#setup-wizard")).to_be_visible()
        page.locator("button", has_text="开始设置").click()
        test_btn = page.locator("#wizard-model-list button[data-model-id]").first
        expect(test_btn).to_be_visible()
        test_btn.click()
        # While the (hanging) test is in flight the button becomes a cancel
        # control and skip/back stay enabled.
        expect(test_btn).to_contain_text("取消", timeout=2000)
        expect(page.locator("#wizard-skip-2")).to_be_enabled()
        expect(page.locator("button", has_text="上一步")).to_be_enabled()
        test_btn.click()  # cancel
        expect(test_btn).to_contain_text("测试", timeout=3000)
        result_text = page.locator("#wizard-model-list").inner_text()
        assert "已取消" in result_text
        calls = page.evaluate("() => window.__testModelCalls")
        assert calls == 1, f"duplicate in-flight tests: {calls}"
        # Skip still works immediately after cancelling.
        page.locator("#wizard-skip-2").click()
        expect(page.locator("#setup-wizard")).to_be_hidden()

    def test_failed_test_shows_friendly_error_no_json(
        self, pending_server: tuple[str, str], page: Page
    ) -> None:
        _stub_models(page)
        page.add_init_script(_FAILING_TEST_MODEL_STUB)
        _goto_shell(page, pending_server)
        page.locator("button", has_text="开始设置").click()
        test_btn = page.locator("#wizard-model-list button[data-model-id]").first
        test_btn.click()
        page.wait_for_timeout(1500)
        result_text = page.locator("#wizard-model-list").inner_text()
        assert "{" not in result_text, f"raw JSON leaked into wizard: {result_text}"
        # Buttons restored after failure.
        expect(test_btn).to_be_enabled()
        expect(page.locator("#wizard-skip-2")).to_be_enabled()

    def test_no_model_hint_non_blocking(
        self, page: Page, appshell_authed_server: tuple[str, str]
    ) -> None:
        _goto_shell(page, appshell_authed_server)
        _wait_shell_ready(page)
        hint = page.locator("#model-hint")
        expect(hint).to_be_visible()
        expect(hint).to_contain_text("尚未配置模型")
        # Main UI fully usable.
        expect(page.locator("#chat-input")).to_be_enabled()
        hint.click()
        expect(page.locator("#tab-models")).to_be_visible()


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


class TestModelsPage:
    def test_configured_models_render_as_flat_grouped_rows(
        self, pending_server: tuple[str, str], page: Page
    ) -> None:
        models = dict(_FAKE_MODELS)
        models["active_model"] = "fakep/m1"
        page.route(
            "**/api/models",
            lambda route: route.fulfill(
                status=200,
                body=json.dumps(models),
                content_type="application/json",
            ),
        )
        _goto_shell(page, pending_server)
        page.locator("#wizard-skip-1").click()
        page.evaluate("window.switchTab('models')")
        group = page.locator("#models-content .model-provider-group")
        expect(group).to_have_count(1)
        row = group.locator(".model-list-row")
        expect(row).to_have_count(1)
        backgrounds = row.evaluate(
            "node => [getComputedStyle(node).backgroundColor, "
            "getComputedStyle(node.parentElement).backgroundColor]"
        )
        assert backgrounds[0] == "rgba(0, 0, 0, 0)", backgrounds

    def test_visible_model_actions_use_semantic_palette(
        self, pending_server: tuple[str, str], page: Page
    ) -> None:
        models = dict(_FAKE_MODELS)
        models["active_model"] = "fakep/m1"
        page.route(
            "**/api/models",
            lambda route: route.fulfill(
                status=200,
                body=json.dumps(models),
                content_type="application/json",
            ),
        )
        _goto_shell(page, pending_server)
        page.locator("#wizard-skip-1").click()
        page.evaluate("window.switchTab('models')")
        expect(page.locator("#active-model-badge")).to_be_visible()
        page.wait_for_timeout(300)
        forbidden = {
            "rgb(30, 58, 138)",
            "rgb(37, 99, 235)",
            "rgb(59, 130, 246)",
            "rgb(96, 165, 250)",
        }
        visible_colors = page.locator("#tab-models").evaluate(
            """root => Array.from(root.querySelectorAll('*'))
                .filter(node => {
                    const rect = node.getBoundingClientRect();
                    const style = getComputedStyle(node);
                    return rect.width > 0 && rect.height > 0 && style.visibility !== 'hidden';
                })
                .flatMap(node => {
                    const style = getComputedStyle(node);
                    return [style.color, style.backgroundColor, style.borderColor];
                })"""
        )
        assert not (set(visible_colors) & forbidden), (
            f"legacy visible blue remains: {sorted(set(visible_colors) & forbidden)}"
        )
        for theme in ("light", "dark"):
            page.evaluate(
                "value => document.documentElement.setAttribute('data-theme', value)",
                theme,
            )
            ratios = page.evaluate(CONTRAST_JS, ["#active-model-badge"])
            assert ratios["#active-model-badge"] >= 4.5

    def test_onboarding_welcome_screenshot(
        self, pending_server: tuple[str, str], page: Page
    ) -> None:
        EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
        page.set_viewport_size({"width": 1440, "height": 1024})
        _goto_shell(page, pending_server)
        expect(page.locator("#setup-wizard")).to_be_visible()
        expect(page.locator("#wizard-skip-1")).to_be_visible()
        path = EVIDENCE_DIR / "onboarding-welcome-1440x1024.png"
        page.screenshot(path=str(path), full_page=False)
        assert path.is_file() and path.stat().st_size > 10_000

    def test_presets_render_as_grouped_list_not_chip_wall(
        self, pending_server: tuple[str, str], page: Page
    ) -> None:
        models = dict(_FAKE_MODELS)
        models["presets"] = [
            {
                "id": "deepseek",
                "name": "DeepSeek",
                "description": "深度求索",
                "api_key_env": "DEEPSEEK_API_KEY",
                "models": [
                    {"id": "deepseek-chat", "name": "DeepSeek Chat", "context_window": 65536},
                    {"id": "deepseek-reasoner", "name": "DeepSeek R", "context_window": 65536},
                ],
            }
        ]
        page.route(
            "**/api/models",
            lambda route: route.fulfill(
                status=200, body=json.dumps(models), content_type="application/json"
            ),
        )
        _goto_shell(page, pending_server)
        page.wait_for_function("() => window.__shellReady === true")
        page.evaluate("window.switchTab('models')")
        expect(page.locator("#tab-models")).to_be_visible()
        rows = page.locator("#models-content .preset-model-row")
        expect(rows).to_have_count(2)
        # API key input must not be permanently visible on the page chrome.
        expect(page.locator("#api-key-input")).to_be_hidden()

    def test_wizard_single_select_lists_only_configured_providers(
        self, pending_server: tuple[str, str], page: Page
    ) -> None:
        """Wizard step-2 single-select must list only configured-provider models.

        Presets must NOT appear in the wizard radio list; they belong only in
        the "add cloud model" area.
        """
        models = dict(_FAKE_MODELS)
        models["presets"] = [
            {
                "id": "deepseek",
                "name": "DeepSeek",
                "description": "深度求索",
                "api_key_env": "DEEPSEEK_API_KEY",
                "models": [
                    {"id": "deepseek-chat", "name": "DeepSeek Chat", "context_window": 65536},
                ],
            }
        ]
        page.route(
            "**/api/models",
            lambda route: route.fulfill(
                status=200, body=json.dumps(models), content_type="application/json"
            ),
        )
        _goto_shell(page, pending_server)
        page.locator("button", has_text="开始设置").click()
        # Wait for wizard model list to render.
        radios = page.locator("#wizard-model-list input[name='wizard-model']")
        expect(radios).to_have_count(1)
        # The only radio must be the configured provider's model, not a preset.
        radio_val = radios.first.evaluate("el => el.value")
        assert radio_val == "fakep/m1", f"wizard listed unexpected model: {radio_val}"

    def test_no_active_model_hides_badge_and_shows_unconfigured(
        self, pending_server: tuple[str, str], page: Page
    ) -> None:
        """With no active model, the badge must be hidden and chat bar shows unconfigured."""
        models = dict(_FAKE_MODELS)
        models["active_model"] = None
        page.route(
            "**/api/models",
            lambda route: route.fulfill(
                status=200, body=json.dumps(models), content_type="application/json"
            ),
        )
        _goto_shell(page, pending_server)
        page.locator("#wizard-skip-1").click()
        _wait_shell_ready(page)
        page.evaluate("window.switchTab('models')")
        # active-model-badge must be hidden when there is no active model.
        badge = page.locator("#active-model-badge")
        expect(badge).to_be_hidden()
        # Chat bar must show "未配置模型", not "默认模型".
        name_el = page.locator("#chat-model-name")
        expect(name_el).to_contain_text("未配置模型")

    def test_non_empty_invalid_active_model_is_cleared(
        self, pending_server: tuple[str, str], page: Page
    ) -> None:
        """Server returns a non-empty active_model that is not in availableModels.

        The UI must clear state.selectedModel, clear localStorage, hide the
        badge, and show "未配置模型" in the chat bar.
        """
        models = dict(_FAKE_MODELS)
        models["active_model"] = "ghost/nonexistent-model"
        page.route(
            "**/api/models",
            lambda route: route.fulfill(
                status=200, body=json.dumps(models), content_type="application/json"
            ),
        )
        # Pre-seed localStorage with a stale value to verify it gets cleared.
        page.add_init_script(
            "localStorage.setItem('js-selected-model', 'ghost/nonexistent-model')"
        )
        _goto_shell(page, pending_server)
        page.locator("#wizard-skip-1").click()
        _wait_shell_ready(page)
        page.evaluate("window.switchTab('models')")
        # Badge must be hidden because the active model is invalid.
        badge = page.locator("#active-model-badge")
        expect(badge).to_be_hidden()
        # Chat bar must show "未配置模型".
        name_el = page.locator("#chat-model-name")
        expect(name_el).to_contain_text("未配置模型")
        # localStorage must be cleared.
        stored = page.evaluate("localStorage.getItem('js-selected-model')")
        assert stored is None, f"localStorage should be cleared, got {stored!r}"
        # The select dropdown must reset to empty.
        select_val = page.locator("#current-model").evaluate("el => el.value")
        assert select_val == "", f"select should reset to empty, got {select_val!r}"

    def test_switch_model_success_updates_badge_and_chat(
        self, pending_server: tuple[str, str], page: Page
    ) -> None:
        """Successful model switch must sync select, active summary, badge, chat, and localStorage.

        Two configured-provider models m1 and m2 exist; the server starts
        with active=m1.  A real select_option(m2) triggers onchange -> POST
        /api/models/switch.  The route handler must be hit exactly once and
        return success with model_id=m2.  Afterwards the select, active
        summary name/meta, badge visibility, chat-model-name, and
        localStorage must all reflect m2.
        """
        models = {
            "active_model": "fakep/m1",
            "providers": [
                {
                    "name": "fakep",
                    "healthy": True,
                    "has_key": True,
                    "models": [
                        {
                            "id": "m1",
                            "name": "fake-model-1",
                            "provider": "fakep",
                            "context_window": 8192,
                        },
                        {
                            "id": "m2",
                            "name": "fake-model-2",
                            "provider": "fakep",
                            "context_window": 16384,
                        },
                    ],
                }
            ],
            "presets": [],
        }
        page.route(
            "**/api/models",
            lambda route: route.fulfill(
                status=200, body=json.dumps(models), content_type="application/json"
            ),
        )
        switch_calls: list[int] = []

        def _switch_handler(route: object) -> None:
            switch_calls.append(1)
            request = route.request  # type: ignore[attr-defined]
            body = json.loads(request.post_data or "{}")
            assert body.get("model_id") == "fakep/m2", (
                f"POST body model_id should be fakep/m2, got {body.get('model_id')!r}"
            )
            route.fulfill(  # type: ignore[attr-defined]
                status=200,
                body=json.dumps({"success": True, "model_id": "fakep/m2", "warning": None}),
                content_type="application/json",
            )

        page.route("**/api/models/switch", _switch_handler)
        _goto_shell(page, pending_server)
        page.locator("#wizard-skip-1").click()
        _wait_shell_ready(page)
        page.evaluate("window.switchTab('models')")
        # Wait until the select is populated and reflects the server active model m1.
        page.wait_for_function(
            "() => { const s = document.getElementById('current-model');"
            " return s && s.value === 'fakep/m1' && s.options.length >= 3; }"
        )
        # Trigger a real select_option(m2) -> onchange -> POST.
        page.locator("#current-model").select_option("fakep/m2")
        page.wait_for_timeout(200)
        # The route handler must be called exactly once.
        assert len(switch_calls) == 1, (
            f"switch endpoint should be hit exactly once, got {len(switch_calls)}"
        )
        # Select must now reflect m2.
        select_val = page.locator("#current-model").evaluate("el => el.value")
        assert select_val == "fakep/m2", f"select should be fakep/m2, got {select_val!r}"
        # Active model name and meta must reflect m2.
        expect(page.locator("#active-model-name")).to_contain_text("fake-model-2")
        expect(page.locator("#active-model-meta")).to_contain_text("fakep")
        expect(page.locator("#active-model-meta")).to_contain_text("16384")
        # Badge must be visible.
        expect(page.locator("#active-model-badge")).to_be_visible()
        # Chat bar model name must reflect m2.
        expect(page.locator("#chat-model-name")).to_contain_text("fake-model-2")
        # localStorage must be synced to m2.
        stored = page.evaluate("localStorage.getItem('js-selected-model')")
        assert stored == "fakep/m2", f"localStorage should be fakep/m2, got {stored!r}"

    def test_router_dynamic_model_success_syncs_all_authoritative_surfaces(
        self, pending_server: tuple[str, str], page: Page
    ) -> None:
        """A listed router-only dynamic model must remain active after a real switch."""
        models = {
            "active_model": "fakep/m1",
            "providers": [
                {
                    "name": "fakep",
                    "healthy": True,
                    "has_key": True,
                    "models": [
                        {
                            "id": "m1",
                            "name": "fake-model-1",
                            "provider": "fakep",
                            "context_window": 8192,
                        },
                        {
                            "id": "dynamic-model",
                            "name": "Dynamic Model",
                            "provider": "fakep",
                            "context_window": 32768,
                        },
                    ],
                }
            ],
            "presets": [],
        }
        page.route(
            "**/api/models",
            lambda route: route.fulfill(
                status=200, body=json.dumps(models), content_type="application/json"
            ),
        )
        switch_calls: list[int] = []

        def _switch_handler(route: object) -> None:
            switch_calls.append(1)
            request = route.request  # type: ignore[attr-defined]
            assert json.loads(request.post_data or "{}")["model_id"] == (
                "fakep/dynamic-model"
            )
            route.fulfill(  # type: ignore[attr-defined]
                status=200,
                body=json.dumps(
                    {
                        "success": True,
                        "model_id": "fakep/dynamic-model",
                        "warning": None,
                    }
                ),
                content_type="application/json",
            )

        page.route("**/api/models/switch", _switch_handler)
        _goto_shell(page, pending_server)
        page.locator("#wizard-skip-1").click()
        _wait_shell_ready(page)
        page.evaluate("window.switchTab('models')")
        page.wait_for_function(
            "() => document.getElementById('current-model')?.value === 'fakep/m1'"
        )
        page.locator("#current-model").select_option("fakep/dynamic-model")

        expect(page.locator("#current-model")).to_have_value("fakep/dynamic-model")
        assert switch_calls == [1]
        expect(page.locator("#active-model-name")).to_contain_text("Dynamic Model")
        expect(page.locator("#active-model-meta")).to_contain_text("32768")
        expect(page.locator("#active-model-badge")).to_be_visible()
        expect(page.locator("#chat-model-name")).to_contain_text("Dynamic Model")
        assert page.evaluate("localStorage.getItem('js-selected-model')") == (
            "fakep/dynamic-model"
        )
        selected_state = page.evaluate(
            "() => import('/static/state/store.js').then(m => m.state.selectedModel)"
        )
        assert selected_state == "fakep/dynamic-model"

    def test_selecting_empty_default_rolls_back_to_active_model(
        self, pending_server: tuple[str, str], page: Page
    ) -> None:
        """Selecting the empty option must not visually clear the active model."""
        models = {
            "active_model": "fakep/m1",
            "providers": [
                {
                    "name": "fakep",
                    "healthy": True,
                    "has_key": True,
                    "models": [
                        {
                            "id": "m1",
                            "name": "fake-model-1",
                            "provider": "fakep",
                            "context_window": 8192,
                        }
                    ],
                }
            ],
            "presets": [],
        }
        page.route(
            "**/api/models",
            lambda route: route.fulfill(
                status=200, body=json.dumps(models), content_type="application/json"
            ),
        )
        switch_calls: list[int] = []
        page.route("**/api/models/switch", lambda route: switch_calls.append(1))
        _goto_shell(page, pending_server)
        page.locator("#wizard-skip-1").click()
        _wait_shell_ready(page)
        page.evaluate("window.switchTab('models')")
        page.wait_for_function(
            "() => document.getElementById('current-model')?.value === 'fakep/m1'"
        )

        page.locator("#current-model").select_option("")

        expect(page.locator("#current-model")).to_have_value("fakep/m1")
        assert switch_calls == []
        expect(page.locator("#active-model-badge")).to_be_visible()
        expect(page.locator("#chat-model-name")).to_contain_text("fake-model-1")
        assert page.evaluate("localStorage.getItem('js-selected-model')") == "fakep/m1"
        selected_state = page.evaluate(
            "() => import('/static/state/store.js').then(m => m.state.selectedModel)"
        )
        assert selected_state == "fakep/m1"

    def test_switch_model_failure_rolls_back_select(
        self, pending_server: tuple[str, str], page: Page
    ) -> None:
        """Failed model switch must roll back select, badge, chat, and localStorage to m1.

        Two configured-provider models m1 and m2 exist; the server starts
        with active=m1.  A real select_option(m2) triggers onchange -> POST
        /api/models/switch.  The route handler must be hit exactly once and
        return a structured error.  Afterwards the select must roll back to m1, and the
        badge/chat/localStorage must still reflect m1.
        """
        models = {
            "active_model": "fakep/m1",
            "providers": [
                {
                    "name": "fakep",
                    "healthy": True,
                    "has_key": True,
                    "models": [
                        {
                            "id": "m1",
                            "name": "fake-model-1",
                            "provider": "fakep",
                            "context_window": 8192,
                        },
                        {
                            "id": "m2",
                            "name": "fake-model-2",
                            "provider": "fakep",
                            "context_window": 16384,
                        },
                    ],
                }
            ],
            "presets": [],
        }
        page.route(
            "**/api/models",
            lambda route: route.fulfill(
                status=200, body=json.dumps(models), content_type="application/json"
            ),
        )
        switch_calls: list[int] = []

        def _switch_handler(route: object) -> None:
            switch_calls.append(1)
            route.fulfill(  # type: ignore[attr-defined]
                status=409,
                body=json.dumps(
                    {
                        "detail": {
                            "needs_config": True,
                            "error": "请先配置模型 Provider",
                        }
                    }
                ),
                content_type="application/json",
            )

        page.route("**/api/models/switch", _switch_handler)
        _goto_shell(page, pending_server)
        page.locator("#wizard-skip-1").click()
        _wait_shell_ready(page)
        page.evaluate("window.switchTab('models')")
        # Wait until the select is populated and reflects the server active model m1.
        page.wait_for_function(
            "() => { const s = document.getElementById('current-model');"
            " return s && s.value === 'fakep/m1' && s.options.length >= 3; }"
        )
        # Trigger a real select_option(m2) -> onchange -> POST (returns an error).
        page.locator("#current-model").select_option("fakep/m2")
        page.wait_for_timeout(200)
        # The route handler must be called exactly once.
        assert len(switch_calls) == 1, (
            f"switch endpoint should be hit exactly once, got {len(switch_calls)}"
        )
        # Select must roll back to m1.
        select_val = page.locator("#current-model").evaluate("el => el.value")
        assert select_val == "fakep/m1", (
            f"select should roll back to fakep/m1 after failure, got {select_val!r}"
        )
        # Badge must still be visible (m1 is still active).
        expect(page.locator("#active-model-badge")).to_be_visible()
        # Chat bar must still show m1.
        expect(page.locator("#chat-model-name")).to_contain_text("fake-model-1")
        # localStorage must still be m1.
        stored = page.evaluate("localStorage.getItem('js-selected-model')")
        assert stored == "fakep/m1", f"localStorage should still be fakep/m1, got {stored!r}"
        expect(page.locator("#toast-region [data-toast-type='error']").last).to_contain_text(
            "请先配置模型 Provider"
        )
