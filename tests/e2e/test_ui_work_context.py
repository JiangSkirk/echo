"""B3 browser checks: Work context panel, band, collapse, no polling."""

from __future__ import annotations

import time

import pytest
from playwright.sync_api import Page, expect

from tests.e2e.test_ui_shell import _goto_shell, _wait_product, _wait_shell_ready

pytestmark = pytest.mark.playwright


def _enter_work(page: Page, server: tuple[str, str]) -> None:
    _goto_shell(page, server)
    _wait_shell_ready(page)
    product = _wait_product(page)
    if product == "js-agent":
        page.locator("#product-work-btn").click()
        page.wait_for_load_state("load")
        _wait_shell_ready(page)
        page.wait_for_function(
            "() => document.body.dataset.product === 'js-work'", timeout=15_000
        )


class TestWorkContextPanel:
    def test_directory_grant_entry_is_honest_when_native_picker_is_unavailable(
        self, page: Page, appshell_authed_server: tuple[str, str]
    ) -> None:
        _enter_work(page, appshell_authed_server)
        action = page.locator("#wcp-directory-grant")
        expect(action).to_be_visible()
        action.click()
        expect(page.locator("body")).to_contain_text("目录授权尚未启用")

    def test_approval_refresh_emits_work_context_update_event(
        self, page: Page, appshell_authed_server: tuple[str, str]
    ) -> None:
        _enter_work(page, appshell_authed_server)
        page.evaluate(
            """() => {
                window.__approvalUpdateEvents = 0;
                document.addEventListener('js:approvals-updated', () => {
                    window.__approvalUpdateEvents += 1;
                });
            }"""
        )
        page.evaluate("() => window.loadApprovals()")
        page.wait_for_function("() => window.__approvalUpdateEvents >= 1", timeout=5_000)

    def test_band_and_panel_render_real_summary(
        self, page: Page, appshell_authed_server: tuple[str, str]
    ) -> None:
        _enter_work(page, appshell_authed_server)
        band = page.locator("#work-context-band")
        expect(band).to_be_visible()
        workspace_text = band.locator("#band-workspace").inner_text()
        assert workspace_text.startswith("ws-"), f"unexpected workspace label: {workspace_text}"
        grants_text = band.locator("#band-grants").inner_text()
        # Must never fabricate a directory-grant count.
        assert "个已授权目录" not in grants_text or grants_text.split("个")[0].isdigit()
        assert grants_text in {"尚无活动目录授权", "授权状态不可用"} or "个已授权目录" in grants_text
        for section in ("wcp-files", "wcp-artifacts", "wcp-approvals", "wcp-current-task"):
            expect(page.locator(f"#{section}")).to_be_visible()

    def test_panel_collapse_and_expand(
        self, page: Page, appshell_authed_server: tuple[str, str]
    ) -> None:
        _enter_work(page, appshell_authed_server)
        panel = page.locator("#work-context-panel")
        expect(panel).to_be_visible()
        page.locator("#wcp-collapse").click()
        expect(panel).to_be_hidden()
        expect(page.locator("#wcp-expand-handle")).to_be_visible()
        page.locator("#wcp-expand-handle").click()
        expect(panel).to_be_visible()

    def test_no_infinite_polling(self, page: Page, appshell_authed_server: tuple[str, str]) -> None:
        requests: list[str] = []
        page.on(
            "request",
            lambda request: (
                requests.append(request.url)
                if "/api/appshell/work-context" in request.url
                else None
            ),
        )
        _enter_work(page, appshell_authed_server)
        count_after_load = len(requests)
        time.sleep(3)
        assert len(requests) == count_after_load, (
            f"work-context must not poll: {len(requests) - count_after_load} extra requests in 3s"
        )
        # Manual refresh is allowed and issues exactly one request.
        page.locator("#wcp-refresh").click()
        page.wait_for_timeout(800)
        assert len(requests) <= count_after_load + 1

    def test_personal_never_calls_work_context(
        self, page: Page, appshell_authed_server: tuple[str, str]
    ) -> None:
        requests: list[str] = []
        page.on(
            "request",
            lambda request: (
                requests.append(request.url)
                if "/api/appshell/work-context" in request.url
                else None
            ),
        )
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
        page.wait_for_timeout(1500)
        assert requests == [], f"personal mode must not call work-context: {requests}"
