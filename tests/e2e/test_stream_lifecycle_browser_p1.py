from __future__ import annotations

import json

import pytest
from playwright.sync_api import Page, Route, expect

pytestmark = pytest.mark.playwright

_FAKE_WEBSOCKET = """
class LifecycleFakeWebSocket {
  static OPEN = 1;
  constructor(url) {
    this.url = url;
    this.readyState = LifecycleFakeWebSocket.OPEN;
    this.sent = [];
    if (url.endsWith('/ws/fleet')) window.__fleetSocket = this;
    else window.__chatSocket = this;
    setTimeout(() => this.onopen && this.onopen(), 0);
  }
  send(payload) { this.sent.push(JSON.parse(payload)); }
  close() { this.readyState = 3; if (this.onclose) this.onclose(); }
  emit(frame) { if (this.onmessage) this.onmessage({data: JSON.stringify(frame)}); }
}
window.WebSocket = LifecycleFakeWebSocket;
"""

_FAKE_CONFIGURED_MODELS = {
    "active_model": "lifecycle-fixture/model",
    "providers": [
        {
            "name": "lifecycle-fixture",
            "healthy": False,
            "has_key": True,
            "models": [{
                "id": "model", "name": "Lifecycle Fixture",
                "provider": "lifecycle-fixture", "context_window": 8192,
            }],
        }
    ],
    "presets": [],
}


def _open(page: Page, live_server: str) -> None:
    page.add_init_script(_FAKE_WEBSOCKET)
    page.route(
        "**/api/models",
        lambda route: route.fulfill(
            status=200,
            body=json.dumps(_FAKE_CONFIGURED_MODELS),
            content_type="application/json",
        ),
    )
    page.goto(live_server, wait_until="domcontentloaded")
    page.wait_for_function("() => window.__chatSocket && typeof window.sendMessage === 'function'")
    page.wait_for_function("() => document.body.dataset.modelCatalogSnapshot === 'true'")


def test_wrong_identity_and_late_done_do_not_mutate_new_session(
    live_server: str,
    page: Page,
) -> None:
    _open(page, live_server)
    page.locator("#chat-input").fill("turn a")
    page.evaluate("window.sendMessage()")
    sent = page.evaluate("window.__chatSocket.sent[0]")
    page.evaluate("window.newSession()")
    page.evaluate(
        "frame => window.__chatSocket.emit(frame)",
        {
            "type": "token",
            "content": "LATE_A",
            "request_id": sent["request_id"],
            "turn_id": sent["turn_id"],
            "run_id": "run-a",
            "session_id": sent["session_id"],
        },
    )
    page.evaluate(
        "frame => window.__chatSocket.emit(frame)",
        {
            "type": "done",
            "request_id": sent["request_id"],
            "turn_id": sent["turn_id"],
            "run_id": "run-a",
            "session_id": sent["session_id"],
        },
    )
    expect(page.locator("#chat-messages")).not_to_contain_text("LATE_A")
    assert page.evaluate("window.__chatSocket.sent.at(-1).type") == "cancel"


def test_double_enter_submits_only_one_turn(live_server: str, page: Page) -> None:
    _open(page, live_server)
    page.locator("#chat-input").fill("exactly once")
    page.locator("#chat-input").press("Enter")
    page.locator("#chat-input").fill("second while active")
    page.locator("#chat-input").press("Enter")
    assert page.evaluate("window.__chatSocket.sent.filter(x => x.type === 'stream').length") == 1


def test_chat_disconnect_ends_active_identity_and_allows_new_turn(
    live_server: str,
    page: Page,
) -> None:
    _open(page, live_server)
    page.locator("#chat-input").fill("turn before disconnect")
    page.evaluate("window.sendMessage()")
    first = page.evaluate("window.__chatSocket.sent[0]")
    page.evaluate(
        """() => {
          window.__closedChatSocket = window.__chatSocket;
          window.__closedChatSocket.close();
        }"""
    )

    expect(page.locator("#chat-messages")).to_have_attribute("aria-busy", "false")
    page.wait_for_function(
        """() => import('/static/state/store.js').then(({state}) =>
          state.activeStream === null && state.streamGeneration > 1)"""
    )
    page.wait_for_function(
        "() => window.__chatSocket && window.__chatSocket !== window.__closedChatSocket",
        timeout=5_000,
    )

    page.locator("#chat-input").fill("turn after reconnect")
    page.evaluate("window.sendMessage()")
    assert page.evaluate("window.__chatSocket.sent.filter(x => x.type === 'stream').length") == 1
    page.evaluate(
        """frame => window.__closedChatSocket.emit({
          ...frame, type: 'token', run_id: 'late-run', content: 'LATE_DISCONNECTED'
        })""",
        first,
    )
    expect(page.locator("#chat-messages")).not_to_contain_text("LATE_DISCONNECTED")


def test_fleet_only_authoritative_result_ends_run_and_rejects_cross_talk(
    live_server: str,
    page: Page,
) -> None:
    _open(page, live_server)
    page.evaluate("window.toggleFleetMode()")
    page.locator("#chat-input").fill("connect fleet")
    page.evaluate("window.sendMessage()")
    page.wait_for_function("() => window.__fleetSocket")
    page.locator("#chat-input").fill("first fleet task")
    page.evaluate("window.sendMessage()")
    sent = page.evaluate("window.__fleetSocket.sent.find(x => x.type === 'collaborate')")
    assert isinstance(sent["session_id"], str) and sent["session_id"]

    page.evaluate(
        """identity => window.__fleetSocket.emit({
          type: 'agent_done', request_id: 'other-request', turn_id: 'other-turn',
          session_id: identity.session_id,
          agent_id: 'crossed', agent_name: 'Crossed', agent_role: 'worker',
          status: 'done', result: 'CROSSED_EVENT'
        })""",
        sent,
    )
    expect(page.locator("#chat-messages")).not_to_contain_text("CROSSED_EVENT")

    page.evaluate(
        """identity => window.__fleetSocket.emit({
          type: 'agent_done', request_id: identity.request_id, turn_id: identity.turn_id,
          session_id: identity.session_id,
          agent_id: 'worker-a', agent_name: 'Worker A', agent_role: 'worker',
          status: 'done', result: 'WORKER_RESULT'
        })""",
        sent,
    )
    expect(page.locator("#chat-messages")).to_contain_text("WORKER_RESULT")
    expect(page.locator("#chat-messages")).to_have_attribute("aria-busy", "true")
    expect(
        page.locator("#chat-messages [data-message-role='assistant']").last
    ).to_have_attribute("aria-label", "JS Agent 协作成员 Worker A")

    page.evaluate(
        """identity => window.__fleetSocket.emit({
          type: 'agent_done', request_id: identity.request_id, turn_id: identity.turn_id,
          agent_id: 'missing-session', agent_name: 'Missing', agent_role: 'worker',
          status: 'done', result: 'MISSING_SESSION_EVENT'
        })""",
        sent,
    )
    expect(page.locator("#chat-messages")).not_to_contain_text("MISSING_SESSION_EVENT")

    page.locator("#chat-input").fill("second must wait")
    page.evaluate("window.sendMessage()")
    assert page.locator("#chat-input").input_value() == "second must wait"
    assert page.evaluate(
        "window.__fleetSocket.sent.filter(x => x.type === 'collaborate').length"
    ) == 1

    page.evaluate(
        """identity => window.__fleetSocket.emit({
          type: 'collaborate_result', request_id: identity.request_id,
          turn_id: identity.turn_id, session_id: identity.session_id,
          final: 'AUTHORITATIVE_FINAL', subtasks: {}
        })""",
        sent,
    )
    expect(page.locator("#chat-messages")).to_have_attribute("aria-busy", "false")
    page.wait_for_function(
        "() => import('/static/state/store.js').then(({state}) => state.activeFleetRun === null)"
    )
    expect(page.locator("#chat-messages")).to_contain_text("AUTHORITATIVE_FINAL")
    final_message = page.locator("#chat-messages [data-message-role='assistant']").last
    expect(final_message).to_have_attribute("role", "article")
    expect(final_message).to_have_attribute("aria-label", "JS Agent 协作结果")


def test_fleet_history_keyboard_actions_use_selected_session_and_label_result(
    live_server: str,
    page: Page,
) -> None:
    requested: list[tuple[str, str]] = []
    session_id = "fleet-history-selected"

    def route_fleet_history(route: Route) -> None:
        request = route.request
        requested.append((request.method, request.url))
        if request.url.endswith("/api/fleet/history"):
            route.fulfill(
                status=200,
                body=json.dumps(
                    {
                        "history": [
                            {
                                "session_id": session_id,
                                "main_task": "键盘历史任务",
                                "subtask_count": 1,
                                "has_review": False,
                                "created_at": 1_700_000_000,
                            }
                        ]
                    }
                ),
                content_type="application/json",
            )
            return
        if request.url.endswith(f"/api/fleet/sessions/{session_id}"):
            if request.method == "DELETE":
                route.fulfill(
                    status=200,
                    body='{"success":true}',
                    content_type="application/json",
                )
                return
            route.fulfill(
                status=200,
                body=json.dumps(
                    {
                        "session": {
                            "session_id": session_id,
                            "main_task": "键盘历史任务",
                            "subtasks": [],
                            "subtask_results": {},
                            "review": None,
                            "final": "历史最终答案",
                        }
                    }
                ),
                content_type="application/json",
            )
            return
        route.fulfill(status=404, body="{}", content_type="application/json")

    page.route("**/api/fleet/**", route_fleet_history)
    _open(page, live_server)
    page.evaluate(
        """() => import('/static/state/store.js').then(({state}) => {
          state.sessionId = 'wrong-main-chat-session';
          const list = document.createElement('div');
          list.id = 'fleet-history-list';
          document.body.appendChild(list);
          return window.refreshFleetHistory();
        })"""
    )

    open_button = page.get_by_role("button", name="打开协作历史：键盘历史任务")
    delete_button = page.get_by_role("button", name="删除协作历史：键盘历史任务")
    expect(open_button).to_have_attribute("type", "button")
    expect(delete_button).to_have_attribute("type", "button")

    open_button.focus()
    open_button.press("Enter")
    history_result = page.locator(
        "#chat-messages [data-message-role='assistant'][aria-label='JS Agent 协作历史结果']"
    )
    expect(history_result).to_have_attribute("role", "article")
    expect(history_result).to_contain_text("历史最终答案")
    current_session = page.evaluate(
        "() => import('/static/state/store.js').then(({state}) => state.currentFleetSessionId)"
    )
    assert current_session == session_id

    page.evaluate("window.confirm = () => true")
    delete_button.press("Space")
    page.wait_for_function(
        """() => document.getElementById('toast-region')?.textContent.includes('已删除')"""
    )

    selected_url = f"/api/fleet/sessions/{session_id}"
    assert any(method == "GET" and url.endswith(selected_url) for method, url in requested)
    assert any(method == "DELETE" and url.endswith(selected_url) for method, url in requested)
    assert all("wrong-main-chat-session" not in url for _method, url in requested)


def test_switching_out_of_fleet_cancels_and_rejects_late_event(
    live_server: str,
    page: Page,
) -> None:
    _open(page, live_server)
    page.evaluate("window.toggleFleetMode()")
    page.locator("#chat-input").fill("connect fleet")
    page.evaluate("window.sendMessage()")
    page.wait_for_function("() => window.__fleetSocket")
    page.locator("#chat-input").fill("fleet tool")
    page.evaluate("window.sendMessage()")
    page.evaluate("window.toggleFleetMode()")
    assert page.evaluate("window.__fleetSocket.sent.at(-1).type") == "cancel"
    page.evaluate(
        "window.__fleetSocket.emit({type:'agent_token', content:'LATE_FLEET', agent_name:'w'})"
    )
    expect(page.locator("#chat-messages")).not_to_contain_text("LATE_FLEET")


def test_stop_uses_exact_identity_and_reports_non_2xx(
    live_server: str,
    page: Page,
) -> None:
    page.route(
        "**/api/cancel/*",
        lambda route: route.fulfill(
            status=409,
            body=json.dumps({"detail": "run mismatch"}),
            content_type="application/json",
        ),
    )
    _open(page, live_server)
    page.locator("#chat-input").fill("stop exact")
    page.evaluate("window.sendMessage()")
    page.evaluate(
        "window.__chatSocket.emit({...window.__chatSocket.sent[0], type:'status', run_id:'run-exact'})"
    )
    page.locator("#chat-stop-button").click()
    page.wait_for_timeout(100)
    assert page.evaluate("window.__chatSocket.sent.at(-1).type") == "cancel"
    assert page.evaluate("window.__chatSocket.sent.at(-1).run_id") == "run-exact"
    page.evaluate(
        "frame => window.__chatSocket.emit(frame)",
        {
            **page.evaluate("window.__chatSocket.sent[0]"),
            "type": "token",
            "run_id": "run-exact",
            "content": "LATE_AFTER_STOP",
        },
    )
    expect(page.locator("#chat-messages")).not_to_contain_text("LATE_AFTER_STOP")
    expect(page.locator("#chat-messages")).to_contain_text("停止请求失败")
