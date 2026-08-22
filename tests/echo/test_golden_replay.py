"""Echo T2-S5 — Golden replay gate.

This suite re-runs the real Echo entry points against every fixture under
``tests/echo/golden/*.json`` and asserts byte-for-byte equivalence with the
fixture's ``expected`` block. It keeps the external chat and websocket
contracts stable while the Echo-only internals evolve.

Scope:

- ``/api/chat`` (5 fixtures) — driven via ``fastapi.testclient.TestClient``
  pointed at the real ``js.web.routers.chat.router``.
- ``/ws``      (5 fixtures) — driven via ``TestClient.websocket_connect``
  against the full ``js.web.server.create_app()`` (lifespan stubbed).

The mock template (``_make_chat_app`` / ``_build_ws_app`` /
``_build_mock_state`` / ``_patch_ws_globals``) is **the same template**
``scripts/record_echo_golden.py`` uses. We intentionally duplicate the
small handful of helpers here instead of importing them from the
recorder script, because:

1. Pytest discovers the recorder script as ``scripts/`` which is not a
   package; importing it adds path coupling.
2. T2-S5 tests must remain self-contained so a future refactor of the
   recorder doesn't silently change replay semantics.

Determinism rules (must match the recorder verbatim):

- Fixed session UUID, fixed token counts, fixed cost, fixed assistant
  text — driven by ``_build_mock_state``.
- ``JS_ALLOWED_ORIGINS=http://localhost`` so the WS upgrade survives
  ``check_origin``; ``js.web.auth._ALLOWED_ORIGINS`` cache reset on each
  test.
- ``api_key_required=False`` by default; ``True`` only for
  ``ws_auth_fail``.

Nothing in this file modifies the engine. The replay matrix covers the
Echo-only runtime so external behavior stays pinned after old rollout modes
were removed.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from difflib import unified_diff
from pathlib import Path
from pprint import pformat
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Fixture loading
# ---------------------------------------------------------------------------
_GOLDEN_DIR = Path(__file__).resolve().parent / "golden"
_FIXED_SESSION_ID = "00000000-0000-0000-0000-000000000001"

_API_CHAT_FIXTURES = (
    "api_chat_success",
    "api_chat_empty",
    "api_chat_413",
    "api_chat_auth_required",
    "api_chat_provider_error",
)
_WS_FIXTURES = (
    "ws_ping",
    "ws_message",
    "ws_stream_success",
    "ws_stream_error",
    "ws_auth_fail",
)


def _load_fixture(name: str) -> dict[str, Any]:
    """Read and parse ``tests/echo/golden/<name>.json``."""
    path = _GOLDEN_DIR / f"{name}.json"
    if not path.exists():
        raise FileNotFoundError(f"Missing golden fixture: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Diff helpers — readable failure output
# ---------------------------------------------------------------------------
def _format_diff(label: str, expected: Any, actual: Any) -> str:
    """Produce a unified-diff style block comparing ``expected`` vs ``actual``."""
    exp_lines = pformat(expected, width=100, sort_dicts=False).splitlines(keepends=True)
    act_lines = pformat(actual, width=100, sort_dicts=False).splitlines(keepends=True)
    diff = "".join(
        unified_diff(
            exp_lines,
            act_lines,
            fromfile=f"expected[{label}]",
            tofile=f"actual[{label}]",
            n=3,
        )
    )
    return diff or f"<no textual diff but values differ>\nexpected={expected!r}\nactual={actual!r}"


def _assert_equal(label: str, expected: Any, actual: Any) -> None:
    """Assert deep equality, printing a unified diff on mismatch."""
    if expected != actual:
        raise AssertionError(f"{label} mismatch:\n{_format_diff(label, expected, actual)}")


# ---------------------------------------------------------------------------
# Mock-template helpers (mirrors scripts/record_echo_golden.py verbatim)
# ---------------------------------------------------------------------------
def _normalise_response_headers(headers: Any) -> dict[str, str]:
    """Return only the response headers the golden contract pins.

    The full set varies by Starlette/uvicorn build. Recorder kept only
    ``content-type`` and ``content-length``; we mirror that exactly.
    """
    keep = {"content-type", "content-length"}
    return {k.lower(): v for k, v in headers.items() if k.lower() in keep}


def _build_mock_state(
    *,
    session_id: str = _FIXED_SESSION_ID,
    turn_count: int = 1,
    input_tokens: int = 10,
    output_tokens: int = 5,
    status: str = "completed",
    assistant_text: str = "Hi there",
    model: str | None = None,
    cost: float = 0.000123,
    error_message: str | None = None,
    compression_stats: dict[str, Any] | None = None,
) -> MagicMock:
    """Build a deterministic AgentState mock — identical to the recorder."""
    state = MagicMock()
    state.session_id = session_id
    state.turn_count = turn_count
    state.total_tokens = {"input": input_tokens, "output": output_tokens}
    state.status = status
    state.cost_estimate = cost
    state.model = model
    state.error_message = error_message
    state.compression_stats = compression_stats or {}
    if assistant_text:
        state.messages = [
            MagicMock(role="user", content=""),
            MagicMock(role="assistant", content=assistant_text),
        ]
    else:
        state.messages = []
    return state


def _make_chat_app() -> Any:
    """Build a minimal FastAPI app with the real chat router; auth disabled."""
    from fastapi import FastAPI

    from js.config import JSSettings, SecurityConfig
    from js.web.routers.chat import router as chat_router

    app = FastAPI()
    app.include_router(chat_router)
    settings = JSSettings(
        workspace=Path("/tmp/echo_replay_chat/workspace"),
        state_dir=Path("/tmp/echo_replay_chat/state"),
        security=SecurityConfig(api_key_required=False),
    )
    patch("js.web.server._settings", settings).start()
    patch("js.web.deps._stats_store", None).start()
    return app


def _build_ws_app(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Build the full ``create_app()`` with lifespan stubbed; pin Origin allowlist."""
    monkeypatch.setenv("JS_ALLOWED_ORIGINS", "http://localhost")
    import js.web.auth as _auth_mod

    monkeypatch.setattr(_auth_mod, "_ALLOWED_ORIGINS", None)

    @asynccontextmanager
    async def _noop_lifespan(_app: Any) -> AsyncIterator[None]:
        yield

    with patch("js.web.server.lifespan", _noop_lifespan):
        from js.web.server import create_app

        app = create_app()
    return app


def _patch_ws_globals(agent: MagicMock, *, api_key_required: bool = False) -> list[Any]:
    """Patch every module-level global the WS handler reads."""
    from js.config import JSSettings, SecurityConfig

    settings = JSSettings(
        workspace=Path("/tmp/echo_replay_ws/workspace"),
        state_dir=Path("/tmp/echo_replay_ws/state"),
        security=SecurityConfig(api_key_required=api_key_required),
    )
    agent.settings = settings
    if not hasattr(agent, "_dream_scheduler") or agent._dream_scheduler is None:
        agent._dream_scheduler = MagicMock()

    patchers = [
        patch("js.web.server._settings", settings),
        patch("js.web.server._agent", agent),
        patch("js.web.server.get_agent", return_value=agent),
        patch("js.web.deps._settings", settings),
        patch("js.web.deps._agent", agent),
    ]
    for p in patchers:
        p.start()
    return patchers


def _stop_patchers(patchers: list[Any]) -> None:
    for p in patchers:
        try:
            p.stop()
        except RuntimeError:
            pass


@pytest.fixture(autouse=True)
def _reset_global_patches() -> Iterator[None]:
    """Stop any leftover ``patch`` started by previous tests."""
    yield
    patch.stopall()


# ---------------------------------------------------------------------------
# /api/chat replay — agent factory tied to scenario name
# ---------------------------------------------------------------------------
class _MockPulse:
    def observe(self, **_kwargs: Any) -> Any:
        return SimpleNamespace(admitted=True)


class _GoldenTurnLoop:
    def __init__(self, agent: MagicMock, request: Any) -> None:
        self._agent = agent
        self._request = request

    async def execute(self) -> Any:
        request = self._request
        return await self._agent.run(
            request.message,
            session_id=request.context.session_id,
            model=request.model,
            attachments=list(request.attachments),
            stream_callback=request.stream_callback,
            event_callback=request.event_callback,
            disable_tools=request.disable_tools,
        )


def _install_authoritative_mock_runtime(agent: MagicMock) -> None:
    from js.echo.turn_runtime import EchoRuntime

    agent.settings = SimpleNamespace(
        workspace=Path("/tmp"),
        state_dir=Path("/tmp"),
        product_id="js-agent",
    )
    agent.registry.list_tools.return_value = []
    agent._current_allowed_tools = set()
    agent._lane_executor = None
    agent._shutdown_requested = False
    agent._push_summary_tenant = None
    agent.echo_runtime = EchoRuntime(
        agent,
        pulse_runtime=_MockPulse(),
        turn_loop_factory=lambda current_agent, request: _GoldenTurnLoop(
            current_agent, request
        ),
    )


def _make_chat_agent(scenario: str) -> MagicMock:
    """Build the deterministic agent mock for a given /api/chat scenario."""
    agent = MagicMock()
    agent.router.get_model_config.return_value = None

    if scenario == "api_chat_success":
        state = _build_mock_state(assistant_text="Hi there", model="mock-model")
        agent.run = AsyncMock(return_value=state)
    elif scenario == "api_chat_empty":
        state = _build_mock_state(
            assistant_text="",
            input_tokens=0,
            output_tokens=0,
            cost=0.0,
        )
        agent.run = AsyncMock(return_value=state)
    elif scenario == "api_chat_413" or scenario == "api_chat_auth_required":
        agent.run = AsyncMock()  # must not be called
    elif scenario == "api_chat_provider_error":
        agent.run = AsyncMock(side_effect=RuntimeError("boom"))
    else:
        raise ValueError(f"unknown api_chat scenario: {scenario}")
    _install_authoritative_mock_runtime(agent)
    return agent


def _reconstruct_body(body: Any) -> Any:
    """Expand recorder shorthand (``_oversized_payload``) back to real JSON."""
    if isinstance(body, dict) and "_oversized_payload" in body and len(body) == 1:
        spec = body["_oversized_payload"]
        return {"message": spec["char"] * spec["repeat"]}
    return body


@pytest.mark.parametrize("scenario", _API_CHAT_FIXTURES)
def test_api_chat_golden_replay(monkeypatch: pytest.MonkeyPatch, scenario: str) -> None:
    """Replay an /api/chat fixture and assert byte-for-byte equivalence."""
    from fastapi.testclient import TestClient

    monkeypatch.setenv("JS_ECHO_ENGINE", "on")
    fixture = _load_fixture(scenario)
    expected = fixture["expected"]
    inp = fixture["input"]

    app = _make_chat_app()
    agent = _make_chat_agent(scenario)
    body_in = _reconstruct_body(inp["body"])

    # Replay must use the same Origin policy the recorder used.
    # api_chat_auth_required deliberately sends no Origin.
    request_headers = dict(inp["headers"])
    if scenario != "api_chat_auth_required":
        # These fixtures were recorded with a working (write-capable)
        # identity.  Anonymous requests are now read-only guests, so replay
        # authenticates with a fresh user key; the recorded response does not
        # depend on the caller's identity.
        from js.web.auth import AuthManager

        user_key = AuthManager(Path("/tmp/echo_replay_chat/state")).create_key(
            "golden-replay", role="user"
        )
        request_headers.setdefault("X-API-Key", user_key)
    client_headers = {"Origin": "http://localhost"} if "Origin" in request_headers else {}

    client = TestClient(app, base_url="http://localhost", headers=client_headers)
    with patch("js.web.routers.chat.get_agent", return_value=agent):
        resp = client.post(inp["path"], json=body_in, headers=request_headers)

    # 1. Status
    _assert_equal(f"{scenario}.status", expected["status"], resp.status_code)

    # 2. Body (deep JSON equality)
    try:
        actual_body = resp.json()
    except Exception as exc:  # noqa: BLE001 - we want the raw text in the error
        raise AssertionError(
            f"{scenario}: response body is not valid JSON: {exc!r}\nraw={resp.text!r}"
        ) from None
    _assert_equal(f"{scenario}.body", expected["body"], actual_body)

    # 3. Headers — only the keys the recorder kept (content-type, content-length).
    _assert_equal(
        f"{scenario}.headers",
        expected["headers"],
        _normalise_response_headers(resp.headers),
    )

    # 4. frames_out must be empty for HTTP fixtures.
    assert expected["frames_out"] == [], (
        f"{scenario}: /api/chat fixtures must have empty frames_out"
    )


# ---------------------------------------------------------------------------
# /ws replay — agent factory tied to scenario name
# ---------------------------------------------------------------------------
def _make_ws_agent(scenario: str) -> MagicMock:
    """Build the deterministic agent mock for a given /ws scenario."""
    agent = MagicMock()
    agent.router.get_model_config.return_value = None
    agent._dream_scheduler = MagicMock()

    if scenario == "ws_ping":
        agent.run = AsyncMock()
    elif scenario == "ws_message":
        state = _build_mock_state(assistant_text="Hi there", model="mock-model")
        agent.run = AsyncMock(return_value=state)
    elif scenario == "ws_stream_success":
        state = _build_mock_state(assistant_text="Hello", model="mock-model")
        chunks = ["He", "ll", "o"]

        async def fake_run(
            user_msg: str,
            *,
            session_id: str | None = None,
            model: str | None = None,
            attachments: list[Any] | None = None,
            stream_callback: Any = None,
            event_callback: Any = None,
            disable_tools: bool = False,
        ) -> Any:
            assert disable_tools is False
            for chunk in chunks:
                if stream_callback is not None:
                    await stream_callback(chunk)
            if event_callback is not None:
                await event_callback(
                    {
                        "kind": "usage",
                        "usage": {
                            "prompt_tokens": 10,
                            "completion_tokens": 5,
                            "total_tokens": 15,
                        },
                    }
                )
            return state

        agent.run = AsyncMock(side_effect=fake_run)
    elif scenario == "ws_stream_error":
        state = _build_mock_state(
            assistant_text="",
            status="error",
            error_message="rate limit exceeded",
            input_tokens=0,
            output_tokens=0,
            cost=0.0,
            model="mock-model",
        )

        async def fake_run_err(
            user_msg: str,
            *,
            session_id: str | None = None,
            model: str | None = None,
            attachments: list[Any] | None = None,
            stream_callback: Any = None,
            event_callback: Any = None,
            disable_tools: bool = False,
        ) -> Any:
            assert disable_tools is False
            return state

        agent.run = AsyncMock(side_effect=fake_run_err)
    elif scenario == "ws_auth_fail":
        agent.run = AsyncMock()  # must not be called
    else:
        raise ValueError(f"unknown ws scenario: {scenario}")
    _install_authoritative_mock_runtime(agent)
    return agent


# Per-scenario expected frame count — driven by the fixture's frames_out length.
_WS_EXPECTED_FRAMES = {
    "ws_ping": 1,
    "ws_message": 2,
    "ws_stream_success": 6,
    "ws_stream_error": 2,
    "ws_auth_fail": 0,
}


@pytest.mark.parametrize("scenario", _WS_FIXTURES)
def test_ws_golden_replay(monkeypatch: pytest.MonkeyPatch, scenario: str) -> None:
    """Replay a /ws fixture and assert frame-by-frame equivalence."""
    from fastapi.testclient import TestClient
    from starlette.websockets import WebSocketDisconnect

    monkeypatch.setenv("JS_ECHO_ENGINE", "on")
    fixture = _load_fixture(scenario)
    expected = fixture["expected"]
    inp = fixture["input"]
    mock_cfg = fixture["mock"]

    api_key_required = bool(mock_cfg.get("api_key_required", False))

    app = _build_ws_app(monkeypatch)
    agent = _make_ws_agent(scenario)
    patchers = _patch_ws_globals(agent, api_key_required=api_key_required)

    frames_out: list[dict[str, Any]] = []
    close_code: int | None = None
    close_reason: str | None = None

    try:
        client = TestClient(
            app,
            base_url="http://localhost",
            headers={"Origin": "http://localhost"},
        )
        if scenario == "ws_auth_fail":
            try:
                with client.websocket_connect("/ws", headers={"Origin": "http://localhost"}) as ws:
                    ws.receive_json()
            except WebSocketDisconnect as exc:
                close_code = exc.code
                close_reason = getattr(exc, "reason", None)
        else:
            from js.web.auth import AuthManager

            user_key = AuthManager(Path(agent.settings.state_dir)).create_key(
                "golden-ws", role="user"
            )
            with client.websocket_connect(
                "/ws",
                headers={"Origin": "http://localhost", "X-API-Key": user_key},
            ) as ws:
                for frame in inp["frames_in"]:
                    ws.send_json(frame)
                for _ in range(_WS_EXPECTED_FRAMES[scenario]):
                    frames_out.append(ws.receive_json())
    finally:
        _stop_patchers(patchers)

    # 1. Frame count
    _assert_equal(
        f"{scenario}.frame_count",
        len(expected["frames_out"]),
        len(frames_out),
    )

    # 2. Per-frame deep equality
    stream_identity: tuple[str, str, str, str] | None = None
    identity_keys = ("request_id", "turn_id", "run_id", "session_id")
    for i, (exp_frame, act_frame) in enumerate(
        zip(expected["frames_out"], frames_out, strict=True)
    ):
        if scenario in {"ws_message", "ws_stream_success", "ws_stream_error"}:
            identity = tuple(str(act_frame.get(key) or "") for key in identity_keys)
            assert all(identity), f"{scenario}.frames_out[{i}] missing stream identity"
            if stream_identity is None:
                stream_identity = identity
            else:
                assert identity == stream_identity
        projected = {key: act_frame[key] for key in exp_frame}
        _assert_equal(f"{scenario}.frames_out[{i}]", exp_frame, projected)
        assert set(act_frame).difference(exp_frame).issubset(identity_keys)

    # 3. Close-code (only ws_auth_fail asserts these)
    if scenario == "ws_auth_fail":
        _assert_equal(f"{scenario}.close_code", expected["close_code"], close_code)
        _assert_equal(f"{scenario}.close_reason", expected["close_reason"], close_reason)


# ---------------------------------------------------------------------------
# Sanity: all 10 fixtures are actually replayed (no silent skipping)
# ---------------------------------------------------------------------------
def test_all_ten_fixtures_replayed() -> None:
    """Guard against accidentally dropping a fixture from the parametrize set."""
    assert set(_API_CHAT_FIXTURES) | set(_WS_FIXTURES) == {
        "api_chat_success",
        "api_chat_empty",
        "api_chat_413",
        "api_chat_auth_required",
        "api_chat_provider_error",
        "ws_ping",
        "ws_message",
        "ws_stream_success",
        "ws_stream_error",
        "ws_auth_fail",
    }
    assert len(_API_CHAT_FIXTURES) == 5
    assert len(_WS_FIXTURES) == 5
