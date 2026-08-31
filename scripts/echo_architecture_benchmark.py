#!/usr/bin/env python3
"""Deterministic Echo-only architecture benchmark.

The benchmark never calls a real model provider. It drives the real FastAPI
chat/websocket edges with either a deterministic JSAgent+fake provider or a
minimal mocked agent state. That keeps the numbers about Echo runtime overhead
rather than network/model variance.
"""

from __future__ import annotations

import argparse
import asyncio
import copy
import hashlib
import json
import math
import os
import statistics
import tempfile
import threading
import time
from collections import Counter
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from contextlib import ExitStack, asynccontextmanager, contextmanager
from dataclasses import asdict, dataclass, field
from functools import partial
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import psutil
from fastapi import FastAPI
from fastapi.testclient import TestClient
from httpx import ASGITransport, AsyncClient

from js.utils.log import configure_logging

if __name__ == "__main__":
    # Bind INFO filtering before any js.* import creates cached module loggers.
    configure_logging("INFO")

from js.agent import JSAgent  # noqa: E402
from js.config import JSSettings, MemoryConfig, ModelConfig, SecurityConfig  # noqa: E402
from js.echo.context_runtime import (  # noqa: E402
    get_context_runtime_snapshot_for_tests,
    reset_context_runtime_for_tests,
)
from js.echo.ledger import journal as journal_module  # noqa: E402
from js.echo.ledger.archive_store import ArchiveRecord, ArchiveStore  # noqa: E402
from js.echo.ledger.journal import FileEchoLedger  # noqa: E402
from js.echo.ledger.release_gates import (  # noqa: E402
    _TOKENIZER_TREE_DIGEST_VERSION,
    release_source_digest,
    tokenizer_resource_digest,
)
from js.echo.ledger.security_matrix import run_security_matrix  # noqa: E402
from js.echo.slo_contract import SLO_CONTRACT  # noqa: E402
from js.echo.state import AgentState  # noqa: E402
from js.echo.turn_runtime import EchoRuntime  # noqa: E402
from js.models.providers import ChatMessage, ChatResponse, ModelProvider  # noqa: E402
from js.models.router import ModelRouter, RoutingDecision  # noqa: E402
from js.models.stream_events import StreamEvent  # noqa: E402
from js.web.routers.chat import router as chat_router  # noqa: E402


@dataclass(frozen=True)
class ModeSpec:
    name: str
    echo_engine: str


@dataclass
class BenchProvider:
    chat_calls: int = 0
    stream_event_calls: int = 0
    stream_calls: int = 0
    prompt_tokens: list[int] = field(default_factory=list)
    payload_evidence: list[dict[str, Any]] = field(default_factory=list)
    concurrency_events: list[dict[str, Any]] = field(default_factory=list)
    stream_started: int = 0
    stream_completed: int = 0
    stream_cancelled: int = 0
    stream_started_event: threading.Event = field(
        default_factory=threading.Event,
        repr=False,
    )
    stream_cancelled_event: threading.Event = field(
        default_factory=threading.Event,
        repr=False,
    )


MODES = (ModeSpec("echo", "on"),)
SLO_THRESHOLDS = SLO_CONTRACT.benchmark_latency_thresholds()
MAX_API_FULL_AGENT_PROMPT_P95 = 9_000.0
LONG_HISTORY_MESSAGES = 40
LONG_HISTORY_WORDS_PER_MESSAGE = 80
MODEL_PROMPT_LATENCY_MS_PER_TOKEN = 0.002
CONCURRENCY_WORKERS = SLO_CONTRACT.concurrency_workers
CONCURRENCY_ROUNDS = SLO_CONTRACT.concurrency_rounds
MAX_CONCURRENCY_RSS_MB = SLO_CONTRACT.max_rss_mb
TOKENIZER_METHOD = "tiktoken_cl100k_base_canonical_json"
BASELINE_COMMIT = "65cc545e3ec893f5bab62d356514643f14456a58"
HISTORY_MARKER_PREFIX = "benchmark long history message "
# Echo's context vault intentionally sends only the latest 14 user/assistant
# history messages. The benchmark seeds 40 and verifies that exact bounded window.
EXPECTED_PROVIDER_HISTORY_MESSAGES = 14
EXPECTED_HISTORY_MARKERS = tuple(
    f"{HISTORY_MARKER_PREFIX}{index}"
    for index in range(
        LONG_HISTORY_MESSAGES - EXPECTED_PROVIDER_HISTORY_MESSAGES, LONG_HISTORY_MESSAGES
    )
)
EXPECTED_HISTORY_MARKER_SHA256 = hashlib.sha256(
    json.dumps(
        list(EXPECTED_HISTORY_MARKERS),
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode()
).hexdigest()
WS_STREAM_FIRST_TEXT_DELAY_MS = 5.0
WS_STREAM_INTER_TEXT_DELAY_MS = 1.0
WS_SLOW_CONSUMER_PAUSE_MS = 10.0
WS_RESILIENCE_TIMEOUT_MS = 1_000.0
WS_STREAM_EXPECTED_FRAME_TYPES = (
    "status",
    "thinking",
    "token",
    "token",
    "token",
    "usage",
    "done",
)
COMPACTION_DECISION_COUNT = 1_000
COMPACTION_RETAIN_RECORDS = 100
COMPACTION_EFFECT_ID = "benchmark-effect-1"
COMPACTION_LOGICAL_RECORD_COUNT = COMPACTION_DECISION_COUNT + 2
COMPACTION_ACTIVE_RECORD_COUNT = COMPACTION_RETAIN_RECORDS + 1
COMPACTION_SAMPLE_INDICES = (0, 1, 2, 501, 901, 1_001)
COMPACTION_RECEIPT_VERSION = "echo-compaction-semantic-receipt-v1"


def _tokenizer() -> Any:
    """Lazy, offline-first tokenizer: never touch the network at import.

    Uses the version-pinned vendored BPE cache (resources/tokenizer/, named
    by tiktoken's own cache-key convention) when present; otherwise tiktoken
    resolves its own cache or raises -- we never silently substitute an
    imprecise counter for the token gate.
    """
    import os

    if not os.environ.get("TIKTOKEN_CACHE_DIR"):
        vendored = Path(__file__).resolve().parents[1] / "resources" / "tokenizer"
        if vendored.is_dir() and any(vendored.iterdir()):
            os.environ["TIKTOKEN_CACHE_DIR"] = str(vendored)
    import tiktoken  # noqa: PLC0415 -- deliberate lazy import; hermetic import time

    return tiktoken.get_encoding("cl100k_base")


def _content_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    return json.dumps(content, ensure_ascii=False, sort_keys=True, default=str)


def _prompt_tokens_for_messages(
    messages: list[ChatMessage],
    tools: list[dict[str, Any]] | None,
) -> int:
    payload = {
        "messages": [
            {
                "role": message.role,
                "content": _content_text(message.content),
                "name": message.name,
                "tool_calls": message.tool_calls,
                "tool_call_id": message.tool_call_id,
                "reasoning_content": message.reasoning_content,
            }
            for message in messages
        ],
        "tools": tools or [],
    }
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        default=str,
    )
    return max(1, len(_tokenizer().encode(canonical)))


def _provider_payload_evidence(
    messages: list[ChatMessage],
    tools: list[dict[str, Any]] | None,
) -> dict[str, Any]:
    message_identities = [
        {
            "role": message.role,
            "content": _content_text(message.content),
            "name": message.name,
            "tool_calls": message.tool_calls,
            "tool_call_id": message.tool_call_id,
            "reasoning_content": message.reasoning_content,
        }
        for message in messages
    ]
    observed_markers: list[str] = []
    for identity in message_identities:
        content = str(identity["content"])
        search_from = 0
        while True:
            marker_start = content.find(HISTORY_MARKER_PREFIX, search_from)
            if marker_start < 0:
                break
            digits_start = marker_start + len(HISTORY_MARKER_PREFIX)
            digits_end = digits_start
            while digits_end < len(content) and content[digits_end].isdigit():
                digits_end += 1
            if digits_end > digits_start:
                observed_markers.append(content[marker_start:digits_end])
            search_from = max(digits_end, digits_start + 1)
    marker_counts = dict(sorted(Counter(observed_markers).items()))
    messages_json = json.dumps(
        message_identities,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        default=str,
    ).encode()
    payload_json = json.dumps(
        {"messages": message_identities, "tools": tools or []},
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        default=str,
    ).encode()
    marker_json = json.dumps(
        observed_markers,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode()
    return {
        "message_count": len(messages),
        "history_marker_count": len(observed_markers),
        "history_marker_counts": marker_counts,
        "history_marker_sha256": hashlib.sha256(marker_json).hexdigest(),
        "message_identity_sha256": hashlib.sha256(messages_json).hexdigest(),
        "provider_payload_sha256": hashlib.sha256(payload_json).hexdigest(),
    }


def _validate_long_provider_payloads(
    evidence: list[dict[str, Any]],
    *,
    expected_payloads: int,
) -> dict[str, Any]:
    failures: list[str] = []
    expected_counts = dict.fromkeys(EXPECTED_HISTORY_MARKERS, 1)
    if len(evidence) != expected_payloads:
        failures.append(
            "long-context provider payload count mismatch: "
            f"expected {expected_payloads}, observed {len(evidence)}"
        )
    for index, observation in enumerate(evidence):
        counts = observation.get("history_marker_counts")
        marker_count = observation.get("history_marker_count")
        marker_digest = observation.get("history_marker_sha256")
        if (
            counts != expected_counts
            or marker_count != EXPECTED_PROVIDER_HISTORY_MESSAGES
            or marker_digest != EXPECTED_HISTORY_MARKER_SHA256
        ):
            missing_or_duplicate = [
                marker
                for marker in EXPECTED_HISTORY_MARKERS
                if not isinstance(counts, dict) or counts.get(marker) != 1
            ]
            foreign = (
                sorted(marker for marker in counts if marker not in expected_counts)
                if isinstance(counts, dict)
                else []
            )
            failures.append(
                f"long-context provider payload {index} history markers invalid: "
                f"missing_or_duplicate={missing_or_duplicate} foreign={foreign}"
            )
    return {
        "ok": not failures,
        "expected_payloads": expected_payloads,
        "observed_payloads": len(evidence),
        "seeded_history_message_count": LONG_HISTORY_MESSAGES,
        "expected_provider_history_message_count": EXPECTED_PROVIDER_HISTORY_MESSAGES,
        "dropped_by_context_vault_count": (
            LONG_HISTORY_MESSAGES - EXPECTED_PROVIDER_HISTORY_MESSAGES
        ),
        "expected_history_markers": list(EXPECTED_HISTORY_MARKERS),
        "expected_history_marker_sha256": EXPECTED_HISTORY_MARKER_SHA256,
        "failures": failures,
    }


def _validate_short_provider_payloads(
    evidence: list[dict[str, Any]],
    *,
    expected_payloads: int,
) -> dict[str, Any]:
    failures: list[str] = []
    if len(evidence) != expected_payloads:
        failures.append(
            "short-context provider payload count mismatch: "
            f"expected {expected_payloads}, observed {len(evidence)}"
        )
    for index, observation in enumerate(evidence):
        if observation.get("history_marker_count") != 0:
            failures.append(
                f"short-context provider payload {index} contains long-context history markers"
            )
    return {
        "ok": not failures,
        "expected_payloads": expected_payloads,
        "observed_payloads": len(evidence),
        "failures": failures,
    }


def _benchmark_history() -> list[dict[str, str]]:
    return [
        {
            "role": "user" if index % 2 == 0 else "assistant",
            "content": f"benchmark long history message {index} "
            + ("context " * LONG_HISTORY_WORDS_PER_MESSAGE),
        }
        for index in range(LONG_HISTORY_MESSAGES)
    ]


def _seed_long_history(agent: JSAgent, session_id: str, *, owner_key_hash: str) -> None:
    agent.memory.store_messages(
        session_id,
        _benchmark_history(),
        owner_key_hash=owner_key_hash,
    )


class DeterministicProvider(ModelProvider):
    def __init__(
        self,
        stats: BenchProvider,
        *,
        content: str = "benchmark response",
        thinking: str = "benchmark thinking step",
        min_delay_seconds: float = 0.0,
        stream_prompt_delay_seconds: float | None = None,
        stream_first_text_delay_seconds: float = 0.0,
        stream_inter_text_delay_seconds: float = 0.0,
    ) -> None:
        self._stats = stats
        self._content = content
        self._thinking = thinking
        self._min_delay_seconds = min_delay_seconds
        self._stream_prompt_delay_seconds = stream_prompt_delay_seconds
        self._stream_first_text_delay_seconds = stream_first_text_delay_seconds
        self._stream_inter_text_delay_seconds = stream_inter_text_delay_seconds
        self.active_chat_calls = 0
        self.peak_chat_calls = 0

    async def chat(
        self,
        messages: list[ChatMessage],
        model: str,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> ChatResponse:
        self._stats.chat_calls += 1
        self._stats.payload_evidence.append(_provider_payload_evidence(messages, tools))
        prompt_tokens = _prompt_tokens_for_messages(messages, tools)
        self._stats.prompt_tokens.append(prompt_tokens)
        user_texts = [
            str(message.content)
            for message in messages
            if message.role == "user" and isinstance(message.content, str)
        ]
        latest_user = user_texts[-1] if user_texts else ""
        concurrency_request = (
            latest_user if latest_user.startswith("benchmark-concurrency:") else None
        )
        if concurrency_request is not None:
            self._stats.concurrency_events.append(
                {
                    "sequence": len(self._stats.concurrency_events) + 1,
                    "phase": "start",
                    "request_id": concurrency_request,
                }
            )
        self.active_chat_calls += 1
        self.peak_chat_calls = max(self.peak_chat_calls, self.active_chat_calls)
        try:
            await asyncio.sleep(
                max(
                    (prompt_tokens * MODEL_PROMPT_LATENCY_MS_PER_TOKEN) / 1000.0,
                    self._min_delay_seconds,
                )
            )
            isolation_secrets = [
                text for text in user_texts if text.startswith("benchmark-isolation-secret:")
            ]
            content = self._content
            if latest_user.startswith("benchmark-concurrency:"):
                secret = isolation_secrets[-1] if isolation_secrets else "missing-isolation-secret"
                content = f"{latest_user}|{secret}"
            return ChatResponse(
                content=content,
                tool_calls=[],
                model="bench-model",
                usage={
                    "prompt_tokens": prompt_tokens,
                    "completion_tokens": 4,
                    "total_tokens": prompt_tokens + 4,
                },
                finish_reason="stop",
                reasoning_content=self._thinking,
            )
        finally:
            self.active_chat_calls -= 1
            if concurrency_request is not None:
                self._stats.concurrency_events.append(
                    {
                        "sequence": len(self._stats.concurrency_events) + 1,
                        "phase": "end",
                        "request_id": concurrency_request,
                    }
                )

    def chat_stream(
        self,
        messages: list[ChatMessage],
        model: str,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> AsyncIterator[str]:
        self._stats.stream_calls += 1

        async def _gen() -> AsyncIterator[str]:
            yield "bench"
            yield "mark"
            yield " response"

        return _gen()

    async def chat_stream_events(
        self,
        messages: list[ChatMessage],
        model: str,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> AsyncIterator[StreamEvent]:
        self._stats.stream_event_calls += 1
        self._stats.stream_started += 1
        self._stats.stream_started_event.set()
        prompt_tokens = _prompt_tokens_for_messages(messages, tools)
        self._stats.prompt_tokens.append(prompt_tokens)
        prompt_delay = self._stream_prompt_delay_seconds
        if prompt_delay is None:
            prompt_delay = (prompt_tokens * MODEL_PROMPT_LATENCY_MS_PER_TOKEN) / 1000.0
        completed = False
        try:
            if prompt_delay > 0:
                await asyncio.sleep(prompt_delay)
            yield StreamEvent(kind="thinking_delta", text=self._thinking, model=model)
            if self._stream_first_text_delay_seconds > 0:
                await asyncio.sleep(self._stream_first_text_delay_seconds)
            for index, chunk in enumerate(("bench", "mark", " response")):
                if index and self._stream_inter_text_delay_seconds > 0:
                    await asyncio.sleep(self._stream_inter_text_delay_seconds)
                yield StreamEvent(kind="text_delta", text=chunk, model=model)
            yield StreamEvent(
                kind="usage",
                usage={
                    "prompt_tokens": prompt_tokens,
                    "completion_tokens": 4,
                    "total_tokens": prompt_tokens + 4,
                },
                model=model,
            )
            completed = True
            yield StreamEvent(kind="done", finish_reason="stop", model=model)
        finally:
            if completed:
                self._stats.stream_completed += 1
            else:
                self._stats.stream_cancelled += 1
                self._stats.stream_cancelled_event.set()

    async def health_check(self) -> bool:
        return True

    async def close(self) -> None:
        pass


class DeterministicRouter(ModelRouter):
    def __init__(self, provider: DeterministicProvider, *, permit_verifier: Any) -> None:
        self.settings = JSSettings(providers=[], models=[])
        self._provider = provider
        self._providers: dict[str, ModelProvider] = {"bench": provider}
        self._model_map: dict[str, tuple[str, ModelConfig]] = {}
        self._permit_verifier = permit_verifier

    async def select_model(
        self, task_complexity: str = "medium", preferred: str | None = None
    ) -> RoutingDecision:
        return RoutingDecision(
            provider=self._provider,
            model="bench-model",
            provider_name="bench",
            reason="deterministic benchmark",
        )

    async def chat(
        self,
        messages: list[ChatMessage],
        model: str | None = None,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
        before_model_call: Callable[
            [RoutingDecision, list[ChatMessage], list[dict[str, Any]] | None],
            Awaitable[Any],
        ]
        | None = None,
        after_model_call: Callable[
            [Any, ChatResponse | None, BaseException | None],
            Awaitable[None],
        ]
        | None = None,
        permit_grant: Callable[
            [RoutingDecision, list[ChatMessage], list[dict[str, Any]] | None],
            Any,
        ]
        | None = None,
    ) -> ChatResponse:
        if before_model_call is None or after_model_call is None or permit_grant is None:
            raise RuntimeError(
                "Echo benchmark router requires model gate callbacks and a runtime permit"
            )
        decision = await self.select_model(preferred=model)
        self._consume_model_permit(permit_grant, decision, messages, tools)
        context = await before_model_call(decision, messages, tools)
        try:
            response = await self._provider.chat(
                messages=messages,
                model=decision.model,
                tools=tools,
                temperature=temperature,
                max_tokens=max_tokens,
            )
        except Exception as exc:
            await after_model_call(context, None, exc)
            raise
        await after_model_call(context, response, None)
        return response

    def get_model_config(self, model_id: str) -> None:
        return None


def _settings(base: Path, mode: ModeSpec) -> JSSettings:
    return JSSettings(
        workspace=base / "workspace",
        state_dir=base / "state",
        providers=[],
        models=[],
        max_turns=3,
        echo_engine=mode.echo_engine,
        security=SecurityConfig(api_key_required=False),
        memory=MemoryConfig(capsule_enabled=False),
    )


def _apply_env(mode: ModeSpec) -> None:
    os.environ["JS_ECHO_ENGINE"] = mode.echo_engine
    os.environ["JS_ALLOWED_ORIGINS"] = "http://localhost"

    import js.web.auth as auth_mod

    auth_mod._ALLOWED_ORIGINS = None
    auth_mod._ALLOWED_ORIGINS_ENV = None


@contextmanager
def _isolated_benchmark_environment(mode: ModeSpec) -> Iterator[None]:
    keys = ("JS_ECHO_ENGINE", "JS_ALLOWED_ORIGINS")
    previous = {key: os.environ.get(key) for key in keys}
    import js.web.auth as auth_mod

    previous_origins = auth_mod._ALLOWED_ORIGINS
    previous_origins_env = auth_mod._ALLOWED_ORIGINS_ENV
    _apply_env(mode)
    try:
        yield
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        auth_mod._ALLOWED_ORIGINS = previous_origins
        auth_mod._ALLOWED_ORIGINS_ENV = previous_origins_env


def _percentile(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, max(0, round((len(ordered) - 1) * p)))
    return ordered[idx]


def _summary(values: list[float]) -> dict[str, float | int]:
    if not values:
        return {"n": 0, "min_ms": 0, "mean_ms": 0, "p50_ms": 0, "p95_ms": 0, "max_ms": 0}
    p95_ms = round(_percentile(values, 0.95), 3)
    max_ms = max(round(max(values), 3), p95_ms)
    return {
        "n": len(values),
        "min_ms": round(min(values), 3),
        "mean_ms": round(statistics.fmean(values), 3),
        "p50_ms": round(statistics.median(values), 3),
        "p95_ms": p95_ms,
        "max_ms": max_ms,
    }


def _token_summary(values: list[int]) -> dict[str, float | int | str]:
    if not values:
        return {
            "n": 0,
            "min": 0,
            "mean": 0,
            "p50": 0,
            "p95": 0,
            "max": 0,
            "source": "tokenizer",
            "method": TOKENIZER_METHOD,
        }
    floats = [float(value) for value in values]
    return {
        "n": len(values),
        "min": int(min(values)),
        "mean": round(statistics.fmean(floats), 3),
        "p50": round(statistics.median(floats), 3),
        "p95": round(_percentile(floats, 0.95), 3),
        "max": int(max(values)),
        "source": "tokenizer",
        "method": TOKENIZER_METHOD,
    }


def _time_call(fn: Callable[[], Any]) -> tuple[float, Any, BaseException | None]:
    start = time.perf_counter()
    try:
        result = fn()
        return (time.perf_counter() - start) * 1000, result, None
    except BaseException as exc:  # noqa: BLE001 - benchmark records failures.
        return (time.perf_counter() - start) * 1000, None, exc


def _journal_record_count(settings: JSSettings) -> int:
    root = settings.state_dir / "echo" / "ledger"
    candidates = [root]
    tenants_root = root / "tenants"
    if tenants_root.exists():
        candidates.extend(path for path in tenants_root.iterdir() if path.is_dir())

    count = 0
    for journal_root in candidates:
        key_path = journal_root / "journal.key"
        journal_path = journal_root / "chat.jsonl"
        if not key_path.exists() or not journal_path.exists():
            continue
        key = bytes.fromhex(key_path.read_text(encoding="utf-8"))
        count += len(FileEchoLedger(journal_path, mac_key=key).records)
    return count


def _build_chat_client(settings: JSSettings, agent: Any) -> ExitStack:
    stack = ExitStack()
    app = FastAPI()
    app.include_router(chat_router)
    stack.enter_context(patch("js.web.server._settings", settings))
    stack.enter_context(patch("js.web.deps._settings", settings))
    stack.enter_context(patch("js.web.routers.chat.get_agent", return_value=agent))
    stack.enter_context(patch("js.web.routers.chat.get_stats_store", return_value=None))
    # Anonymous requests are read-only guests; the benchmark drives /api/chat,
    # so authenticate with a benchmark-scoped user key.
    from js.web.auth import AuthManager

    auth = AuthManager(settings.state_dir)
    user_key = auth.create_key("echo-benchmark", role="user")
    owner_key_hash = auth.verify(user_key)["key_hash"]
    if not isinstance(owner_key_hash, str) or not owner_key_hash:
        raise RuntimeError("benchmark API key did not resolve to a canonical owner hash")
    client = TestClient(
        app,
        base_url="http://localhost",
        headers={"Origin": "http://localhost", "X-API-Key": user_key},
    )
    stack.enter_context(client)
    stack.client = client  # type: ignore[attr-defined]
    stack.user_key = user_key  # type: ignore[attr-defined]
    stack.owner_key_hash = owner_key_hash  # type: ignore[attr-defined]
    return stack


def _build_chat_app(settings: JSSettings, agent: Any) -> ExitStack:
    stack = ExitStack()
    app = FastAPI()
    app.include_router(chat_router)
    stack.enter_context(patch("js.web.server._settings", settings))
    stack.enter_context(patch("js.web.deps._settings", settings))
    stack.enter_context(patch("js.web.routers.chat.get_agent", return_value=agent))
    stack.enter_context(patch("js.web.routers.chat.get_stats_store", return_value=None))
    stack.app = app  # type: ignore[attr-defined]
    return stack


def _build_ws_client(settings: JSSettings, agent: Any) -> ExitStack:
    @asynccontextmanager
    async def _noop_lifespan(_app: Any) -> AsyncIterator[None]:
        yield

    stack = ExitStack()
    stack.enter_context(patch("js.web.server.lifespan", _noop_lifespan))
    from js.web.auth import AuthManager
    from js.web.server import create_app

    app = create_app()
    stack.enter_context(patch("js.web.server._settings", settings))
    stack.enter_context(patch("js.web.server._agent", agent))
    stack.enter_context(patch("js.web.server.get_agent", return_value=agent))
    stack.enter_context(patch("js.web.deps._settings", settings))
    stack.enter_context(patch("js.web.deps._agent", agent))
    user_key = AuthManager(settings.state_dir).create_key("echo-ws-benchmark", role="user")
    client = TestClient(
        app,
        base_url="http://localhost",
        headers={"Origin": "http://localhost", "X-API-Key": user_key},
    )
    stack.enter_context(client)
    stack.client = client  # type: ignore[attr-defined]
    stack.user_key = user_key  # type: ignore[attr-defined]
    return stack


def _make_real_agent(settings: JSSettings, provider_stats: BenchProvider) -> JSAgent:
    agent = JSAgent(settings)
    agent.router = DeterministicRouter(
        DeterministicProvider(provider_stats),
        permit_verifier=agent._model_permit_issuer,
    )
    return agent


def _mock_state(
    *,
    content: str = "mock response",
    session_id: str = "mock-session",
    run_id: str = "mock-run",
) -> AgentState:
    return AgentState(
        session_id=session_id,
        run_id=run_id,
        turn_count=1,
        messages=[ChatMessage(role="assistant", content=content)],
        total_tokens={"input": 10, "output": 5},
        status="completed",
        model="bench-model",
    )


class _BenchmarkTurnLoop:
    def __init__(self, agent: MagicMock, request: Any, *, delay_seconds: float) -> None:
        self._agent = agent
        self._request = request
        self._delay_seconds = delay_seconds

    async def execute(self) -> AgentState:
        self._agent.echo_turn_calls += 1
        self._agent.active_echo_turns += 1
        self._agent.runtime_peak_inflight = max(
            self._agent.runtime_peak_inflight,
            self._agent.active_echo_turns,
        )
        try:
            if self._delay_seconds > 0:
                await asyncio.sleep(self._delay_seconds)
            if self._request.event_callback is not None:
                await self._request.event_callback(
                    {"kind": "thinking_delta", "text": "stream thinking"}
                )
            if self._request.stream_callback is not None:
                await self._request.stream_callback("stream ")
                await self._request.stream_callback("response")
                content = "stream response"
            elif "benchmark-concurrency:" in self._request.message:
                content = self._request.message
            else:
                content = "mock response"
            return _mock_state(
                content=content,
                session_id=self._request.context.session_id or "mock-session",
                run_id=self._request.context.run_id,
            )
        finally:
            self._agent.active_echo_turns -= 1


class _ProviderStreamBenchmarkTurnLoop:
    """Minimal Echo turn loop that consumes the deterministic provider stream.

    This remains a wrapper benchmark: it does not claim full-agent model
    latency.  Unlike the legacy mocked callback, however, every WS frame is
    now causally driven by a provider event with an explicit cadence.
    """

    def __init__(self, agent: MagicMock, request: Any, provider: DeterministicProvider) -> None:
        self._agent = agent
        self._request = request
        self._provider = provider

    async def execute(self) -> AgentState:
        self._agent.echo_turn_calls += 1
        self._agent.active_echo_turns += 1
        self._agent.runtime_peak_inflight = max(
            self._agent.runtime_peak_inflight,
            self._agent.active_echo_turns,
        )
        content_parts: list[str] = []
        usage: dict[str, int] = {}
        try:
            async for event in self._provider.chat_stream_events(
                [ChatMessage(role="user", content=self._request.message)],
                "bench-model",
            ):
                if event.kind == "text_delta":
                    content_parts.append(event.text)
                    if self._request.stream_callback is not None:
                        await self._request.stream_callback(event.text)
                elif event.kind in {"thinking_delta", "usage"}:
                    if event.kind == "usage" and event.usage is not None:
                        usage = dict(event.usage)
                    if self._request.event_callback is not None:
                        await self._request.event_callback(event.to_dict())
                elif event.kind == "error":
                    raise RuntimeError(event.error or "deterministic provider stream failed")
                elif event.kind == "done":
                    break
            state = _mock_state(
                content="".join(content_parts),
                session_id=self._request.context.session_id or "mock-session",
                run_id=self._request.context.run_id,
            )
            if usage:
                state.total_tokens = {
                    "input": int(usage.get("prompt_tokens", 0)),
                    "output": int(usage.get("completion_tokens", 0)),
                }
            return state
        finally:
            self._agent.active_echo_turns -= 1


def _make_mock_agent(
    settings: JSSettings,
    *,
    delay_seconds: float = 0.0,
    stream_provider: DeterministicProvider | None = None,
) -> MagicMock:
    agent = MagicMock()
    agent.settings = settings
    agent._lane_executor = None
    agent._role = "benchmark"
    agent._work_profile = "default"
    agent._current_allowed_tools = set()
    agent._shutdown_requested = False
    agent._dream_scheduler = MagicMock()
    agent.echo_turn_calls = 0
    agent.active_echo_turns = 0
    agent.runtime_peak_inflight = 0
    agent.router.get_model_config.return_value = None
    # Real cancel-token map so WS connection binding matches production Agent.
    agent._cancel_tokens = {}
    agent._active_run_tasks = {}
    agent.audit = MagicMock()
    agent.logger = MagicMock()

    from js.agent import JSAgent

    agent.bind_cancel_token = lambda *args, **kwargs: JSAgent.bind_cancel_token(
        agent, *args, **kwargs
    )
    agent.unbind_cancel_token = lambda *args, **kwargs: JSAgent.unbind_cancel_token(
        agent, *args, **kwargs
    )
    agent.request_cancel = lambda *args, **kwargs: JSAgent.request_cancel(agent, *args, **kwargs)

    def _turn_loop_factory(
        _agent: Any,
        request: Any,
    ) -> _BenchmarkTurnLoop | _ProviderStreamBenchmarkTurnLoop:
        if stream_provider is not None:
            return _ProviderStreamBenchmarkTurnLoop(agent, request, stream_provider)
        return _BenchmarkTurnLoop(agent, request, delay_seconds=delay_seconds)

    agent.echo_runtime = EchoRuntime(agent, turn_loop_factory=_turn_loop_factory)
    return agent


def _run_concurrency_probe(
    base: Path,
    mode: ModeSpec,
    *,
    workers: int,
    rounds: int,
) -> dict[str, Any]:
    """Drive concurrent ASGI requests through the real Echo runtime boundary."""
    with _isolated_benchmark_environment(mode):
        return _run_concurrency_probe_unisolated(
            base,
            mode,
            workers=workers,
            rounds=rounds,
        )


def _run_concurrency_probe_unisolated(
    base: Path,
    mode: ModeSpec,
    *,
    workers: int,
    rounds: int,
) -> dict[str, Any]:
    settings = _settings(base / mode.name / "concurrency", mode)
    provider_stats = BenchProvider()
    provider = DeterministicProvider(provider_stats, min_delay_seconds=0.750)
    agent = JSAgent(settings)
    agent.router = DeterministicRouter(
        provider,
        permit_verifier=agent._model_permit_issuer,
    )
    process = psutil.Process(os.getpid())
    rss_before = process.memory_info().rss

    # Anonymous requests are read-only guests; the probe drives /api/chat, so
    # authenticate with a probe-scoped user key and seed under its owner.
    from js.web.auth import AuthManager

    probe_key = AuthManager(settings.state_dir).create_key("echo-probe", role="user")
    probe_owner = AuthManager(settings.state_dir).verify(probe_key)["key_hash"]

    for round_index in range(rounds):
        for index in range(workers):
            session_id = f"echo-concurrency-{round_index}-{index}"
            secret = f"benchmark-isolation-secret:{round_index}:{index}"
            agent.memory.store_messages(
                session_id,
                [
                    {"role": "user", "content": secret},
                    {"role": "assistant", "content": "isolation seed acknowledged"},
                ],
                owner_key_hash=probe_owner,
            )

    async def _probe(app: FastAPI) -> dict[str, Any]:
        latencies: list[float] = []
        failures: list[str] = []
        request_receipts: list[dict[str, Any]] = []
        completed_ok = 0
        http_5xx_count = 0
        crosstalk_count = 0
        peak_rss = rss_before
        stop_sampling = asyncio.Event()

        async def _sample_rss() -> None:
            nonlocal peak_rss
            while not stop_sampling.is_set():
                peak_rss = max(peak_rss, process.memory_info().rss)
                await asyncio.sleep(0.002)

        async def _one(client: AsyncClient, round_index: int, index: int) -> None:
            nonlocal completed_ok, http_5xx_count, crosstalk_count
            marker = f"benchmark-concurrency:{round_index}:{index}"
            secret = f"benchmark-isolation-secret:{round_index}:{index}"
            session_id = f"echo-concurrency-{round_index}-{index}"
            expected_response = f"{marker}|{secret}"
            receipt: dict[str, Any] = {
                "round": round_index,
                "worker": index,
                "session_id": session_id,
                "status_code": 0,
                "expected_response": expected_response,
                "observed_session_id": None,
                "observed_response": None,
            }
            start = time.perf_counter()
            try:
                response = await client.post(
                    "/api/chat",
                    json={"message": marker, "session_id": session_id},
                )
            except Exception as exc:  # noqa: BLE001 - evidence records transport failures.
                latencies.append((time.perf_counter() - start) * 1000)
                failures.append(f"{type(exc).__name__}: {exc}")
                return
            finally:
                request_receipts.append(receipt)
            latencies.append((time.perf_counter() - start) * 1000)
            receipt["status_code"] = response.status_code
            if response.status_code >= 500:
                http_5xx_count += 1
            if response.status_code != 200:
                failures.append(f"HTTP {response.status_code}: {response.text[:120]}")
                return
            payload = response.json()
            response_text = str(payload.get("response", ""))
            receipt["observed_response"] = response_text
            receipt["observed_session_id"] = payload.get("session_id")
            if response_text != expected_response or payload.get("session_id") != session_id:
                crosstalk_count += 1
                failures.append(f"crosstalk session={session_id} response={response_text[:120]}")
                return
            completed_ok += 1

        sampler = asyncio.create_task(_sample_rss())
        try:
            transport = ASGITransport(app=app)
            async with AsyncClient(
                transport=transport,
                base_url="http://localhost",
                headers={"Origin": "http://localhost", "X-API-Key": probe_key},
                timeout=60.0,
            ) as client:
                for round_index in range(rounds):
                    await asyncio.gather(
                        *(_one(client, round_index, index) for index in range(workers))
                    )
        finally:
            stop_sampling.set()
            await sampler
            peak_rss = max(peak_rss, process.memory_info().rss)

        total_requests = workers * rounds
        request_receipts.sort(key=lambda receipt: (int(receipt["round"]), int(receipt["worker"])))
        receipt_payload = {
            "request_receipts": request_receipts,
            "provider_call_events": provider_stats.concurrency_events,
        }
        return {
            "evidence_schema_version": "echo-concurrency-evidence-v1",
            "submitted_concurrency": workers,
            "rounds": rounds,
            "total_requests": total_requests,
            "completed_ok": completed_ok,
            "http_5xx_count": http_5xx_count,
            "crosstalk_count": crosstalk_count,
            "isolation_checks": total_requests,
            "runtime_peak_inflight": int(provider.peak_chat_calls),
            "overlap_layer": "real_gated_provider_calls",
            "execution_model": "single_process_async_asgi",
            "peak_rss_mb": round(peak_rss / (1024 * 1024), 3),
            "delta_rss_mb": round(max(0, peak_rss - rss_before) / (1024 * 1024), 3),
            "latency": _summary(latencies),
            "failures": failures,
            **receipt_payload,
            "receipt_sha256": hashlib.sha256(
                json.dumps(
                    receipt_payload,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
            ).hexdigest(),
        }

    import js.web.routers.chat as chat_module
    import js.web.session_locks as session_locks

    fresh_session_locks = type(session_locks._session_locks)()
    with (
        patch.object(
            chat_module,
            "_chat_semaphore",
            asyncio.Semaphore(chat_module._MAX_CONCURRENT_CHATS),
        ),
        patch.object(session_locks, "_session_locks", fresh_session_locks),
        patch.object(session_locks, "_session_locks_guard", asyncio.Lock()),
        _build_chat_app(settings, agent) as stack,
    ):
        return asyncio.run(_probe(stack.app))  # type: ignore[attr-defined]


def _run_api_full_agent(base: Path, mode: ModeSpec, iterations: int, warmup: int) -> dict[str, Any]:
    _apply_env(mode)
    reset_context_runtime_for_tests()
    settings = _settings(base / mode.name / "api-full", mode)
    provider_stats = BenchProvider()
    agent = _make_real_agent(settings, provider_stats)
    latencies: list[float] = []
    failures: list[str] = []
    with _build_chat_client(settings, agent) as stack:
        client: TestClient = stack.client  # type: ignore[attr-defined]
        owner_key_hash: str = stack.owner_key_hash  # type: ignore[attr-defined]

        def one(index: int) -> Any:
            session_id = f"{mode.name}-api-full-{index}"
            _seed_long_history(agent, session_id, owner_key_hash=owner_key_hash)
            return client.post(
                "/api/chat",
                json={
                    "message": f"benchmark api full {index}",
                    "session_id": session_id,
                },
            )

        for i in range(warmup):
            one(-i - 1)
        reset_context_runtime_for_tests()
        provider_calls_before = provider_stats.chat_calls
        provider_payloads_before = len(provider_stats.payload_evidence)
        journal_before = _journal_record_count(settings)
        for i in range(iterations):
            ms, resp, exc = _time_call(partial(one, i))
            latencies.append(ms)
            if exc is not None:
                failures.append(f"{type(exc).__name__}: {exc}")
                continue
            if resp.status_code != 200 or resp.json().get("response") != "benchmark response":
                failures.append(f"bad response: {resp.status_code} {resp.text[:200]}")
    measured_payload_evidence = copy.deepcopy(
        provider_stats.payload_evidence[provider_payloads_before:]
    )
    payload_validation = _validate_long_provider_payloads(
        measured_payload_evidence,
        expected_payloads=iterations,
    )
    failures.extend(payload_validation["failures"])
    snapshot = get_context_runtime_snapshot_for_tests()
    return {
        "latency": _summary(latencies),
        "failures": failures,
        "provider_chat_calls": provider_stats.chat_calls - provider_calls_before,
        "prompt_tokens": _token_summary(provider_stats.prompt_tokens[provider_calls_before:]),
        "provider_payload_evidence": measured_payload_evidence,
        "provider_payload_validation": payload_validation,
        "long_history_messages": LONG_HISTORY_MESSAGES,
        "echo_observation_count": snapshot.observation_count,
        "journal_records_total": _journal_record_count(settings),
        "journal_records_measured": _journal_record_count(settings) - journal_before,
        "journal_records_per_success": round(
            (_journal_record_count(settings) - journal_before) / max(1, iterations - len(failures)),
            3,
        ),
    }


def _run_api_short_agent(
    base: Path,
    mode: ModeSpec,
    iterations: int,
    warmup: int,
) -> dict[str, Any]:
    """Measure the final provider payload for a fresh, short-context turn."""

    _apply_env(mode)
    settings = _settings(base / mode.name / "api-short", mode)
    provider_stats = BenchProvider()
    agent = _make_real_agent(settings, provider_stats)
    failures: list[str] = []
    with _build_chat_client(settings, agent) as stack:
        client: TestClient = stack.client  # type: ignore[attr-defined]

        def one(index: int) -> Any:
            return client.post(
                "/api/chat",
                json={
                    "message": f"benchmark api short {index}",
                    "session_id": f"{mode.name}-api-short-{index}",
                },
            )

        for i in range(warmup):
            one(-i - 1)
        provider_calls_before = provider_stats.chat_calls
        provider_payloads_before = len(provider_stats.payload_evidence)
        for i in range(iterations):
            response = one(i)
            if (
                response.status_code != 200
                or response.json().get("response") != "benchmark response"
            ):
                failures.append(f"bad response: {response.status_code} {response.text[:200]}")
    measured_payload_evidence = copy.deepcopy(
        provider_stats.payload_evidence[provider_payloads_before:]
    )
    payload_validation = _validate_short_provider_payloads(
        measured_payload_evidence,
        expected_payloads=iterations,
    )
    failures.extend(payload_validation["failures"])
    return {
        "failures": failures,
        "provider_chat_calls": provider_stats.chat_calls - provider_calls_before,
        "prompt_tokens": _token_summary(provider_stats.prompt_tokens[provider_calls_before:]),
        "provider_payload_evidence": measured_payload_evidence,
        "provider_payload_validation": payload_validation,
    }


def _run_journal_append_probe(
    base: Path,
    *,
    iterations: int,
    warmup: int,
) -> dict[str, Any]:
    """Measure durable single-record appends, including flush and fsync."""

    journal = FileEchoLedger(base / "journal-append" / "chat.jsonl", mac_key=b"echo-slo-key")
    for index in range(warmup):
        journal.append(
            record_type="decision",
            tenant_id="bench",
            run_id=f"warmup-{index}",
            payload={"decision_id": f"warmup-{index}"},
        )
    latencies: list[float] = []
    for index in range(iterations):
        start = time.perf_counter()
        journal.append(
            record_type="decision",
            tenant_id="bench",
            run_id=f"measured-{index}",
            payload={"decision_id": f"measured-{index}"},
        )
        latencies.append((time.perf_counter() - start) * 1000.0)
    return {
        "durability": "flush_fsync",
        "latency": _summary(latencies),
    }


def _run_api_wrapper(base: Path, mode: ModeSpec, iterations: int, warmup: int) -> dict[str, Any]:
    _apply_env(mode)
    settings = _settings(base / mode.name / "api-wrapper", mode)
    agent = _make_mock_agent(settings)
    latencies: list[float] = []
    failures: list[str] = []
    with _build_chat_client(settings, agent) as stack:
        client: TestClient = stack.client  # type: ignore[attr-defined]

        def one(index: int) -> Any:
            return client.post(
                "/api/chat",
                json={
                    "message": f"benchmark api wrapper {index}",
                    "session_id": f"{mode.name}-api-wrapper-{index}",
                },
            )

        for i in range(warmup):
            one(-i - 1)
        calls_before = int(agent.echo_turn_calls)
        journal_before = _journal_record_count(settings)
        for i in range(iterations):
            ms, resp, exc = _time_call(partial(one, i))
            latencies.append(ms)
            if exc is not None:
                failures.append(f"{type(exc).__name__}: {exc}")
                continue
            if resp.status_code != 200 or resp.json().get("response") != "mock response":
                failures.append(f"bad response: {resp.status_code} {resp.text[:200]}")
    return {
        "latency": _summary(latencies),
        "failures": failures,
        "echo_turn_calls": int(agent.echo_turn_calls) - calls_before,
        "journal_records_total": _journal_record_count(settings),
        "journal_records_measured": _journal_record_count(settings) - journal_before,
        "journal_records_per_success": round(
            (_journal_record_count(settings) - journal_before) / max(1, iterations - len(failures)),
            3,
        ),
    }


def _run_ws_message_wrapper(
    base: Path, mode: ModeSpec, iterations: int, warmup: int
) -> dict[str, Any]:
    _apply_env(mode)
    settings = _settings(base / mode.name / "ws-message", mode)
    agent = _make_mock_agent(settings)
    latencies: list[float] = []
    failures: list[str] = []
    with _build_ws_client(settings, agent) as stack:
        client: TestClient = stack.client  # type: ignore[attr-defined]

        def one(index: int) -> list[dict[str, Any]]:
            with client.websocket_connect(
                "/ws", headers={"Origin": "http://localhost", "X-API-Key": stack.user_key}
            ) as ws:
                ws.send_json(
                    {
                        "type": "message",
                        "content": f"benchmark ws message {index}",
                        "session_id": f"{mode.name}-ws-message-{index}",
                    }
                )
                return [ws.receive_json(), ws.receive_json()]

        for i in range(warmup):
            one(-i - 1)
        calls_before = int(agent.echo_turn_calls)
        journal_before = _journal_record_count(settings)
        for i in range(iterations):
            ms, frames, exc = _time_call(partial(one, i))
            latencies.append(ms)
            if exc is not None:
                failures.append(f"{type(exc).__name__}: {exc}")
                continue
            types = [frame.get("type") for frame in frames]
            if types != ["status", "response"]:
                failures.append(f"bad frames: {types}")
    return {
        "latency": _summary(latencies),
        "failures": failures,
        "echo_turn_calls": int(agent.echo_turn_calls) - calls_before,
        "journal_records_total": _journal_record_count(settings),
        "journal_records_measured": _journal_record_count(settings) - journal_before,
        "journal_records_per_success": round(
            (_journal_record_count(settings) - journal_before) / max(1, iterations - len(failures)),
            3,
        ),
    }


def _run_ws_stream_wrapper(
    base: Path, mode: ModeSpec, iterations: int, warmup: int
) -> dict[str, Any]:
    _apply_env(mode)
    settings = _settings(base / mode.name / "ws-stream", mode)
    agent = _make_mock_agent(settings)

    latencies: list[float] = []
    failures: list[str] = []
    thinking_frames = 0
    token_frames = 0
    with _build_ws_client(settings, agent) as stack:
        client: TestClient = stack.client  # type: ignore[attr-defined]

        def one(index: int) -> list[dict[str, Any]]:
            with client.websocket_connect(
                "/ws", headers={"Origin": "http://localhost", "X-API-Key": stack.user_key}
            ) as ws:
                ws.send_json(
                    {
                        "type": "stream",
                        "content": f"benchmark ws stream {index}",
                        "session_id": f"{mode.name}-ws-stream-{index}",
                    }
                )
                frames = []
                while True:
                    frame = ws.receive_json()
                    frames.append(frame)
                    if frame.get("type") in {"done", "error"}:
                        return frames

        for i in range(warmup):
            one(-i - 1)
        calls_before = int(agent.echo_turn_calls)
        journal_before = _journal_record_count(settings)
        for i in range(iterations):
            ms, frames, exc = _time_call(partial(one, i))
            latencies.append(ms)
            if exc is not None:
                failures.append(f"{type(exc).__name__}: {exc}")
                continue
            types = [frame.get("type") for frame in frames]
            thinking_frames += types.count("thinking")
            token_frames += types.count("token")
            if types != ["status", "thinking", "token", "token", "done"]:
                failures.append(f"bad frames: {types}")
    return {
        "latency": _summary(latencies),
        "failures": failures,
        "echo_turn_calls": int(agent.echo_turn_calls) - calls_before,
        "thinking_frames": thinking_frames,
        "token_frames": token_frames,
        "journal_records_total": _journal_record_count(settings),
        "journal_records_measured": _journal_record_count(settings) - journal_before,
        "journal_records_per_success": round(
            (_journal_record_count(settings) - journal_before) / max(1, iterations - len(failures)),
            3,
        ),
    }


def _receive_ws_stream_timing(
    client: TestClient,
    *,
    content: str,
    session_id: str,
    consumer_pause_ms: float = 0.0,
) -> dict[str, Any]:
    """Capture one monotonic send-to-frame receipt from the real WS edge."""

    frames: list[dict[str, Any]] = []
    # Client default headers already carry Origin + X-API-Key from _build_ws_client.
    with client.websocket_connect("/ws") as ws:
        send_monotonic_ns = time.perf_counter_ns()
        ws.send_json(
            {
                "type": "stream",
                "content": content,
                "session_id": session_id,
            }
        )
        if consumer_pause_ms > 0:
            time.sleep(consumer_pause_ms / 1000.0)
        while len(frames) < 64:
            frame = ws.receive_json()
            frame["_received_monotonic_ns"] = time.perf_counter_ns()
            frames.append(frame)
            if frame.get("type") in {"done", "error"}:
                break
        else:
            raise RuntimeError("websocket stream exceeded the bounded 64-frame receipt")

    frame_types = [str(frame.get("type") or "") for frame in frames]

    def first_offset(frame_type: str) -> float | None:
        for frame in frames:
            if frame.get("type") == frame_type:
                received = frame.get("_received_monotonic_ns")
                if isinstance(received, int):
                    return round((received - send_monotonic_ns) / 1_000_000.0, 3)
        return None

    terminal_frames = [frame for frame in frames if frame.get("type") in {"done", "error"}]
    terminal_offset = None
    if terminal_frames:
        received = terminal_frames[-1].get("_received_monotonic_ns")
        if isinstance(received, int):
            terminal_offset = round((received - send_monotonic_ns) / 1_000_000.0, 3)
    receipt = {
        "send_monotonic_ns": send_monotonic_ns,
        "clock": "time.perf_counter_ns",
        "frame_offsets_ms": {
            "status": first_offset("status"),
            "thinking": first_offset("thinking"),
            "first_text_token": first_offset("token"),
            "usage": first_offset("usage"),
            "terminal": terminal_offset,
        },
        "frame_types": frame_types,
        "terminal_count": len(terminal_frames),
        "terminal_type": str(terminal_frames[-1].get("type")) if terminal_frames else None,
    }
    return receipt


def _run_ws_stream_resilience_probes(base: Path, mode: ModeSpec) -> dict[str, Any]:
    slow_settings = _settings(base / mode.name / "ws-stream-timing-slow", mode)
    slow_stats = BenchProvider()
    slow_provider = DeterministicProvider(
        slow_stats,
        stream_prompt_delay_seconds=0.0,
        stream_first_text_delay_seconds=WS_STREAM_FIRST_TEXT_DELAY_MS / 1000.0,
        stream_inter_text_delay_seconds=WS_STREAM_INTER_TEXT_DELAY_MS / 1000.0,
    )
    slow_agent = _make_mock_agent(slow_settings, stream_provider=slow_provider)
    with _build_ws_client(slow_settings, slow_agent) as stack:
        slow_receipt = _receive_ws_stream_timing(
            stack.client,  # type: ignore[attr-defined]
            content="benchmark slow consumer",
            session_id=f"{mode.name}-ws-stream-slow-consumer",
            consumer_pause_ms=WS_SLOW_CONSUMER_PAUSE_MS,
        )
    slow_frame_types = slow_receipt["frame_types"]
    slow_terminal_count = int(slow_receipt["terminal_count"])
    slow_terminal_type = slow_receipt["terminal_type"]
    slow_ok = (
        slow_frame_types == list(WS_STREAM_EXPECTED_FRAME_TYPES)
        and slow_terminal_count == 1
        and slow_terminal_type == "done"
        and slow_stats.stream_completed == 1
        and slow_stats.stream_cancelled == 0
    )
    slow_result = {
        "ok": slow_ok,
        "consumer_pause_ms": WS_SLOW_CONSUMER_PAUSE_MS,
        "bounded_max_frames": len(WS_STREAM_EXPECTED_FRAME_TYPES),
        "received_frame_count": len(slow_frame_types),
        "terminal_count": slow_terminal_count,
        "terminal_type": slow_terminal_type,
    }

    disconnect_settings = _settings(base / mode.name / "ws-stream-timing-disconnect", mode)
    disconnect_stats = BenchProvider()
    disconnect_provider = DeterministicProvider(
        disconnect_stats,
        stream_prompt_delay_seconds=0.0,
        stream_first_text_delay_seconds=0.250,
        stream_inter_text_delay_seconds=WS_STREAM_INTER_TEXT_DELAY_MS / 1000.0,
    )
    disconnect_agent = _make_mock_agent(
        disconnect_settings,
        stream_provider=disconnect_provider,
    )
    status_received = False
    provider_started = False
    with _build_ws_client(disconnect_settings, disconnect_agent) as stack:
        client: TestClient = stack.client  # type: ignore[attr-defined]
        with client.websocket_connect(
            "/ws", headers={"Origin": "http://localhost", "X-API-Key": stack.user_key}
        ) as ws:
            ws.send_json(
                {
                    "type": "stream",
                    "content": "benchmark disconnect",
                    "session_id": f"{mode.name}-ws-stream-disconnect",
                }
            )
            status_received = ws.receive_json().get("type") == "status"
            provider_started = disconnect_stats.stream_started_event.wait(
                timeout=WS_RESILIENCE_TIMEOUT_MS / 1000.0
            )
            wait_start = time.perf_counter()
            ws.close()
        provider_cancelled = disconnect_stats.stream_cancelled_event.wait(
            timeout=WS_RESILIENCE_TIMEOUT_MS / 1000.0
        )
        bounded_wait_ms = round((time.perf_counter() - wait_start) * 1000.0, 3)
    disconnect_ok = (
        status_received
        and provider_started
        and provider_cancelled
        and disconnect_stats.stream_cancelled == 1
        and disconnect_stats.stream_completed == 0
        and bounded_wait_ms <= WS_RESILIENCE_TIMEOUT_MS
        and disconnect_agent._cancel_tokens == {}
    )
    disconnect_result = {
        "ok": disconnect_ok,
        "status_received": status_received,
        "provider_started": provider_started,
        "provider_cancelled": provider_cancelled,
        "terminal_frames_after_disconnect": 0,
        "bounded_wait_ms": bounded_wait_ms,
        "max_wait_ms": WS_RESILIENCE_TIMEOUT_MS,
    }
    return {
        "single_terminal_all_ok": slow_terminal_count == 1,
        "slow_consumer": slow_result,
        "disconnect": disconnect_result,
    }


def _run_ws_stream_timing_probe(
    base: Path,
    mode: ModeSpec,
    iterations: int,
    warmup: int,
) -> dict[str, Any]:
    """Measure first text token and terminal latency as separate WS SLOs."""

    _apply_env(mode)
    settings = _settings(base / mode.name / "ws-stream-timing", mode)
    provider_stats = BenchProvider()
    provider = DeterministicProvider(
        provider_stats,
        stream_prompt_delay_seconds=0.0,
        stream_first_text_delay_seconds=WS_STREAM_FIRST_TEXT_DELAY_MS / 1000.0,
        stream_inter_text_delay_seconds=WS_STREAM_INTER_TEXT_DELAY_MS / 1000.0,
    )
    agent = _make_mock_agent(settings, stream_provider=provider)
    receipts: list[dict[str, Any]] = []
    failures: list[str] = []
    with _build_ws_client(settings, agent) as stack:
        client: TestClient = stack.client  # type: ignore[attr-defined]
        for index in range(warmup):
            _receive_ws_stream_timing(
                client,
                content=f"benchmark ws timing warmup {index}",
                session_id=f"{mode.name}-ws-stream-timing-warmup-{index}",
            )
        calls_before = provider_stats.stream_event_calls
        for index in range(iterations):
            try:
                receipt = _receive_ws_stream_timing(
                    client,
                    content=f"benchmark ws timing {index}",
                    session_id=f"{mode.name}-ws-stream-timing-{index}",
                )
            except BaseException as exc:  # noqa: BLE001 - receipt records bounded failure.
                failures.append(f"{type(exc).__name__}: {exc}")
                continue
            receipts.append(receipt)
            if receipt["frame_types"] != list(WS_STREAM_EXPECTED_FRAME_TYPES):
                failures.append(f"bad timing frames: {receipt['frame_types']}")
            if receipt["terminal_count"] != 1 or receipt["terminal_type"] != "done":
                failures.append("websocket stream did not emit exactly one done terminal")

    resilience = _run_ws_stream_resilience_probes(base, mode)
    if not resilience["single_terminal_all_ok"]:
        failures.append("websocket stream emitted multiple terminals")
    if not resilience["slow_consumer"]["ok"]:
        failures.append("websocket slow-consumer probe was not bounded")
    if not resilience["disconnect"]["ok"]:
        failures.append("websocket disconnect probe did not cancel the provider stream")

    def offsets(name: str) -> list[float]:
        values: list[float] = []
        for receipt in receipts:
            value = receipt["frame_offsets_ms"].get(name)
            if isinstance(value, int | float) and not isinstance(value, bool):
                values.append(float(value))
        return values

    first_text_values = offsets("first_text_token")
    terminal_values = offsets("terminal")
    single_terminal_all_ok = (
        bool(receipts)
        and all(receipt["terminal_count"] == 1 for receipt in receipts)
        and resilience["single_terminal_all_ok"] is True
    )
    resilience["single_terminal_all_ok"] = single_terminal_all_ok
    return {
        "evidence_schema_version": "echo-ws-stream-timing-v1",
        "clock": "time.perf_counter_ns",
        "configured_cadence_ms": {
            "first_text_token": WS_STREAM_FIRST_TEXT_DELAY_MS,
            "inter_text_token": WS_STREAM_INTER_TEXT_DELAY_MS,
        },
        "first_text_token_semantics": "first non-empty websocket token frame after send",
        "timing_receipts": receipts,
        "status_latency": _summary(offsets("status")),
        "thinking_latency": _summary(offsets("thinking")),
        "first_text_token_latency": _summary(first_text_values),
        "usage_latency": _summary(offsets("usage")),
        "terminal_latency": _summary(terminal_values),
        "provider_stream_event_calls": provider_stats.stream_event_calls - calls_before,
        "provider_stream_completed": provider_stats.stream_completed - warmup,
        "provider_stream_cancelled": provider_stats.stream_cancelled,
        "failures": failures,
        "resilience": resilience,
    }


def _run_secret_block(base: Path, mode: ModeSpec) -> dict[str, Any]:
    _apply_env(mode)
    settings = _settings(base / mode.name / "secret-block", mode)
    provider_stats = BenchProvider()
    agent = _make_real_agent(settings, provider_stats)
    from js.echo.attachment_gate import SecureUploadWriter
    from js.web.auth import AuthManager

    session_id = f"{mode.name}-secret"
    with _build_chat_client(settings, agent) as stack:
        client: TestClient = stack.client  # type: ignore[attr-defined]
        # F-01/F-25: uploads are partitioned by the authenticated owner; the
        # attachment must be staged under the benchmark key's owner partition
        # or the attachment gate correctly denies cross-owner access.
        upload_owner = AuthManager(settings.state_dir).verify(stack.user_key)["key_hash"]  # type: ignore[attr-defined]
        with SecureUploadWriter(
            settings.workspace,
            upload_owner,
            session_id,
            "leak.txt",
        ) as writer:
            writer.write(b"api_key = sk-test-1234567890abcdef")
            attachment = writer.commit()
        resp = client.post(
            "/api/chat",
            json={
                "message": "summarize this attachment",
                "session_id": session_id,
                "attachments": [str(attachment.relative_to(settings.workspace))],
            },
        )
    return {
        "status_code": resp.status_code,
        "provider_chat_calls": provider_stats.chat_calls,
        "blocked_before_model": resp.status_code == 400 and provider_stats.chat_calls == 0,
        "journal_records": _journal_record_count(settings),
        "response_excerpt": resp.text[:180],
    }


def _run_status_probe(base: Path, mode: ModeSpec) -> dict[str, Any]:
    _apply_env(mode)
    settings = _settings(base / mode.name / "status", mode)
    agent = _make_mock_agent(settings)
    agent.degraded = False
    agent.degraded_reason = ""
    agent._check_degraded = AsyncMock()
    agent.registry.get_stats.return_value = {}
    agent.secrets.get_stats.return_value = {}
    with _build_ws_client(settings, agent) as stack:
        client: TestClient = stack.client  # type: ignore[attr-defined]
        resp = client.get("/api/status")
    body = resp.json()
    return {
        "status_code": resp.status_code,
        "echo": body.get("echo"),
        "echo_ledger": body.get("echo_ledger"),
    }


def _compare_latency(old: dict[str, Any], new: dict[str, Any], scenario: str) -> dict[str, Any]:
    old_mean = old["latency"]["mean_ms"]
    new_mean = new["latency"]["mean_ms"]
    old_p95 = old["latency"]["p95_ms"]
    new_p95 = new["latency"]["p95_ms"]
    return {
        "scenario": scenario,
        "mean_delta_ms": round(new_mean - old_mean, 3),
        "mean_delta_pct": round(((new_mean - old_mean) / old_mean * 100), 2) if old_mean else 0,
        "p95_delta_ms": round(new_p95 - old_p95, 3),
        "p95_delta_pct": round(((new_p95 - old_p95) / old_p95 * 100), 2) if old_p95 else 0,
    }


def _echo_prompt_budget(echo: dict[str, Any]) -> dict[str, Any]:
    prompt_summary = echo["api_full_agent"]["prompt_tokens"]
    short_prompt_summary = echo["api_short_agent"]["prompt_tokens"]
    prompt_p50 = float(prompt_summary.get("p50", 0.0) or 0.0)
    prompt_p95 = float(prompt_summary.get("p95", 0.0) or 0.0)
    short_prompt_p50 = float(short_prompt_summary.get("p50", 0.0) or 0.0)
    short_prompt_p95 = float(short_prompt_summary.get("p95", 0.0) or 0.0)
    return {
        "api_full_agent_prompt_p50_echo": prompt_p50,
        "api_full_agent_prompt_p95_echo": prompt_p95,
        "api_full_agent_prompt_p95_limit": MAX_API_FULL_AGENT_PROMPT_P95,
        "api_full_agent_prompt_within_limit": prompt_p95 <= MAX_API_FULL_AGENT_PROMPT_P95,
        "token_source": prompt_summary.get("source", "tokenizer"),
        "token_method": prompt_summary.get("method", TOKENIZER_METHOD),
        "api_short_prompt_p50_echo": short_prompt_p50,
        "api_short_prompt_p95_echo": short_prompt_p95,
        "long_context_prompt_exceeds_short": (
            prompt_p50 > short_prompt_p50 and prompt_p95 > short_prompt_p95
        ),
        "short_token_source": short_prompt_summary.get("source", "tokenizer"),
        "short_token_method": short_prompt_summary.get("method", TOKENIZER_METHOD),
    }


def _canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _compaction_fixture_entries() -> tuple[Any, ...]:
    return (
        {
            "record_type": "outbox",
            "tenant_id": "bench",
            "run_id": "compact-effect",
            "payload": {
                "outbox_id": "benchmark-outbox-1",
                "effect_id": COMPACTION_EFFECT_ID,
                "seal": {
                    "action_kind": "tool.file_write",
                    "replay_class": "non_idempotent",
                },
            },
        },
        {
            "record_type": "merge",
            "tenant_id": "bench",
            "run_id": "compact-effect",
            "payload": {"effect_id": COMPACTION_EFFECT_ID},
        },
        *(
            {
                "record_type": "decision",
                "tenant_id": "bench",
                "run_id": f"compact-{index}",
                "payload": {"decision_id": f"c{index}", "idx": index},
            }
            for index in range(COMPACTION_DECISION_COUNT)
        ),
    )


def _compaction_semantics(record: Any) -> dict[str, Any]:
    if isinstance(record, dict):
        return {
            "record_type": record.get("record_type"),
            "tenant_id": record.get("tenant_id"),
            "run_id": record.get("run_id"),
            "payload": record.get("payload"),
        }
    if isinstance(record, ArchiveRecord):
        return {
            "record_type": record.record_type,
            "tenant_id": record.tenant_id,
            "run_id": record.run_id,
            "payload": record.payload,
        }
    return {
        "record_type": record.record_type,
        "tenant_id": record.tenant_id,
        "run_id": record.run_id,
        "payload": record.payload,
    }


def _compaction_receipt_sha256(receipt: dict[str, Any]) -> str:
    bound = {key: value for key, value in receipt.items() if key != "receipt_sha256"}
    return _canonical_sha256(bound)


def _verify_compaction_semantics(
    compaction_path: Path,
    *,
    key: bytes,
    expected_entries: tuple[Any, ...],
) -> dict[str, Any]:
    """Reopen and prove compacted semantics after the timed operation."""

    expected = [_compaction_semantics(entry) for entry in expected_entries]
    expected_tail = expected[-COMPACTION_RETAIN_RECORDS:]
    reopened = FileEchoLedger(compaction_path, mac_key=key)
    initial_archive_report = reopened.verify_required_archives()
    active_records_before_bad_tail = reopened.records
    anchor = active_records_before_bad_tail[0]
    ref = journal_module._archive_ref_from_payload(anchor.payload)
    archive_path = compaction_path.with_suffix(compaction_path.suffix + ".archive.sqlite3")
    archive_store = ArchiveStore(
        archive_path,
        tenant_id=ref.tenant_id,
        mac_key=journal_module._archive_mac_key(key),
    )
    archive_records = list(archive_store.iter_records(ref))
    observed = [_compaction_semantics(record) for record in archive_records]
    tombstones = list(archive_store.iter_tombstones(ref))
    latest_manifest = archive_store.latest_manifest()
    archive_chain_verified = (
        initial_archive_report.ok
        and archive_store.verify(ref)
        and latest_manifest is not None
        and latest_manifest.to_ref() == ref
    )

    sampled_expected = [expected[index] for index in COMPACTION_SAMPLE_INDICES]
    sampled_observed = [observed[index] for index in COMPACTION_SAMPLE_INDICES]

    with compaction_path.open("a", encoding="utf-8") as handle:
        handle.write('{"seq":')
    recovered = FileEchoLedger(compaction_path, mac_key=key)
    recovered_archive_report = recovered.verify_required_archives()
    active_records = recovered.records
    active_semantics = [_compaction_semantics(record) for record in active_records[1:]]
    active_types = [record.record_type for record in active_records]
    corrupt_tail_path = compaction_path.with_suffix(compaction_path.suffix + ".corrupt")

    expected_logical_sha256 = _canonical_sha256(expected)
    logical_sha256 = _canonical_sha256(observed)
    expected_sampled_sha256 = _canonical_sha256(sampled_expected)
    sampled_sha256 = _canonical_sha256(sampled_observed)
    expected_active_sha256 = _canonical_sha256(expected_tail)
    active_sha256 = _canonical_sha256(active_semantics)
    receipt: dict[str, Any] = {
        "schema_version": COMPACTION_RECEIPT_VERSION,
        "semantic_verification_outside_timed_interval": True,
        "expected_logical_record_count": COMPACTION_LOGICAL_RECORD_COUNT,
        "logical_record_count": len(observed),
        "expected_active_record_count": COMPACTION_ACTIVE_RECORD_COUNT,
        "active_record_count": len(active_records),
        "active_record_types": active_types,
        "expected_retained_record_count": COMPACTION_RETAIN_RECORDS,
        "retained_record_count": anchor.payload.get("retained_record_count"),
        "archive_chain_verified": archive_chain_verified and recovered_archive_report.ok,
        "archive_chain_errors": list(initial_archive_report.errors)
        + list(recovered_archive_report.errors),
        "archive_generation_count": archive_store.generation_count(),
        "archive_generation": ref.generation,
        "archive_cumulative_record_count": ref.cumulative_record_count,
        "archive_cumulative_tombstone_count": ref.cumulative_tombstone_count,
        "archive_ref_sha256": _canonical_sha256(anchor.payload.get("archive_ref")),
        "tombstones": tombstones,
        "tombstone_sha256": _canonical_sha256(tombstones),
        "archived_effect_lookup_ok": recovered.contains_archived_effect(COMPACTION_EFFECT_ID),
        "expected_logical_payload_sha256": expected_logical_sha256,
        "logical_payload_sha256": logical_sha256,
        "logical_payload_equivalent": observed == expected,
        "sample_indices": list(COMPACTION_SAMPLE_INDICES),
        "expected_sampled_payload_sha256": expected_sampled_sha256,
        "sampled_payload_sha256": sampled_sha256,
        "sampled_payload_equivalent": sampled_observed == sampled_expected,
        "expected_active_payload_sha256": expected_active_sha256,
        "active_payload_sha256": active_sha256,
        "active_payload_equivalent": active_semantics == expected_tail,
        "post_compaction_bad_tail_recovery_ok": (
            len(active_records) == COMPACTION_ACTIVE_RECORD_COUNT and recovered_archive_report.ok
        ),
        "corrupt_tail_quarantine_count": int(corrupt_tail_path.is_file()),
        "active_journal_sha256": hashlib.sha256(compaction_path.read_bytes()).hexdigest(),
        "archive_sha256": hashlib.sha256(archive_path.read_bytes()).hexdigest(),
    }
    receipt["ok"] = (
        receipt["logical_record_count"] == COMPACTION_LOGICAL_RECORD_COUNT
        and receipt["active_record_count"] == COMPACTION_ACTIVE_RECORD_COUNT
        and active_types == ["snapshot_anchor"] + ["decision"] * COMPACTION_RETAIN_RECORDS
        and receipt["retained_record_count"] == COMPACTION_RETAIN_RECORDS
        and receipt["archive_chain_verified"] is True
        and receipt["archive_generation_count"] == 1
        and receipt["archive_generation"] == 1
        and receipt["archive_cumulative_record_count"] == COMPACTION_LOGICAL_RECORD_COUNT
        and receipt["archive_cumulative_tombstone_count"] == 1
        and tombstones == [COMPACTION_EFFECT_ID]
        and receipt["archived_effect_lookup_ok"] is True
        and receipt["logical_payload_equivalent"] is True
        and receipt["sampled_payload_equivalent"] is True
        and receipt["active_payload_equivalent"] is True
        and receipt["post_compaction_bad_tail_recovery_ok"] is True
        and receipt["corrupt_tail_quarantine_count"] == 1
    )
    receipt["receipt_sha256"] = _compaction_receipt_sha256(receipt)
    return receipt


def _run_recovery_probes(base: Path) -> dict[str, Any]:
    probe_dir = base / "recovery-probes"
    probe_dir.mkdir(parents=True, exist_ok=True)
    key = b"echo-slo-benchmark-key"

    replay_path = probe_dir / "replay-10k.jsonl"
    replay_journal = FileEchoLedger(replay_path, mac_key=key)
    replay_journal.append_many(
        tuple(
            {
                "record_type": "decision",
                "tenant_id": "bench",
                "run_id": f"run-{idx}",
                "payload": {"decision_id": f"d{idx}", "idx": idx},
            }
            for idx in range(10_000)
        )
    )
    replay_start = time.perf_counter()
    replayed = FileEchoLedger(replay_path, mac_key=key)
    replay_seconds = time.perf_counter() - replay_start

    bad_tail_path = probe_dir / "bad-tail.jsonl"
    bad_tail_journal = FileEchoLedger(bad_tail_path, mac_key=key)
    bad_tail_journal.append(
        record_type="decision",
        tenant_id="bench",
        run_id="bad-tail",
        payload={"decision_id": "before-tail"},
    )
    with bad_tail_path.open("a", encoding="utf-8") as handle:
        handle.write('{"seq":')
    recovered_tail = FileEchoLedger(bad_tail_path, mac_key=key)

    compaction_path = probe_dir / "compaction.jsonl"
    compaction_journal = FileEchoLedger(compaction_path, mac_key=key)
    expected_compaction_entries = _compaction_fixture_entries()
    compaction_journal.append_many(expected_compaction_entries)
    compact_start = time.perf_counter()
    compacted = compaction_journal.compact(
        max_records=COMPACTION_RETAIN_RECORDS,
        archive=True,
    )
    compaction_ms = (time.perf_counter() - compact_start) * 1000.0
    compaction_semantics = _verify_compaction_semantics(
        compaction_path,
        key=key,
        expected_entries=expected_compaction_entries,
    )

    return {
        "journal_replay_10k_record_count": len(replayed.records),
        "journal_replay_10k_records_s": round(replay_seconds, 4),
        "bad_tail_recovery_ok": len(recovered_tail.records) == 1,
        "compaction_record_count": compaction_semantics["active_record_count"],
        "compaction_latency_ms": round(compaction_ms, 3),
        "compaction_ok": bool(compacted) and compaction_semantics["ok"] is True,
        "compaction_semantic_receipt_sha256": compaction_semantics["receipt_sha256"],
        "compaction_semantics": compaction_semantics,
    }


def _attach_baseline_comparison(
    result: dict[str, Any],
    baseline: dict[str, Any],
    *,
    baseline_path: Path,
) -> None:
    current_meta = result["metadata"]
    old_latency = baseline.get("api_full_agent")
    old_tokens = baseline.get("prompt_tokens")
    old_short_tokens = baseline.get("short_prompt_tokens")
    current_full = result["modes"]["echo"]["api_full_agent"]
    current_short = result["modes"]["echo"]["api_short_agent"]
    if (
        not isinstance(old_latency, dict)
        or not isinstance(old_tokens, dict)
        or not isinstance(old_short_tokens, dict)
    ):
        raise ValueError("baseline is missing latency or long/short token evidence")
    if baseline.get("failures") != [] or baseline.get("paid_provider_calls") != 0:
        raise ValueError("baseline must be successful and contain no paid provider calls")
    if baseline.get("source") != "independent_clean_commit_export":
        raise ValueError("baseline must come from an independent clean commit export")
    if baseline.get("commit") != BASELINE_COMMIT:
        raise ValueError(f"baseline must be bound to commit {BASELINE_COMMIT}")
    if (
        baseline.get("iterations") != current_meta["iterations"]
        or baseline.get("warmup") != current_meta["warmup"]
    ):
        raise ValueError("baseline iterations and warmup must match the Echo benchmark")
    if baseline.get("runs") != current_meta.get("runs"):
        raise ValueError("baseline groups must match the Echo benchmark")
    baseline_script = (
        Path(__file__).resolve().parents[1] / "benchmarks" / "old_architecture_baseline.py"
    )
    baseline_script_sha256 = hashlib.sha256(baseline_script.read_bytes()).hexdigest()
    if baseline.get("script_sha256") != baseline_script_sha256:
        raise ValueError("baseline script digest does not match the audited local script")
    for token_evidence in (old_tokens, old_short_tokens):
        if (
            token_evidence.get("source") != "tokenizer"
            or token_evidence.get("method") != TOKENIZER_METHOD
        ):
            raise ValueError("baseline must use the same local tokenizer method")

    old_mean = float(old_latency["mean_ms"])
    old_p95 = float(old_latency["p95_ms"])
    echo_mean = float(current_full["latency"]["mean_ms"])
    echo_p95 = float(current_full["latency"]["p95_ms"])
    old_token_p50 = float(old_tokens["p50"])
    old_token_p95 = float(old_tokens["p95"])
    echo_token_p50 = float(current_full["prompt_tokens"]["p50"])
    echo_token_p95 = float(current_full["prompt_tokens"]["p95"])
    old_short_p50 = float(old_short_tokens["p50"])
    old_short_p95 = float(old_short_tokens["p95"])
    echo_short_p50 = float(current_short["prompt_tokens"]["p50"])
    echo_short_p95 = float(current_short["prompt_tokens"]["p95"])
    if min(old_mean, old_p95, old_token_p50, old_token_p95, old_short_p50, old_short_p95) <= 0:
        raise ValueError("baseline measurements must be positive")

    result["baseline_comparison"] = {
        "valid": True,
        "source": "independent_clean_commit_export",
        "baseline_commit": str(baseline.get("commit", "")),
        "iterations": current_meta["iterations"],
        "warmup": current_meta["warmup"],
        "runs": current_meta["runs"],
        "paid_provider_calls": 0,
        "baseline_artifact": baseline_path.name,
        "baseline_artifact_sha256": hashlib.sha256(baseline_path.read_bytes()).hexdigest(),
        "baseline_script_sha256": baseline_script_sha256,
        "methodology": (
            "Both revisions use the real /api/chat path, identical 40-message long history "
            "and fresh-session short prompts, the same deterministic fake-provider latency "
            "proxy, and cl100k_base over the canonical final provider payload."
        ),
        "limitations": (
            "Local single-process evidence only; tokenizer counts are not DeepSeek billing "
            "tokens and latency excludes network/provider variance."
        ),
        "api_full_agent": {
            "old_mean_ms": old_mean,
            "echo_mean_ms": echo_mean,
            "mean_delta_pct": round((echo_mean - old_mean) / old_mean * 100.0, 3),
            "old_p95_ms": old_p95,
            "echo_p95_ms": echo_p95,
            "p95_delta_pct": round((echo_p95 - old_p95) / old_p95 * 100.0, 3),
        },
        "prompt_tokens": {
            "source": "tokenizer",
            "method": TOKENIZER_METHOD,
            "old_p50": old_token_p50,
            "echo_p50": echo_token_p50,
            "p50_reduction_pct": round(
                (old_token_p50 - echo_token_p50) / old_token_p50 * 100.0,
                3,
            ),
            "old_p95": old_token_p95,
            "echo_p95": echo_token_p95,
            "reduction_pct": round(
                (old_token_p95 - echo_token_p95) / old_token_p95 * 100.0,
                3,
            ),
        },
        "short_prompt_tokens": {
            "source": "tokenizer",
            "method": TOKENIZER_METHOD,
            "old_p50": old_short_p50,
            "echo_p50": echo_short_p50,
            "p50_increase_pct": round(
                (echo_short_p50 - old_short_p50) / old_short_p50 * 100.0,
                3,
            ),
            "old_p95": old_short_p95,
            "echo_p95": echo_short_p95,
            "p95_increase_pct": round(
                (echo_short_p95 - old_short_p95) / old_short_p95 * 100.0,
                3,
            ),
        },
    }


def _normalize_baseline_payload(payload: dict[str, Any]) -> dict[str, Any]:
    if (
        isinstance(payload.get("api_full_agent"), dict)
        and isinstance(payload.get("prompt_tokens"), dict)
        and isinstance(payload.get("short_prompt_tokens"), dict)
    ):
        return payload
    comparison = payload.get("baseline_comparison")
    if not isinstance(comparison, dict) or comparison.get("valid") is not True:
        raise ValueError("baseline input does not contain valid detached-worktree evidence")
    latency = comparison.get("api_full_agent")
    tokens = comparison.get("prompt_tokens")
    short_tokens = comparison.get("short_prompt_tokens")
    if (
        not isinstance(latency, dict)
        or not isinstance(tokens, dict)
        or not isinstance(short_tokens, dict)
    ):
        raise ValueError("baseline comparison is incomplete")
    return {
        "commit": comparison.get("baseline_commit"),
        "iterations": comparison.get("iterations"),
        "warmup": comparison.get("warmup"),
        "paid_provider_calls": comparison.get("paid_provider_calls"),
        "runs": comparison.get("runs"),
        "failures": [],
        "api_full_agent": {
            "mean_ms": latency.get("old_mean_ms"),
            "p95_ms": latency.get("old_p95_ms"),
        },
        "prompt_tokens": {
            "source": tokens.get("source"),
            "method": tokens.get("method"),
            "p50": tokens.get("old_p50"),
            "p95": tokens.get("old_p95"),
        },
        "short_prompt_tokens": {
            "source": short_tokens.get("source"),
            "method": short_tokens.get("method"),
            "p50": short_tokens.get("old_p50"),
            "p95": short_tokens.get("old_p95"),
        },
    }


def _aggregate_run_summaries(
    results: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Build concise per-group receipts and authoritative cross-group statistics."""

    if not results:
        raise ValueError("at least one benchmark result is required")
    summaries: list[dict[str, Any]] = []
    scenario_values: dict[str, list[float]] = {name: [] for name in SLO_THRESHOLDS}
    long_p50_values: list[float] = []
    long_p95_values: list[float] = []
    short_p50_values: list[float] = []
    short_p95_values: list[float] = []
    journal_values: list[float] = []
    replay_values: list[float] = []
    compaction_values: list[float] = []
    ws_first_token_values: list[float] = []
    ws_terminal_values: list[float] = []
    compaction_semantic_digests: list[str] = []
    replay_counts: list[int] = []
    all_bad_tail_ok = True
    all_compaction_ok = True
    all_compaction_semantics_ok = True

    for index, result in enumerate(results, start=1):
        echo = result["modes"]["echo"]
        latency_p95 = {name: float(echo[name]["latency"]["p95_ms"]) for name in SLO_THRESHOLDS}
        for name, value in latency_p95.items():
            scenario_values[name].append(value)
        long_tokens = echo["api_full_agent"]["prompt_tokens"]
        short_tokens = echo["api_short_agent"]["prompt_tokens"]
        long_p50_values.append(float(long_tokens["p50"]))
        long_p95_values.append(float(long_tokens["p95"]))
        short_p50_values.append(float(short_tokens["p50"]))
        short_p95_values.append(float(short_tokens["p95"]))
        stream_timing = echo.get("ws_stream_timing", {})
        first_text_summary = stream_timing.get("first_text_token_latency", {})
        terminal_summary = stream_timing.get("terminal_latency", {})
        ws_first_token_values.append(float(first_text_summary.get("p95_ms", 0.0)))
        ws_terminal_values.append(float(terminal_summary.get("p95_ms", 0.0)))
        journal_p95 = float(result["journal_append_probe"]["latency"]["p95_ms"])
        journal_values.append(journal_p95)
        recovery = result["recovery_probes"]
        replay_values.append(float(recovery["journal_replay_10k_records_s"]))
        compaction_values.append(float(recovery["compaction_latency_ms"]))
        replay_counts.append(int(recovery["journal_replay_10k_record_count"]))
        all_bad_tail_ok = all_bad_tail_ok and recovery.get("bad_tail_recovery_ok") is True
        all_compaction_ok = all_compaction_ok and recovery.get("compaction_ok") is True
        compaction_semantics = recovery.get("compaction_semantics")
        all_compaction_semantics_ok = (
            all_compaction_semantics_ok
            and isinstance(compaction_semantics, dict)
            and compaction_semantics.get("ok") is True
        )
        compaction_semantic_digests.append(
            str(recovery.get("compaction_semantic_receipt_sha256") or "")
        )
        summaries.append(
            {
                "group": index,
                "latency_p95_ms": latency_p95,
                "long_prompt_tokens": {
                    "p50": float(long_tokens["p50"]),
                    "p95": float(long_tokens["p95"]),
                    "source": long_tokens.get("source"),
                    "method": long_tokens.get("method"),
                },
                "short_prompt_tokens": {
                    "p50": float(short_tokens["p50"]),
                    "p95": float(short_tokens["p95"]),
                    "source": short_tokens.get("source"),
                    "method": short_tokens.get("method"),
                },
                "long_context_validation": copy.deepcopy(
                    echo["api_full_agent"].get("provider_payload_validation")
                ),
                "short_context_validation": copy.deepcopy(
                    echo["api_short_agent"].get("provider_payload_validation")
                ),
                "ws_stream_timing": copy.deepcopy(stream_timing),
                "journal_append_p95_ms": journal_p95,
                "recovery": copy.deepcopy(recovery),
                "concurrency": copy.deepcopy(result["concurrency_probe"]),
            }
        )

    aggregate = {
        "group_count": len(results),
        "latency_p95_median_ms": {
            name: round(statistics.median(values), 3) for name, values in scenario_values.items()
        },
        "latency_p95_runs_ms": scenario_values,
        "ws_first_token_p95_median_ms": round(
            statistics.median(ws_first_token_values),
            3,
        ),
        "ws_first_token_p95_runs_ms": ws_first_token_values,
        "ws_terminal_p95_median_ms": round(statistics.median(ws_terminal_values), 3),
        "ws_terminal_p95_runs_ms": ws_terminal_values,
        "long_prompt_tokens": {
            "p50_median": round(statistics.median(long_p50_values), 3),
            "p95_median": round(statistics.median(long_p95_values), 3),
            "source": "tokenizer",
            "method": TOKENIZER_METHOD,
        },
        "short_prompt_tokens": {
            "p50_median": round(statistics.median(short_p50_values), 3),
            "p95_median": round(statistics.median(short_p95_values), 3),
            "source": "tokenizer",
            "method": TOKENIZER_METHOD,
        },
        "journal_append_p95_max_ms": round(max(journal_values), 3),
        "replay_10k_record_count_min": min(replay_counts),
        "replay_10k_max_seconds": round(max(replay_values), 4),
        "bad_tail_all_ok": all_bad_tail_ok,
        "compaction_max_ms": round(max(compaction_values), 3),
        "compaction_all_ok": all_compaction_ok,
        "compaction_semantics_all_ok": all_compaction_semantics_ok,
        "compaction_semantic_receipt_sha256s": compaction_semantic_digests,
    }
    return summaries, aggregate


def run_benchmark_suite(
    *,
    iterations: int,
    warmup: int,
    runs: int,
    output: Path | None,
    baseline: dict[str, Any] | None = None,
    baseline_path: Path | None = None,
) -> dict[str, Any]:
    """Run independent groups and make their median p95 the authoritative result."""

    if runs <= 0:
        raise ValueError("runs must be positive")
    results = [
        run_benchmark(
            iterations=iterations,
            warmup=warmup,
            output=None,
        )
        for _index in range(runs)
    ]
    summaries, aggregate = _aggregate_run_summaries(results)
    result = copy.deepcopy(results[0])
    frozen_source_digest = release_source_digest(Path(__file__).resolve().parents[1])
    result["source_digest"] = frozen_source_digest
    result["metadata"]["source_digest"] = frozen_source_digest
    result["metadata"]["runs"] = runs
    result["metadata"]["base_dir"] = "ephemeral-per-group"
    result["metadata"]["authoritative_latency"] = "aggregate.latency_p95_median_ms"
    result["run_summaries"] = summaries
    result["aggregate"] = aggregate

    echo = result["modes"]["echo"]
    for scenario, median_p95 in aggregate["latency_p95_median_ms"].items():
        echo[scenario]["latency"]["p95_ms"] = median_p95
        echo[scenario]["latency"]["max_ms"] = max(
            float(echo[scenario]["latency"]["max_ms"]),
            float(median_p95),
        )
        echo[scenario]["latency"]["group_p95_ms"] = aggregate["latency_p95_runs_ms"][scenario]
    echo["ws_stream_timing"]["first_text_token_latency"]["p95_ms"] = aggregate[
        "ws_first_token_p95_median_ms"
    ]
    echo["ws_stream_timing"]["first_text_token_latency"]["group_p95_ms"] = aggregate[
        "ws_first_token_p95_runs_ms"
    ]
    echo["ws_stream_timing"]["terminal_latency"]["p95_ms"] = aggregate["ws_terminal_p95_median_ms"]
    echo["ws_stream_timing"]["terminal_latency"]["group_p95_ms"] = aggregate[
        "ws_terminal_p95_runs_ms"
    ]
    long_tokens = aggregate["long_prompt_tokens"]
    echo["api_full_agent"]["prompt_tokens"]["p50"] = long_tokens["p50_median"]
    echo["api_full_agent"]["prompt_tokens"]["p95"] = long_tokens["p95_median"]
    echo["api_full_agent"]["prompt_tokens"]["max"] = max(
        float(echo["api_full_agent"]["prompt_tokens"]["max"]),
        float(long_tokens["p95_median"]),
    )
    short_tokens = aggregate["short_prompt_tokens"]
    echo["api_short_agent"]["prompt_tokens"]["p50"] = short_tokens["p50_median"]
    echo["api_short_agent"]["prompt_tokens"]["p95"] = short_tokens["p95_median"]
    echo["api_short_agent"]["prompt_tokens"]["max"] = max(
        float(echo["api_short_agent"]["prompt_tokens"]["max"]),
        float(short_tokens["p95_median"]),
    )
    result["token_comparison"] = _echo_prompt_budget(echo)
    result["journal_append_probe"]["latency"]["p95_ms"] = aggregate["journal_append_p95_max_ms"]
    result["journal_append_probe"]["latency"]["max_ms"] = max(
        float(result["journal_append_probe"]["latency"]["max_ms"]),
        float(aggregate["journal_append_p95_max_ms"]),
    )
    result["recovery_probes"].update(
        {
            "journal_replay_10k_record_count": aggregate["replay_10k_record_count_min"],
            "journal_replay_10k_records_s": aggregate["replay_10k_max_seconds"],
            "bad_tail_recovery_ok": aggregate["bad_tail_all_ok"],
            "compaction_latency_ms": aggregate["compaction_max_ms"],
            "compaction_ok": aggregate["compaction_all_ok"],
        }
    )
    if baseline is not None:
        if baseline_path is None:
            raise ValueError("baseline_path is required with baseline evidence")
        _attach_baseline_comparison(result, baseline, baseline_path=baseline_path)
    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return result


def run_benchmark(
    *,
    iterations: int,
    warmup: int,
    output: Path | None,
    baseline: dict[str, Any] | None = None,
    baseline_path: Path | None = None,
) -> dict[str, Any]:
    with _isolated_benchmark_environment(MODES[0]):
        return _run_benchmark_unisolated(
            iterations=iterations,
            warmup=warmup,
            output=output,
            baseline=baseline,
            baseline_path=baseline_path,
        )


def _run_benchmark_unisolated(
    *,
    iterations: int,
    warmup: int,
    output: Path | None,
    baseline: dict[str, Any] | None,
    baseline_path: Path | None,
) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="echo-architecture-benchmark-") as tmp:
        base = Path(tmp)
        repo_root = Path(__file__).resolve().parents[1]
        frozen_source_digest = release_source_digest(repo_root)
        result: dict[str, Any] = {
            "source_digest": frozen_source_digest,
            "metadata": {
                "iterations": iterations,
                "warmup": warmup,
                "source_digest": frozen_source_digest,
                "slo_contract": SLO_CONTRACT.as_dict(),
                "benchmark_script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                "tokenizer_tree_digest_version": _TOKENIZER_TREE_DIGEST_VERSION.decode(
                    "ascii"
                ).rstrip("\0"),
                "tokenizer_resource_sha256": tokenizer_resource_digest(repo_root),
                "base_dir": str(base),
                "modes": [asdict(mode) for mode in MODES],
                "note": (
                    "Deterministic local benchmark; fake provider, no network LLM calls. "
                    "Numbers measure FastAPI/TestClient architecture overhead plus a "
                    "deterministic prompt-size latency proxy. Prompt counts use the local "
                    "cl100k_base tokenizer and are not provider billing data."
                ),
            },
            "modes": {},
            "comparisons": {},
            "token_comparison": {},
            "security_matrix": {},
            "recovery_probes": {},
            "concurrency_probe": {},
            "journal_append_probe": {},
        }
        for mode in MODES:
            result["modes"][mode.name] = {
                "api_full_agent": _run_api_full_agent(base, mode, iterations, warmup),
                "api_short_agent": _run_api_short_agent(base, mode, iterations, warmup),
                "api_wrapper_only": _run_api_wrapper(base, mode, iterations, warmup),
                "ws_message_wrapper": _run_ws_message_wrapper(base, mode, iterations, warmup),
                "ws_stream_wrapper": _run_ws_stream_wrapper(base, mode, iterations, warmup),
                "ws_stream_timing": _run_ws_stream_timing_probe(
                    base,
                    mode,
                    iterations,
                    warmup,
                ),
                "secret_block": _run_secret_block(base, mode),
                "status_probe": _run_status_probe(base, mode),
            }
        result["token_comparison"] = _echo_prompt_budget(result["modes"]["echo"])
        result["concurrency_probe"] = _run_concurrency_probe(
            base,
            MODES[0],
            workers=CONCURRENCY_WORKERS,
            rounds=CONCURRENCY_ROUNDS,
        )
        matrix = run_security_matrix()
        result["security_matrix"] = {
            "ok": matrix.ok,
            "passed": matrix.passed,
            "total": matrix.total,
            "failed": list(matrix.failed),
        }
        result["recovery_probes"] = _run_recovery_probes(base)
        result["journal_append_probe"] = _run_journal_append_probe(
            base,
            iterations=iterations,
            warmup=warmup,
        )
        if baseline is not None:
            if baseline_path is None:
                raise ValueError("baseline_path is required with baseline evidence")
            _attach_baseline_comparison(result, baseline, baseline_path=baseline_path)
        if output is not None:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        return result


def _print_table(result: dict[str, Any]) -> None:
    print(json.dumps(result["metadata"], ensure_ascii=False, indent=2))
    print(f"\nPrompt-token budget: {result.get('token_comparison', {})}")
    print("\nMode details:")
    for mode_name, mode_data in result["modes"].items():
        print(f"\n[{mode_name}]")
        for scenario in (
            "api_full_agent",
            "api_wrapper_only",
            "ws_message_wrapper",
            "ws_stream_wrapper",
        ):
            data = mode_data[scenario]
            print(
                f"  {scenario}: failures={len(data['failures'])}, "
                f"mean={data['latency']['mean_ms']}ms, "
                f"p50={data['latency']['p50_ms']}ms, p95={data['latency']['p95_ms']}ms, "
                f"journal_records_measured={data['journal_records_measured']}"
            )
            if scenario == "api_full_agent":
                print(f"    prompt_tokens={data.get('prompt_tokens')}")
        print(f"  secret_block: {mode_data['secret_block']}")
        print(f"  status_echo: {mode_data['status_probe'].get('echo')}")
    print(f"\nSecurity matrix: {result['security_matrix']}")


def _evaluate_baseline_comparison(comparison: object) -> list[str]:
    """Validate honest latency and long/short token deltas against the old baseline."""

    failures: list[str] = []
    if not isinstance(comparison, dict) or comparison.get("valid") is not True:
        return ["baseline: missing detached-worktree comparison"]

    def number(mapping: object, key: str) -> float | None:
        if not isinstance(mapping, dict):
            return None
        value = mapping.get(key)
        if isinstance(value, bool) or not isinstance(value, int | float):
            return None
        return float(value)

    latency = comparison.get("api_full_agent")
    old_latency = number(latency, "old_p95_ms")
    echo_latency = number(latency, "echo_p95_ms")
    claimed_latency_delta = number(latency, "p95_delta_pct")
    if (
        old_latency is None
        or old_latency <= 0
        or echo_latency is None
        or claimed_latency_delta is None
    ):
        failures.append("baseline: invalid full-request latency comparison")
    else:
        calculated = (echo_latency - old_latency) / old_latency * 100.0
        if echo_latency > old_latency or abs(claimed_latency_delta - calculated) > 0.01:
            failures.append("baseline: full-request p95 regressed or claim is inconsistent")

    long_tokens = comparison.get("prompt_tokens")
    short_tokens = comparison.get("short_prompt_tokens")
    for label, mapping in (("long-context", long_tokens), ("short-context", short_tokens)):
        if (
            not isinstance(mapping, dict)
            or mapping.get("source") != "tokenizer"
            or mapping.get("method") != TOKENIZER_METHOD
        ):
            failures.append(f"baseline: invalid {label} token source")

    for percentile, claim_key in (("p50", "p50_reduction_pct"), ("p95", "reduction_pct")):
        old_value = number(long_tokens, f"old_{percentile}")
        echo_value = number(long_tokens, f"echo_{percentile}")
        claimed = number(long_tokens, claim_key)
        if old_value is None or old_value <= 0 or echo_value is None or claimed is None:
            failures.append(f"baseline: invalid long-context {percentile} token comparison")
            continue
        reduction = (old_value - echo_value) / old_value * 100.0
        if abs(claimed - reduction) > 0.01:
            failures.append(f"baseline: inconsistent long-context {percentile} token claim")
        if reduction < SLO_CONTRACT.long_context_min_reduction_pct:
            failures.append(
                f"baseline: long-context {percentile} token reduction {reduction:.3f}% "
                f"is below {SLO_CONTRACT.long_context_min_reduction_pct:.3f}%"
            )

    for percentile, claim_key in (
        ("p50", "p50_increase_pct"),
        ("p95", "p95_increase_pct"),
    ):
        old_value = number(short_tokens, f"old_{percentile}")
        echo_value = number(short_tokens, f"echo_{percentile}")
        claimed = number(short_tokens, claim_key)
        if old_value is None or old_value <= 0 or echo_value is None or claimed is None:
            failures.append(f"baseline: invalid short-context {percentile} token comparison")
            continue
        increase = (echo_value - old_value) / old_value * 100.0
        if abs(claimed - increase) > 0.01:
            failures.append(f"baseline: inconsistent short-context {percentile} token claim")
        if increase > SLO_CONTRACT.short_context_max_increase_pct:
            failures.append(
                f"baseline: short-context {percentile} token increase {increase:.3f}% "
                f"exceeds {SLO_CONTRACT.short_context_max_increase_pct:.3f}%"
            )
    return failures


def _finite_float(value: object) -> float | None:
    if isinstance(value, int | float) and not isinstance(value, bool):
        parsed = float(value)
        if math.isfinite(parsed):
            return parsed
    return None


def _evaluate_ws_stream_timing(
    timing: object,
    *,
    label: str,
    first_text_p95: object | None = None,
    terminal_p95: object | None = None,
) -> list[str]:
    failures: list[str] = []
    if not isinstance(timing, dict):
        return [f"{label}: missing websocket stream timing receipt"]

    first_summary = timing.get("first_text_token_latency")
    terminal_summary = timing.get("terminal_latency")
    if first_text_p95 is None and isinstance(first_summary, dict):
        first_text_p95 = first_summary.get("p95_ms")
    if terminal_p95 is None and isinstance(terminal_summary, dict):
        terminal_p95 = terminal_summary.get("p95_ms")
    first_text_value = _finite_float(first_text_p95)
    terminal_value = _finite_float(terminal_p95)
    if first_text_value is None:
        failures.append(f"{label}: missing first text token p95")
    elif first_text_value > SLO_CONTRACT.ws_first_token_p95_ms:
        failures.append(
            f"{label}: first text token p95 {first_text_value:.3f}ms exceeds "
            f"{SLO_CONTRACT.ws_first_token_p95_ms:.3f}ms"
        )
    if terminal_value is None:
        failures.append(f"{label}: missing terminal p95")
    elif terminal_value > SLO_CONTRACT.ws_terminal_p95_ms:
        failures.append(
            f"{label}: terminal p95 {terminal_value:.3f}ms exceeds "
            f"{SLO_CONTRACT.ws_terminal_p95_ms:.3f}ms"
        )

    if timing.get("configured_cadence_ms") != {
        "first_text_token": WS_STREAM_FIRST_TEXT_DELAY_MS,
        "inter_text_token": WS_STREAM_INTER_TEXT_DELAY_MS,
    }:
        failures.append(f"{label}: websocket stream cadence mismatch")
    if (
        timing.get("evidence_schema_version") != "echo-ws-stream-timing-v1"
        or timing.get("clock") != "time.perf_counter_ns"
        or timing.get("first_text_token_semantics")
        != "first non-empty websocket token frame after send"
    ):
        failures.append(f"{label}: websocket stream timing schema mismatch")

    sample_count = first_summary.get("n") if isinstance(first_summary, dict) else None
    terminal_count = terminal_summary.get("n") if isinstance(terminal_summary, dict) else None
    receipts = timing.get("timing_receipts")
    if (
        not isinstance(sample_count, int)
        or isinstance(sample_count, bool)
        or sample_count <= 0
        or terminal_count != sample_count
        or not isinstance(receipts, list)
        or len(receipts) != sample_count
    ):
        failures.append(f"{label}: websocket stream timing sample mismatch")
        receipts = []
        sample_count = 0

    for receipt in receipts:
        if not isinstance(receipt, dict):
            failures.append(f"{label}: malformed websocket stream timing receipt")
            continue
        send_ns = receipt.get("send_monotonic_ns")
        offsets = receipt.get("frame_offsets_ms")
        if (
            not isinstance(send_ns, int)
            or isinstance(send_ns, bool)
            or send_ns <= 0
            or not isinstance(offsets, dict)
        ):
            failures.append(f"{label}: malformed websocket stream timing receipt")
            continue
        ordered_offsets = [
            offsets.get(name)
            for name in ("status", "thinking", "first_text_token", "usage", "terminal")
        ]
        numeric_offsets = [
            value
            for value in (_finite_float(item) for item in ordered_offsets)
            if value is not None
        ]
        if (
            len(numeric_offsets) != len(ordered_offsets)
            or not all(value >= 0 for value in numeric_offsets)
            or any(
                numeric_offsets[index] > numeric_offsets[index + 1]
                for index in range(len(numeric_offsets) - 1)
            )
            or receipt.get("clock") != "time.perf_counter_ns"
            or receipt.get("frame_types") != list(WS_STREAM_EXPECTED_FRAME_TYPES)
            or receipt.get("terminal_count") != 1
            or receipt.get("terminal_type") != "done"
        ):
            failures.append(f"{label}: malformed websocket stream timing receipt")

    if (
        timing.get("provider_stream_event_calls") != sample_count
        or timing.get("provider_stream_completed") != sample_count
        or timing.get("provider_stream_cancelled") != 0
        or timing.get("failures") != []
    ):
        failures.append(f"{label}: provider stream timing execution mismatch")
    resilience = timing.get("resilience")
    if (
        not isinstance(resilience, dict)
        or resilience.get("single_terminal_all_ok") is not True
        or not isinstance(resilience.get("slow_consumer"), dict)
        or resilience["slow_consumer"].get("ok") is not True
        or not isinstance(resilience.get("disconnect"), dict)
        or resilience["disconnect"].get("ok") is not True
    ):
        failures.append(f"{label}: websocket stream resilience evidence failed")
    return failures


def _evaluate_compaction_semantics(recovery: object, *, label: str) -> list[str]:
    prefix = f"{label}: compaction semantic"
    if not isinstance(recovery, dict):
        return [f"{prefix} receipt missing"]
    if recovery.get("compaction_record_count") != COMPACTION_ACTIVE_RECORD_COUNT:
        return [f"{prefix} active record count mismatch"]
    receipt = recovery.get("compaction_semantics")
    if not isinstance(receipt, dict):
        return [f"{prefix} receipt missing"]
    receipt_sha256 = receipt.get("receipt_sha256")
    if (
        not isinstance(receipt_sha256, str)
        or receipt_sha256 != _compaction_receipt_sha256(receipt)
        or recovery.get("compaction_semantic_receipt_sha256") != receipt_sha256
    ):
        failures = [f"{prefix} receipt digest mismatch"]
    else:
        failures = []

    expected_entries = [_compaction_semantics(entry) for entry in _compaction_fixture_entries()]
    expected_sampled = [expected_entries[index] for index in COMPACTION_SAMPLE_INDICES]
    expected_tail = expected_entries[-COMPACTION_RETAIN_RECORDS:]
    expected_values = {
        "schema_version": COMPACTION_RECEIPT_VERSION,
        "semantic_verification_outside_timed_interval": True,
        "expected_logical_record_count": COMPACTION_LOGICAL_RECORD_COUNT,
        "logical_record_count": COMPACTION_LOGICAL_RECORD_COUNT,
        "expected_active_record_count": COMPACTION_ACTIVE_RECORD_COUNT,
        "active_record_count": COMPACTION_ACTIVE_RECORD_COUNT,
        "active_record_types": ["snapshot_anchor"] + ["decision"] * COMPACTION_RETAIN_RECORDS,
        "expected_retained_record_count": COMPACTION_RETAIN_RECORDS,
        "retained_record_count": COMPACTION_RETAIN_RECORDS,
        "archive_chain_verified": True,
        "archive_chain_errors": [],
        "archive_generation_count": 1,
        "archive_generation": 1,
        "archive_cumulative_record_count": COMPACTION_LOGICAL_RECORD_COUNT,
        "archive_cumulative_tombstone_count": 1,
        "tombstones": [COMPACTION_EFFECT_ID],
        "tombstone_sha256": _canonical_sha256([COMPACTION_EFFECT_ID]),
        "archived_effect_lookup_ok": True,
        "expected_logical_payload_sha256": _canonical_sha256(expected_entries),
        "logical_payload_sha256": _canonical_sha256(expected_entries),
        "logical_payload_equivalent": True,
        "sample_indices": list(COMPACTION_SAMPLE_INDICES),
        "expected_sampled_payload_sha256": _canonical_sha256(expected_sampled),
        "sampled_payload_sha256": _canonical_sha256(expected_sampled),
        "sampled_payload_equivalent": True,
        "expected_active_payload_sha256": _canonical_sha256(expected_tail),
        "active_payload_sha256": _canonical_sha256(expected_tail),
        "active_payload_equivalent": True,
        "post_compaction_bad_tail_recovery_ok": True,
        "corrupt_tail_quarantine_count": 1,
        "ok": True,
    }
    if any(receipt.get(key) != value for key, value in expected_values.items()):
        failures.append(f"{prefix} receipt fields mismatch")
    for field_name in (
        "archive_ref_sha256",
        "active_journal_sha256",
        "archive_sha256",
    ):
        value = receipt.get(field_name)
        if (
            not isinstance(value, str)
            or len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)
        ):
            failures.append(f"{prefix} receipt file binding mismatch")
            break
    return failures


def evaluate_slo_failures(result: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    metadata = result.get("metadata")
    if not isinstance(metadata, dict):
        failures.append("benchmark: missing metadata")
    else:
        if metadata.get("slo_contract") != SLO_CONTRACT.as_dict():
            failures.append("benchmark: SLO contract mismatch")
        if metadata.get("runs") != SLO_CONTRACT.benchmark_groups:
            failures.append(
                f"benchmark: expected {SLO_CONTRACT.benchmark_groups} independent groups"
            )
        if metadata.get("iterations") != SLO_CONTRACT.benchmark_measured:
            failures.append(
                f"benchmark: expected {SLO_CONTRACT.benchmark_measured} measured requests per group"
            )
        if metadata.get("warmup") != SLO_CONTRACT.benchmark_warmup:
            failures.append(
                f"benchmark: expected {SLO_CONTRACT.benchmark_warmup} warmup requests per group"
            )
        expected_tok = tokenizer_resource_digest(Path(__file__).resolve().parents[1])
        if metadata.get("tokenizer_tree_digest_version") != _TOKENIZER_TREE_DIGEST_VERSION.decode(
            "ascii"
        ).rstrip("\0"):
            failures.append("benchmark: tokenizer tree digest version mismatch")
        if metadata.get("tokenizer_resource_sha256") != expected_tok:
            failures.append("benchmark: tokenizer resource digest mismatch")
    run_summaries = result.get("run_summaries")
    if not isinstance(run_summaries, list) or len(run_summaries) != SLO_CONTRACT.benchmark_groups:
        failures.append(f"benchmark: missing {SLO_CONTRACT.benchmark_groups} per-group receipts")
        run_summaries = []
    aggregate = result.get("aggregate")
    aggregate_latency = (
        aggregate.get("latency_p95_median_ms") if isinstance(aggregate, dict) else None
    )
    if (
        not isinstance(aggregate, dict)
        or aggregate.get("group_count") != SLO_CONTRACT.benchmark_groups
    ):
        failures.append("benchmark: invalid cross-group aggregate")
    if not isinstance(aggregate_latency, dict):
        aggregate_latency = {}
    echo_mode = result.get("modes", {}).get("echo", {})
    for scenario, thresholds in SLO_THRESHOLDS.items():
        latency = echo_mode.get(scenario, {}).get("latency", {})
        sample_count = latency.get("n")
        if not isinstance(sample_count, int) or isinstance(sample_count, bool) or sample_count <= 0:
            failures.append(f"{scenario}: missing latency samples")
            continue
        p95_value = aggregate_latency.get(scenario, latency.get("p95_ms"))
        if isinstance(p95_value, bool) or not isinstance(p95_value, int | float):
            failures.append(f"{scenario}: missing p95 latency")
            continue
        p95_ms = float(p95_value)
        max_p95 = thresholds["p95_ms"]
        if p95_ms > max_p95:
            failures.append(f"{scenario}: echo p95 {p95_ms:.3f}ms exceeds {max_p95:.3f}ms")
    aggregate_first_text = (
        aggregate.get("ws_first_token_p95_median_ms") if isinstance(aggregate, dict) else None
    )
    aggregate_terminal = (
        aggregate.get("ws_terminal_p95_median_ms") if isinstance(aggregate, dict) else None
    )
    failures.extend(
        _evaluate_ws_stream_timing(
            echo_mode.get("ws_stream_timing"),
            label="ws_stream_timing",
            first_text_p95=aggregate_first_text,
            terminal_p95=aggregate_terminal,
        )
    )
    token_comparison = result.get("token_comparison", {})
    token_source = token_comparison.get("token_source")
    if token_source not in {"provider_actual", "tokenizer"}:
        failures.append("token evidence: missing or invalid token source")
    prompt_value = token_comparison.get("api_full_agent_prompt_p95_echo")
    limit_value = token_comparison.get("api_full_agent_prompt_p95_limit")
    if (
        isinstance(prompt_value, bool)
        or not isinstance(prompt_value, int | float)
        or isinstance(limit_value, bool)
        or not isinstance(limit_value, int | float)
    ):
        failures.append("api_full_agent: missing prompt token evidence")
    else:
        prompt_p95 = float(prompt_value)
        prompt_limit = float(limit_value)
        within_limit = prompt_p95 <= prompt_limit
        if token_comparison.get("api_full_agent_prompt_within_limit") is not within_limit:
            failures.append("api_full_agent: prompt token result is internally inconsistent")
        if not within_limit:
            failures.append(
                f"api_full_agent: prompt p95 {prompt_p95:.1f} exceeds {prompt_limit:.1f}"
            )

    def validate_long_short_tokens(
        long_tokens: object,
        short_tokens: object,
        *,
        label: str,
    ) -> None:
        if not isinstance(long_tokens, dict) or not isinstance(short_tokens, dict):
            failures.append(f"{label}: missing long/short prompt token evidence")
            return
        for percentile in ("p50", "p95"):
            long_value = long_tokens.get(percentile)
            short_value = short_tokens.get(percentile)
            if (
                isinstance(long_value, bool)
                or not isinstance(long_value, int | float)
                or isinstance(short_value, bool)
                or not isinstance(short_value, int | float)
                or float(long_value) <= float(short_value)
            ):
                failures.append(
                    f"{label}: long-context prompt tokens must exceed short-context "
                    f"at {percentile} (long={long_value!r}, short={short_value!r})"
                )

    validate_long_short_tokens(
        echo_mode.get("api_full_agent", {}).get("prompt_tokens"),
        echo_mode.get("api_short_agent", {}).get("prompt_tokens"),
        label="benchmark",
    )
    if token_comparison.get("long_context_prompt_exceeds_short") is not True:
        failures.append("benchmark: long/short prompt token result is internally inconsistent")

    def validate_payload_gate(validation: object, *, label: str) -> None:
        if not isinstance(validation, dict):
            failures.append(f"{label}: missing provider payload validation")
            return
        if validation.get("ok") is not True or validation.get("failures") != []:
            failures.append(f"{label}: provider payload validation failed")

    validate_payload_gate(
        echo_mode.get("api_full_agent", {}).get("provider_payload_validation"),
        label="api_full_agent",
    )
    validate_payload_gate(
        echo_mode.get("api_short_agent", {}).get("provider_payload_validation"),
        label="api_short_agent",
    )
    for scenario in ("api_full_agent", "api_short_agent"):
        scenario_failures = echo_mode.get(scenario, {}).get("failures")
        if isinstance(scenario_failures, list) and scenario_failures:
            failures.append(f"{scenario}: benchmark request failures observed")

    for index, summary in enumerate(run_summaries, start=1):
        if not isinstance(summary, dict):
            continue
        validate_long_short_tokens(
            summary.get("long_prompt_tokens"),
            summary.get("short_prompt_tokens"),
            label=f"benchmark group {index}",
        )
        validate_payload_gate(
            summary.get("long_context_validation"),
            label=f"benchmark group {index} long-context",
        )
        validate_payload_gate(
            summary.get("short_context_validation"),
            label=f"benchmark group {index} short-context",
        )
        failures.extend(
            _evaluate_ws_stream_timing(
                summary.get("ws_stream_timing"),
                label=f"benchmark group {index} ws_stream_timing",
            )
        )

    def validate_concurrency(concurrency: object, *, label: str) -> None:
        if not isinstance(concurrency, dict):
            failures.append(f"{label}: missing evidence")
            return
        if concurrency.get("submitted_concurrency") != CONCURRENCY_WORKERS:
            failures.append(f"{label}: expected 50 submitted requests per round")
        if concurrency.get("rounds") != CONCURRENCY_ROUNDS:
            failures.append(f"{label}: expected 3 rounds")
        if concurrency.get("total_requests") != CONCURRENCY_WORKERS * CONCURRENCY_ROUNDS:
            failures.append(f"{label}: expected 150 total requests")
        if concurrency.get("completed_ok") != CONCURRENCY_WORKERS * CONCURRENCY_ROUNDS:
            failures.append(f"{label}: fewer than 150 requests completed successfully")
        if concurrency.get("http_5xx_count") != 0:
            failures.append(f"{label}: HTTP 5xx responses observed")
        if concurrency.get("crosstalk_count") != 0:
            failures.append(f"{label}: owner/session crosstalk observed")
        runtime_peak = concurrency.get("runtime_peak_inflight")
        if (
            not isinstance(runtime_peak, int)
            or isinstance(runtime_peak, bool)
            or runtime_peak < CONCURRENCY_WORKERS
        ):
            failures.append(
                f"{label}: workload did not reach the required concurrency "
                f"floor of {CONCURRENCY_WORKERS} in the Echo runtime "
                f"(observed runtime_peak_inflight={runtime_peak!r})"
            )
        peak_rss = concurrency.get("peak_rss_mb")
        if isinstance(peak_rss, bool) or not isinstance(peak_rss, int | float):
            failures.append(f"{label}: missing peak RSS evidence")
        elif float(peak_rss) > MAX_CONCURRENCY_RSS_MB:
            failures.append(
                f"{label}: peak RSS {float(peak_rss):.3f}MB exceeds {MAX_CONCURRENCY_RSS_MB:.3f}MB"
            )
        if concurrency.get("isolation_checks") != CONCURRENCY_WORKERS * CONCURRENCY_ROUNDS:
            failures.append(f"{label}: incomplete owner/session isolation checks")
        if concurrency.get("overlap_layer") != "real_gated_provider_calls":
            failures.append(f"{label}: overlap was not measured at real gated provider calls")
        if concurrency.get("execution_model") != "single_process_async_asgi":
            failures.append(f"{label}: missing execution-model disclosure")

    if run_summaries:
        for index, summary in enumerate(run_summaries, start=1):
            if not isinstance(summary, dict) or summary.get("group") != index:
                failures.append(f"benchmark group {index}: malformed receipt")
                continue
            validate_concurrency(summary.get("concurrency"), label=f"concurrency group {index}")
    else:
        validate_concurrency(result.get("concurrency_probe"), label="concurrency")

    journal_max = (
        aggregate.get("journal_append_p95_max_ms") if isinstance(aggregate, dict) else None
    )
    if isinstance(journal_max, bool) or not isinstance(journal_max, int | float):
        failures.append("journal: missing durable append p95 evidence")
    elif float(journal_max) > SLO_CONTRACT.journal_append_p95_ms:
        failures.append(
            f"journal: append p95 {float(journal_max):.3f}ms exceeds "
            f"{SLO_CONTRACT.journal_append_p95_ms:.3f}ms"
        )
    recovery = result.get("recovery_probes", {})
    replay_value = aggregate.get("replay_10k_max_seconds") if isinstance(aggregate, dict) else None
    replay_seconds = float(
        replay_value
        if isinstance(replay_value, int | float) and not isinstance(replay_value, bool)
        else recovery.get("journal_replay_10k_records_s", 999.0) or 999.0
    )
    replay_count_value = (
        aggregate.get("replay_10k_record_count_min") if isinstance(aggregate, dict) else None
    )
    replay_count = int(
        replay_count_value
        if isinstance(replay_count_value, int) and not isinstance(replay_count_value, bool)
        else recovery.get("journal_replay_10k_record_count", 0) or 0
    )
    if replay_count < 10_000:
        failures.append("recovery: journal replay did not cover 10k records")
    if replay_seconds > SLO_CONTRACT.replay_10k_seconds:
        failures.append(
            "recovery: 10k replay "
            f"{replay_seconds:.3f}s exceeds {SLO_CONTRACT.replay_10k_seconds:.3f}s"
        )
    bad_tail_ok = aggregate.get("bad_tail_all_ok") if isinstance(aggregate, dict) else None
    if bad_tail_ok is not True:
        failures.append("recovery: bad-tail recovery probe failed")
    compaction_value = aggregate.get("compaction_max_ms") if isinstance(aggregate, dict) else None
    compaction_ms = float(
        compaction_value
        if isinstance(compaction_value, int | float) and not isinstance(compaction_value, bool)
        else recovery.get("compaction_latency_ms", 999_999.0) or 999_999.0
    )
    compaction_ok = aggregate.get("compaction_all_ok") if isinstance(aggregate, dict) else None
    if compaction_ok is not True:
        failures.append("recovery: compaction probe failed")
    if compaction_ms > SLO_CONTRACT.compaction_ms:
        failures.append(
            "recovery: compaction latency "
            f"{compaction_ms:.3f}ms exceeds {SLO_CONTRACT.compaction_ms:.3f}ms"
        )
    failures.extend(_evaluate_compaction_semantics(recovery, label="recovery"))
    group_compaction_digests: list[str] = []
    for index, summary in enumerate(run_summaries, start=1):
        if not isinstance(summary, dict):
            continue
        group_recovery = summary.get("recovery")
        failures.extend(
            _evaluate_compaction_semantics(
                group_recovery,
                label=f"benchmark group {index} recovery",
            )
        )
        if isinstance(group_recovery, dict):
            digest = group_recovery.get("compaction_semantic_receipt_sha256")
            if isinstance(digest, str):
                group_compaction_digests.append(digest)
    if run_summaries and (
        not isinstance(aggregate, dict)
        or aggregate.get("compaction_semantics_all_ok") is not True
        or aggregate.get("compaction_semantic_receipt_sha256s") != group_compaction_digests
    ):
        failures.append("recovery: compaction semantic aggregate mismatch")
    failures.extend(_evaluate_baseline_comparison(result.get("baseline_comparison")))
    return failures


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=SLO_CONTRACT.benchmark_measured)
    parser.add_argument("--warmup", type=int, default=SLO_CONTRACT.benchmark_warmup)
    parser.add_argument("--runs", type=int, default=SLO_CONTRACT.benchmark_groups)
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument(
        "--baseline",
        type=Path,
        default=None,
        help="JSON evidence produced from the detached pre-Echo baseline worktree.",
    )
    parser.add_argument(
        "--enforce-slo",
        action="store_true",
        help="Fail if Echo latency exceeds deterministic local SLO thresholds.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    baseline = None
    if args.baseline is not None:
        raw_baseline = json.loads(args.baseline.read_text(encoding="utf-8"))
        if not isinstance(raw_baseline, dict):
            raise ValueError("baseline JSON must be an object")
        baseline = _normalize_baseline_payload(raw_baseline)
    result = run_benchmark_suite(
        iterations=args.iterations,
        warmup=args.warmup,
        runs=args.runs,
        output=args.output,
        baseline=baseline,
        baseline_path=args.baseline,
    )
    _print_table(result)
    failures: list[str] = []
    for mode_name, mode_data in result["modes"].items():
        for scenario, data in mode_data.items():
            if isinstance(data, dict) and data.get("failures"):
                failures.append(f"{mode_name}/{scenario}: {data['failures'][:3]}")
    if not result["security_matrix"]["ok"]:
        failures.append(f"security_matrix: {result['security_matrix']['failed']}")
    if not result["modes"]["echo"]["secret_block"].get("blocked_before_model"):
        failures.append(f"echo/secret_block: {result['modes']['echo']['secret_block']}")
    if args.enforce_slo:
        failures.extend(evaluate_slo_failures(result))
    if failures:
        print("\nFAILURES:")
        for failure in failures:
            print(f"- {failure}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
