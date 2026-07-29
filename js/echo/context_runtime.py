"""Echo T8-S3B — real prompt context runtime.

This module is the narrow adapter between the agent prompt path and Echo's
context-savings primitives. It intentionally does not import
``js.agent`` / ``js.web`` / provider classes. Callers pass plain message-like
objects and JSON-ish tool schemas; this module serializes them into
``ContextEntry`` values and records process-local CAS metrics.

The measurement is best-effort. Any serializer, tokenizer, or CAS failure is
reported in the returned observation and must never affect the caller's model
request.
"""

from __future__ import annotations

import json
import threading
import weakref
from collections import OrderedDict
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, field
from typing import Any

from js.echo.context_savings import (
    ContentAddressableStore,
    ContextBudget,
    ContextEntry,
    summarize_context,
)
from js.echo.context_tokenizer import HEURISTIC_TOKEN_UNIT_ID, TokenCounter, heuristic_counter

__all__ = [
    "ContextRuntimeObservation",
    "ContextRuntimeSnapshot",
    "get_context_runtime_snapshot_for_tests",
    "observe_prompt_context",
    "reset_context_runtime_for_tests",
]


_DEFAULT_BUDGET = ContextBudget(max_tokens=10**9)
_MAX_SCOPES = 256
_MAX_OWNER_SCOPES = 32
_MAX_HARD_SCOPES = 512
_MAX_HARD_OWNER_SCOPES = 128
_MAX_SCOPE_PAYLOAD_BYTES = 2 * 1024 * 1024
_MAX_SCOPE_RECORDS = 256
_MAX_OWNER_RETAINED_PAYLOAD_BYTES = 16 * 1024 * 1024
_MAX_RETAINED_PAYLOAD_BYTES = 128 * 1024 * 1024


@dataclass(frozen=True)
class ContextRuntimeObservation:
    mode: str
    product_id: str
    channel: str
    session_id: str
    owner_key_hash: str | None
    run_id: str
    turn: int
    model: str | None
    scope_key: str
    naive_tokens: int
    saved_tokens: int
    new_cas_tokens: int
    unsent_prompt_tokens: int
    total_entries: int
    unique_entries: int
    newly_stored_entries: int
    savings_ratio: float
    cross_turn_unsent_ratio: float
    within_budget: bool
    store_size: int
    retained_payload_bytes: int
    record_eviction_count: int
    record_evicted_payload_bytes: int
    retention_rejection_count: int
    rejected_payload_bytes: int
    token_unit_id: str
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ContextRuntimeSnapshot:
    observation_count: int
    failure_count: int
    scope_count: int
    retained_payload_bytes: int
    eviction_count: int
    scope_eviction_count: int
    record_eviction_count: int
    evicted_payload_bytes: int
    retention_rejection_count: int
    rejected_payload_bytes: int
    last_observation: ContextRuntimeObservation | None


@dataclass
class _ScopeState:
    scope_key: str
    owner_key: str
    store: ContentAddressableStore = field(init=False)
    active_observers: int = 0
    retained_payload_bytes: int = 0


class _ContextRuntime:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._scopes: OrderedDict[str, _ScopeState] = OrderedDict()
        self._owner_retained_payload_bytes: dict[str, int] = {}
        self._retained_payload_bytes = 0
        self._observation_count = 0
        self._failure_count = 0
        self._eviction_count = 0
        self._scope_eviction_count = 0
        self._record_eviction_count = 0
        self._evicted_payload_bytes = 0
        self._retention_rejection_count = 0
        self._rejected_payload_bytes = 0
        self._last_observation: ContextRuntimeObservation | None = None

    def reset(self) -> None:
        with self._lock:
            self._scopes.clear()
            self._owner_retained_payload_bytes.clear()
            self._retained_payload_bytes = 0
            self._observation_count = 0
            self._failure_count = 0
            self._eviction_count = 0
            self._scope_eviction_count = 0
            self._record_eviction_count = 0
            self._evicted_payload_bytes = 0
            self._retention_rejection_count = 0
            self._rejected_payload_bytes = 0
            self._last_observation = None

    def snapshot(self) -> ContextRuntimeSnapshot:
        with self._lock:
            return ContextRuntimeSnapshot(
                observation_count=self._observation_count,
                failure_count=self._failure_count,
                scope_count=len(self._scopes),
                retained_payload_bytes=self._retained_payload_bytes,
                eviction_count=self._eviction_count,
                scope_eviction_count=self._scope_eviction_count,
                record_eviction_count=self._record_eviction_count,
                evicted_payload_bytes=self._evicted_payload_bytes,
                retention_rejection_count=self._retention_rejection_count,
                rejected_payload_bytes=self._rejected_payload_bytes,
                last_observation=self._last_observation,
            )

    def _new_scope(self, *, scope_key: str, owner_key: str, token_unit_id: str) -> _ScopeState:
        state = _ScopeState(scope_key=scope_key, owner_key=owner_key)
        state_ref = weakref.ref(state)

        def reserve_payload_bytes(payload_bytes: int) -> bool:
            current = state_ref()
            return current is not None and self._reserve_payload_bytes(current, payload_bytes)

        def release_payload_bytes(payload_bytes: int) -> None:
            current = state_ref()
            if current is not None:
                self._record_payload_eviction(current, payload_bytes)

        def reject_payload(payload_bytes: int) -> None:
            current = state_ref()
            if current is not None:
                self._record_payload_rejection(current, payload_bytes)

        state.store = ContentAddressableStore(
            token_unit_id=token_unit_id,
            max_payload_bytes=_MAX_SCOPE_PAYLOAD_BYTES,
            max_records=_MAX_SCOPE_RECORDS,
            reserve_payload_bytes=reserve_payload_bytes,
            release_payload_bytes=release_payload_bytes,
            on_payload_rejected=reject_payload,
        )
        return state

    def _reserve_payload_bytes(self, state: _ScopeState, payload_bytes: int) -> bool:
        with self._lock:
            if self._scopes.get(state.scope_key) is not state:
                return False

            self._enforce_scope_limits_locked()
            self._evict_owner_payload_until_fits_locked(state.owner_key, payload_bytes)
            self._evict_global_payload_until_fits_locked(payload_bytes)

            owner_retained = self._owner_retained_payload_bytes.get(state.owner_key, 0)
            if (
                owner_retained + payload_bytes
                > max(0, _MAX_OWNER_RETAINED_PAYLOAD_BYTES)
                or self._retained_payload_bytes + payload_bytes
                > max(0, _MAX_RETAINED_PAYLOAD_BYTES)
            ):
                return False

            state.retained_payload_bytes += payload_bytes
            self._retained_payload_bytes += payload_bytes
            self._owner_retained_payload_bytes[state.owner_key] = (
                owner_retained + payload_bytes
            )
            return True

    def _record_payload_eviction(self, state: _ScopeState, payload_bytes: int) -> None:
        with self._lock:
            if self._scopes.get(state.scope_key) is not state:
                return
            released = min(payload_bytes, state.retained_payload_bytes)
            state.retained_payload_bytes -= released
            self._retained_payload_bytes -= released
            self._decrement_owner_retained_locked(state.owner_key, released)
            self._eviction_count += 1
            self._record_eviction_count += 1
            self._evicted_payload_bytes += released

    def _record_payload_rejection(self, state: _ScopeState, payload_bytes: int) -> None:
        with self._lock:
            if self._scopes.get(state.scope_key) is not state:
                return
            self._retention_rejection_count += 1
            self._rejected_payload_bytes += payload_bytes

    def _decrement_owner_retained_locked(self, owner_key: str, payload_bytes: int) -> None:
        remaining = self._owner_retained_payload_bytes.get(owner_key, 0) - payload_bytes
        if remaining > 0:
            self._owner_retained_payload_bytes[owner_key] = remaining
        else:
            self._owner_retained_payload_bytes.pop(owner_key, None)

    def _oldest_evictable_scope_key_locked(self, *, owner_key: str | None = None) -> str | None:
        for scope_key, state in self._scopes.items():
            if state.active_observers > 0:
                continue
            if owner_key is not None and state.owner_key != owner_key:
                continue
            return scope_key
        return None

    def _evict_scope_locked(self, scope_key: str) -> None:
        state = self._scopes[scope_key]
        if state.active_observers > 0:
            raise RuntimeError("attempted to evict an active context scope")
        del self._scopes[scope_key]
        retained = state.retained_payload_bytes
        self._retained_payload_bytes -= retained
        self._decrement_owner_retained_locked(state.owner_key, retained)
        self._eviction_count += 1
        self._scope_eviction_count += 1
        self._evicted_payload_bytes += retained

    def _evict_owner_payload_until_fits_locked(
        self,
        owner_key: str,
        incoming_payload_bytes: int,
    ) -> None:
        limit = max(0, _MAX_OWNER_RETAINED_PAYLOAD_BYTES)
        while (
            self._owner_retained_payload_bytes.get(owner_key, 0) + incoming_payload_bytes
            > limit
        ):
            candidate = self._oldest_evictable_scope_key_locked(owner_key=owner_key)
            if candidate is None:
                return
            self._evict_scope_locked(candidate)

    def _evict_global_payload_until_fits_locked(self, incoming_payload_bytes: int) -> None:
        limit = max(0, _MAX_RETAINED_PAYLOAD_BYTES)
        while self._retained_payload_bytes + incoming_payload_bytes > limit:
            candidate = self._oldest_evictable_scope_key_locked()
            if candidate is None:
                return
            self._evict_scope_locked(candidate)

    def _owner_scope_count_locked(self, owner_key: str) -> int:
        return sum(1 for state in self._scopes.values() if state.owner_key == owner_key)

    def _enforce_scope_limits_locked(self) -> None:
        owner_limit = max(0, _MAX_OWNER_SCOPES)
        owner_keys = tuple(dict.fromkeys(state.owner_key for state in self._scopes.values()))
        for owner_key in owner_keys:
            while self._owner_scope_count_locked(owner_key) > owner_limit:
                candidate = self._oldest_evictable_scope_key_locked(owner_key=owner_key)
                if candidate is None:
                    break
                self._evict_scope_locked(candidate)

        scope_limit = max(0, _MAX_SCOPES)
        while len(self._scopes) > scope_limit:
            candidate = self._oldest_evictable_scope_key_locked()
            if candidate is None:
                break
            self._evict_scope_locked(candidate)

    def observe(
        self,
        *,
        mode: str,
        product_id: str,
        channel: str,
        session_id: str,
        owner_key_hash: str | None,
        run_id: str,
        turn: int,
        model: str | None,
        messages: Sequence[Any],
        tools_schema: Sequence[Mapping[str, Any]] | None,
        token_counter: TokenCounter | None,
        budget: ContextBudget,
    ) -> ContextRuntimeObservation:
        unit = token_counter.token_unit_id if token_counter is not None else HEURISTIC_TOKEN_UNIT_ID
        owner_key = _owner_key(product_id=product_id, owner_key_hash=owner_key_hash)
        scope_key = _scope_key(
            product_id=product_id,
            owner_key_hash=owner_key_hash,
            session_id=session_id,
            token_unit_id=unit,
        )
        with self._lock:
            scope = self._scopes.get(scope_key)
            capacity_fallback = False
            if scope is None:
                self._enforce_scope_limits_locked()
                scope = self._new_scope(
                    scope_key=scope_key,
                    owner_key=owner_key,
                    token_unit_id=unit,
                )
                if (
                    len(self._scopes) >= max(0, _MAX_HARD_SCOPES)
                    or self._owner_scope_count_locked(owner_key)
                    >= max(0, _MAX_HARD_OWNER_SCOPES)
                ):
                    capacity_fallback = True
                else:
                    self._scopes[scope_key] = scope
            else:
                self._scopes.move_to_end(scope_key)
            scope.active_observers += 1
            self._enforce_scope_limits_locked()

        failed = capacity_fallback
        try:
            entries = _build_context_entries(messages=messages, tools_schema=tools_schema)
            result = summarize_context(
                entries,
                budget,
                store=scope.store,
                token_counter=token_counter,
            )
            unsent = result.saved_tokens - result.new_cas_tokens
            cross_turn_ratio = unsent / result.naive_tokens if result.naive_tokens else 0.0
            store_metrics = scope.store.metrics()
            observation = ContextRuntimeObservation(
                mode=mode,
                product_id=product_id,
                channel=channel,
                session_id=session_id,
                owner_key_hash=owner_key_hash,
                run_id=run_id,
                turn=turn,
                model=model,
                scope_key=scope_key,
                naive_tokens=result.naive_tokens,
                saved_tokens=result.saved_tokens,
                new_cas_tokens=result.new_cas_tokens,
                unsent_prompt_tokens=unsent,
                total_entries=result.total_entries,
                unique_entries=result.unique_entries,
                newly_stored_entries=result.newly_stored_entries,
                savings_ratio=result.savings_ratio,
                cross_turn_unsent_ratio=cross_turn_ratio,
                within_budget=result.within_budget,
                store_size=store_metrics.record_count,
                retained_payload_bytes=store_metrics.retained_payload_bytes,
                record_eviction_count=store_metrics.eviction_count,
                record_evicted_payload_bytes=store_metrics.evicted_payload_bytes,
                retention_rejection_count=store_metrics.rejection_count,
                rejected_payload_bytes=store_metrics.rejected_payload_bytes,
                token_unit_id=unit,
                error=(
                    "ContextCapacityFallback: scope metrics were not retained"
                    if capacity_fallback
                    else None
                ),
            )
        except Exception as exc:  # noqa: BLE001 - context metrics are non-critical
            failed = True
            store_metrics = scope.store.metrics()
            observation = ContextRuntimeObservation(
                mode=mode,
                product_id=product_id,
                channel=channel,
                session_id=session_id,
                owner_key_hash=owner_key_hash,
                run_id=run_id,
                turn=turn,
                model=model,
                scope_key=scope_key,
                naive_tokens=0,
                saved_tokens=0,
                new_cas_tokens=0,
                unsent_prompt_tokens=0,
                total_entries=0,
                unique_entries=0,
                newly_stored_entries=0,
                savings_ratio=0.0,
                cross_turn_unsent_ratio=0.0,
                within_budget=True,
                store_size=store_metrics.record_count,
                retained_payload_bytes=store_metrics.retained_payload_bytes,
                record_eviction_count=store_metrics.eviction_count,
                record_evicted_payload_bytes=store_metrics.evicted_payload_bytes,
                retention_rejection_count=store_metrics.rejection_count,
                rejected_payload_bytes=store_metrics.rejected_payload_bytes,
                token_unit_id=unit,
                error=f"{type(exc).__name__}: {exc}",
            )

        with self._lock:
            if failed:
                self._failure_count += 1
            self._observation_count += 1
            self._last_observation = observation
            if self._scopes.get(scope_key) is scope:
                scope.active_observers -= 1
            self._enforce_scope_limits_locked()
        return observation


_runtime = _ContextRuntime()


def observe_prompt_context(
    *,
    product_id: str = "js-agent",
    channel: str,
    session_id: str,
    owner_key_hash: str | None,
    run_id: str,
    turn: int,
    model: str | None,
    messages: Sequence[Any],
    tools_schema: Sequence[Mapping[str, Any]] | None,
    token_counter: TokenCounter | None = None,
    budget: ContextBudget = _DEFAULT_BUDGET,
) -> ContextRuntimeObservation | None:
    """Measure the real model-bound prompt in Echo primary mode."""
    mode = "on"
    return _runtime.observe(
        mode=mode,
        product_id=product_id,
        channel=channel,
        session_id=session_id,
        owner_key_hash=owner_key_hash,
        run_id=run_id,
        turn=turn,
        model=model,
        messages=messages,
        tools_schema=tools_schema,
        token_counter=token_counter or heuristic_counter,
        budget=budget,
    )


def get_context_runtime_snapshot_for_tests() -> ContextRuntimeSnapshot:
    return _runtime.snapshot()


def reset_context_runtime_for_tests() -> None:
    _runtime.reset()


def _owner_key(*, product_id: str, owner_key_hash: str | None) -> str:
    return f"{product_id or 'js-agent'}:{owner_key_hash or 'anon'}"


def _scope_key(
    *,
    product_id: str,
    owner_key_hash: str | None,
    session_id: str,
    token_unit_id: str,
) -> str:
    owner = _owner_key(product_id=product_id, owner_key_hash=owner_key_hash)
    return f"{token_unit_id}:{owner}:{session_id}"


def _build_context_entries(
    *,
    messages: Sequence[Any],
    tools_schema: Sequence[Mapping[str, Any]] | None,
) -> tuple[ContextEntry, ...]:
    entries: list[ContextEntry] = []
    for index, message in enumerate(messages):
        role = _message_value(message, "role") or "unknown"
        content = _message_value(message, "content")
        tool_calls = _message_value(message, "tool_calls")
        tool_call_id = _message_value(message, "tool_call_id")
        name = _message_value(message, "name")
        payload = {
            "index": index,
            "role": role,
            "content": content,
            "tool_calls": tool_calls,
            "tool_call_id": tool_call_id,
            "name": name,
        }
        entries.append(ContextEntry(kind=f"message:{role}", payload=_stable_payload(payload)))
    if tools_schema:
        entries.append(
            ContextEntry(kind="tool_schema", payload=_stable_payload(list(tools_schema)))
        )
    return tuple(entries)


def _message_value(message: Any, key: str) -> Any:
    if isinstance(message, Mapping):
        return message.get(key)
    return getattr(message, key, None)


def _stable_payload(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        default=_json_default,
    ).encode("utf-8")


def _json_default(value: Any) -> Any:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, tuple):
        return list(value)
    if hasattr(value, "__dict__"):
        return vars(value)
    return repr(value)
