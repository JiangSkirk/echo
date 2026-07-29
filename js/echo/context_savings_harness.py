"""Echo T8-S2 — Tool-heavy 20-turn Context Savings Harness.

Builds a deterministic 20-turn tool-heavy conversation fixture and folds it
through :func:`js.echo.context_savings.summarize_context` over a shared
:class:`js.echo.context_savings.ContentAddressableStore`, producing per-turn
metrics and an aggregate. T8-S2 is an **empirical curve**, not a threshold
gate; no PASS criterion in this module or its tests is keyed on any savings
percentage.

Field semantics (read carefully — the names are inherited from T8-S1 and do
NOT mean what they sound like)
-----------------------------------------------------------------------------
* :attr:`TurnMetrics.saved_tokens` — the **in-call** unique-digest token
  total returned by :class:`ContextSavingsResult`. Concretely: after
  same-turn dedup, the sum of ``estimate_tokens(payload)`` for every
  distinct payload-digest in the turn. This is **NOT** "tokens already
  saved" — it is the in-call deduped load.
* :attr:`TurnMetrics.new_cas_tokens` — tokens whose payloads were genuinely
  inserted into the shared CAS during this turn's ``summarize_context``
  call. Drops across turns as the shared store warms up.
* :attr:`TurnMetrics.unsent_prompt_tokens` — counterfactual cross-turn
  saving: for this turn's unique digests, the token mass whose payload was
  **already in the shared store before this call**. This is what could be
  omitted *if* the model supported "reference an old entry by digest". It
  is **NOT** production-realised savings.

Identity (locked by ``test_identity_unsent_equals_in_call_unique_minus_new_cas_tokens``):

    unsent_prompt_tokens(N) ≡ saved_tokens(N) - new_cas_tokens(N)

The harness computes ``unsent_prompt_tokens`` *independently* via a
pre-call ``store.contains(digest)`` snapshot rather than the algebraic
shortcut, so the identity test is a genuine two-source cross-check and
not a tautology.

Constraints
-----------
* Production harness module imports **only** from
  :mod:`js.echo.context_savings` plus stdlib ``hashlib`` /
  ``collections.abc`` / ``dataclasses``. No ``time`` / ``random`` /
  ``os`` / ``pathlib`` / ``socket`` / ``urllib`` / ``asyncio`` /
  ``subprocess`` / ``requests`` / ``httpx`` / ``tiktoken`` /
  ``sentencepiece`` / ``transformers``; no ``js.echo.runtime`` /
  ``gateway`` / ``core`` / ``capability`` / ``sandbox`` / ``amber`` /
  ``amber_tree``; no ``js.config`` or other
  legacy ``js.*`` packages.
* :func:`build_tool_heavy_20_turn_fixture` returns pure-literal bytes
  payloads — deterministic across calls.
* Not re-exported through ``js.echo.__init__.__all__``; same convention
  as :mod:`js.echo.context_savings`.
* Does NOT touch runtime / gateway / pulse hot paths. ``JS_ECHO_ENGINE=on``
  is not required and remains rejected by ``JSSettings``.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass

from js.echo.context_savings import (
    ContentAddressableStore,
    ContextBudget,
    ContextEntry,
    estimate_tokens,
    summarize_context,
)
from js.echo.context_tokenizer import TokenCounter

__all__ = [
    "HarnessAggregate",
    "ToolHeavyFixture",
    "TurnMetrics",
    "build_tool_heavy_20_turn_fixture",
    "run_harness",
]


# ---------------------------------------------------------------------------
# Kind vocabulary (module constants, not a Literal — ContextEntry.kind is str)
# ---------------------------------------------------------------------------
_KIND_SYSTEM = "system"
_KIND_USER = "user"
_KIND_ASSISTANT = "assistant"
_KIND_TOOL_CALL = "tool_call"
_KIND_TOOL_RESULT = "tool_result"


# ---------------------------------------------------------------------------
# Shared payload constants (cross-turn dedup ammunition)
#
# Each constant is a fixed bytes literal. Re-using the same constant across
# turns guarantees identical SHA-256 digest and therefore CAS hits when the
# harness runs with a shared store.
# ---------------------------------------------------------------------------
_SYS_BASE = (
    b"system:base-prompt-v1\n"
    b"You are Titan Agent, a helpful AI assistant.\n"
    b"Follow user instructions precisely. Use tools when needed.\n"
    b"Refuse unsafe requests. Always cite tool results.\n"
    b"This system prompt is constant across all conversation turns.\n"
)

_SYS_TOOLSCHEMA = (
    b"system:tool-schema-v1\n"
    b"available_tools = [\n"
    b'  {"name": "weather", "args": ["city"], "returns": "forecast"},\n'
    b'  {"name": "db_query", "args": ["sql"], "returns": "rows"},\n'
    b'  {"name": "http_get", "args": ["url"], "returns": "body"},\n'
    b'  {"name": "ping", "args": [], "returns": "pong"},\n'
    b'  {"name": "calendar", "args": ["date"], "returns": "events"},\n'
    b"]\n"
    b"# This schema is shared and constant across all turns.\n"
    b"# Keep this prefix loaded throughout the session.\n"
    b"# Tool invocations must match the schema exactly.\n"
    b"# Each tool returns a deterministic, structured payload.\n"
    b"# Padding to make the toolschema payload sufficiently large.\n"
    b"# ----------------------------------------------------------\n"
    b"# Padding-line-2: same content every turn for digest stability.\n"
    b"# Padding-line-3: same content every turn for digest stability.\n"
    b"# Padding-line-4: same content every turn for digest stability.\n"
)

_TOOL_WEATHER_SF = (
    b'tool_result:{"tool":"weather","city":"SF","forecast":"sunny 72F",'
    b'"timestamp":"fixed-T-001","cached":true}\n'
)

_TOOL_DB_QUERY_X = (
    b'tool_result:{"tool":"db_query","sql":"SELECT id,total FROM orders WHERE id=42",'
    b'"rows":[{"id":42,"total":99.50,"status":"paid","items":3}],'
    b'"cached":true,"ts":"fixed-T-002"}\n'
)

_TOOL_HTTP_GET_Y = (
    b'tool_result:{"tool":"http_get","url":"https://example.invalid/api/v1/data",'
    b'"status":200,"body":"<deterministic-html-body>...</deterministic-html-body>",'
    b'"bytes":1024,"cached":true,"ts":"fixed-T-003"}\n'
)

_ASSIST_PLAN_A = (
    b"assistant:plan-A\n"
    b"Step 1: gather context from system prompt.\n"
    b"Step 2: identify which tool to call.\n"
    b"Step 3: call the tool and parse the result.\n"
    b"Step 4: respond to user with structured answer.\n"
)

_USER_FAQ_Q1 = b"user:faq-q1: How do I check the weather for a specific city?\n"


def _entry(kind: str, payload: bytes) -> ContextEntry:
    return ContextEntry(kind=kind, payload=payload)


# ---------------------------------------------------------------------------
# Frozen carriers
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class TurnMetrics:
    """Per-turn measurement.

    See module docstring for the precise meaning of every token field;
    in particular ``saved_tokens`` is the in-call unique-digest load, not
    "already-saved tokens", and ``unsent_prompt_tokens`` is the
    counterfactual cross-turn save (digest seen in the shared store
    before this turn started), not production-realised savings.
    """

    turn_index: int
    naive_tokens: int
    saved_tokens: int
    new_cas_tokens: int
    unsent_prompt_tokens: int
    total_entries: int
    unique_entries: int
    newly_stored_entries: int
    digest_order: tuple[bytes, ...]


@dataclass(frozen=True)
class HarnessAggregate:
    """20-turn aggregate.

    ``saved_in_call_total`` aggregates the in-call unique-digest load (NOT
    "already-saved tokens"); ``unsent_total`` aggregates the counterfactual
    cross-turn save (NOT production-realised savings). The ratios are
    mechanical fractions over ``naive_total`` and are not threshold
    judgments — T8-S2 is an empirical curve.
    """

    turns: tuple[TurnMetrics, ...]
    naive_total: int
    saved_in_call_total: int
    new_cas_total: int
    unsent_total: int
    in_call_dedup_ratio: float
    cross_turn_unsent_ratio: float
    cas_growth_ratio: float
    total_savings_ratio: float
    store_final_size: int


@dataclass(frozen=True)
class ToolHeavyFixture:
    """A deterministic multi-turn conversation fixture for the harness."""

    turns: tuple[tuple[ContextEntry, ...], ...]
    label: str = "tool_heavy_20_turn_v1"


# ---------------------------------------------------------------------------
# Fixture builder
# ---------------------------------------------------------------------------
def build_tool_heavy_20_turn_fixture() -> ToolHeavyFixture:
    """Build a deterministic 20-turn tool-heavy conversation fixture.

    The fixture exercises:

    * 5 ``kind`` values: ``system / user / assistant / tool_call / tool_result``
    * Cross-turn repetition via module-level payload constants
      (``_SYS_BASE`` / ``_SYS_TOOLSCHEMA`` appear in every turn; tool
      results repeat across designated turns)
    * In-call repetition on turns 3, 8, 14, 16 (same payload appears more
      than once inside one turn → ``unique_entries < total_entries``)
    * Net-new payloads on turns 17 and 18 to prevent late-session plateau

    The function is pure: it returns ``ToolHeavyFixture`` literal-by-literal
    on every call; two invocations are equal.
    """
    turns: list[tuple[ContextEntry, ...]] = []

    # Turn 1 — bootstrap + ping self-check
    turns.append(
        (
            _entry(_KIND_SYSTEM, _SYS_BASE),
            _entry(_KIND_SYSTEM, _SYS_TOOLSCHEMA),
            _entry(_KIND_USER, b"user:turn-01:hello, please verify your toolchain works."),
            _entry(_KIND_ASSISTANT, _ASSIST_PLAN_A),
            _entry(_KIND_TOOL_CALL, b'tool_call:{"tool":"ping","args":{}}'),
            _entry(
                _KIND_TOOL_RESULT, b'tool_result:{"tool":"ping","reply":"pong","ts":"fixed-T-ping"}'
            ),
        )
    )

    # Turn 2 — DB query
    turns.append(
        (
            _entry(_KIND_SYSTEM, _SYS_BASE),
            _entry(_KIND_SYSTEM, _SYS_TOOLSCHEMA),
            _entry(_KIND_USER, b"user:turn-02:look up the order with id 42."),
            _entry(
                _KIND_TOOL_CALL,
                b'tool_call:{"tool":"db_query","sql":"SELECT id,total FROM orders WHERE id=42"}',
            ),
            _entry(_KIND_TOOL_RESULT, _TOOL_DB_QUERY_X),
            _entry(_KIND_ASSISTANT, b"assistant:turn-02:order 42 totals 99.50 USD, paid, 3 items."),
        )
    )

    # Turn 3 — weather + in-call repeat
    turns.append(
        (
            _entry(_KIND_SYSTEM, _SYS_BASE),
            _entry(_KIND_SYSTEM, _SYS_TOOLSCHEMA),
            _entry(_KIND_USER, b"user:turn-03:what's the weather in SF? repeat for confirmation."),
            _entry(_KIND_TOOL_CALL, b'tool_call:{"tool":"weather","city":"SF"}'),
            _entry(_KIND_TOOL_RESULT, _TOOL_WEATHER_SF),
            _entry(_KIND_TOOL_RESULT, _TOOL_WEATHER_SF),  # in-call duplicate
            _entry(_KIND_ASSISTANT, b"assistant:turn-03:SF is sunny 72F (confirmed twice)."),
        )
    )

    # Turn 4 — HTTP GET
    turns.append(
        (
            _entry(_KIND_SYSTEM, _SYS_BASE),
            _entry(_KIND_SYSTEM, _SYS_TOOLSCHEMA),
            _entry(_KIND_USER, b"user:turn-04:fetch the API at example.invalid/api/v1/data."),
            _entry(
                _KIND_TOOL_CALL,
                b'tool_call:{"tool":"http_get","url":"https://example.invalid/api/v1/data"}',
            ),
            _entry(_KIND_TOOL_RESULT, _TOOL_HTTP_GET_Y),
            _entry(_KIND_ASSISTANT, b"assistant:turn-04:fetched 1024 bytes from example.invalid."),
        )
    )

    # Turn 5 — FAQ + DB
    turns.append(
        (
            _entry(_KIND_SYSTEM, _SYS_BASE),
            _entry(_KIND_SYSTEM, _SYS_TOOLSCHEMA),
            _entry(_KIND_USER, _USER_FAQ_Q1),  # introduces cross-turn user payload
            _entry(
                _KIND_TOOL_CALL,
                b'tool_call:{"tool":"db_query","sql":"SELECT id,total FROM orders WHERE id=42"}',
            ),
            _entry(_KIND_TOOL_RESULT, _TOOL_DB_QUERY_X),  # cross-turn repeat
            _entry(_KIND_ASSISTANT, b"assistant:turn-05:see previous order data."),
        )
    )

    # Turn 6 — re-use ASSIST_PLAN_A
    turns.append(
        (
            _entry(_KIND_SYSTEM, _SYS_BASE),
            _entry(_KIND_SYSTEM, _SYS_TOOLSCHEMA),
            _entry(_KIND_USER, b"user:turn-06:remind me of your plan."),
            _entry(_KIND_ASSISTANT, _ASSIST_PLAN_A),  # cross-turn repeat
            _entry(_KIND_TOOL_CALL, b'tool_call:{"tool":"ping","args":{}}'),
            _entry(
                _KIND_TOOL_RESULT,
                b'tool_result:{"tool":"ping","reply":"pong","ts":"fixed-T-ping-6"}',
            ),
        )
    )

    # Turn 7 — weather repeat
    turns.append(
        (
            _entry(_KIND_SYSTEM, _SYS_BASE),
            _entry(_KIND_SYSTEM, _SYS_TOOLSCHEMA),
            _entry(_KIND_USER, b"user:turn-07:remind me of SF weather."),
            _entry(_KIND_TOOL_RESULT, _TOOL_WEATHER_SF),
            _entry(_KIND_ASSISTANT, b"assistant:turn-07:still sunny 72F."),
        )
    )

    # Turn 8 — DB triple recall + in-call duplicate
    turns.append(
        (
            _entry(_KIND_SYSTEM, _SYS_BASE),
            _entry(_KIND_SYSTEM, _SYS_TOOLSCHEMA),
            _entry(_KIND_USER, b"user:turn-08:re-confirm order 42, twice."),
            _entry(
                _KIND_TOOL_CALL,
                b'tool_call:{"tool":"db_query","sql":"SELECT id,total FROM orders WHERE id=42"}',
            ),
            _entry(_KIND_TOOL_RESULT, _TOOL_DB_QUERY_X),
            _entry(_KIND_TOOL_RESULT, _TOOL_DB_QUERY_X),  # in-call duplicate
            _entry(_KIND_ASSISTANT, b"assistant:turn-08:order 42 confirmed twice."),
        )
    )

    # Turn 9 — HTTP repeat
    turns.append(
        (
            _entry(_KIND_SYSTEM, _SYS_BASE),
            _entry(_KIND_SYSTEM, _SYS_TOOLSCHEMA),
            _entry(_KIND_USER, b"user:turn-09:re-fetch the example API."),
            _entry(_KIND_TOOL_RESULT, _TOOL_HTTP_GET_Y),
            _entry(_KIND_ASSISTANT, b"assistant:turn-09:same 1024 bytes."),
        )
    )

    # Turn 10 — FAQ recall
    turns.append(
        (
            _entry(_KIND_SYSTEM, _SYS_BASE),
            _entry(_KIND_SYSTEM, _SYS_TOOLSCHEMA),
            _entry(_KIND_USER, _USER_FAQ_Q1),
            _entry(
                _KIND_ASSISTANT, b"assistant:turn-10:you can call the weather tool with a city."
            ),
        )
    )

    # Turn 11 — weather + new calendar tool
    turns.append(
        (
            _entry(_KIND_SYSTEM, _SYS_BASE),
            _entry(_KIND_SYSTEM, _SYS_TOOLSCHEMA),
            _entry(_KIND_USER, b"user:turn-11:any events today, and how's SF?"),
            _entry(_KIND_TOOL_CALL, b'tool_call:{"tool":"calendar","date":"2026-06-27"}'),
            _entry(
                _KIND_TOOL_RESULT,
                b'tool_result:{"tool":"calendar","events":["standup 10am","review 2pm"]}',
            ),
            _entry(_KIND_TOOL_RESULT, _TOOL_WEATHER_SF),
            _entry(_KIND_ASSISTANT, b"assistant:turn-11:2 events; SF sunny."),
        )
    )

    # Turn 12 — DB fourth occurrence
    turns.append(
        (
            _entry(_KIND_SYSTEM, _SYS_BASE),
            _entry(_KIND_SYSTEM, _SYS_TOOLSCHEMA),
            _entry(_KIND_USER, b"user:turn-12:order 42 again, please."),
            _entry(_KIND_TOOL_RESULT, _TOOL_DB_QUERY_X),
            _entry(_KIND_ASSISTANT, b"assistant:turn-12:order 42 unchanged."),
        )
    )

    # Turn 13 — HTTP third occurrence
    turns.append(
        (
            _entry(_KIND_SYSTEM, _SYS_BASE),
            _entry(_KIND_SYSTEM, _SYS_TOOLSCHEMA),
            _entry(_KIND_USER, b"user:turn-13:fetch the API once more."),
            _entry(_KIND_TOOL_RESULT, _TOOL_HTTP_GET_Y),
            _entry(_KIND_ASSISTANT, b"assistant:turn-13:still 1024 bytes."),
        )
    )

    # Turn 14 — ASSIST_PLAN_A third occurrence + in-call duplicate
    turns.append(
        (
            _entry(_KIND_SYSTEM, _SYS_BASE),
            _entry(_KIND_SYSTEM, _SYS_TOOLSCHEMA),
            _entry(_KIND_USER, b"user:turn-14:repeat your plan twice."),
            _entry(_KIND_ASSISTANT, _ASSIST_PLAN_A),
            _entry(_KIND_ASSISTANT, _ASSIST_PLAN_A),  # in-call duplicate
            _entry(_KIND_TOOL_CALL, b'tool_call:{"tool":"ping","args":{}}'),
            _entry(
                _KIND_TOOL_RESULT,
                b'tool_result:{"tool":"ping","reply":"pong","ts":"fixed-T-ping-14"}',
            ),
        )
    )

    # Turn 15 — weather fourth
    turns.append(
        (
            _entry(_KIND_SYSTEM, _SYS_BASE),
            _entry(_KIND_SYSTEM, _SYS_TOOLSCHEMA),
            _entry(_KIND_USER, b"user:turn-15:SF weather once more."),
            _entry(_KIND_TOOL_RESULT, _TOOL_WEATHER_SF),
            _entry(_KIND_ASSISTANT, b"assistant:turn-15:sunny."),
        )
    )

    # Turn 16 — HTTP fourth + in-call duplicate
    turns.append(
        (
            _entry(_KIND_SYSTEM, _SYS_BASE),
            _entry(_KIND_SYSTEM, _SYS_TOOLSCHEMA),
            _entry(_KIND_USER, b"user:turn-16:fetch the API twice for redundancy."),
            _entry(_KIND_TOOL_RESULT, _TOOL_HTTP_GET_Y),
            _entry(_KIND_TOOL_RESULT, _TOOL_HTTP_GET_Y),  # in-call duplicate
            _entry(_KIND_ASSISTANT, b"assistant:turn-16:two identical fetches."),
        )
    )

    # Turn 17 — net-new payload set A
    turns.append(
        (
            _entry(_KIND_SYSTEM, _SYS_BASE),
            _entry(_KIND_SYSTEM, _SYS_TOOLSCHEMA),
            _entry(_KIND_USER, b"user:turn-17:explore a new topic, query for support tickets."),
            _entry(
                _KIND_TOOL_CALL,
                b'tool_call:{"tool":"db_query","sql":"SELECT id FROM tickets WHERE status=\\"open\\""}',
            ),
            _entry(
                _KIND_TOOL_RESULT,
                b'tool_result:{"tool":"db_query","rows":[{"id":901},{"id":902}],"ts":"fixed-T-new-17"}',
            ),
            _entry(_KIND_ASSISTANT, b"assistant:turn-17:2 open tickets found."),
        )
    )

    # Turn 18 — net-new payload set B
    turns.append(
        (
            _entry(_KIND_SYSTEM, _SYS_BASE),
            _entry(_KIND_SYSTEM, _SYS_TOOLSCHEMA),
            _entry(_KIND_USER, b"user:turn-18:fetch a different URL for comparison."),
            _entry(
                _KIND_TOOL_CALL,
                b'tool_call:{"tool":"http_get","url":"https://example.invalid/api/v2/status"}',
            ),
            _entry(
                _KIND_TOOL_RESULT,
                b'tool_result:{"tool":"http_get","status":204,"body":"","bytes":0,"ts":"fixed-T-new-18"}',
            ),
            _entry(_KIND_ASSISTANT, b"assistant:turn-18:status endpoint returned 204 no-content."),
        )
    )

    # Turn 19 — weather fifth + winding down
    turns.append(
        (
            _entry(_KIND_SYSTEM, _SYS_BASE),
            _entry(_KIND_SYSTEM, _SYS_TOOLSCHEMA),
            _entry(_KIND_USER, b"user:turn-19:last weather check for SF before we stop."),
            _entry(_KIND_TOOL_RESULT, _TOOL_WEATHER_SF),
            _entry(_KIND_ASSISTANT, b"assistant:turn-19:final reading: sunny 72F."),
        )
    )

    # Turn 20 — FAQ wrap-up
    turns.append(
        (
            _entry(_KIND_SYSTEM, _SYS_BASE),
            _entry(_KIND_SYSTEM, _SYS_TOOLSCHEMA),
            _entry(_KIND_USER, _USER_FAQ_Q1),
            _entry(_KIND_ASSISTANT, b"assistant:turn-20:thanks for using Titan Agent."),
        )
    )

    return ToolHeavyFixture(turns=tuple(turns))


# ---------------------------------------------------------------------------
# Harness driver
# ---------------------------------------------------------------------------
def _digest(payload: bytes) -> bytes:
    return hashlib.sha256(payload).digest()


def _compute_unsent_prompt_tokens(
    entries: Sequence[ContextEntry],
    store: ContentAddressableStore,
    *,
    token_counter: TokenCounter | None = None,
) -> int:
    """Independent count of "this turn's unique-digest tokens that the store
    already contained before the call".

    Same-turn duplicates are credited only once (matching ``saved_tokens``
    in-call dedup semantics). This count is computed without consulting
    ``summarize_context``'s return value so the algebraic identity
    ``unsent == saved - new_cas`` is a genuine two-source cross-check.

    T8-S3A: ``token_counter`` is forwarded to :func:`estimate_tokens`
    when provided so the snapshot is expressed in the same units as
    ``summarize_context``'s saved/naive tallies for this turn.
    """
    total = 0
    seen_this_turn: set[bytes] = set()
    for entry in entries:
        digest = _digest(entry.payload)
        if digest in seen_this_turn:
            continue
        seen_this_turn.add(digest)
        if store.contains(digest):
            total += estimate_tokens(entry.payload, token_counter=token_counter)
    return total


def run_harness(
    fixture: ToolHeavyFixture,
    budget: ContextBudget,
    *,
    store: ContentAddressableStore | None = None,
    token_counter: TokenCounter | None = None,
) -> HarnessAggregate:
    """Fold ``fixture.turns`` through ``summarize_context`` over a shared CAS.

    If ``store`` is ``None`` a fresh :class:`ContentAddressableStore` is
    instantiated and used only for this run. Passing an existing store
    allows callers to measure cross-run plateau behaviour (a second
    invocation against the same store must report ``new_cas_total == 0``).

    For each turn this function:

    1. Snapshots, **before** calling ``summarize_context``, which of the
       turn's unique digests the shared store already contains. This
       snapshot becomes ``TurnMetrics.unsent_prompt_tokens`` for the turn.
    2. Calls ``summarize_context(turn_entries, budget, store=store)`` and
       reads ``naive_tokens / saved_tokens / new_cas_tokens / digest_order
       / total_entries / unique_entries / newly_stored_entries`` directly.

    The two sources are independent — step 1 uses ``hashlib.sha256`` and
    ``store.contains``; step 2 uses ``summarize_context`` — making the
    identity ``unsent == saved - new_cas`` (asserted by the test suite) a
    real cross-check rather than a tautology.

    All result fields are deterministic given a deterministic ``fixture``
    and an empty initial ``store``.
    """
    cas = store if store is not None else ContentAddressableStore()

    turn_metrics: list[TurnMetrics] = []
    naive_total = 0
    saved_in_call_total = 0
    new_cas_total = 0
    unsent_total = 0

    for turn_index, entries in enumerate(fixture.turns, start=1):
        unsent_this_turn = _compute_unsent_prompt_tokens(entries, cas, token_counter=token_counter)
        result = summarize_context(entries, budget, store=cas, token_counter=token_counter)

        turn_metrics.append(
            TurnMetrics(
                turn_index=turn_index,
                naive_tokens=result.naive_tokens,
                saved_tokens=result.saved_tokens,
                new_cas_tokens=result.new_cas_tokens,
                unsent_prompt_tokens=unsent_this_turn,
                total_entries=result.total_entries,
                unique_entries=result.unique_entries,
                newly_stored_entries=result.newly_stored_entries,
                digest_order=result.digest_order,
            )
        )

        naive_total += result.naive_tokens
        saved_in_call_total += result.saved_tokens
        new_cas_total += result.new_cas_tokens
        unsent_total += unsent_this_turn

    if naive_total > 0:
        in_call_dedup_ratio = (naive_total - saved_in_call_total) / naive_total
        cross_turn_unsent_ratio = unsent_total / naive_total
        cas_growth_ratio = new_cas_total / naive_total
        total_savings_ratio = (naive_total - new_cas_total) / naive_total
    else:
        in_call_dedup_ratio = 0.0
        cross_turn_unsent_ratio = 0.0
        cas_growth_ratio = 0.0
        total_savings_ratio = 0.0

    return HarnessAggregate(
        turns=tuple(turn_metrics),
        naive_total=naive_total,
        saved_in_call_total=saved_in_call_total,
        new_cas_total=new_cas_total,
        unsent_total=unsent_total,
        in_call_dedup_ratio=in_call_dedup_ratio,
        cross_turn_unsent_ratio=cross_turn_unsent_ratio,
        cas_growth_ratio=cas_growth_ratio,
        total_savings_ratio=total_savings_ratio,
        store_final_size=cas.size(),
    )
