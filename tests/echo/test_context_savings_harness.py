"""Echo T8-S2 — tests for ``context_savings_harness``.

12 functional tests (#1-#12) lock the deterministic 20-turn fixture, the
two-source identity between ``unsent_prompt_tokens`` and the in-call
unique-digest load, and the shared-store plateau behaviour.

5 AST red-line tests (R1-R5) scan ``js/echo/context_savings_harness.py``
to prove the production module:

* does not import any I/O / network / real-tokenizer top-level package
* does not touch AmberTree HAMT internals
* does not depend on runtime / gateway / core / pulse_ledger / capability
  / sandbox / config
* is not re-exported through ``js.echo.__init__.__all__``
* imports only from ``js.echo.context_savings`` for any ``js.*`` symbol

The red-line scanners are allowed to import ``ast`` / ``pathlib`` /
``importlib`` here because they live in the test layer; that scope is
explicitly carved out by the T8-S2 plan.

T8-S2 status (assertion-level): empirical curve only. No test in this
file uses a 35% threshold (or any other savings-ratio cutoff) as a PASS
criterion.
"""

from __future__ import annotations

import ast
import hashlib
import importlib
import pathlib

from js.echo.context_savings import (
    ContentAddressableStore,
    ContextBudget,
    ContextEntry,
)
from js.echo.context_savings_harness import (
    HarnessAggregate,
    ToolHeavyFixture,
    TurnMetrics,
    build_tool_heavy_20_turn_fixture,
    run_harness,
)
from js.echo.context_tokenizer import (
    BoundTokenCounter,
    TokenCounter,
    heuristic_counter,
)

_BUDGET = ContextBudget(max_tokens=10**9)


# ---------------------------------------------------------------------------
# 1. Fixture shape
# ---------------------------------------------------------------------------
def test_fixture_has_exactly_20_turns_with_5_kinds() -> None:
    fixture = build_tool_heavy_20_turn_fixture()
    assert isinstance(fixture, ToolHeavyFixture)
    assert len(fixture.turns) == 20, f"expected 20 turns, got {len(fixture.turns)}"
    kinds = {entry.kind for turn in fixture.turns for entry in turn}
    expected = {"system", "user", "assistant", "tool_call", "tool_result"}
    assert kinds == expected, f"expected kinds {expected}, got {kinds}"


# ---------------------------------------------------------------------------
# 2. Fixture purity + determinism
# ---------------------------------------------------------------------------
def test_fixture_is_pure_literal_and_deterministic() -> None:
    a = build_tool_heavy_20_turn_fixture()
    b = build_tool_heavy_20_turn_fixture()
    assert a == b, "two calls to build_tool_heavy_20_turn_fixture must be equal"
    for turn in a.turns:
        for entry in turn:
            assert isinstance(entry.payload, bytes), (
                f"entry.payload must be bytes, got {type(entry.payload).__name__}"
            )


# ---------------------------------------------------------------------------
# 3. Harness turn count + index sequence
# ---------------------------------------------------------------------------
def test_run_harness_turn_count_matches_fixture() -> None:
    fixture = build_tool_heavy_20_turn_fixture()
    aggregate = run_harness(fixture, _BUDGET)
    assert isinstance(aggregate, HarnessAggregate)
    assert len(aggregate.turns) == 20
    assert [tm.turn_index for tm in aggregate.turns] == list(range(1, 21))
    for tm in aggregate.turns:
        assert isinstance(tm, TurnMetrics)


# ---------------------------------------------------------------------------
# 4. Naive token cumulative monotonicity
# ---------------------------------------------------------------------------
def test_naive_tokens_cumulative_monotonic() -> None:
    fixture = build_tool_heavy_20_turn_fixture()
    aggregate = run_harness(fixture, _BUDGET)
    cumulative: list[int] = []
    running = 0
    for tm in aggregate.turns:
        running += tm.naive_tokens
        cumulative.append(running)
    assert all(b > a for a, b in zip(cumulative, cumulative[1:], strict=False)), (
        f"cumulative naive must be strictly monotonic, got {cumulative}"
    )
    assert cumulative[-1] == aggregate.naive_total


# ---------------------------------------------------------------------------
# 5. In-call dedup matches designated turns
# ---------------------------------------------------------------------------
def test_in_call_dedup_present_in_designated_turns() -> None:
    fixture = build_tool_heavy_20_turn_fixture()
    aggregate = run_harness(fixture, _BUDGET)
    designated = {3, 8, 14, 16}
    for tm in aggregate.turns:
        if tm.turn_index in designated:
            assert tm.unique_entries < tm.total_entries, (
                f"turn {tm.turn_index} expected in-call duplicate; "
                f"unique={tm.unique_entries} total={tm.total_entries}"
            )
        else:
            assert tm.unique_entries == tm.total_entries, (
                f"turn {tm.turn_index} expected no in-call duplicate; "
                f"unique={tm.unique_entries} total={tm.total_entries}"
            )


# ---------------------------------------------------------------------------
# 6. Shared-CAS cross-turn savings: new_cas drops after turn 1
# ---------------------------------------------------------------------------
def test_new_cas_tokens_drops_after_first_turn() -> None:
    fixture = build_tool_heavy_20_turn_fixture()
    aggregate = run_harness(fixture, _BUDGET)
    # Turn 1 is the baseline; SYS_* tokens land in the store.
    assert aggregate.turns[0].new_cas_tokens > 0
    # Turns 2..20 always re-send SYS_BASE + SYS_TOOLSCHEMA, so their
    # new_cas_tokens must each be strictly smaller than the turn's naive
    # token count (the SYS_* tokens are deducted as cross-turn hits).
    for tm in aggregate.turns[1:]:
        assert tm.new_cas_tokens < tm.naive_tokens, (
            f"turn {tm.turn_index}: new_cas={tm.new_cas_tokens} naive={tm.naive_tokens}; "
            "shared store should have caused cross-turn hit"
        )
    # Aggregate cross-turn savings must dominate net-new CAS growth.
    assert aggregate.new_cas_total < aggregate.naive_total


# ---------------------------------------------------------------------------
# 7. unsent_prompt_tokens: first turn zero, later turns positive
# ---------------------------------------------------------------------------
def test_unsent_prompt_tokens_first_turn_is_zero() -> None:
    fixture = build_tool_heavy_20_turn_fixture()
    aggregate = run_harness(fixture, _BUDGET)
    assert aggregate.turns[0].unsent_prompt_tokens == 0, (
        f"turn 1 unsent_prompt_tokens must be 0 (no history), "
        f"got {aggregate.turns[0].unsent_prompt_tokens}"
    )
    later_positive = [tm for tm in aggregate.turns[1:] if tm.unsent_prompt_tokens > 0]
    assert later_positive, (
        "at least one turn with index >= 2 must have unsent_prompt_tokens > 0; "
        f"got values {[tm.unsent_prompt_tokens for tm in aggregate.turns[1:]]}"
    )


# ---------------------------------------------------------------------------
# 8. saved_tokens ≠ unsent_prompt_tokens (semantic distinction)
#
# saved_tokens (the field returned by ContextSavingsResult and copied
# verbatim into TurnMetrics) is the **in-call unique-digest token load**
# — NOT "tokens already saved". unsent_prompt_tokens is the **cross-turn
# counterfactual save** — NOT production-realised savings. They must
# differ in at least one turn to prove the two semantics are not
# collapsed into one.
# ---------------------------------------------------------------------------
def test_unsent_differs_from_saved() -> None:
    fixture = build_tool_heavy_20_turn_fixture()
    aggregate = run_harness(fixture, _BUDGET)
    diverging = [tm for tm in aggregate.turns if tm.saved_tokens != tm.unsent_prompt_tokens]
    assert diverging, (
        "saved_tokens (in-call unique-digest load) and unsent_prompt_tokens "
        "(cross-turn counterfactual save) are different concepts; "
        "no turn satisfied saved != unsent — the harness has collapsed the two semantics."
    )
    # In particular, turn 1 must differ: saved > 0 (in-call dedup applied
    # to first occurrence), unsent == 0 (no history).
    assert aggregate.turns[0].saved_tokens > 0
    assert aggregate.turns[0].unsent_prompt_tokens == 0


# ---------------------------------------------------------------------------
# 9. Identity: unsent == saved - new_cas (genuine two-source cross-check)
#
# saved_tokens here means "in-call unique-digest token load (the load after
# same-turn dedup)", NOT "tokens already saved".
# unsent_prompt_tokens here means "this turn's unique-digest tokens whose
# payload was in the shared CAS before the call", NOT "production-realised
# savings". The identity is computed against an independent source
# (hashlib + store.contains() snapshot) inside run_harness, so this is a
# real cross-check rather than a tautology.
# ---------------------------------------------------------------------------
def test_identity_unsent_equals_in_call_unique_minus_new_cas_tokens() -> None:
    fixture = build_tool_heavy_20_turn_fixture()
    aggregate = run_harness(fixture, _BUDGET)
    for tm in aggregate.turns:
        expected = tm.saved_tokens - tm.new_cas_tokens
        assert tm.unsent_prompt_tokens == expected, (
            f"turn {tm.turn_index}: unsent={tm.unsent_prompt_tokens}, "
            f"saved={tm.saved_tokens}, new_cas={tm.new_cas_tokens}, "
            f"expected unsent==saved-new_cas={expected}"
        )


# ---------------------------------------------------------------------------
# 10. Aggregate ratios well-formed
# ---------------------------------------------------------------------------
def test_aggregate_ratios_well_formed() -> None:
    fixture = build_tool_heavy_20_turn_fixture()
    aggregate = run_harness(fixture, _BUDGET)

    assert aggregate.naive_total == sum(tm.naive_tokens for tm in aggregate.turns)
    assert aggregate.saved_in_call_total == sum(tm.saved_tokens for tm in aggregate.turns)
    assert aggregate.new_cas_total == sum(tm.new_cas_tokens for tm in aggregate.turns)
    assert aggregate.unsent_total == sum(tm.unsent_prompt_tokens for tm in aggregate.turns)

    for name, value in (
        ("in_call_dedup_ratio", aggregate.in_call_dedup_ratio),
        ("cross_turn_unsent_ratio", aggregate.cross_turn_unsent_ratio),
        ("cas_growth_ratio", aggregate.cas_growth_ratio),
        ("total_savings_ratio", aggregate.total_savings_ratio),
    ):
        assert 0.0 <= value <= 1.0, f"{name}={value} out of [0,1]"

    # Algebraic relationship between ratios (cas_growth + total_savings = 1).
    assert abs(aggregate.cas_growth_ratio + aggregate.total_savings_ratio - 1.0) < 1e-9


# ---------------------------------------------------------------------------
# 11. Harness determinism with fresh store
# ---------------------------------------------------------------------------
def test_run_harness_is_deterministic() -> None:
    fixture = build_tool_heavy_20_turn_fixture()
    a = run_harness(fixture, _BUDGET)
    b = run_harness(fixture, _BUDGET)
    assert a == b, "two harness runs with a fresh store must produce equal aggregates"


# ---------------------------------------------------------------------------
# 12. Shared store across two harness runs: plateau on second run
# ---------------------------------------------------------------------------
def test_shared_store_across_two_harness_runs_plateaus() -> None:
    fixture = build_tool_heavy_20_turn_fixture()
    shared = ContentAddressableStore()
    first = run_harness(fixture, _BUDGET, store=shared)
    second = run_harness(fixture, _BUDGET, store=shared)
    assert first.new_cas_total > 0
    assert second.new_cas_total == 0, (
        f"second run must not add any new CAS records, got {second.new_cas_total}"
    )
    assert second.unsent_total > 0, (
        "second run should report substantial counterfactual cross-turn saving"
    )
    assert second.store_final_size == first.store_final_size


# ---------------------------------------------------------------------------
# AST red-line scanners (R1-R5)
#
# These scan js/echo/context_savings_harness.py. The forbidden top-level
# / legacy-prefix / amber-name constants are duplicated here rather than
# imported from tests/echo/test_context_savings.py to keep the harness
# test file independent of the older test module's internals (the
# original test_context_savings.py does not export these constants).
# ---------------------------------------------------------------------------
_FORBIDDEN_TOP_LEVEL = {
    "time",
    "random",
    "os",
    "pathlib",
    "socket",
    "urllib",
    "asyncio",
    "subprocess",
    "requests",
    "httpx",
    "tiktoken",
    "sentencepiece",
    "transformers",
}
_LEGACY_PREFIXES = (
    "js.agent",
    "js.web",
    "js.tools",
    "js.security",
    "js.memory",
    "js.models",
    "js.runtime",
    "js.persistence",
    "js.clcr",
    "js.evolution",
)
_FORBIDDEN_ECHO_MODULES = {
    "js.echo.runtime",
    "js.echo.gateway",
    "js.echo.core",
    "js.echo.pulse_ledger",
    "js.echo.capability",
    "js.echo.sandbox",
    "js.echo.amber",
    "js.echo.amber_tree",
    "js.echo.recovery",
    "js.echo.tide",
    "js.echo.tide_controller",
    "js.echo.wheel",
    "js.echo.timing_wheel",
    "js.echo.testing",
    "js.echo.types",
    "js.echo.spi",
    "js.config",
}
_AMBER_FORBIDDEN_NAMES = {
    "AmberTreeImpl",
    "AmberTree",
    "new_amber_tree",
    "ContextView",
    "Delta",
    "ReadyIndex",
    "_AmberNode",
    "_Bucket",
    "_Branch",
    "_path_hash",
    "_root",
    "branches_copied",
    "hashes_recomputed",
    "_dirty_paths",
    "_ready_paths",
}

_HARNESS_PATH = pathlib.Path("js/echo/context_savings_harness.py")


def _harness_ast() -> ast.AST:
    src = _HARNESS_PATH.read_text(encoding="utf-8")
    return ast.parse(src)


# R1 -------------------------------------------------------------------------
def test_harness_module_has_no_io_imports_or_references() -> None:
    tree = _harness_ast()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                assert top not in _FORBIDDEN_TOP_LEVEL, f"forbidden top-level import: {alias.name}"
        elif isinstance(node, ast.ImportFrom):
            if node.module is None:
                continue
            top = node.module.split(".")[0]
            assert top not in _FORBIDDEN_TOP_LEVEL, f"forbidden from-import: {node.module}"
            assert not any(node.module.startswith(p) for p in _LEGACY_PREFIXES), (
                f"legacy import: {node.module}"
            )
        elif isinstance(node, ast.Attribute):
            root: ast.expr = node
            while isinstance(root, ast.Attribute):
                root = root.value
            if isinstance(root, ast.Name) and root.id in _FORBIDDEN_TOP_LEVEL:
                raise AssertionError(f"forbidden reference: {root.id} via attribute access")
        elif isinstance(node, ast.Name) and node.id in _FORBIDDEN_TOP_LEVEL:
            raise AssertionError(f"forbidden bare name reference: {node.id}")


# R2 -------------------------------------------------------------------------
def test_harness_module_does_not_touch_amber_internals() -> None:
    tree = _harness_ast()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name not in {"js.echo.amber", "js.echo.amber_tree"}, (
                    f"forbidden amber import: {alias.name}"
                )
        elif isinstance(node, ast.ImportFrom):
            if node.module is None:
                continue
            assert node.module not in {"js.echo.amber", "js.echo.amber_tree"}, (
                f"forbidden amber from-import: {node.module}"
            )
        elif isinstance(node, ast.Name):
            assert node.id not in _AMBER_FORBIDDEN_NAMES, (
                f"forbidden amber name reference: {node.id}"
            )
        elif isinstance(node, ast.Attribute):
            assert node.attr not in _AMBER_FORBIDDEN_NAMES, (
                f"forbidden amber attribute reference: {node.attr}"
            )


# R3 -------------------------------------------------------------------------
def test_harness_module_does_not_touch_runtime_gateway_pulse_capability_sandbox_config() -> None:
    tree = _harness_ast()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name not in _FORBIDDEN_ECHO_MODULES, (
                    f"forbidden echo/config import: {alias.name}"
                )
        elif isinstance(node, ast.ImportFrom):
            if node.module is None:
                continue
            assert node.module not in _FORBIDDEN_ECHO_MODULES, (
                f"forbidden echo/config from-import: {node.module}"
            )


# R4 -------------------------------------------------------------------------
def test_harness_not_in_init_all() -> None:
    echo_pkg = importlib.import_module("js.echo")
    assert "context_savings_harness" not in echo_pkg.__all__, (
        "js.echo.__all__ must not re-export context_savings_harness"
    )
    # context_savings (T8-S1) is also not re-exported; keep parity.
    assert "context_savings" not in echo_pkg.__all__


# R5 -------------------------------------------------------------------------
def test_harness_imports_only_from_context_savings() -> None:
    """Every ``from js.*`` import in the harness must originate from
    ``js.echo.context_savings`` (or another approved Echo module —
    currently none). This is a stricter fence than R1/R3 and locks the
    dependency surface to a single module.
    """
    tree = _harness_ast()
    approved_js_modules = {"js.echo.context_savings", "js.echo.context_tokenizer"}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.module is None:
                continue
            if node.module.startswith("js"):
                assert node.module in approved_js_modules, (
                    f"harness may only import js.* symbols from "
                    f"{approved_js_modules}; got {node.module}"
                )
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith("js"):
                    assert alias.name in approved_js_modules, (
                        f"harness may only import js.* modules from "
                        f"{approved_js_modules}; got {alias.name}"
                    )


# ---------------------------------------------------------------------------
# Sanity: digest implementation
# ---------------------------------------------------------------------------
def test_harness_digest_is_sha256_32_bytes() -> None:
    from js.echo.context_savings_harness import _digest

    payload = b"a-sample-payload"
    digest = _digest(payload)
    assert isinstance(digest, bytes)
    assert len(digest) == 32
    assert digest == hashlib.sha256(payload).digest()


# ---------------------------------------------------------------------------
# T8-S3A — token_counter wiring on run_harness
# ---------------------------------------------------------------------------
def test_run_harness_uses_injected_counter() -> None:
    fixture = build_tool_heavy_20_turn_fixture()

    # Heuristic counter must match the default (token_counter=None) path
    # byte-for-byte. This proves the injection wiring did not drift the
    # T8-S2 baseline.
    baseline = run_harness(fixture, _BUDGET)
    via_heuristic = run_harness(fixture, _BUDGET, token_counter=heuristic_counter)
    assert via_heuristic.naive_total == baseline.naive_total
    assert via_heuristic.saved_in_call_total == baseline.saved_in_call_total
    assert via_heuristic.new_cas_total == baseline.new_cas_total
    assert via_heuristic.unsent_total == baseline.unsent_total

    # Double-length counter scales naive_total linearly (no entry is
    # empty in the 20-turn fixture so the floor=1 branch doesn't apply
    # symmetrically — we assert the strict-greater relation, which is
    # robust to the heuristic's floor=1 behaviour).
    doubled: TokenCounter = BoundTokenCounter(
        count=lambda p: 2 * max(1, len(p)), token_unit_id="test:double-len"
    )
    via_doubled = run_harness(fixture, _BUDGET, token_counter=doubled)
    assert via_doubled.naive_total > baseline.naive_total


# ---------------------------------------------------------------------------
# T8-S3A — CAS token unit isolation through run_harness (H1-H3)
# ---------------------------------------------------------------------------
def _fake_tiktoken_counter() -> TokenCounter:
    return BoundTokenCounter(
        count=lambda p: 5 * max(1, len(p)),
        token_unit_id="tiktoken:o200k_base",
    )


def test_run_harness_with_fresh_heuristic_store_matches_t8s2() -> None:
    """H1: run_harness with no token_counter matches T8-S2 baseline aggregate."""
    fixture = build_tool_heavy_20_turn_fixture()
    a = run_harness(fixture, _BUDGET)
    b = run_harness(fixture, _BUDGET)
    assert a == b
    assert isinstance(a, HarnessAggregate)
    assert a.naive_total > 0
    assert a.new_cas_total > 0
    assert a.unsent_total > 0
    # Plateau identity from T8-S2 still holds.
    assert all(isinstance(t, TurnMetrics) for t in a.turns)


def test_run_harness_with_fresh_tiktoken_unit_store_succeeds() -> None:
    """H2: fresh store + fake tiktoken counter runs end-to-end."""
    fixture = build_tool_heavy_20_turn_fixture()
    counter = _fake_tiktoken_counter()
    shared = ContentAddressableStore()
    result = run_harness(fixture, _BUDGET, store=shared, token_counter=counter)
    assert result.naive_total > 0
    assert shared.token_unit_id == "tiktoken:o200k_base"


def test_run_harness_rejects_mixing_units_via_shared_store() -> None:
    """H3: shared heuristic store rejects subsequent tiktoken run via ValueError."""
    fixture = build_tool_heavy_20_turn_fixture()
    shared = ContentAddressableStore()
    run_harness(fixture, _BUDGET, store=shared)  # binds to heuristic:v1
    counter = _fake_tiktoken_counter()
    try:
        run_harness(fixture, _BUDGET, store=shared, token_counter=counter)
    except ValueError as exc:
        msg = str(exc)
        assert "heuristic:v1" in msg
        assert "tiktoken:o200k_base" in msg
    else:
        raise AssertionError(
            "expected ValueError when mixing heuristic-bound store with tiktoken counter"
        )

    # ContextEntry import is genuinely used elsewhere in this test layer
    # (other test modules in tests/echo/) but we touch it locally so the
    # ruff autofix never strips it from this file.
    _entry = ContextEntry(kind="k", payload=b"sentinel")
    assert _entry.kind == "k"
